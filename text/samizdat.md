# Samizdat

## TL;DR

Lantern's primary protocol. One TLS 1.3 connection with a uTLS Chrome
ClientHello to a cover-site SNI (e.g. `ok.ru`); HTTP/2 CONNECT
multiplexes many tunneled streams over the single TCP connection;
authentication is a HMAC tag in the TLS SessionID; on auth failure
the server transparently TCP-proxies the connection to the real cover
domain, so an active probe sees the real site's cert and behavior end
to end. Targets the full TSPU detection stack (entropy fingerprinting,
TLS-over-TLS, cross-layer RTT, TCP-DPI SNI extraction, connection-count
policing, active probing).

## Threat Model

Specifically built against Russia's TSPU and the live-blocking
techniques observed against Lantern + other circumvention tools. From
the upstream README and live measurements:

- **First-packet entropy detection** (e.g. against Shadowsocks) — high-
  entropy first packet is an unconditional "no real protocol matches"
  signal.
- **TLS-over-TLS detection** — encrypted traffic with the structural
  signature of a TLS handshake nested inside another TLS connection.
- **Cross-layer RTT fingerprinting** — passive timing analysis to
  detect "TLS handshake then sudden quiet then bulk encrypted data"
  vs. "natural HTTP browsing rhythm."
- **15-20 KB data-volume thresholds** triggering inspection escalation.
- **TLS connection-count policing on port 443** — too many concurrent
  TLS handshakes from one client.
- **Active probing** — the censor connects to suspected proxy IPs
  with replayed or random ClientHellos to confirm.
- **Post-handshake fingerprinting** — distinctive client-info exchanges
  in the first encrypted bytes after the handshake.
- **Stateless TCP-DPI SNI extraction** — pulling SNI from a single
  packet without TCP reassembly.

It does **not** defend against IP-reputation blocking (the server's IP
still has to be reachable; if the IP is blocklisted, samizdat traffic
to it never starts). That's why Lantern pairs samizdat with infra
diversity (OCI / Linode / Alicloud) and the residential-peer-proxies
work.

## Wire Format

```
Client                                      Server
  |                                            |
  |  TCP SYN                                   |
  |  TLS 1.3 ClientHello (uTLS Chrome) ----->  |  ClientHello fragmented across
  |    SNI = ok.ru (cover domain)              |  >=2 TCP segments at SNI
  |    SessionID = shortID || nonce || HMAC    |  boundary, 1-30ms gap between
  |                                            |  segments (defeats stateless
  |                                            |  TCP-DPI SNI extraction)
  |                                            |
  |                                            |  Server peels SessionID:
  |                                            |    shortID -> lookup PSK
  |                                            |    PSK = HKDF-SHA256(serverPub,
  |                                            |              shortID, "SAMIZDAT")
  |                                            |    verify HMAC tag
  |                                            |  If FAIL: hand the buffered
  |                                            |  ClientHello bytes to the
  |                                            |  TCP-masquerade proxy
  |                                            |
  |  <-- ServerHello + cert (real cover cert)  |
  |  TLS handshake completes                   |
  |  ALPN -> h2                                |
  |  HTTP/2 SETTINGS exchange  <----------->   |
  |                                            |
  |  H2 CONNECT host:port (stream N) ------->  |
  |  <-- 200 OK                                |
  |  bidirectional H2 DATA frames              |  payload bytes; outgoing
  |                                            |  side adds 1-30ms jitter
  |                                            |
  |  ... more CONNECT streams over the same    |
  |      single TCP/TLS connection ...         |
```

The SessionID is a standard TLS 1.3 field carried in the ClientHello,
so the wire shape on the network is identical to a normal Chrome
handshake — no extra extensions, no extra bytes.

## Cover Protocol

To a passive observer: HTTPS to the cover domain (e.g. `ok.ru`). Same
SNI, same cert chain, same HTTP/2 negotiation, same long-lived TCP
connection that's typical of an HTTP/2-using browser tab.

## Authentication

In-band, embedded in the TLS SessionID field of the ClientHello.

- **Pre-shared between client and server**: server's X25519 public key
  (32 bytes) and an 8-byte short ID.
- **PSK derivation**: `HKDF-SHA256(IKM=serverPubKey, salt=shortID,
  info="SAMIZDAT")` → 32-byte PSK. Both sides compute it independently.
- **SessionID layout (32 bytes)**:
  - `[0:8]` shortID (plaintext, lets the server look up the PSK)
  - `[8:16]` random nonce (per-connection)
  - `[16:32]` HMAC-SHA256(PSK, nonce) truncated to 16 bytes

The server peels off the shortID, derives the PSK, recomputes the
HMAC, and compares. There's no separate handshake message — the
authentication signal lives inside a field that real TLS clients are
free to fill arbitrarily, so passive DPI can't tell the difference
between an authenticated samizdat ClientHello and a normal Chrome
ClientHello.

## Probe Resistance

When `verifyAuth` fails (no matching PSK or HMAC mismatch — including
plain probes with random or replayed SessionIDs), the server **does
not send any samizdat-specific response**. Instead it hands the raw
buffered ClientHello bytes to a TCP-level transparent proxy
(`Masquerade.ProxyConnection` in `masquerade.go`) which:

1. Dials the real cover domain over TCP.
2. Forwards the original ClientHello bytes verbatim.
3. Runs `io.Copy` in both directions until either side closes (default
   5-minute idle timeout, 10-minute absolute cap).

The probe completes a real TLS handshake with the real cover domain's
cert and behaves identically to a real visit. The server doesn't parse
or modify any TLS / HTTP content — it's purely byte-forwarding at
TCP level. Inspired by `getlantern/tlsmasq`.

This means an active prober scanning the IP can't distinguish the
samizdat server from the real cover domain at any layer: same cert,
same TLS quirks, same HTTP responses, same timing.

## Implementation

Pinned at upstream commit
[`9256300`](https://github.com/getlantern/samizdat/commit/9256300).

Repo: `github.com/getlantern/samizdat` (Apache-2.0). Pure Go.
Consumed by `getlantern/lantern-box` (sing-box outbound + inbound) and
ultimately by Lantern's bandit-driven proxy selection.

Key files:

- [`auth.go`](https://github.com/getlantern/samizdat/blob/9256300/auth.go) — HKDF PSK derivation, SessionID build / verify; constants `authLabel = "SAMIZDAT"`, `sessionIDLen = 32`, `hmacTagLen = 16`, `shortIDLen = 8`, `nonceLen = 8`.
- [`samizdat.go`](https://github.com/getlantern/samizdat/blob/9256300/samizdat.go) — `ClientConfig` / `ServerConfig` + defaults: `Fingerprint="chrome"`, `MaxJitterMs=30`, `MaxStreamsPerConn=100` (client) / `MaxConcurrentStreams=250` (server), `IdleTimeout=5m`, `ConnectTimeout=15s`.
- [`fragmenter.go`](https://github.com/getlantern/samizdat/blob/9256300/fragmenter.go) — Geneva-inspired TCP fragmentation; intercepts the first `Write` and splits at the SNI field boundary with a randomized delay.
- [`shaper.go`](https://github.com/getlantern/samizdat/blob/9256300/shaper.go) — outgoing-frame timing jitter (1 to `MaxJitterMs` ms, default 30).
- [`h2transport.go`](https://github.com/getlantern/samizdat/blob/9256300/h2transport.go) — HTTP/2 transport wrapping the TLS connection.
- [`connpool.go`](https://github.com/getlantern/samizdat/blob/9256300/connpool.go) — multiplexing pool that reuses one TCP/TLS conn for many H2 CONNECT streams.
- [`masquerade.go`](https://github.com/getlantern/samizdat/blob/9256300/masquerade.go) — `Masquerade.ProxyConnection(conn, clientHello)` — the TCP-level transparent proxy on auth failure.
- [`server.go`](https://github.com/getlantern/samizdat/blob/9256300/server.go) — verifies auth, falls back to masquerade at line 188.
- [`client.go`](https://github.com/getlantern/samizdat/blob/9256300/client.go) — uTLS dialer that builds the auth-bearing SessionID and wires up fragmentation + shaping.

## Known Weaknesses

- **IP reputation**: the server IP is reachable to the censored
  client; if the IP shows up on a blocklist, samizdat traffic to it
  is dropped at L3/L4 before any of the protocol-level evasions
  matter. Lantern compensates with infrastructure diversity and the
  in-progress residential-peer-proxies work.
- **Cover-domain reputation / availability**: if the censor blocks
  the cover domain itself (e.g. `ok.ru`), the cover collapses. Picking
  a domain with high collateral damage is part of the operational
  story.
- **TLS 1.3 ECH gap**: as written, samizdat does not require ECH; the
  cover SNI is still in clear-but-fragmented form. A censor that
  reassembles TCP segments and matches SNI against a blocklist still
  blocks. Geneva fragmentation defeats the *stateless* class of TCP-
  DPI SNI extractors only.
- **uTLS fingerprint drift**: a Chrome JA3/JA4 from a stale uTLS
  release can diverge from current Chrome. Needs ongoing maintenance
  against the moving target.

## Deployment Notes

- Primary protocol on Lantern's bandit. Selected per (ASN, country)
  by EXP3.S based on observed performance.
- Cover domain configured per track (e.g. `ok.ru` for Russia-focused
  tracks).
- Single-TCP / many-streams design means a Lantern client typically
  has 1-2 long-lived TCP connections to the proxy regardless of how
  many tabs / apps are using the VPN — defeats per-IP TLS-conn-count
  policing on port 443.
- Sensitive to MTU on the path: very small client-side MTU has
  triggered observable behaviors in the past — see Lantern's internal
  silence-timeout / Reflex work for related findings.

## Cross-References

- Internal: [`2026-04-non-protocol-evasion`](../circumvention-corpus-private/docs/2026-04-non-protocol-evasion.yaml) — recommendations that include samizdat-side hardening
- Internal: [`2026-04-residential-peer-proxies`](../circumvention-corpus-private/docs/2026-04-residential-peer-proxies.yaml) — proposes running the full samizdat stack on volunteer residential IPs (R1.1)
- Internal: [`2026-04-reflex-whitepaper`](../circumvention-corpus-private/docs/2026-04-reflex-whitepaper.yaml) — TLS handshake role reversal; samizdat is the natural inner protocol for Reflex
- Related protocols (this catalog): `tlsmasq` (the TCP-masquerade ancestor of samizdat's probe-resistance design), `vless-reality` (different mechanism, similar threat model — borrows real cert via outbound-to-real-server instead of forwarding probes).
