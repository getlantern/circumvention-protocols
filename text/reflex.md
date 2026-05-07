# Reflex

## TL;DR

Reverse the TLS role relative to TCP: the TCP client (censored side) is
the TLS server; the TCP server (proxy) is the TLS client. The first
bytes the censor sees in the client→server direction are not a
ClientHello — they're nothing, until the proxy speaks. Authentication
is the SHA-256 fingerprint of the client's TLS cert, validated inside
the standard TLS handshake. Probes that speak first (replayed
ClientHellos, ordinary scanners) get transparently TCP-proxied to a
real TLS service and never see Reflex.

## Threat Model

Reflex is targeted at the three TLS-based detection techniques that
share the assumption "the censored client sends the first ClientHello":

- **SNI extraction** (USENIX Security 2025) — pulling the SNI from the
  client→server first record and matching against a domain blocklist.
- **JA3 / JA4 fingerprinting** — hashing the client→server ClientHello's
  cipher-suite / extension / supported-group ordering to identify
  non-browser TLS stacks.
- **Fully-encrypted-traffic detection** (USENIX Security 2023) —
  flagging high-entropy traffic whose first client→server packet
  doesn't match any known protocol signature.

All three inspect the **client→server direction of the first data
packet**. In Reflex, that direction either contains nothing (during the
silence window) or eventually contains a TLS ServerHello, never a
ClientHello.

It does **not** defend against IP-reputation blocking (the proxy IP is
still reachable and probable). It also doesn't help against UDP-only
censorship channels — Reflex is TCP-only by design.

## Wire Format

```
Censored client (TCP client / TLS server)        Proxy (TCP server / TLS client)
  |                                                  |
  |-- TCP SYN ------------------------------------>  |  Server has just accepted
  |   (no application data sent)                     |  a TCP connection.
  |                                                  |
  |   ... silent for                                 |  Server starts a
  |       silence_timeout ± silence_jitter ...       |  jittered countdown.
  |                                                  |
  |                                                  |  If any byte arrives in
  |                                                  |  this window: forward
  |                                                  |  the connection (with
  |                                                  |  the byte prefixed) to
  |                                                  |  masquerade_upstream.
  |                                                  |
  |  <-- TLS 1.3 ClientHello -----------------------  |  Silence elapsed →
  |   (server initiates the TLS handshake)           |  proxy sends CH.
  |                                                  |
  |  -- ServerHello + cert (client's cert) -------->  |  Client (TLS-server) replies.
  |  <-- Finished -----------------------------------  |  Standard TLS 1.3.
  |  -- Finished ----------------------------------->  |
  |                                                  |  Server checks:
  |                                                  |    sha256(peer cert DER)
  |                                                  |    in auth_tokens?
  |                                                  |  If no: drop.
  |                                                  |
  |  bidirectional standard TLS 1.3 Application Data |
  |  (indistinguishable from any other TLS 1.3 conn  |
  |   at the record level)                           |
```

The SNI in the ClientHello is whatever `server_name` the proxy is
configured with; since that ClientHello travels server→client, the
SNI is **not visible** to a typical SNI-extraction DPI which only
parses the client→server side.

## Cover Protocol

Once the TLS handshake completes, the connection is bit-identical to a
normal TLS 1.3 session at the record layer. To a passive observer the
flow is "TCP connection to a server, brief silence, then a TLS 1.3
handshake (in the unusual direction), then encrypted application
data." The unusual direction is the only oddity, and it's not a
fingerprint that current production censors trigger on (yet — the
team explicitly tracks this as a future research risk).

## Authentication

Embedded in the TLS handshake. No pre-handshake auth message; no
custom records; nothing that could fingerprint the protocol.

- The censored client (TLS server in this protocol) presents a TLS
  certificate during the handshake.
- The proxy (TLS client) computes `sha256(cert.Raw)` of the peer's
  presented cert and looks it up in a configured set of allowed
  fingerprints (`auth_tokens` in the config: lowercase hex, exactly
  64 chars / 32 bytes, validated at startup).
- If the fingerprint isn't in the set, the proxy drops the connection.

This is symmetric to a standard mTLS validation, except the auth
direction is reversed (proxy validates the client's cert by
fingerprint instead of by chain-to-CA).

## Probe Resistance

Silence-based, two-layer:

1. **Silence gate**: When the proxy accepts a TCP connection, it
   reads for up to `silence_timeout ± silence_jitter`. A real Lantern
   client sends nothing in this window — it's waiting for the proxy
   to send its ClientHello. An active probe (e.g. a censor scanner
   replaying a real ClientHello, or a misdirected ordinary TLS client)
   speaks immediately. **Any byte received during the window** is
   the "this is not a Lantern client" signal.
2. **Masquerade fallback**: If the gate fires (client spoke), the
   proxy forwards the connection (with the consumed byte prefixed)
   to `masquerade_upstream` — typically a real TLS service like
   `www.example.com:443`. The probe completes a real TLS handshake
   with the upstream's real cert and behaves identically to a real
   visit. The proxy doesn't parse or modify any TLS / HTTP content;
   it's pure byte-forwarding via `io.Copy` in both directions.

Combined: a probe that connects to the proxy and immediately replays
a ClientHello (the standard active-probing technique against TLS-
mimicry protocols) gets transparently TCP-proxied to a real TLS
service and never sees Reflex, never gets a Reflex-specific response,
and can't tell the proxy IP from any other TLS-fronted host.

The whitepaper notes a small first-byte-latency cost for legitimate
Lantern clients (they wait `silence_timeout` for the proxy's
ClientHello). The Universal IP Gate / R11.3 work removes that cost
for known clients by allowing them to skip the silence window.

## Implementation

Pinned at lantern-box commit
[`1b42ea8`](https://github.com/getlantern/lantern-box/commit/1b42ea8).

Repo: `github.com/getlantern/lantern-box` (Apache-2.0). Pure Go.
Registers as a sing-box inbound + outbound under
`constant.TypeReflex` and is consumed via standard sing-box config.

Key files:

- [`option/reflex.go`](https://github.com/getlantern/lantern-box/blob/1b42ea8/option/reflex.go) — `ReflexInboundOptions` (`auth_tokens`, `server_name`, `silence_timeout`, `silence_jitter`, `masquerade_upstream`) and `ReflexOutboundOptions` (`cert_pem` / `key_pem` / `cert_path` / `key_path`, `connect_timeout`).
- [`protocol/reflex/outbound.go`](https://github.com/getlantern/lantern-box/blob/1b42ea8/protocol/reflex/outbound.go) — package doc spelling out role reversal; outbound dials TCP, then runs as `tls.Server(...)`.
- [`protocol/reflex/inbound.go`](https://github.com/getlantern/lantern-box/blob/1b42ea8/protocol/reflex/inbound.go) — accepts TCP, runs `waitForSilence`, then either forwards to masquerade or runs as `tls.Client(...)` and validates `sha256(peerCert.Raw)`.
- [`protocol/reflex/silence.go`](https://github.com/getlantern/lantern-box/blob/1b42ea8/protocol/reflex/silence.go) — `waitForSilence(conn, timeout)` reads up to one byte with a deadline; `(nil, nil)` = silence elapsed (good); `(data, nil)` = client spoke (bad, hand off to masquerade).
- [`protocol/reflex/masquerade.go`](https://github.com/getlantern/lantern-box/blob/1b42ea8/protocol/reflex/masquerade.go) — `forwardToMasquerade(ctx, conn, upstream, prefix)`: dials upstream over TCP, replays the prefix bytes, runs bidirectional `io.Copy` until either side closes (10 s dial timeout).

Defaults observed in the inbound constructor: `serverName` defaults
to `"www.example.com"`; `defaultSilenceJitter = 2 * time.Second` when
`silence_timeout` is set without an explicit jitter; auth-token
strings must be exactly 64 lowercase hex chars (32-byte SHA-256).

## Known Weaknesses

- **The role-reversal asymmetry is itself a fingerprint candidate**.
  Today's production censors don't appear to flag "TCP server sends
  the ClientHello," but that's a behavioral signature an adversary
  could learn. The whitepaper acknowledges this and pairs Reflex
  with samizdat-style infra diversity rather than relying on it as
  the only line of defense.
- **Silence-based probe resistance has a latency tax** for legit
  clients during the first byte (≈ `silence_timeout`, default ~5 s
  in production). The Universal IP Gate (R11.3 in
  `2026-04-non-protocol-evasion`) is the planned fix for known
  clients.
- **Misbehaving middleboxes** can spuriously inject bytes during the
  silence window and trip the masquerade — a class of false-positive
  the team has documented in the whitepaper's silence-timeout
  middlebox-interference section.
- **IP reputation** is unaddressed by Reflex itself; combine with
  residential peer proxies / cover-domain fronting for end-to-end
  evasion.

## Deployment Notes

- Status per the internal whitepaper (Apr 12, 2026): "Implemented,
  E2E tested, deployed."
- Naturally composes with: residential peer proxies (both endpoints
  on residential IPs → no datacenter-IP signal); samizdat (Reflex's
  encrypted channel can carry samizdat as the inner protocol);
  Universal IP Gate (eliminates the silence-window latency cost for
  known clients).
- The internal `2026-04-non-protocol-evasion` doc lists Reflex as
  the recommended TLS-side hardening (R11.1) and is the integration
  reference for fleet-wide deployment.

## Cross-References

- Internal whitepaper: `2026-04-reflex-whitepaper`
- Internal recommendations doc: `2026-04-non-protocol-evasion` (R11.1, R11.3)
- Related protocols (this catalog):
  - `samizdat` — sibling Lantern protocol; same TCP-masquerade-on-failure pattern, different "is this a Lantern client?" signal (in-band TLS SessionID auth vs. silence-based gate).
  - `vless-reality` — also defeats SNI / JA3 / JA4, but via real-cert borrowing in the standard TLS direction rather than by reversing roles.
