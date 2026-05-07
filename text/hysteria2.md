# Hysteria 2

## TL;DR

QUIC proxy that does HTTP/3-shaped auth (a single request to
`https://hysteria/auth` with a `Hysteria-Auth: <password>` header,
server returns status `233`) and then carries proxy traffic as
custom-typed QUIC stream frames + QUIC datagrams. An optional
**Salamander** UDP-layer obfuscation wraps each packet (including
the QUIC handshake) in a BLAKE2b-256 keystream XOR keyed by a PSK +
per-packet random salt. Without Salamander: looks like normal
HTTP/3. With Salamander: looks like opaque UDP noise.

## Threat Model

Different shape from the TLS-mimicry family. Hysteria2 targets:

- **HTTP/3-aware DPI**: most production censors haven't built up
  HTTP/3 deep-inspection capabilities to the level they have for
  TLS over TCP. A passive observer of an unobfuscated hysteria2
  connection sees a plausible HTTP/3 session.
- **Active probing**: a probe that connects to the QUIC endpoint
  has to complete a real QUIC + TLS-1.3 handshake, then send the
  exact `/auth` request with the right `Hysteria-Auth` value.
  Wrong auth → server returns a normal HTTP error.
- **Generic UDP blocking**: Salamander turns the QUIC connection
  into "random-looking UDP packets with no handshake structure," so
  censors that match QUIC's distinctive Initial-packet header
  (long-header, version, connection-IDs, fingerprintable TLS
  ClientHello inside Initial) can't pattern-match.

Does **not** address:

- **All-UDP-blocked networks** (e.g. some Russian mobile carriers).
  Hysteria2 is fundamentally UDP, no TCP fallback in protocol — fall
  back to a different protocol entirely.
- **IP reputation** — same as the rest of the catalog.
- **Behavioral-volume profiling** of a single long-lived UDP flow
  carrying high throughput (Hysteria's congestion control is
  intentionally aggressive for performance, which is itself a
  fingerprint candidate against bandwidth-shaping observers).

## Wire Format

### Top-level layering

```
                   ┌─────────────────────────────────────┐
                   │ Salamander (optional, off by default) │
                   │  per-packet: 8-byte salt prefix +     │
                   │  BLAKE2b-256(psk||salt)-keystream XOR │
                   ├─────────────────────────────────────┤
                   │ QUIC v1 (apernet/quic-go fork)        │
                   │  TLS 1.3 handshake, streams + dgrams  │
                   ├─────────────────────────────────────┤
                   │ HTTP/3 — auth only                    │
                   │  client -> POST https://hysteria/auth │
                   │  server -> status 233 if OK           │
                   ├─────────────────────────────────────┤
                   │ Hysteria framing                      │
                   │  TCP requests on streams (0x401)      │
                   │  UDP messages on QUIC datagrams       │
                   └─────────────────────────────────────┘
```

### Auth (HTTP/3)

Client opens a QUIC connection (Salamander-wrapped if enabled),
completes the QUIC + TLS handshake, then sends a single HTTP/3
request:

```
GET https://hysteria/auth
Hysteria-Auth: <psk-password>
Hysteria-CC-RX: <client-uplink-bandwidth-uint64-or-0>
Hysteria-Padding: <random-bytes>
```

Server response on success:

```
HTTP/3 233 (StatusAuthOK — non-standard intentional)
Hysteria-UDP: true|false
Hysteria-CC-RX: <server-side-rate-limit-or-"auto">
Hysteria-Padding: <random-bytes>
```

The non-standard `233` status code is the canonical "this is a real
hysteria server saying yes" — meaningless to a generic HTTP/3
client, distinctive enough to authenticate the protocol identity.
Any other response (including `404`) → not a hysteria server.

The `Hysteria-Padding` header is filled with random bytes to
randomize the size of the auth request/response — counters fixed-size
DPI heuristics on first-RTT byte counts.

### TCP request frame (proxy traffic)

Per [`core/internal/protocol/proxy.go:32-84`](https://github.com/apernet/hysteria/blob/ed4127a/core/internal/protocol/proxy.go#L32-L84):

```
[QUIC varint: FrameTypeTCPRequest = 0x401]
[QUIC varint: addr length]
[bytes:        target addr (e.g. "example.com:443")]
[QUIC varint: padding length]
[bytes:        random padding]
```

Server responds in-stream:

```
[byte:         status (0x00 = ok, 0x01 = error)]
[QUIC varint: msg length]
[bytes:        error message (empty on ok)]
[QUIC varint: padding length]
[bytes:        random padding]
```

After the response header, the QUIC stream is just bidirectional
proxy bytes.

### UDP datagram

Per `proxy.go:151-172`:

```
[uint32 BE: SessionID]
[uint16 BE: PacketID]
[uint8:    FragID]
[uint8:    FragCount]
[QUIC varint: addr length]
[bytes:    target UDP addr]
[bytes:    payload]
```

Carries a single proxied UDP packet (or one fragment thereof) as
one QUIC datagram. UDP-over-UDP, no per-flow stream state, with
explicit fragmentation for paths whose path-MTU < proxied packet.

### Salamander packet wrapping (optional)

Per [`extras/obfs/salamander.go`](https://github.com/apernet/hysteria/blob/ed4127a/extras/obfs/salamander.go):

```
output[0:8]   = random salt (read fresh per packet)
key           = BLAKE2b-256(PSK || salt)        // 32 bytes
output[8:]    = input[i] XOR key[i mod 32]
```

PSK length minimum: 4 bytes. Same wrapping is applied symmetrically
on receive. Because the salt is per-packet random, the resulting
wire bytes have no structural regularity — no QUIC long-header,
no TLS ClientHello, nothing a fingerprinter can match against.

## Cover Protocol

Two operating modes, picked at config time:

- **No Salamander**: connection looks like a normal QUIC v1 +
  HTTP/3 session to a generic HTTP/3 server. SNI / ALPN are real
  TLS extensions. Auth blends into the HTTP/3 traffic — the
  `Hysteria-*` headers are bespoke but a passive HTTP/3 observer
  doesn't usually inspect headers. **Vulnerable to**: a censor that
  builds a fingerprint for "HTTP/3 connection that gets exactly one
  request to a virtual host of `hysteria` and one `233` response."
- **Salamander on**: the connection looks like UDP packets with
  random payloads; the QUIC handshake itself is hidden inside the
  XOR layer, so a passive observer sees no QUIC at all. **Vulnerable
  to**: probabilistic UDP-flow analysis (entropy, packet-size
  distribution, packet-rate). Salamander is not designed to mimic
  any specific cover protocol — it's "look-like-nothing" obfuscation
  applied over QUIC.

## Authentication

Pre-shared password.

- Client puts the password in `Hysteria-Auth: <password>` and sends
  the auth request inside the established QUIC + TLS-1.3 connection.
- Server compares (constant-time, in the canonical implementation)
  against its configured value. Match → status 233 + `UDPEnabled`
  capability + a server-side rate hint. Mismatch → standard HTTP/3
  error response, connection torn down.
- If Salamander is enabled, the password feeding Salamander is
  **separate** from the auth password by default — operators can
  configure them differently, though most deployments use one
  shared secret.

There is no key exchange beyond what QUIC's TLS 1.3 already provides;
the password is just an HTTP-header credential transmitted inside
the encrypted QUIC channel.

## Probe Resistance

Layered:

1. **QUIC + TLS 1.3 handshake required.** A probe must complete a
   full QUIC handshake before it can send any HTTP/3 traffic. The
   handshake itself is bog-standard QUIC v1, so no obvious
   tells — but it does mean every probe pays a real RTT cost.
2. **Wrong auth → real HTTP/3 error.** No special "you're a probe"
   response — the server just returns a non-`233` HTTP/3 status. A
   probe can't distinguish "wrong password" from "this server
   doesn't know about hysteria."
3. **Salamander makes step 1 unreachable.** With Salamander
   enabled, a probe that doesn't know the PSK can't even initiate
   the QUIC handshake (its packets get XOR'd with a key derived
   from a salt the server doesn't know). The server simply doesn't
   see a valid QUIC Initial packet and never responds.

Step 3 is the biggest evasion lever — without Salamander, a
sufficiently determined censor can scan IPs by sending HTTP/3
requests to `https://hysteria/auth` and looking for `233` responses,
which is a clean fingerprint. With Salamander, the proxy IP looks
like dead UDP and active probing is materially harder.

## Implementation

Pinned at upstream commit
[`ed4127a`](https://github.com/apernet/hysteria/commit/ed4127a).

Repo: `github.com/apernet/hysteria` (MIT). Pure Go. Uses a fork of
quic-go ([`apernet/quic-go`](https://github.com/apernet/quic-go))
for the custom congestion-control hooks ("Brutal CC").

Key files:

- [`core/internal/protocol/http.go`](https://github.com/apernet/hysteria/blob/ed4127a/core/internal/protocol/http.go) — auth wire format. Constants `URLHost = "hysteria"`, `URLPath = "/auth"`, `RequestHeaderAuth = "Hysteria-Auth"`, `ResponseHeaderUDPEnabled = "Hysteria-UDP"`, `CommonHeaderCCRX = "Hysteria-CC-RX"`, `CommonHeaderPadding = "Hysteria-Padding"`, `StatusAuthOK = 233`.
- [`core/internal/protocol/proxy.go`](https://github.com/apernet/hysteria/blob/ed4127a/core/internal/protocol/proxy.go) — `FrameTypeTCPRequest = 0x401`, max sizes (`MaxAddressLength = 2048`, `MaxMessageLength = 2048`, `MaxPaddingLength = 4096`, `MaxDatagramFrameSize = 1200`, `MaxUDPSize = 4096`), TCP/UDP frame readers/writers.
- [`core/internal/protocol/padding.go`](https://github.com/apernet/hysteria/blob/ed4127a/core/internal/protocol/padding.go) — variable-size padding tables for the auth and per-frame padding fields.
- [`extras/obfs/salamander.go`](https://github.com/apernet/hysteria/blob/ed4127a/extras/obfs/salamander.go) — `SalamanderObfuscator`. `smPSKMinLen = 4`, `smSaltLen = 8`, `smKeyLen = 32` (BLAKE2b-256 output). Wraps the underlying `net.PacketConn` so QUIC sees pre-de-obfuscated bytes.
- [`extras/obfs/conn.go`](https://github.com/apernet/hysteria/blob/ed4127a/extras/obfs/conn.go) — the `PacketConn` wrapper integration.

Notable defaults: padding lengths are randomized per-call; UDP
fragmentation kicks in if a proxied UDP packet exceeds
`MaxDatagramFrameSize`; congestion control plug points are part of
the apernet/quic-go fork (not the upstream quic-go), so any
non-apernet QUIC stack reimplementing hysteria2 (e.g. sing-box's
internal version) needs to track those CC hooks separately.

## Known Weaknesses

- **HTTP/3-aware DPI** (when Salamander is off): the auth pattern —
  one HTTP/3 request to `https://hysteria/auth` with a custom header,
  one `233` response — is fingerprintable if the censor builds for
  it. Not seen in production censors as of the catalog's writing,
  but a foreseeable arms-race step.
- **All-UDP-blocked networks**: nothing in hysteria2 falls back to
  TCP. This is a known limitation; deployments in Russia / mobile-
  carrier contexts pair it with TCP-based protocols (samizdat,
  reflex, REALITY).
- **High-throughput-flow profiling**: hysteria's aggressive
  congestion control is part of the appeal, but a long-lived UDP
  flow at sustained high bandwidth is a behavioral signal that
  doesn't match typical cover-protocol traffic (browsing, streaming).
  Censors that block based on flow-level statistics rather than
  protocol fingerprinting can still flag hysteria2 connections.
- **Salamander key reuse**: every packet uses a fresh salt, but the
  PSK is long-term. A censor that records a session and ever learns
  the PSK can decrypt the obfuscation layer retroactively. (This is
  inherent to "PSK + per-packet salt" stream obfuscators.)
- **`StatusAuthOK = 233`** is intentionally weird, which makes it
  easy for a censor to scan for. Not exploitable without first
  reaching the HTTP/3 layer (i.e. Salamander mitigates this), but
  it's a strong fingerprint when Salamander is off.

## Deployment Notes

- One of the protocols Lantern's bandit can pick from for `lantern-box`-based clients. Available in `circumvention-corpus-private`'s `2026-04-non-protocol-evasion` recommendations as a complement to (not replacement for) the TLS-side protocols when UDP is permitted.
- Best paired with Salamander on hostile networks. Without
  Salamander, treat the protocol as "fast in lossy networks but
  not heavily-censored networks."
- sing-box ships its own hysteria2 implementation (different QUIC
  stack); behavior is wire-compatible but operational ergonomics
  differ slightly (CC tuning, mux defaults).
- Mobile carriers that block all UDP / inhibit QUIC by AS-level
  policy disable hysteria2 entirely; bandit data on those ASNs
  shows hysteria2 routes failing fast, which the bandit handles
  via EXP3 weights but is worth knowing when designing rollouts.

## Cross-References

- Internal: `2026-04-non-protocol-evasion` — discusses hysteria2 in
  the protocol-stack inventory and notes the UDP-only constraint as
  a deployment caveat.
- Related protocols (this catalog):
  - `samizdat` / `reflex` / `vless-reality` — TCP-based TLS-mimicry
    siblings. Pair with hysteria2 across (TCP, UDP) for network-
    diverse coverage rather than treating any one as a one-stop
    answer.
  - (TBD) `tuic` — QUIC-based proxy with a different auth design;
    relevant comparison for "what other QUIC protocols exist?"
  - (TBD) `naive` — uses HTTP/2 over TLS instead of HTTP/3 over QUIC,
    with full-Chromium-stack mimicry. Different spot in the design
    space (TCP cover, browser fingerprint borrow) from hysteria2's
    UDP cover.
