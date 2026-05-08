# Outline Shadowsocks (AEAD)

## TL;DR

Outline's implementation of AEAD-Shadowsocks (per the `shadowsocks.org`
AEAD spec). Wire format: 16/24/32-byte random salt → AEAD-encrypted
SOCKS-style target address → AEAD-encrypted application payload.
HKDF-SHA1 key derivation from a shared password. Supported ciphers:
ChaCha20-Poly1305, AES-128/192/256-GCM. The Outline-specific
contribution beyond stock Shadowsocks is **lazy-write packet
shaping** on the client side and **salt-replay history + first-
packet prefix support** on the server side.

The Outline product (Outline Manager / Outline Client) wraps this
protocol with a turn-key key-distribution / server-management UX
that reaches non-developer users; the SDK (this entry) factors out
the protocol logic for embedding in other apps.

## Threat Model

Stock Shadowsocks-AEAD is a "look-like-nothing" protocol: the wire
is high-entropy from the salt onward, no recognizable cover
protocol, no SNI, no banner. The threat model is therefore:

- **Defeats simple keyword / banner-matching DPI** — there's
  nothing to keyword-match.
- **Defeats key-based authentication probes** — without the
  shared password, a probe can't construct a valid AEAD message;
  the server's salt-history check silently drops the connection.
- **Does NOT defeat fully-encrypted-traffic detection** (USENIX
  Security 2023). High-entropy first packet without a known
  protocol signature is exactly the FET classifier's target.
  This is why Shadowsocks deployments worldwide started getting
  blocked by GFW + several other censors in ~2022-2023, and why
  Outline's response is the **prefix feature + Smart Dialer**
  rather than continued investment in raw look-like-nothing.

## Wire Format

Per [shadowsocks.org/guide/aead.html](https://shadowsocks.org/guide/aead.html):

```
[ salt — N bytes, per-connection random ]
[ AEAD-encrypted record:
    [2-byte BE payload length] [16-byte Poly1305 tag]
    [encrypted payload (length bytes)]
]
[ subsequent AEAD records, each chunk-sized ... ]
```

Where N depends on the AEAD cipher (per `cipher.go:46-48`):

| Cipher                | Key size | Salt size | Tag size |
| --------------------- | -------- | --------- | -------- |
| ChaCha20-Poly1305     | 32       | 32        | 16       |
| AES-256-GCM           | 32       | 32        | 16       |
| AES-192-GCM           | 24       | 24        | 16       |
| AES-128-GCM           | 16       | 16        | 16       |

Key derivation:

```
masterKey = openssl-EVP-style derivation from password (legacy MD5-based)
sessionKey = HKDF-SHA1(IKM=masterKey, salt=connection-salt, info="ss-subkey")
```

Each record's nonce: `[12-byte little-endian counter]`, starting
at 0 and incrementing per record. Counter must not repeat
(checked on read; failure = drop).

The first AEAD record on a stream contains the SOCKS-style target
address (atyp + addr + port). Subsequent records carry
application payload.

### Outline's lazy-write contribution (`stream_dialer.go:80-103`)

The `StreamDialer.DialStream` doesn't immediately send the salt +
address. It returns a `transport.StreamConn` to the caller and
**buffers the first application Write** for up to
`ClientDataWait` (default 10ms). When the buffered application
data arrives — or the timer fires — it sends salt + SOCKS address
+ first app payload **in one TCP packet**.

The doc comment on `DialStream` explains the trade:

> *"This makes the size of the initial packet hard to predict,
> avoiding packet size fingerprinting. We can only get the
> application initial data if we return a connection first.
> [...] The Shadowsocks StreamDialer returns a connection after
> the connection to the proxy is established, but before the
> connection to the target is established. That means we cannot
> signal 'connection refused' or 'connection timeout' errors from
> the target to the application. This behavior breaks IPv6 Happy
> Eyeballs..."*

So the lazy-write is an explicit trade: better evasion (variable
first-packet size) at the cost of slightly broken Happy Eyeballs
and indistinguishable proxy-connect-fail vs. target-connect-fail
errors.

## Cover Protocol

None — this is the canonical look-like-nothing protocol. To a
passive observer the wire is a TCP connection that immediately
starts pumping random-looking bytes.

This is the **central design weakness for 2026 censorship
contexts**. The Outline team has acknowledged it operationally
and shipped the prefix feature (server-side configurable byte
prefix that prepends a recognizable-protocol-shaped header before
the salt) as a stopgap, plus the Smart Dialer (tries multiple
strategies until one works) as the broader response.

## Authentication

In-band, via the AEAD construction.

- **Shared password** between client and server (the only
  pre-shared secret).
- **HKDF-derived per-connection key** from password + per-conn
  salt.
- **AEAD construction** authenticates the encrypted payload —
  any modification fails the Poly1305 tag check on the next read.

There's no separate cert / pubkey / cert-fingerprint layer; the
password is the only auth. This is by design — Shadowsocks values
operational simplicity and password rotation as the response to
key compromise.

## Probe Resistance

`outline-ss-server`-side:

- **Salt-history cache**: server stores recently-seen salts with
  a TTL. A connection whose salt is in the cache is silently
  dropped (no response sent). This catches replay-based probing.
- **Random-delay drop on auth fail**: same trick obfs4 uses —
  delay the TCP RST so a probe can't time-distinguish "fast drop
  = obfuscation server" from "slow drop = real timeout".
- **Configurable first-packet prefix** (the "prefix feature"):
  server can require / produce a configurable byte prefix before
  the salt. Lets operators make Outline traffic match e.g. an
  HTTP request shape. Same idea as Psiphon's OSSH prefix layer
  and Conjure's prefix transport.
- **Multiple-key support per port**: server can host multiple
  Outline access keys on one port; each key has its own
  password. Means a probe that learns one password can only
  observe traffic encrypted with that one key.

## Implementation

Pinned at:

- `Jigsaw-Code/outline-sdk` main @ [`bc36b14`](https://github.com/Jigsaw-Code/outline-sdk/commit/bc36b14)
- `Jigsaw-Code/outline-ss-server` master @ [`4d09f75`](https://github.com/Jigsaw-Code/outline-ss-server/commit/4d09f75)

License: Apache-2.0. Pure Go. **Module path migrated** from
`github.com/Jigsaw-Code/outline-sdk` to
`golang.getoutline.org/sdk` (Outline Foundation transition);
update any imports.

Key files (in outline-sdk):

- [`transport/shadowsocks/cipher.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/shadowsocks/cipher.go) — AEAD cipher specs (`CHACHA20IETFPOLY1305`, `AES256GCM`, etc.) + cipher-suite metadata.
- [`transport/shadowsocks/stream_dialer.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/shadowsocks/stream_dialer.go) — `StreamDialer.DialStream`, the lazy-write packet-shaping trick (lines 80-103).
- [`transport/shadowsocks/stream.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/shadowsocks/stream.go) — `Reader` / `Writer` for the AEAD stream framing.
- [`transport/shadowsocks/salt.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/shadowsocks/salt.go) — `SaltGenerator` interface (allows custom salt derivation, e.g. for predictable testing).
- [`transport/shadowsocks/packet.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/shadowsocks/packet.go) / [`packet_listener.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/shadowsocks/packet_listener.go) — UDP variant.

Server-side in outline-ss-server:

- `service/` — the connection handler with salt-replay defense + multi-key support.
- Outline Manager / Outline Server (`Jigsaw-Code/outline-server`) — the user-facing wrapper that handles cloud-provider provisioning, key generation, and access-key URL formatting (`ss://...?outline=1`).

## Known Weaknesses

- **Fully-encrypted-traffic detection** (USENIX Security 2023).
  This is the canonical FET target. Bare Outline-Shadowsocks is
  blocked broadly by GFW and several other censors. Mitigation
  is the prefix feature + the broader SDK's TLS-fragmentation /
  Smart-Dialer suite.
- **Password-only auth**. No PFS for new connections from a
  compromised password — every connection's key derives from
  the same password + per-conn salt. Outline mitigates by
  per-server-per-key access-control + easy rotation, not by
  changing the protocol.
- **`ClientDataWait` adds 10ms latency** to first byte. The
  trade is acceptable for evasion but visible in timing-sensitive
  applications.
- **Salt-history size and TTL are operational parameters**.
  Aggressive replay-window settings reject legitimate
  reconnections; permissive settings let a sophisticated probe
  learn salt structure. Outline ships sane defaults but operators
  customizing this can break either evasion or reliability.
- **No Happy Eyeballs.** The doc comment on `DialStream`
  explicitly notes IPv6 Happy Eyeballs is broken because the
  proxy connection succeeds before the target connection is
  attempted. IPv6 reachability through Outline is therefore
  effectively single-path, not redundant.

## Deployment Notes

- The **most-deployed Shadowsocks-AEAD implementation** by user
  count globally (Outline Manager runs on millions of
  installations). Operational hardening at scale informs every
  feature.
- The Outline Foundation (spun out of Jigsaw in 2024) is the
  current home; Go module paths migrated accordingly.
  `github.com/Jigsaw-Code/outline-sdk` is **deprecated** —
  new code should import `golang.getoutline.org/sdk`.
- Compose with `outline-tls-fragmentation` (record-level), the
  `tcp-split` / `disorder` tricks, and the `outline-smart-dialer`
  meta-strategy. Outline's design philosophy is that no single
  protocol works in every region — let the dialer probe.

## Cross-References

- Related protocols (this catalog):
  - `outline-tls-fragmentation` — TLS record-level fragmentation
    (the niere-2023 paper's technique). Not Shadowsocks itself
    but a complementary first-packet-shape evasion you can apply
    to TLS-tunneled traffic.
  - `outline-tcp-tricks` — TCP-segment splitting + TTL-disorder.
    Cousin tricks at the TCP layer.
  - `outline-smart-dialer` — the orchestrator. Picks among the
    above and others per-region until something works.
  - `obfs4` — the Tor-PT canonical look-like-nothing reference.
    Same FET-vulnerability story.
  - `psiphon-ossh` — Psiphon's RC4-obfuscated SSH substrate.
    Same look-like-nothing family; both rely on prefix features
    for FET resistance.
