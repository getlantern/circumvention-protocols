# Trojan

## TL;DR

TLS-tunneled proxy with password auth and an HTTP fallback. The
trojan server is a real TLS terminator (operator owns the cert);
clients open a real TLS handshake and then send a SHA224-hashed
password + SOCKS5-style request as the first encrypted bytes. If
auth fails, the server transparently TCP-proxies the rest of the
post-handshake bytes to a configured fallback (default
`127.0.0.1:80` — a real HTTP server). The censor sees: a
TLS-terminated server that sometimes serves real HTTP and
sometimes carries arbitrary HTTPS. No distinguishable "this is a
Trojan server" response on probing.

The upstream protocol README puts the design philosophy
plainly: *"Trojan is not a fixed program or protocol. It's an
idea, an idea that imitating the most common service, to an
extent that it behaves identically, could help you get across
the Great FireWall permanently, without being identified ever.
We are the GreatER Fire; we ship Trojan Horses."*

## Threat Model

- **TLS protocol identification**: defeated by being a real TLS
  server. Standard handshake, real cert, real cipher negotiation.
- **SNI extraction**: defeated by serving a real cover domain
  with a real cert that's chosen by the operator. The operator
  controls what the SNI is and what the cert chain looks like;
  anything legitimate works.
- **Active probing of the proxy IP**: defeated by the HTTP
  fallback. A probe that completes a TLS handshake and sends
  garbage gets the bytes forwarded to the local HTTP server,
  which responds like a normal web server.
- **Length-pattern detection**: partially mitigated — per the
  spec, the first packet carries the auth header **plus the
  initial application payload** (Payload field), so the
  size of the first packet is variable rather than fixed.
- **Active probing with a captured TLS ClientHello**: the cert is
  the operator's own (not a relay to a third party), so the probe
  successfully completes TLS just as a normal client would; the
  only "probe-resistance" is then the HTTP-fallback behavior at
  the application layer.

What it does **not** address:

- **Cert reputation / cert-CA fingerprinting**: the operator
  needs a real cert from a real CA. Operators using Let's Encrypt
  certs for trojan look like every other Let's Encrypt-served
  small site. Censors that prefer specific-CA allow-listing can
  in principle filter by CA, though this hasn't been a primary
  attack vector against trojan in practice.
- **TLS-over-TLS detection** (USENIX Sec 2024 family): trojan's
  inner payload is "any TCP stream the client requested," which
  often *is* TLS to a destination. So a connection to a Trojan
  server tunneling to `https://example.com` is structurally
  TLS-inside-TLS, with the matching observable pattern.
  Production Trojan deployments increasingly compose with
  Shadowsocks-style obfuscation plugins (in trojan-go) to
  mitigate, or with REALITY (Xray) to wrap the outer TLS.

## Wire Format

Per [`docs/protocol.md`](https://github.com/trojan-gfw/trojan/blob/master/docs/protocol.md)
in the canonical C++ repo. After a normal TLS 1.2/1.3 handshake
to the trojan server, the client sends inside the encrypted TLS
stream:

```
+-----------------------+---------+----------------+---------+----------+
| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|         56 B          | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+
```

`Trojan Request` is a SOCKS5-shaped destination spec:

```
+-----+------+----------+----------+
| CMD | ATYP | DST.ADDR | DST.PORT |
+-----+------+----------+----------+
|  1  |  1   | Variable |    2     |
+-----+------+----------+----------+
   CMD: 0x01 = CONNECT (TCP), 0x03 = UDP ASSOCIATE
   ATYP: 0x01 = IPv4, 0x03 = domain (length-prefixed), 0x04 = IPv6
```

After this prefix, the rest of the TLS-encrypted stream is the
proxied bytes verbatim. The first packet from the client carries
the **auth header + first application payload together** —
deliberately, to avoid a fixed-size first-packet signature.

### UDP ASSOCIATE

If `CMD = 0x03`, each subsequent UDP packet is wrapped in a
length-framed envelope (still inside TLS records):

```
+------+----------+----------+--------+---------+----------+
| ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
+------+----------+----------+--------+---------+----------+
|  1 B | Variable |    2 B   |   2 B  | X'0D0A' | Variable |
+------+----------+----------+--------+---------+----------+
```

### Auth-failure path

When the server receives the first encrypted bytes from the
client, it computes `SHA224(client-supplied-bytes-up-to-first-CRLF)`,
compares against its configured password hash table, and:

- **Match** → strip the auth header + Trojan request, open a TCP
  (or UDP) tunnel to `DST.ADDR:DST.PORT`, forward subsequent
  bytes verbatim.
- **No match** → treat the entire post-handshake stream as
  "other protocol traffic." TCP-proxy the (already-decrypted) bytes
  to a configured fallback upstream — by default
  `127.0.0.1:80`, but configurable to any TCP service. The
  fallback service handles whatever HTTP request the client (or
  probe) sent.

This is the design's distinguishing feature: there's no separate
"reject" branch a probe can detect.

## Cover Protocol

A real HTTPS site that the operator hosts. The TLS layer is real
(operator's cert, real handshake). The fallback service is also
real (real HTTP server). To a passive observer, the IP serves a
website with a normal cert; clients sometimes get HTTP responses,
sometimes get whatever bytes Trojan tunnels back.

Per the upstream README, the C++ server has supported nginx-like
behavior for plain HTTP requests since early in the project's
history.

## Authentication

Pre-shared **password**, hashed with SHA224 hex-encoded:

- Server config: a list of allowed passwords (or, in the C++
  server, a MySQL-backed users table).
- Client config: one password.
- Wire: client sends `hex(SHA224(password))` (lowercase, 56
  characters) as the first 56 encrypted bytes.

No additional cryptographic auth — the TLS layer's confidentiality
+ integrity protect the password-in-the-clear inside TLS, and the
fallback-on-failure means a stolen password doesn't reveal that
the IP runs Trojan (the probe still gets HTTP fallback if the
password is wrong, just because of the failure path).

The hash isn't bcrypt / scrypt / Argon2 — it's a single SHA224.
That's a deliberate choice for low-cost server-side validation
(the server hashes once per connection); the security model
relies on TLS confidentiality preventing offline cracking.

## Probe Resistance

Two layers:

1. **Outer TLS terminator**: a probe that connects gets a real
   TLS handshake with a real cert. Same as any HTTPS server.
2. **HTTP fallback**: a probe that completes the handshake and
   sends arbitrary bytes (e.g. a normal HTTP request, or random
   bytes, or even a crafted-but-invalid Trojan auth header)
   gets those bytes proxied to the configured fallback service.
   The fallback responds however a normal HTTP server would.

A probe that completes the handshake, sends garbage, and gets
back a 400 or a 404 from the fallback HTTP server has learned
nothing — it looks exactly like any misconfigured probe against
any HTTPS site.

## Implementation

Two canonical implementations:

### C++ — `trojan-gfw/trojan`

Pinned at master @
[`3e7bb9a`](https://github.com/trojan-gfw/trojan/commit/3e7bb9a).

License: GPLv3. Boost.Asio + OpenSSL. The original.

- [`docs/protocol.md`](https://github.com/trojan-gfw/trojan/blob/3e7bb9a/docs/protocol.md) — the canonical wire-format spec.
- The server runs as a TLS terminator with optional MySQL-backed user auth, configurable fallback upstream (`run_type: server` config block), and CDN-friendly mode (`run_type: forward`).

### Go — `p4gefau1t/trojan-go`

Pinned at master @
[`2dc60f5`](https://github.com/p4gefau1t/trojan-go/commit/2dc60f5).

License: GPLv3. Single-binary Go reimplementation. Adds:

- **Multiplexing** (mux): one TLS connection carries many proxied
  streams, defeating connection-count policing.
- **Routing**: per-destination routing rules for split traffic.
- **CDN relay**: WebSocket transport over TLS so the connection
  fronts behind a CDN edge.
- **Shadowsocks-style obfuscation plugin**: optional second
  obfuscation layer wrapped around the inner Trojan stream.

trojan-go is the more-deployed implementation in 2026.

### Other implementations

- [`XTLS/Xray-core`](https://github.com/XTLS/Xray-core) — Trojan
  inbound + outbound, often paired with REALITY transport for the
  outer TLS.
- [`sagernet/sing-box`](https://github.com/sagernet/sing-box) —
  `protocol/trojan/` implementation; one of sing-box's standard
  inbounds/outbounds.

## Known Weaknesses

- **TLS-over-TLS detection** when the inner payload is itself
  TLS (USENIX Sec 2024 work). Trojan tunneling browser HTTPS
  traffic produces structural TLS-in-TLS the classifier can flag.
  Mitigations: trojan-go's mux + Shadowsocks plugin (which adds
  noise to the inner stream); REALITY-wrapping for the outer TLS.
- **Single SHA224 password**. No PFS for repeated connections from
  one client; the password hash is computed once per session
  inside TLS but is the same across all connections that use that
  password. Operators rotate or scope passwords for damage
  control if one leaks.
- **Cert-pinning practice varies**. The reference C++ server
  shipped without strict cert pinning on the client, which means
  a deployed-CA-MITM in some networks (corporate, some national
  PKIs) can intercept and observe the Trojan auth bytes. Modern
  trojan-go pins by default; older C++ deployments are mixed.
- **Operator-owned cert is an audit trail**. The operator's
  Let's-Encrypt-or-similar cert is recorded in CT logs. A censor
  that monitors CT for "small sites with low traffic" can build
  candidate Trojan-server lists from the public CT stream.
  Mitigations: domain-fronting (CDN relay mode) hides the actual
  server identity from CT-based enumeration.
- **No active probe resistance against well-crafted Trojan-aware
  probes**: a probe that completes the TLS handshake and sends a
  zero-byte first packet (or a single CRLF, or garbage that
  doesn't match the SHA224 length) triggers the fallback path.
  Probes that stay long enough to characterise the fallback's
  HTTP responses can identify "this fallback HTTP service is X"
  and pattern-match across IPs that share the same fallback
  setup.

## Deployment Notes

- **Most-deployed TLS-tunneled proxy globally** outside of
  REALITY-based stacks. Production deployments typically pair
  trojan-go's mux + a CDN-relay (WebSocket) front for additional
  cover.
- The "trojan + nginx" pattern: server hosts both a real website
  via nginx on port 443 (with the cert that Trojan also uses) and
  the Trojan server on the same TLS endpoint. Trojan serves any
  request that has a valid SHA224 prefix; nginx serves the rest.
  This requires careful systemd / supervisor wiring.
- Trojan-via-Xray-with-REALITY is the modern go-to for
  active-probing-hostile environments — REALITY hides the cert
  origin (no operator-owned cert observable in CT), Trojan
  provides the inner payload protocol. See [`vless-reality`](vless-reality.md)
  for that design detail.
- Trojan-via-sing-box is what e.g. lantern-box would consume if
  Lantern ever shipped Trojan as one of its bandit options
  (currently doesn't).

## Cross-References

- Related protocols (this catalog):
  - `vless-reality` — REALITY transport carrying VLESS payload.
    REALITY's design philosophy descends from Trojan
    (TLS-cert-based auth + relay-on-failure) but evolves it into
    "no operator cert at all; relay the entire TLS handshake."
    Compare cert-source story.
  - `psiphon-tls-ossh` — Psiphon's analog. In-handshake auth via
    HMAC-in-`client_random` + passthrough-to-real-HTTPS on
    failure. Similar shape; different auth mechanism (HMAC vs
    SHA224 hash).
  - `samizdat` — Lantern's analog. In-handshake auth via
    HMAC-in-`SessionID` + masquerade-on-failure. Same family.
  - `tlsmasq` — Lantern's older analog. Two-phase handshake;
    Trojan is single-phase + simpler.
  - `naive` — different sibling. Reuses Chromium's TLS stack
    instead of being-a-real-TLS-server. Both share the
    "application fronting" design pattern.
