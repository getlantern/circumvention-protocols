# obfs4

## TL;DR

The canonical "look-like-nothing" pluggable transport. Obfuscates a
TCP stream to be statistically indistinguishable from uniform random
bytes — no TLS, no HTTP, no plaintext fields, no recognizable
structure. Handshake is Tor's ntor adapted to use **Elligator 2**
(maps Curve25519 public keys onto uniform random bytes) with
random-length padding and an HMAC marker so the receiver can locate
the MAC inside the otherwise-uniform stream. Steady-state frames
use NaCl secretbox (XSalsa20+Poly1305) with a 2-byte length field
**XORed with a SipHash-OFB keystream** so consecutive frame sizes
don't correlate.

**Status: blocked-broadly.** This is the protocol the GFW's
fully-encrypted-traffic detection (USENIX Security 2023) was built
to find. Treat it as the catalog's canonical anti-pattern for "don't
ship look-like-nothing in 2026."

## Threat Model

The obfs4 spec lists its goals in section 2:

- **Passive DPI**: an inspector that knows the protocol exists must
  not be able to verify "this is obfs4" without out-of-band
  knowledge of the server's `NODEID` + identity public key `B`.
- **Active probing without secrets**: a probe that doesn't know
  `NODEID + B` cannot construct a valid first packet. The server
  also intentionally delays the TCP RST on bad MAC to make
  scanning expensive.
- **Active impersonation with secrets**: even an attacker who has
  `NODEID + B` cannot impersonate the server without the identity
  *private* key (mutual authentication via ntor).
- **Length / shape mitigation**: the spec is explicit that obfs4
  protects against "some" non-content fingerprints (packet size,
  optionally timing), but not all.

Notably absent from the threat model — and the reason the protocol
is now blocked broadly:

- **First-packet entropy / fully-encrypted-traffic detection
  (FET, USENIX 2023)**: obfs4's first byte and beyond are
  designed-to-be-uniform random. FET classifiers identify any
  stream whose first packet is high-entropy and matches no known
  protocol signature, then block it. This works against obfs4 by
  construction — there's no cover protocol whose signature obfs4
  can adopt because the design philosophy is "be statistically
  perfect random bytes."

## Wire Format

### Pre-shared (out-of-band)

- `NODEID` — 20 bytes (server identity)
- `B` — 32-byte Curve25519 public identity key (server's static)
- Server private `b` — kept on server only

### Handshake

Per the spec, all numeric fields are big-endian unless they're
Curve25519 / Elligator material (little-endian).

**Client → server (`clientRequest`)**:

```
clientRequest = X' | P_C | M_C | MAC_C

  X'    = Elligator 2 representative of ephemeral Curve25519 pubkey X (32 bytes)
  P_C   = Random padding, length in [85, 8128] bytes
  M_C   = HMAC-SHA256-128(B || NODEID, X')          // 16-byte marker
  MAC_C = HMAC-SHA256-128(B || NODEID,
                          X' || P_C || M_C || E)    // 16-byte tag
  E     = ASCII string of "hours since UNIX epoch"
```

`M_C` is the marker the server scans for to know where `MAC_C`
ends — necessary because there is no length field for the padding
in the clear; the entire stream looks like noise.

**Server → client (`serverResponse`)**:

```
serverResponse = Y' | AUTH | P_S | M_S | MAC_S

  Y'    = Elligator 2 representative of ephemeral Curve25519 pubkey Y (32 bytes)
  AUTH  = ntor authentication tag (32 bytes)
  P_S   = Random padding, length in [InlineSeedFrameLength, 8096] bytes
  M_S   = HMAC-SHA256-128(B || NODEID, Y')          // marker
  MAC_S = HMAC-SHA256-128(B || NODEID,
                          Y' || AUTH || P_S || M_S || E')
```

After this exchange both sides have a 256-bit `KEY_SEED` derived
via the ntor KDF, expanded into 144 bytes of keying material:

```
S→C: 32B secretbox key, 16B nonce prefix, 16B SipHash key, 8B SipHash IV
C→S: 32B secretbox key, 16B nonce prefix, 16B SipHash key, 8B SipHash IV
```

**Replay tolerance**: server checks `MAC_C` against `E ∈ {E-1, E,
E+1}` (in hours) for clock-skew tolerance. Anti-replay enforcement
beyond that is left to higher layers / connection state.

### Frame format (steady state)

Per spec section 5:

```
+------------+----------+--------+----------+----------+----------+
| 2 B        | 16 B     | 1 B    | 2 B      | (opt)    | (opt)    |
| frame len  | Poly tag | type   | payload  | payload  | padding  |
|            |          |        | length   | bytes    | bytes    |
+------------+----------+--------+----------+----------+----------+
 \__ obfs __/ \________ secretbox (Poly1305/XSalsa20) _________/
```

- The 2-byte frame length is XORed with a SipHash-2-4 OFB keystream
  derived from the per-direction SipHash key + IV. So even though
  every frame has a length prefix, consecutive prefixes look
  uncorrelated to a passive observer.
- secretbox uses XSalsa20 + Poly1305 with the per-direction key
  and a `[24-byte fixed prefix || 8-byte BE counter]` nonce.
  Counter starts at 1, increments per frame.
- Max frame length: 1448 bytes (typical TCP MSS — leaves no
  visible record-size signature).
- Per-frame padding: variable, encrypted along with payload.

## Cover Protocol

**None — by design.** The wire is high-entropy bytes from the first
byte on. There is no SNI, no ALPN, no server name, no plaintext
header. A passive observer sees a TCP connection that immediately
starts pumping random-looking bytes. This is the entire design
philosophy ("look like nothing"), and it's the same property that
makes obfs4 detectable by FET classifiers: high entropy + zero
matches against known protocol signatures = block.

## Authentication

In-band, via the ntor handshake. Mutual:

- Client authenticates the server by checking `AUTH` (the ntor
  output tag) — only a server with knowledge of the identity
  private `b` can produce a matching `AUTH`.
- Server authenticates the client only insofar as the client
  proves knowledge of `B || NODEID` (via `MAC_C`). This isn't
  per-client identity — it's "you are someone who got our bridge
  info out of band."

There is no separate cert / cert-fingerprint / SessionID layer; all
auth is folded into the handshake.

## Probe Resistance

Two layers, in line with the spec's section 2 threat model:

1. **Markers + MACs**: a probe that doesn't know `B || NODEID`
   can't construct a valid `M_C` / `MAC_C`. The server walks the
   first `MaximumHandshakeLength = 8192` bytes looking for `M_C`
   at the right offset; if not found, the conn is rejected.
2. **Random-interval drop on failure**: spec section 4 step 2:
   *"On the event of a failure at this point implementations
   SHOULD delay dropping the TCP connection from the client by a
   random interval to make active probing more difficult."* The
   intent is to prevent timing-based probes from cheaply
   distinguishing "obfs4 server, wrong secrets" from "random
   non-obfs4 service."

What this **does not** defend against, and what gets obfs4 blocked
in practice: a censor doesn't need to actively probe at all. Passive
classification of the *first packet's entropy* is enough to flag the
connection as a circumvention candidate, and the censor can drop
the flow without ever sending bytes back.

## Implementation

Pinned at upstream commit
[`c3e2d44`](https://github.com/Yawning/obfs4/commit/c3e2d44).

Repo: `github.com/Yawning/obfs4` (BSD-2-Clause). Pure Go. The
package is the courtesy mirror of Yawning Angel's original
implementation; the Tor Project's actively-maintained fork is
[`lyrebird`](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird).

Key files (in the upstream layout):

- [`doc/obfs4-spec.txt`](https://github.com/Yawning/obfs4/blob/c3e2d44/doc/obfs4-spec.txt) — the canonical wire-format spec. Anything written here references this document.
- [`transports/obfs4/obfs4.go`](https://github.com/Yawning/obfs4/blob/c3e2d44/transports/obfs4/obfs4.go) — the pluggable-transport entry point: registers `ClientFactory` / `ServerFactory`, wires up the dial / listen paths.
- [`transports/obfs4/handshake_*.go`](https://github.com/Yawning/obfs4/tree/c3e2d44/transports/obfs4) — `handshake_ntor.go`, `handshake_server.go`, `handshake_client.go` implement the ntor + Elligator + marker-search machinery exactly as the spec describes.
- [`transports/obfs4/framing/`](https://github.com/Yawning/obfs4/tree/c3e2d44/transports/obfs4/framing) — secretbox frame encode/decode, SipHash length-mask generation.

Notable constants (spec § 4):

- `MaximumHandshakeLength = 8192`
- `MarkLength = 16` (M_C / M_S)
- `MACLength = 16` (MAC_C / MAC_S)
- `RepresentativeLength = 32` (Elligator 2 rep of a Curve25519 pubkey)
- `AuthLength = 32` (ntor `AUTH`)
- `ClientMinPadLength = 85`, `ClientMaxPadLength = 8128`
- `ServerMinPadLength = 45` (`InlineSeedFrameLength`), `ServerMaxPadLength = 8096`
- `MaxFrameLength = 1448`

## Known Weaknesses

- **Fully-encrypted-traffic detection (USENIX Security 2023)**.
  The protocol's defining property — uniform random bytes from the
  first byte — is exactly what FET classifiers fingerprint. This
  is fundamental, not a bug-fix-able weakness. The GFW has been
  blocking obfs4 connections via FET for several years, and
  several other censors have followed. **This is the reason
  status = `blocked-broadly`.**
- **No cover-protocol fallback**. Unlike samizdat / REALITY /
  hysteria2 / naive, there is no real protocol that a probe sees
  if it doesn't know the secrets. The server either accepts
  (after MAC verification) or drops (after a random delay) — both
  of which are visible signatures.
- **Length-mask seed lasts the connection**. The SipHash-OFB used
  to mask frame lengths derives from a key established at handshake
  time and chains forward via SipHash. A long-lived flow with high
  bandwidth produces enough length-prefix samples to provide
  statistical signal even though individual frames look random.
- **Tor-bridge ecosystem coupling**. obfs4's `NODEID + B` distribution
  is tied to Tor's bridge-distribution infrastructure (BridgeDB,
  Snowflake-rendezvous, mailing lists, etc.). Censors who attack
  bridge distribution end-run the protocol entirely.

## Deployment Notes

- Still deployed in some non-GFW contexts where FET-style detection
  isn't yet operational.
- The Tor Project's [`lyrebird`](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird) fork is the actively-maintained version — bundles obfs4 alongside `meek_lite` and is the binary that Tor Browser ships.
- For new circumvention work in 2026, **don't design new protocols
  modeled on obfs4**. Use it as the negative example to motivate
  cover-protocol-based designs (TLS mimicry, HTTP/3, application
  fronting). The Lantern internal-docs corpus's
  `2026-04-non-protocol-evasion` recommendations are explicit on
  this point.
- A closely-related successor in the look-like-nothing space —
  `obfs5` — has had design discussions but no widely-deployed
  implementation; the field is moving toward cover protocols
  (`webtunnel`, REALITY-family, samizdat, naive) rather than
  iterating on look-like-nothing.

## Cross-References

- Public corpus: a paper (id TBD — this catalog hasn't yet pinned
  the exact USENIX 2023 FET paper's corpus ID) documenting the FET
  technique that defeats obfs4 by construction. Worth filling in
  during the next public-corpus sweep.
- Related protocols (this catalog):
  - All cover-protocol-based entries — `samizdat`, `vless-reality`,
    `naive`, `hysteria2`, `reflex` — are the design's *response*
    to FET. obfs4 is the negative reference point.
  - (TBD) `meek` / `webtunnel` — the Tor Project's own moves away
    from look-like-nothing toward CDN-fronted and HTTPS-imitating
    transports.
  - (TBD) `snowflake` — the WebRTC-based PT that doesn't share
    obfs4's first-packet-entropy problem because WebRTC traffic
    is structured.
