# Psiphon Conjure-OSSH

## TL;DR

OSSH (Psiphon's RC4-obfuscated SSH substrate) carried as the
payload of a Conjure refraction-networking tunnel. Client uses
[`gotapdance`](https://github.com/refraction-networking/gotapdance)
to register with a Conjure station, dials a randomly-chosen phantom
IP, and the station DNATs the matched flow to a local handler that
unwraps the chosen Conjure transport. Inside the unwrapped bytes:
bare OSSH preamble → SSH session. The Conjure transport variants
that ride OSSH are named in psiphon-tunnel-core's `protocol.go`:

```
CONJURE_TRANSPORT_MIN_OSSH    = "Min-OSSH"
CONJURE_TRANSPORT_PREFIX_OSSH = "Prefix-OSSH"
CONJURE_TRANSPORT_DTLS_OSSH   = "DTLS-OSSH"
```

The composite protocol gets Conjure's "the proxy IP doesn't really
exist" probe-resistance plus Psiphon's SSH session crypto. See
[`conjure`](conjure.md) for the refraction layer and
[`psiphon-ossh`](psiphon-ossh.md) for the OSSH layer; this entry
just documents the composition.

## Threat Model

Combines Conjure's IP-layer evasion with OSSH's session
cryptography:

- **IP enumeration / blocklisting**: handled by Conjure — phantom
  IPs are randomly chosen from station-controlled subnets, no
  fixed proxy IP exists.
- **Active probing**: handled by Conjure — probes to a phantom
  without a registered tag get either silence or a default ISP
  response. The OSSH layer is never reached.
- **DPI of session bytes after the tunnel is open**: handled by
  the chosen Conjure transport (Min / Prefix / DTLS) — the wire
  shape of the post-tag bytes depends on which transport the
  registration negotiated. Inside that, OSSH provides RC4
  obfuscation + SSH session crypto.
- **Server identity attack** (MITM after the station unwraps):
  handled by OSSH's SSH-server pubkey pinning. The Conjure station
  can see the OSSH bytes but can't decrypt the SSH session.

What the composite **doesn't** address that pure-Psiphon variants
do address:

- **TLS-shaped cover protocol**. Conjure-OSSH doesn't run inside
  TLS. The Min and DTLS transports are look-like-nothing wire;
  Prefix is a configurable first-packet transform. If a region's
  censor specifically allowlists protocols that look like real
  TLS, Conjure-OSSH won't pass — pair with `psiphon-tls-ossh`
  for that case.

## Wire Format

Three wrapped variants.

### `Min-OSSH`

The minimal Conjure wrapping over OSSH. After the phantom-IP
connection establishes and the station DNATs the flow, bytes are:

```
[ Conjure Min-transport bytes -- minimal framing,
  high-entropy ]
[ OSSH preamble: 16B seed | 4B magic | 4B pad-length
                          | random padding ]
[ SSH session bytes ]
```

Same FET concerns as bare OSSH: high-entropy first packet without
a recognizable cover protocol. Suited for scenarios where IP-layer
evasion (the Conjure phantom-IP design) carries the load and FET
is not the dominant local threat.

### `Prefix-OSSH`

The Conjure prefix transport prepends a configurable byte sequence
generated from a `transforms.Spec`-style template (e.g. an
HTTP-request-shaped prefix, a DNS-query-shaped prefix) before the
OSSH bytes:

```
[ Prefix bytes -- transform-derived, looks like first packet of
  some real protocol ]
[ Prefix terminator ]
[ Conjure Prefix-transport bytes ]
[ OSSH preamble ]
[ SSH session bytes ]
```

This addresses FET on the first packet — the prefix matches a real
protocol's signature, so the FET classifier doesn't flag the flow.
Steady-state is still high-entropy.

### `DTLS-OSSH`

UDP variant. The Conjure phantom-IP connection is UDP-based; the
flow is wrapped in DTLS:

```
[ UDP packets containing DTLS records ]
[ DTLS plaintext: OSSH preamble + SSH session bytes ]
```

Per `protocol.go`, this is the only Conjure-OSSH variant that uses
UDP (`TunnelProtocolUsesPassthrough` returns true only for
`DTLS-OSSH` in this set). DTLS ClientHello fingerprinting concerns
apply here too — pair with `covert-dtls`-style fingerprint
randomization (which Psiphon already maintains for `psiphon-inproxy`'s
DTLS layer).

## Cover Protocol

Conjure's cover is "this is a TCP (or UDP) connection to some IP
in some ISP's subnet." The chosen wrapping transport determines
what the bytes look like once the connection is established —
none of which is "real TLS" or "real HTTPS." This protocol's
strength is at the **network layer** (no fixed proxy IP), not at
the **wire layer** (where Min and DTLS variants are FET-vulnerable).

## Authentication

Two layers, inherited from the components:

- **Conjure registration**: client proves it has the station's
  `ClientConf` and constructs a registration tag the station
  detects. Station authenticates the client at flow-tag-match
  time.
- **OSSH SSH key**: standard SSH server-pubkey pinning at the
  inner layer authenticates the Psiphon server identity.

The Conjure station and the Psiphon server are separate
infrastructure — the station hands the unwrapped flow to a
Psiphon server that runs the SSH key exchange. Operationally, the
Psiphon server can be co-located with the station or downstream
of it.

## Probe Resistance

The phantom-IP design carries the load (see
[`conjure`](conjure.md) for the full story). A probe that
connects to a phantom IP without a registered tag gets nothing;
a probe that intercepts a real Conjure-OSSH flow can replay it
once but the registration is single-use. The OSSH layer's own
probe resistance (magic-value check, randomized-delay drop on
auth fail) is a backup if a probe somehow reaches the OSSH layer.

## Implementation

Pinned at psiphon-tunnel-core master @
[`2b144a4`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/commit/2b144a4),
gotapdance master @
[`a8e3647`](https://github.com/refraction-networking/gotapdance/commit/a8e3647),
conjure master @
[`3d8b86c`](https://github.com/refraction-networking/conjure/commit/3d8b86c).

License: GPL-3.0 (psiphon-tunnel-core), Apache-2.0 (Conjure).

Key files (in psiphon-tunnel-core):

- [`psiphon/common/protocol/protocol.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/protocol/protocol.go) — `TUNNEL_PROTOCOL_CONJURE_OBFUSCATED_SSH = "CONJURE-OSSH"`. `CONJURE_TRANSPORT_MIN_OSSH = "Min-OSSH"`, `CONJURE_TRANSPORT_PREFIX_OSSH = "Prefix-OSSH"`, `CONJURE_TRANSPORT_DTLS_OSSH = "DTLS-OSSH"`. `SupportedConjureTransports = {MIN_OSSH, PREFIX_OSSH, DTLS_OSSH}`. `TunnelProtocolUsesPassthrough(DTLS_OSSH) == true` (the only one that's UDP).
- The dial-side wiring lives in psiphon-tunnel-core's tunnel-protocol selection logic; gotapdance is the imported client library that handles the Conjure registration + transport negotiation. OSSH is layered on top of the resulting `net.Conn` exactly as in any other OSSH-bearing tunnel protocol (see [`psiphon-ossh`](psiphon-ossh.md) for the OSSH details).

Conjure station: see [`conjure`](conjure.md).

## Known Weaknesses

Composes the limitations of both layers:

- **Conjure ISP-cooperation scaling**. `psiphon-conjure-ossh`
  only works where Psiphon's tactics route a client through a
  cooperating ISP. Conjure deployment partners are scarce; this
  variant is therefore deployable only in regions Psiphon has
  paired with refraction-networking infrastructure.
- **Min / DTLS transports are FET-vulnerable**. Use Prefix when
  the local threat profile includes fully-encrypted-traffic
  classifiers; Min / DTLS only when the IP-layer concealment is
  what carries the evasion.
- **Inner OSSH RC4 weaknesses** apply. See
  [`psiphon-ossh`](psiphon-ossh.md) §Known Weaknesses.
- **DTLS fingerprint** for the DTLS-OSSH variant. Same caveat as
  every UDP/DTLS-using protocol post-March-2026 — must use
  fingerprint randomization or browser-mimicry. Psiphon already
  maintains `covert-dtls`; the deployment question is whether
  this variant uses it consistently.
- **Composite operational complexity**. Three moving parts
  (gotapdance client, Conjure station, Psiphon server) means
  three potential failure modes. The Conjure station is
  third-party infrastructure from Psiphon's perspective.

## Deployment Notes

- Default-disabled in the upstream tunnel-protocols list (per
  `protocol.go`); enabled per-region by Psiphon tactics where a
  Conjure station partnership exists.
- All three sub-transports (Min-OSSH, Prefix-OSSH, DTLS-OSSH)
  are independently selected by tactics; clients that don't
  support all three negotiate to a compatible subset.
- Composes with `psiphon-inproxy`: an `INPROXY-WEBRTC-CONJURE-OSSH`
  combination would chain a WebRTC 1st hop into a Conjure tunnel
  into OSSH — at least four moving parts but offering both
  WebRTC P2P advantages and Conjure phantom-IP advantages.
- The 2025 Iran-measurement paper (`2025-alaraj-iran-refraction`)
  uses refraction-networking proxies (Conjure-flavored) as a
  vantage point inside Iran. Useful evidence that the deployment
  posture is real in heavily-censored regions, even if scaled.

## Cross-References

- Public corpus papers: `2019-frolov-conjure`,
  `2025-alaraj-iran-refraction`.
- Related protocols (this catalog):
  - `conjure` — the underlying refraction-networking layer.
  - `psiphon-ossh` — the inner OSSH substrate.
  - `psiphon-inproxy`, `psiphon-tls-ossh` — sibling Psiphon
    variants in different parts of the design space (WebRTC 1st
    hop / TLS-1.3 cover).
  - (TBD) `tapdance` — the predecessor refraction protocol that
    Conjure replaces in production. gotapdance still supports
    both for backwards compatibility.
  - `obfs4` — one of Conjure's available wrapping transports;
    Conjure-OSSH avoids it (uses Min/Prefix/DTLS) but the option
    exists in the Conjure repo.
