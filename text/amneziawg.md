# AmneziaWG (AWG 2.0)

## TL;DR

WireGuard with configurable obfuscation. Cryptography is unchanged
(Curve25519 + Noise IKpsk2 + ChaCha20-Poly1305 + BLAKE2s); the
additions are wire-shape knobs that defeat WireGuard's distinctive
packet signatures:

- **Magic headers (H1-H4)** replace WireGuard's fixed
  `uint32` first-field message type (1=initiation, 2=response,
  3=cookie, 4=transport) with caller-configured values or — new
  in **AWG 2.0** — ranges.
- **Paddings (S1-S4)** prepend random bytes to handshake
  initiation, response, cookie, and transport messages. **AWG 2.0
  added S3 (cookie) and S4 (transport)** to the existing S1/S2.
- **Junk packets (Jc, Jmin, Jmax)**: a count of random-content
  UDP packets, each sized in `[Jmin, Jmax]`, sent before every
  handshake.
- **Signature packets (I1-I5)**: caller-supplied byte sequences
  written from a small DSL — `<b 0xHEX>` (static bytes),
  `<r N>` (N random bytes), `<rd N>` / `<rc N>` (random digits /
  alpha), `<t>` (4-byte UNIX timestamp), plus newer
  `<d>` / `<ds>` / `<dz>` data tags.

Underneath: still real WireGuard, including the inherent
"deny-by-default firewall" property (any packet that doesn't
authenticate with a known peer's symmetric key is silently
dropped).

## Threat Model

WireGuard's defining cryptographic strengths are also its
defining detection liabilities:

- **Distinctive 1-byte message type** at the start of every UDP
  payload (`0x01`/`0x02`/`0x03`/`0x04`). Trivial to match by DPI.
- **Distinctive sender index field** in handshake messages —
  random-looking but always at the same offset.
- **Predictable handshake timing**: ~1 RTT, then bidirectional
  transport messages with ChaCha20-Poly1305 framing.
- **Distinctive handshake message sizes** (148 bytes initiation,
  92 bytes response, fixed) — first-packet size signature.

Censors that pattern-match these (Russia/TSPU has been doing it
since at least 2022) defeat vanilla WireGuard. AmneziaWG addresses
each:

- Magic-header rewriting → no fixed `0x01-0x04` byte to match.
- Padding (S1-S4) → handshake/transport messages are no longer
  fixed-size.
- Junk packets → first packet from a peer isn't the handshake; it's
  a chunk of random-looking UDP noise of variable size.
- Signature packets (I1-I5) → caller can prefix anything that
  resembles a different protocol's first packet, e.g. an
  HTTP-shaped opening or a STUN binding request.

What it does **not** address:

- **UDP-blocked networks** (e.g. some Russian mobile carriers).
  WireGuard is fundamentally UDP; AmneziaWG inherits that.
- **Fully-encrypted-traffic detection over UDP**: even with
  signature packets, the steady-state transport traffic is
  high-entropy ChaCha20 ciphertext that an aggressive UDP-FET
  classifier could flag. The signature/junk knobs target
  first-packet detection, not steady state.
- **Behavioral / timing fingerprints**: one always-on UDP flow
  that handshakes once and then carries variable-size encrypted
  packets is itself a behavioral pattern. AmneziaWG doesn't
  reshape steady-state.

## Wire Format

A normal WireGuard handshake initiation:

```
[1B msgtype=0x01][3B reserved=0][4B sender_index][32B ephemeral][...][16B mac1][16B mac2]
                                                                    total 148B
```

An AmneziaWG initiation (parameters chosen at config time):

```
[ S1 random padding bytes — variable length ]
[ msgtype: a uint32 in the H1 range, replaces 0x01 ]
[ remaining handshake fields — same format/crypto as WireGuard ]
```

Plus, prior to that initiation packet, the client sends:

```
[ I1 — caller-defined byte sequence from the obfuscation DSL ]
[ I2 ]
[ I3 ]
[ I4 ]
[ I5 ]
[ Jc junk packets, each `len ∈ [Jmin, Jmax]` of random bytes ]
```

(`I1`-`I5` are emitted in order; an unset entry is skipped.
Junk packets are emitted after the signature packets and before
the actual handshake initiation. Each sits in its own UDP
datagram.)

The handshake response, cookie, and transport messages get
analogous H2/H3/H4 + S2/S3/S4 treatment.

### Obfuscation tag DSL

From `device/obf.go` — the parser walks `<tag>` blocks and chains
obfuscators:

| Tag | Meaning |
| --- | --- |
| `<b 0xHEX>` | Static bytes — emit `HEX` (must be even-length). |
| `<r N>` | Emit `N` random bytes. |
| `<rd N>` | Emit `N` random ASCII digits (`0-9`). |
| `<rc N>` | Emit `N` random ASCII letters (`a-zA-Z`). |
| `<t>` | Emit 4-byte UNIX timestamp (current system time). |
| `<d>` / `<ds>` / `<dz>` | Newer data tags — embed actual handshake data, with sized / size-prefixed / null-terminated variants. |

So a signature packet that opens like an HTTP/1.1 GET could be
`I1 = <b 0x474554202f20485454502f312e310d0a486f73743a20><rc 8><b 0x0d0a0d0a>` —
`GET / HTTP/1.1\r\nHost: <8 random alpha>\r\n\r\n`.

## Cover Protocol

Dependent on the operator's choice of obfuscation parameters.
With aggressive use of signature packets, AmneziaWG can be made
to **start** like an arbitrary other protocol; the steady-state
transport traffic is still WireGuard's ChaCha20-encrypted UDP
datagrams.

Without signature packets, a passive observer sees variable-size
random-looking UDP datagrams to a single peer — same shape as
many other UDP protocols (QUIC, STUN, encrypted media) but
without their distinctive handshake signatures.

## Authentication

Pure WireGuard.

- Pre-shared peer Curve25519 public keys, exchanged out-of-band.
- Optional pre-shared symmetric key (PSK) for hybrid post-quantum
  resistance.
- Noise_IKpsk2 handshake produces session keys after one RTT.
- Subsequent transport-message authentication via Poly1305 over
  ChaCha20 ciphertext.

The obfuscation knobs don't change the auth path. A peer that
knows the right keys and configures the same H/S/Jc parameters
authenticates normally; a peer with wrong obfuscation config
either looks like noise to AmneziaWG (drop) or fails the
handshake's MAC check (drop).

## Probe Resistance

WireGuard's "stealth" property: the protocol has no response to
unauthenticated input. A probe that sends random bytes to a
WireGuard listener gets nothing back. AmneziaWG inherits this
unchanged.

The obfuscation knobs reduce the chance the probe even **reaches**
the WireGuard listener as a recognizable WireGuard packet — which
matters for **passive DPI**, not for active probes that just send
bytes to see what comes back.

## Implementation

Pinned at amneziawg-go master @
[`12a0122`](https://github.com/amnezia-vpn/amneziawg-go/commit/12a0122).
This is the **AWG 2.0** generation (introduced
[`f654220`](https://github.com/amnezia-vpn/amneziawg-go/commit/f654220),
Sep 2025; refined through Dec 2025).

License: MIT (inherits wireguard-go's license + Apache-2.0 for
some Go modules per the project's LICENSE file).

The Amnezia ecosystem is polyglot:

- **Go userspace** (`amneziawg-go`, this entry's pin): used as a
  library and as a standalone binary; preferred on macOS, used as
  the basis for client apps on iOS (via `amneziawg-apple`),
  Android (via `amneziawg-android`), and Windows (via
  `amneziawg-windows`).
- **Linux kernel module** (`amneziawg-linux-kernel-module`):
  Linux-fast-path AmneziaWG, recommended on Linux servers.
- **Tools** (`amneziawg-tools`): `awg` and `awg-quick` — the
  AmneziaWG-equivalents of `wg(8)` and `wg-quick(8)`.

Key files in `amneziawg-go`:

- [`device/magic-header.go`](https://github.com/amnezia-vpn/amneziawg-go/blob/12a0122/device/magic-header.go) — `magicHeader` struct with `start`/`end`/`Generate()` (the AWG 2.0 ranged version). Per-packet a fresh value is drawn from `[start, end]`.
- [`device/obf.go`](https://github.com/amnezia-vpn/amneziawg-go/blob/12a0122/device/obf.go) — the obfuscation chain parser; reads `<tag value>` strings into `obfChain` instances. Per-tag implementations live in `obf_bytes.go`, `obf_rand.go`, `obf_randchars.go`, `obf_randdigits.go`, `obf_timestamp.go`, `obf_data.go`, `obf_datasize.go`, `obf_datastring.go`.
- [`device/send.go`](https://github.com/amnezia-vpn/amneziawg-go/blob/12a0122/device/send.go) — `SendHandshakeInitiation` (lines ~125-180): emits I1-I5 first, then `Jc` junk packets in `[Jmin, Jmax]` size, then S1-padded initiation message.
- [`device/noise-protocol.go`](https://github.com/amnezia-vpn/amneziawg-go/blob/12a0122/device/noise-protocol.go) — modified to read/write the H1-H4-replaced message-type field at the start of every packet.
- [`device/cookie.go`](https://github.com/amnezia-vpn/amneziawg-go/blob/12a0122/device/cookie.go) — handles S3 padding (cookie messages) and H3 magic header.
- [`outline/`](https://github.com/amnezia-vpn/amneziawg-go/tree/12a0122/outline) — recently-added integration layer for the Outline SDK (commit `449d7cf`, Dec 2025). Lets Outline-based applications consume AmneziaWG as one of their fallback strategies.

## Known Weaknesses

- **Configuration coordination across endpoints**. H/S/Jc parameters
  for handshake/transport-message processing must match between
  client and server (the magic-header rewriter has to be invertible
  on both sides). Junk-packet and signature-packet parameters
  (`Jc`/`Jmin`/`Jmax`/`I1-I5`) **don't** need to match — those are
  emit-only client-side. Operators that try to reuse a vanilla
  WireGuard peer with an AmneziaWG client get silent handshake
  failures.
- **Junk packet MTU footgun**. Per upstream README:
  *"If Jmax >= system MTU (not the one specified in AWG), then the
  system can fracture this packet into fragments, which looks
  suspicious from the censor side."* Junk packets that get IP-
  fragmented are themselves a fingerprint.
- **Static obfuscation parameters per deployment** are still a
  fingerprint per-deployment. A censor that learns "AmneziaWG
  config X uses H1=12345-12399, S1=80-200, Jc=8" can match those
  parameters precisely. Operators rotate these or jitter them per
  client cohort.
- **UDP-only**. WireGuard's design is UDP and AmneziaWG inherits
  it. Networks with all-UDP-blocked policies (some Russian mobile
  carriers, parts of GFW under heavy traffic conditions) defeat
  AmneziaWG without a TCP fallback. Pair with a TCP-based protocol
  in a multi-protocol deployment.
- **AWG 2.0 ↔ AWG 1.5 compatibility**: not all servers and clients
  in the wild have rolled forward. Amnezia's own clients (Android,
  Windows, Apple) have been updating across 2025-2026; mixed-
  version deployments need configuration coordination on which
  AWG features are enabled.
- **Active probing of the UDP listener** is mitigated by
  WireGuard's no-response posture, not by the obfuscation. If a
  censor's probe knows the deobfuscation parameters, it can
  observe the WireGuard handshake-failure silence as the
  fingerprint just like vanilla WireGuard.

## Deployment Notes

- **AWG 2.0 is the generation Amnezia is shipping in 2026**. Tag
  v0.2.15 / v0.2.16 / v0.2.17 (current) are all post-2.0. Older
  tags v0.2.13 / v0.2.14-beta-awg-1.5 still see updates for
  legacy clients.
- The Amnezia client apps (`amnezia-client`, the desktop GUI;
  `amneziawg-android`; `amneziawg-windows`) bundle the relevant
  binaries and provide a UI for the obfuscation knobs. The
  protocol's strength is largely a function of how aggressively
  these knobs are used per-deployment.
- **Outline SDK glue** (Dec 2025) lets Outline-based applications
  consume AmneziaWG as a fallback strategy in the Smart Dialer
  config. So `outline-smart-dialer`-driven deployments can now
  add AmneziaWG to their candidate list. Cross-pollination
  between catalog families.
- Internal Lantern stack: AmneziaWG sits in lantern-box's
  `protocol/amnezia/` per the AGENTS.md (a Lantern-side wrapper
  around the AmneziaWG library); it's one of the protocols the
  bandit selects from.

## Cross-References

- Related protocols (this catalog):
  - **(TBD) `wireguard`** — the unmodified upstream. AmneziaWG is
    a strict superset: same crypto, same Noise pattern, same auth.
    Useful as the "what we'd ship if censorship weren't a thing"
    reference.
  - `outline-smart-dialer` — AmneziaWG can be a fallback strategy
    in a smart-dialer config (since the Dec 2025 outline-glue
    integration).
  - `psiphon-conjure-ossh`'s `DTLS-OSSH` variant — different
    UDP-based circumvention story; comparison point for "how do
    we do UDP-based evasion."
  - `hysteria2` — the other UDP-friendly protocol in the catalog.
    Hysteria2 mimics HTTP/3 over QUIC; AmneziaWG keeps the
    WireGuard-Noise design and fights detection through
    parametric obfuscation. Different families, complementary.
