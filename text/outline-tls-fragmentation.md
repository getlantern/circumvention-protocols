# Outline TLS Record Fragmentation (tlsfrag)

## TL;DR

A composable userspace strategy: wrap any TCP `StreamDialer`,
intercept the first TLS handshake record (the one that carries
the ClientHello), and split it across **multiple TLS records**
before sending. To a censor doing single-record SNI extraction,
the SNI is no longer in any single record. To a censor that
chooses to reassemble, the cost (state + memory) scales linearly
with how aggressively it pursues this technique.

Backed by the [niere et al. ACM CCS 2023 poster](../circumvention-corpus/corpus/papers/2023-niere-poster.yaml) — *"Circumventing the GFW with TLS Record Fragmentation"* — and the broader Paderborn upb-syssec
research line.

This is **not a wire protocol** — it's a wrapping strategy that
applies to any TLS-using transport. The catalog entry exists
because the Outline SDK exposes it as a first-class composable
piece, and the protocol-designer agent should reach for it when
composing first-packet evasion for any TLS-bearing protocol.

## Threat Model

Targets a specific, common DPI implementation choice:

- **SNI extraction by reading a single TLS record.** Many DPI
  middleboxes parse the first TLS record they see and look for
  the `server_name` extension inside the ClientHello. If the
  ClientHello is split across records, the SNI may straddle the
  boundary or sit entirely in the second record — and the
  middlebox sees only the first.
- **Forces reassembly state on the censor.** A determined censor
  can reassemble TLS records, but that requires allocating
  per-flow buffer state and waiting for record N before parsing
  record 1's complete payload. At Internet scale, that's
  expensive. Niere et al. characterise it as "making censorship
  more difficult and resource-intensive."
- **Userspace-only.** The technique fragments the application
  (TLS) layer, not the TCP layer — no raw-socket privileges, no
  kernel modules, no Geneva-style packet manipulation. A
  userspace TLS client can do this on its own.

What it does **not** address:

- Censors that already do TLS-record reassembly comprehensively.
  Modern GFW-class DPI does perform record reassembly in many
  contexts; tlsfrag is a useful tool but not a complete answer
  on its own.
- Steady-state traffic — only the ClientHello is fragmented.
  Every TLS record after that goes through unmodified.

## Wire Format

A normal TLS handshake first packet:

```
[5-byte TLS record header: type=22(handshake), version, length=N]
[handshake record body, length N bytes:
   ClientHello — version, random, session_id,
   cipher_suites, compression, extensions ... including
   the server_name (SNI) extension somewhere in the middle]
```

After tlsfrag splits at index `n`:

```
[5-byte TLS record header: length=n]
[first n bytes of handshake body]

[5-byte TLS record header: length=N-n]
[remaining (N-n) bytes of handshake body]
```

Both records together still constitute a valid TLS handshake
once a peer reassembles them. The split point is chosen by the
caller:

- **Fixed length** (`NewFixedLenStreamDialer(splitLen)`): split
  at exactly the same byte offset on every connection. Most
  efficient, no allocation. Typical pick: 1 byte (split at the
  very beginning so even the handshake-message-type field is in
  its own record).
- **Callback** (`NewStreamDialerFunc(frag)`): the caller's
  `FragFunc(record []byte) int` decides per-ClientHello where
  to split. Useful for "split right before the SNI" or
  "split adaptively based on what the ClientHello looks like".

After the ClientHello, all subsequent reads/writes pass through
unmodified.

## Cover Protocol

The protocol that runs underneath. tlsfrag itself doesn't define
a cover — it's a transformation applied to whatever TLS-using
transport sits beneath it. Common pairings:

- Real HTTPS (when used as part of a domain-fronting or direct
  HTTPS request).
- TLS-OSSH, vless-reality, samizdat, or any other catalog entry
  whose first packet is a TLS ClientHello.

## Authentication

None at this layer. Authentication lives in the underlying
transport (the TLS server identity, plus whatever in-handshake
auth that protocol uses).

## Probe Resistance

Doesn't change probe resistance directly. tlsfrag is a passive
DPI evasion — it makes the SNI harder to extract for an observer
who doesn't reassemble records. Active probes that do a full
TLS handshake see the ClientHello reassembled normally; they
still complete the handshake (or whatever auth fallback the
underlying protocol implements).

## Implementation

Pinned at outline-sdk main @
[`bc36b14`](https://github.com/Jigsaw-Code/outline-sdk/commit/bc36b14).

License: Apache-2.0. Pure Go.

Key files:

- [`transport/tlsfrag/doc.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/tlsfrag/doc.go) — package doc, cites Niere et al. directly.
- [`transport/tlsfrag/stream_dialer.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/tlsfrag/stream_dialer.go) — `NewStreamDialerFunc(base, frag)`, `NewFixedLenStreamDialer(base, splitLen)`, `WrapConnFragFunc`, `WrapConnFixedLen`.
- [`transport/tlsfrag/writer.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/tlsfrag/writer.go) — buffers the Write stream until a complete ClientHello record arrives, then re-emits as two records.
- [`transport/tlsfrag/buffer.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/tlsfrag/buffer.go) / [`tls.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/tlsfrag/tls.go) — TLS record parsing (just enough to identify the ClientHello and find the body).
- [`transport/tlsfrag/record_len_writer.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/tlsfrag/record_len_writer.go) — fixed-length splitter, allocation-free fast path.

## Known Weaknesses

- **DPI middleboxes that do TLS record reassembly defeat this**
  by construction. The technique buys cost on the censor, not
  invisibility. Sophisticated state-level adversaries
  (GFW, TSPU at scale) do reassemble, so tlsfrag alone is
  insufficient against them — pair with a different evasion
  layer.
- **First-packet only.** No effect on steady-state traffic, so
  detection methods that look beyond the first packet (size
  histograms, timing analysis, SNI-from-other-records, etc.)
  are unaffected.
- **Behavioral fingerprint of "ClientHello arrives in N records
  with these specific lengths"** is itself a fingerprint
  candidate. Real browsers don't usually fragment ClientHellos.
  A censor that learns "Outline-style tlsfrag splits at N bytes"
  can match on that. The callback-style API exists to randomize
  the split point per connection and break this fingerprint, but
  most operators use the fixed-length API for simplicity.
- **TLS extensions reordering / padding** is a separate axis
  of evasion that tlsfrag doesn't touch. Combine with uTLS-style
  fingerprint mimicry for a complete cover.

## Deployment Notes

- A **standard tool in the Outline SDK's box** of evasion
  primitives, alongside `split` (TCP-segment splitting),
  `disorder` (TTL trick), and the `smart` dialer (which composes
  them). The SDK README explicitly describes "bypass SNI-based
  blocking" as a use case for tlsfrag.
- Lantern's internal `2026-04-non-protocol-evasion` recommends
  TLS record fragmentation as a low-cost capability to add to
  any TLS-using transport — including REALITY-family stacks.
  Catalog cross-reference: see the niere-2023 entry's
  Implications-for-Lantern note in the public corpus.
- Composable: any catalog entry whose first packet is a TLS
  ClientHello can layer tlsfrag underneath. Concrete pairings
  in this catalog: `samizdat` (already does its own
  Geneva-inspired *TCP-segment* fragmentation but tlsfrag is a
  complementary record-level layer), `psiphon-tls-ossh`,
  `vless-reality`, `naive`.

## Cross-References

- Public corpus: `2023-niere-poster` — the canonical paper
  (Niere, Hebrok, Somorovsky, Merget; ACM CCS 2023 poster).
- Internal docs: `2026-04-non-protocol-evasion` — explicitly
  recommends TLS record fragmentation as a low-cost addition to
  any TLS-using Lantern transport.
- Related protocols (this catalog):
  - `outline-tcp-tricks` — TCP-segment splitting + TTL-disorder.
    Sister tricks at a different protocol layer (TCP, not TLS
    record). Often combined.
  - `outline-shadowsocks` — same toolkit, different problem
    (look-like-nothing AEAD).
  - `outline-smart-dialer` — orchestrates tlsfrag + other
    strategies, picks per-region.
  - All TLS-mimicry catalog entries (`samizdat`,
    `psiphon-tls-ossh`, `vless-reality`, `naive`,
    `tlsmasq`, `reflex`) — tlsfrag is composable underneath any
    of them.
