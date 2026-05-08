# Outline TCP-layer Tricks (split + disorder)

## TL;DR

Two TCP-layer evasion tricks the Outline SDK packages as
composable `StreamDialer` wrappers:

- **`split`**: write the outgoing stream in two `Write()` calls
  at a caller-chosen byte offset. Most TCP stacks turn each
  `Write()` into its own segment (PSH-flagged), so the single
  application-level write becomes two TCP segments on the wire.
  Useful against DPI that reads "exactly one TCP segment of
  payload" to extract SNI / a known protocol fingerprint.

- **`disorder`**: set the TCP socket's IP TTL/HopLimit to 1
  immediately before the **N-th** outgoing Write. That packet
  is dropped at the first hop after the local network — never
  reaches the server. But a censor's middlebox **between** the
  client and that hop sees the packet, parses it, and updates
  its TCP-flow state. After that Write, the dialer restores the
  TTL to its default; the next Write re-sends the same byte
  range normally, the server processes it as the real stream,
  and the censor's middlebox is now desynced (it expected the
  bytes from the dropped packet to come next, but they arrive
  again from the new packet — looks like a TCP retransmit /
  reorder).

Both are Geneva-style stateful-DPI confusion, but applied
entirely in userspace using standard `sockopt` (no raw sockets,
no kernel modules). Composable underneath any TCP-using transport
in the catalog.

## Threat Model

Targets stateful DPI middleboxes that maintain per-flow parsing
state:

### `split`

- **Single-segment SNI matchers**: a DPI that reads the first
  TCP payload segment and parses it as TLS sees only the prefix
  of the ClientHello. If the ClientHello straddles two segments,
  the SNI may live in the second one. Same idea as
  `outline-tls-fragmentation` but at the TCP layer instead of
  the TLS-record layer — both are useful, both are defeated by
  censors that fully reassemble.

### `disorder`

- **DPI that maintains TCP-flow state and trusts what it sees on
  the wire**: a TCP middlebox that processes packets as they
  arrive (rather than reassembling end-to-end) sees the
  TTL=1-doomed packet and updates its parser. When the real
  packet arrives later (re-sent at normal TTL), the middlebox
  sees it as a retransmit of bytes it has already
  "processed" — and either ignores it or gets confused about
  the flow's logical state. The actual TCP server sees a
  perfectly normal stream because it never received the
  TTL=1 packet at all.

What these **do not** address:

- Censors that buffer / fully reassemble TCP streams end-to-end
  before parsing (modern GFW-class adversaries do this in many
  contexts).
- Application-layer threats — these are TCP tricks, not wire
  protocol changes. Pair with TLS-mimicry / first-packet
  shaping / etc.
- ICMP responses from the TTL=1 hop. The `disorder` trick
  generates an ICMP Time-Exceeded reply at the dropping router.
  A censor that watches outbound ICMP can fingerprint the
  pattern. In practice the ICMP usually goes to the dropping
  router, not the censor, but it's a side-channel.

## Wire Format

### `split`

A single `Write([]byte{ A, B, C, D, E })` becomes two physical
writes:

```
write 1: { A, B }      // first split-iterator value: 2
write 2: { C, D, E }
```

Each Go `Write` triggers a separate TCP `send()` syscall, which
under typical TCP_NODELAY-on or under default Nagle behavior
typically produces two segments. The receiving server reassembles
trivially.

The split point is supplied by a `SplitIterator` callback that
returns "how many bytes until the next split, or 0 to stop."
`NewFixedSplitIterator(n)` returns `n` once and then zero — the
common case. More elaborate iterators can do multiple splits,
random splits, etc.

### `disorder`

The dialer counts outgoing Writes. On the configured Nth write
(`runAtPacketN` parameter):

```
1. Save current TCP_TTL via sockopt
2. Set TCP_TTL = 1
3. conn.Write(data)        // packet hits the wire, dies at first hop
4. Restore TCP_TTL = saved value
5. // Next Write happens normally; the failed bytes get re-sent
```

The "next Write happens normally" is doing real work: TCP's own
retransmit mechanism notices the missing ACK and re-sends the
unacked bytes. Since the TTL is now restored, those bytes reach
the server. The censor's middlebox saw the original send (with
TTL=1, before the drop); when the retransmit arrives, the
middlebox either ignores it (looks like dup) or treats it as new
data starting at an unexpected sequence number — DPI state
desyncs.

This is more invasive than `split` — it depends on actually
crossing a hop that's between the client and the censor and
isn't the censor itself. Operationally fragile.

## Cover Protocol

Neither trick changes the wire protocol the underlying transport
uses. They just change the **packet shape** of the outgoing TCP
stream. Composable underneath any TCP-using transport.

## Authentication

None at this layer. Authentication lives in the underlying
transport.

## Probe Resistance

Doesn't change probe resistance directly. These tricks are
orthogonal to "is this connection a probe?" — they target what
the censor's DPI machine sees during a real connection.

## Implementation

Pinned at outline-sdk main @
[`bc36b14`](https://github.com/Jigsaw-Code/outline-sdk/commit/bc36b14).

License: Apache-2.0. Pure Go.

### `split`

- [`transport/split/stream_dialer.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/split/stream_dialer.go) — `NewStreamDialer(base, nextSplit SplitIterator)`.
- [`transport/split/writer.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/transport/split/writer.go) — `splitWriter`, `SplitIterator` callback type, `NewFixedSplitIterator(n)` helper.

### `disorder`

- [`x/disorder/stream_dialer.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/x/disorder/stream_dialer.go) — `NewStreamDialer(base, disorderPacketN int)`.
- [`x/disorder/writer.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/x/disorder/writer.go) — `disorderWriter`, uses `sockopt.TCPOptions.HopLimit()` / `SetHopLimit()` to manipulate TTL on the live connection.
- [`x/sockopt/`](https://github.com/Jigsaw-Code/outline-sdk/tree/bc36b14/x/sockopt) — the cross-platform sockopt wrapper (Linux/macOS/Windows differ).

The `x/disorder` package note explains that the trick is:

> *"Wait for disorderPacketN'th call to Write. All Write
> requests before and after the target packet are written
> normally. Send the disorderPacketN'th packet with TTL == 1.
> This packet is dropped somewhere in the network and never
> reaches the server. TTL is restored. The next part of data
> is sent normally."*

## Known Weaknesses

### General to both

- **End-to-end TCP reassemblers** (GFW-class) defeat both
  tricks. The middlebox waits for the full byte stream before
  parsing.
- **First-packet only by default**. Most operators apply these
  tricks only to the very first Write (the TLS ClientHello or
  initial protocol handshake). Steady-state traffic isn't
  affected.

### `split`-specific

- **Behavioral fingerprint**: a DPI that learns "client splits
  payload at exactly 5 bytes" can match on that. Randomize the
  split iterator to defeat this. Outline's `SplitIterator` API
  supports it.
- **Some networks coalesce small TCP segments** at intermediate
  hops (e.g. via TSO/GRO offload), defeating the segmentation
  on the wire. Less common on the modern Internet but possible.

### `disorder`-specific

- **TTL=1 ICMP Time-Exceeded** reply is generated by the dropping
  router. A censor that watches outbound ICMP can pattern-match.
  Practically: the ICMP goes to the local network's dropping
  router, not back to the client, so the censor usually doesn't
  see it — but if the censor *is* between the client and the
  dropping router, this leaks.
- **Path-dependence**: relies on a hop between the client and
  the censor that drops at TTL=1. On networks where the
  censor and the client share a /24, there may be no
  intermediate hop, and the trick fails.
- **Disrupts TCP timing**. The TCP retransmit adds visible
  latency on the chosen Write. Some applications notice (e.g.
  RTT-sensitive QUIC handshakes done over TCP fallback).
- **Reorders packets at scale** — TCP cares about sequence
  numbers, not arrival order, so this works correctly, but
  some middleboxes get aggressive about flagging out-of-order
  delivery as suspicious.
- **Per-platform sockopt support** — the underlying
  `sockopt.TCPOptions` works on Linux/macOS/Windows but the
  exact behavior of TTL=1 / dropped-packet retransmit varies
  by OS-level TCP stack. Test on the target platform.

## Deployment Notes

- Standard tools in the Outline SDK's evasion toolbox. Both
  pre-date Lantern's `2026-04-non-protocol-evasion`
  recommendations and are referenced there as low-cost first-
  packet evasions.
- Composable: applied as `StreamDialer` wrappers underneath any
  TCP-using transport. Common composition: SOCKS5 / HTTPS-proxy
  → tlsfrag → split → underlying TCP. Outline's Smart Dialer
  config language (`x/configurl`) lets you express this as a
  single URL like `tlsfrag:1|split:2|tcp`.
- Lantern's `samizdat` already does its own Geneva-inspired
  TCP-segment fragmentation for the ClientHello; `split` is the
  Outline-toolkit equivalent. Either works against the same
  threat (single-segment SNI matchers).
- `disorder` is operationally more fragile than `split`; many
  Outline deployments use `split` everywhere and `disorder` only
  in regions where simpler tricks fail. The Smart Dialer's
  strategy search includes both as candidates.

## Cross-References

- Related protocols (this catalog):
  - `outline-tls-fragmentation` — sister trick at the TLS-record
    layer instead of the TCP-segment layer. Often combined.
    Niere et al. 2023 specifically compares the two.
  - `outline-shadowsocks` — Outline's wire protocol; benefits
    from `split` at the very first packet to randomize the
    salt-bearing-segment shape.
  - `outline-smart-dialer` — orchestrates split / disorder /
    tlsfrag / DNS strategies and picks per-region.
  - `samizdat` — does its own Geneva-style TCP fragmentation
    natively; this catalog's most direct in-Lantern analog of
    the `split` trick.
  - All TLS-using catalog entries — `split` / `disorder` are
    composable underneath any of them.
