# Outline Smart Dialer

## TL;DR

Not a wire protocol — a **strategy-finder** that takes a YAML
config listing candidate DNS resolvers, candidate TLS-layer
evasion transforms, and an optional fallback-proxy list, then
races them against a list of test domains. The first combination
that successfully reaches every test domain wins; the dialer
returned uses that combination for all subsequent connections.

The catalog entry exists because this is the **design pattern
Outline pushes** for circumvention: rather than "which single
protocol works in country X today," ship a small set of
strategies and let the client probe per session. Several of the
strategies it composes are independent catalog entries
(`outline-shadowsocks`, `outline-tls-fragmentation`,
`outline-tcp-tricks`).

When the protocol-designer agent is asked "what should we ship
for region X if we don't know what's blocked?" — this is the
shape of the answer.

## Threat Model

The Smart Dialer doesn't have its own threat model — it
inherits the threat model of whatever winning strategy it picks
for a given run. The interesting design property is **what the
attacker observes about the dialer**, not the strategies:

- **Active probing of the test domains**: each `StrategyFinder`
  invocation issues parallel test connections to a small set of
  configured test domains (e.g. `www.cloudflare.com`,
  `dns.google`). Lots of these requests in a short window from
  one client IP look distinctive; pacing knobs (`TestTimeout`,
  the racing pattern) limit the burst.
- **Strategy fingerprinting**: a censor that sees a single
  client cycle through a known sequence of strategies (DNS
  attempt → TLS-frag attempt → split attempt → ...) can
  fingerprint the Smart Dialer itself. Mitigated by
  randomizing the strategy order and not over-shipping unusual
  candidates.
- **Cache leakage**: the dialer caches the winning strategy in
  memory (and the integrationtest fixture caches across runs).
  A single working strategy gets reused, which is good for
  performance but bad if the censor characterises the cached
  strategy and starts blocking specifically.

## Wire Format

The Smart Dialer doesn't define a wire format. The strategies it
chooses among each have their own wire formats; see the
individual catalog entries (`outline-shadowsocks`,
`outline-tls-fragmentation`, `outline-tcp-tricks`).

The **configuration format** is:

```yaml
dns:
  # ordered list of DNS strategies to try
  - system: {}                    # OS resolver
  - https:                        # DoH
      name: 8.8.8.8
  - https:
      name: 9.9.9.9
  - tls:                          # DoT
      name: dns.google
  - udp:
      address: 8.8.8.8
  - tcp:
      address: 8.8.8.8

tls:
  # ordered list of TLS-layer transforms to try
  - ""                              # no transform
  - split:2                         # TCP split-write at byte 2
  - tlsfrag:1                       # TLS record-fragment at byte 1
  - override:host=cloudflare.net|tlsfrag:1   # domain front + frag

fallback:
  # used only if every (DNS, TLS) combination above fails
  - ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprSzdEdHQ0MkJLOE9hRjBKYjdpWGFK@1.2.3.4:9999/?outline=1
  - socks5://user:pass@proxy.example.com:1080
  - psiphon:
      PropagationChannelId: "..."
      SponsorId: "..."
      ...
```

Each `tls:` entry is a `configurl`-mini-language string. Pipe
operator (`|`) chains transforms left to right (outer to inner).

## Cover Protocol

Same as whatever strategy wins. The Smart Dialer is a
meta-protocol; it doesn't carry traffic itself.

## Authentication

None at this layer. Auth lives in the chosen underlying
strategy (e.g. Shadowsocks password if a fallback is selected,
or whatever the proxyless TLS strategy targets).

## Probe Resistance

Not applicable in the usual sense. The dialer's distinctive
behavior is the **strategy search itself** — a censor can
observe a flurry of parallel test connections to known test
domains as a fingerprint. In the racing logic the test domains
are configurable to dilute this, but most deployments use a
small canonical list.

The recommended posture per the upstream README: keep the test
list short and target real high-collateral domains
(`cloudflare.com`, `google.com`, etc.) so the search itself
generates legitimate-looking traffic.

## Implementation

Pinned at outline-sdk main @
[`bc36b14`](https://github.com/Jigsaw-Code/outline-sdk/commit/bc36b14).

License: Apache-2.0. Pure Go.

Key files:

- [`x/smart/doc.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/x/smart/doc.go) — package doc: *"utilities to dynamically find serverless strategies for circumvention."*
- [`x/smart/README.md`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/x/smart/README.md) — the YAML config language reference and usage examples.
- [`x/smart/racer.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/x/smart/racer.go) — `raceTests`. Generic racer that calls a test function on each candidate; returns the first success. Bounds wait time per candidate (`maxWait`) so failed strategies don't block the dialer indefinitely.
- [`x/smart/dns.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/x/smart/dns.go) — DNS strategy testing.
- [`x/smart/cname.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/x/smart/cname.go) — CNAME-aware testing (resolves through CNAMEs to detect partial DNS poisoning).
- [`x/smart/cache.go`](https://github.com/Jigsaw-Code/outline-sdk/blob/bc36b14/x/smart/cache.go) — caches the winning strategy across calls within a session.
- [`x/configurl/`](https://github.com/Jigsaw-Code/outline-sdk/tree/bc36b14/x/configurl) — the URL/string mini-language used in `tls:` and `fallback:` entries. Defines how `tlsfrag:1`, `split:2`, `override:host=...|...`, `ss://`, `socks5://`, etc. parse into composed `StreamDialer`s.

The public API: a `StrategyFinder` struct with `TestTimeout`,
`LogWriter`, `StreamDialer`, `PacketDialer` fields. Call
`NewDialer(testDomains, configBytes)` and you get back a
`transport.StreamDialer` ready to use.

## Known Weaknesses

- **First call has high latency**. The strategy search runs in
  parallel, but worst case (every strategy fails until the
  fallback) takes `len(strategies) * TestTimeout`. Operators
  typically cache the winning strategy across application
  launches to amortize.
- **Strategy fingerprint risk**. A censor that watches a single
  client IP cycle through several test connections at startup
  can flag this as the Smart Dialer pattern. Lantern's
  `2026-04-non-protocol-evasion` cautions about this kind of
  behavioral fingerprint as one of the "non-protocol detection
  vectors" beyond wire-protocol analysis.
- **Test domain censorship**. The dialer's correctness depends
  on the test domains being reachable when censorship isn't in
  the way and unreachable when it is. If a censor blocks the
  test domains (or unblocks them via local DNS injection),
  the dialer's ground-truth signal is wrong. Mitigated by
  picking high-collateral test domains that censors are unlikely
  to fully block.
- **No "this strategy stopped working" recovery**. The cache
  persists a winning strategy; if conditions change (new
  blocking deployed mid-session), the dialer doesn't
  automatically re-search. Operators add their own cache
  invalidation logic on top.
- **Doesn't address steady-state evasion**. The dialer picks a
  strategy at connection time; once a connection is up, the
  underlying strategy carries the load. Detection methods that
  inspect steady-state traffic patterns are unaddressed at this
  layer.

## Deployment Notes

- Standard pattern in the Outline Client and other apps that
  embed the SDK. Reaches millions of users; the configuration
  language is stable and well-documented.
- The `fallback:` block can include a Psiphon configuration
  (with the GPL-encumbered Psiphon library brought in via build
  tag) — so even Outline's "proxyless" pipeline degrades to a
  fully-proxied path automatically when nothing simpler works.
  This is the modern composite-circumvention story in one
  config file.
- Lantern's `2026-04-non-protocol-evasion` discusses the
  "let the client probe" pattern explicitly; the Smart Dialer
  is the off-the-shelf realisation. Worth treating as a design
  reference even when reaching for our own equivalents
  (the bandit + smart-dialer-style probing have similar logic
  but operate at different scales — the bandit is a server-
  selection mechanism, smart-dialer is a per-session
  strategy-selection mechanism).

## Cross-References

- Internal: `2026-04-non-protocol-evasion` — the "non-protocol"
  detection vectors include behavioral fingerprints that probing
  patterns like Smart Dialer's are vulnerable to.
- Related protocols (this catalog):
  - `outline-shadowsocks`, `outline-tls-fragmentation`,
    `outline-tcp-tricks` — the candidate strategies the Smart
    Dialer composes from. Each has its own catalog entry.
  - `psiphon-inproxy`'s broker-mediated discovery — a different
    "let the system pick the strategy" design (server-side
    matchmaking + tactics) at a different scale.
  - All TLS-using catalog entries — Smart Dialer's `tls:` list
    can include strategies that adapt to any of them.
