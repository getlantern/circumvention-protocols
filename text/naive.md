# NaïveProxy

## TL;DR

The client is **a fork of Chromium's network stack** — not a mimic.
Outbound connections use Chrome's actual TLS / HTTP-2 implementation,
so JA3 / JA4 / extension ordering / cipher suite preference / ALPN
are byte-identical to a same-version Chrome browser by definition.
The server is a fork of Caddy's `forwardproxy` plugin: a real Caddy
host that serves a real website and routes HTTP CONNECT proxy
requests gated by a `Proxy-Authorization: Basic` header — probes
without auth see the website, valid clients get the proxy. A small
padding layer (3-byte length-header + 0–255 random pad on the first
few stream packets each direction) defeats first-packet length
analysis.

The whole evasion strategy hinges on **being** Chrome rather than
**looking like** Chrome.

## Threat Model

The README enumerates four named threats and how naive mitigates
each. Quoting the upstream and grounding against the implementation:

- **TLS parameter fingerprinting** (JA3/JA4 family). Defeated
  because the client *is* Chrome's `net/` stack. There's no uTLS
  fingerprint table to maintain — if the client matches Chrome at
  all, it matches all the way down (extensions order, supported
  groups, signature algorithms, GREASE values, the whole stack).
- **Active probing** (replay / scan). Defeated by **application
  fronting**: the server is a real Caddy host serving a real
  website at the configured domain. Proxy traffic is routed inside
  Caddy by `Proxy-Authorization`. A probe that doesn't have the
  password gets the file_server's response, not the proxy's.
- **Website fingerprinting / traffic classification**. Mitigated by
  HTTP/2 multiplexing (one TLS connection carries many streams) and
  the "parroting preambles" of Chrome's own stack.
- **Length-based traffic analysis**. Mitigated by the padding layer
  (`flushingIoCopy` in the forwardproxy fork): adds 3 bytes of
  framing + 0–255 bytes of zero padding to the first
  `NumFirstPaddings` reads each direction. The client peels these
  bytes off symmetrically. Doesn't run forever — just enough to
  break the censor's first-packet histograms.

Does **not** address:

- **IP reputation** — the proxy IP still has to be reachable.
- **Behavioral profiling of repeat HTTP/2 sessions to a single
  domain** (e.g. always-on background traffic to `example.com`),
  which is a higher-layer concern Naive doesn't touch.

## Wire Format

Standard HTTPS to the configured server, with HTTP CONNECT for the
proxy operation. There is **no** custom wire framing in the
SOCKS5 → HTTPS direction — this is the entire point.

```
Client (Chromium fork)                Server (Caddy + forwardproxy fork)
  |                                                |
  |  TCP + TLS 1.3 handshake                       |
  |  (real Chrome ClientHello — extensions,        |
  |   ALPN, cipher prefs, GREASE all real)         |
  |                                                |
  |  HTTP/2 SETTINGS exchange                      |
  |                                                |
  |  HTTP/2 stream N:                              |
  |    :method = CONNECT                           |
  |    :authority = target.example.com:443         |
  |    Proxy-Authorization: Basic <base64(u:p)>    |
  |                                                |
  |                                                |  Caddy routes:
  |                                                |    if Proxy-Authorization matches:
  |                                                |      forward_proxy CONNECT path
  |                                                |    else:
  |                                                |      file_server (real website)
  |                                                |
  |  HTTP/2 stream N response:                     |
  |    :status = 200 (proxy ok)                    |
  |    Padding: <30-62 random bytes>               |
  |                                                |
  |  Bidirectional HTTP/2 DATA frames carry the    |
  |  proxied bytes. First N data frames each       |
  |  direction get a 3-byte length header + a      |
  |  random-sized zero-padding tail (see Padding). |
  |                                                |
  |  HTTP/2 multiplexes additional CONNECT streams |
  |  over the same TLS connection.                 |
```

### Padding layer

Per [`forwardproxy.go:693-740`](https://github.com/klzgrad/forwardproxy/blob/d62c80d/forwardproxy.go#L693-L740) (and matching client code in the Chromium fork):

For each direction, on the first `NumFirstPaddings` data writes:

```
[2-byte BE data length][1-byte pad length][data bytes...][zero pad bytes...]
```

- Data length: actual payload byte count, 0–65535.
- Pad length: random 0–255.
- Padding bytes: literal zero. (The receiver knows the length and
  discards them.)

After the first `NumFirstPaddings` writes, the stream returns to
plain HTTP/2 DATA frames with no extra framing. This intentionally
limits padding to the connection-establishment region where length
fingerprinting is most informative — pure performance optimization.

### `Padding` response header

Per `forwardproxy.go:308-320`, the server's HTTP/2 response also
carries a `Padding:` header with 30 to 61 random bytes drawn from
the alphabet `!#$()+<>?@[]^\`{}` (16 chars, 4-bit indexed) followed
by `~` filler. Randomizes response-byte-count for the first round
trip.

## Cover Protocol

A Caddy-served HTTPS website. Anything the operator chooses for the
`file_server` block — typically a static-site directory. The proxy
endpoint shares the same TLS server identity, the same TCP port, the
same TLS cert. A passive observer cannot distinguish proxy traffic
from "someone is browsing the site over HTTP/2."

The README is explicit: *"The frontend server can be any well-known
reverse proxy that is able to route HTTP/2 traffic based on HTTP
authorization headers ... [k]nown ones include Caddy with its
forwardproxy plugin and HAProxy."* — so the cover protocol is
literally just "real HTTPS hosting."

## Authentication

HTTP Basic over TLS, on the CONNECT request:

- Client config: `"proxy": "https://user:pass@example.com"`.
- Header sent: `Proxy-Authorization: Basic base64("user:pass")`.
- Caddy compares (constant-time) against its `basic_auth` config
  block.
- No match → request is dispatched to whatever else Caddy is serving
  (typically `file_server`).
- Match → forwardproxy plugin handles the CONNECT and tunnels the
  inner TCP stream as HTTP/2 DATA frames.

There is no extra cryptographic auth layer beyond TLS-1.3 +
HTTP-Basic. That's intentional: extra layers would be detectable.

## Probe Resistance

By construction. The server is *also* a real website. There is no
"are you a probe?" branch — there's a "do you have the right
`Proxy-Authorization` header?" branch:

- Probe sends a normal browsing request → gets the website.
- Probe sends a CONNECT with no auth → Caddy returns the website's
  response for the CONNECT (typically a 404 for a real site, with
  the optional `probe_resistance` config switch making this even
  more browser-shaped).
- Probe sends a CONNECT with wrong auth → same as no auth.

The server reveals nothing about the proxy code path unless the
correct password is presented.

## Implementation

Pinned at:

- `klzgrad/naiveproxy` (client): master @ [`95bd3a5`](https://github.com/klzgrad/naiveproxy/commit/95bd3a5)
- `klzgrad/forwardproxy` (server, Caddy plugin): `naive` branch @ [`d62c80d`](https://github.com/klzgrad/forwardproxy/commit/d62c80d)

Client repo (`klzgrad/naiveproxy`) is BSD-3-Clause (Chromium's
license; this is a fork of `chromium/src/net/`). It is built by
checking out a specific Chromium release tag, applying a small
patch that adds SOCKS5 listener mode + the padding layer, and
producing a `naive` binary. Users are explicitly directed to
**always use the latest release** so the binary's TLS fingerprint
matches whatever Chrome version is currently shipping.

Server repo (`klzgrad/forwardproxy`, branch `naive`) is Apache-2.0
(forked from caddyserver/forwardproxy). Pure Go.

Key files (server side):

- [`forwardproxy.go`](https://github.com/klzgrad/forwardproxy/blob/d62c80d/forwardproxy.go) — the whole plugin. Padding constants and code at lines 308-320 (response `Padding` header) and 693-740 (`flushingIoCopy` body padding). `ProbeResistance` config object at line 76. CONNECT handling and `basic_auth` matching dispatched from the surrounding `ServeHTTP`.

Client-side wire-protocol implementation lives inside the Chromium
patch: a custom `URLRequest`/`HttpStream` that interleaves the
3-byte length header + zero padding on the first `NumFirstPaddings`
data writes. Browsing the actual Chromium fork is a substantial
exercise — naive is one of the few circumvention protocols where
"read the upstream" means "read upstream Chromium."

## Known Weaknesses

- **Chromium release-cycle coupling**. The TLS fingerprint mimics
  Chrome by being Chrome. If the operator runs a stale binary that
  matches a 6-month-old Chrome release, the connection's JA4 lags
  the population of real Chrome users — a censor that fingerprints
  by Chrome version (rare but seen) can flag this. The README's
  "always use the latest version" note is mandatory in practice.
- **HTTP CONNECT to one host, repeatedly**. A long-running
  proxied client opens one HTTP/2 connection to the same Caddy
  host and pumps a lot of traffic through it. Real Chrome browsing
  involves connections to many domains. Higher-layer connection-
  graph profiling distinguishes "naïve user" from "real browser
  user." Naive doesn't try to fix this — it accepts the trade.
- **Padding only at start**. The padding layer protects connection
  setup. A censor that does mid-stream length analysis can still
  recover signal from steady-state traffic.
- **HTTP/2 only, no QUIC**. Naive's wire is currently HTTP/2 over
  TCP TLS. HTTP/3 / QUIC support has been discussed upstream but
  isn't the default. In networks that block UDP entirely, that's a
  feature; in networks that want to fingerprint stale HTTP/2 mixes,
  that's a small risk.
- **Caddy as the cover host**. Caddy is widely deployed but
  fingerprintable as a server (HTTP server header, TLS config
  defaults). Operators serious about cover symmetry can swap
  Caddy for HAProxy + the same plugin model, but most deployments
  use Caddy.

## Deployment Notes

- The README explicitly recommends combining Naive with a real
  static site at the same domain (`file_server { root ... }`) — that's
  the source of probe resistance. Skipping the real site weakens the
  cover.
- Built-in `probe_resistance` Caddyfile flag tightens the fronting
  story (returns less revealing data on unauthenticated CONNECT
  attempts).
- Chromium build is heavy. `naiveproxy` releases are pre-built per
  platform (Windows / Mac / Linux / Android / OpenWrt); building
  from source requires a full Chromium checkout. This is a real
  deployment friction relative to pure-Go protocols like samizdat /
  hysteria2 / REALITY.
- Naive is consumed by sing-box (as the `naive` outbound) and by
  several mobile front-ends (Exclave, husi, NekoBox).

## Cross-References

- Related protocols (this catalog):
  - `samizdat` / `vless-reality` / `reflex` — TLS-mimicry siblings
    that **mimic** Chrome (uTLS) rather than **be** Chrome.
    Comparison: naive's fingerprint is automatically perfect at the
    cost of binary size and Chromium-release coupling; uTLS-based
    mimics need explicit fingerprint maintenance but ship as small
    Go binaries.
  - `hysteria2` — UDP/QUIC alternative. Different cover protocol
    family entirely; complementary, not competitive.
  - (TBD) `trojan` — the closest "real-cert TLS proxy" sibling
    without Chromium-stack reuse. Trojan terminates TLS itself with
    its own cert, no application fronting; relies on "fall back to
    a real web app on auth failure."
