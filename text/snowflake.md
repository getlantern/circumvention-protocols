# Snowflake

## TL;DR

Tor's WebRTC pluggable transport. Volunteers run a "snowflake"
proxy in their browser (web extension), as a standalone Go binary,
or as an embedded badge on a participating website; censored Tor
clients pair to a proxy via a central **broker** reached over a
domain-fronted rendezvous channel (AMP cache, HTTPS to Cloudflare/
Fastly, or — newer — Amazon SQS queues). Tor traffic flows
client → WebRTC DataChannel → proxy → WebSocket → Tor bridge.
Same wire-shape family as Lantern's `unbounded` and Psiphon's
`psiphon-inproxy`; Snowflake is the design ancestor of both.

## Threat Model

Standard volunteer-proxy threat model:

- **Datacenter-IP / static-bridge blocking**: defeated by routing
  through ephemeral residential-IP volunteers.
- **Active probing of bridge IPs**: defeated because the proxy
  endpoint is a NAT'd browser/standalone — no public listening
  port to scan.
- **Broker observation**: the broker is reached over a domain-
  fronted HTTPS request. The CDN sees an HTTPS request to a
  popular fronting domain; the actual broker hostname is in the
  encrypted Host header. Newer rendezvous (SQS) sidesteps the CDN
  entirely.
- **WebRTC DataChannel cover**: the data path looks like a
  peer-to-peer media session — UDP datagrams with DTLS inside.

What it does **not** address (and what's currently being
patched):

- **DTLS ClientHello fingerprinting**. The pion-WebRTC default
  ClientHello has a distinctive shape that TSPU/Russia began
  blocking on **2026-03-30** (net4people/bbs#603). This is the
  same attack that motivated Lantern's `covertdtls` package and
  Psiphon's `covert-dtls`. Snowflake upstream and several forks
  (notably tgragnato) have shipped per-connection DTLS fingerprint
  randomization / browser-mimicry; deployments must be on a
  recent build to defeat the attack.
- **Broker centralization**. If a censor blocks every available
  rendezvous channel (AMP cache, HTTPS-to-CDN, SQS), Snowflake
  matchmaking stops in that region. This is the same trade-off
  Unbounded's Freddie and Psiphon's broker make.
- **Bridge enumeration on the 2nd hop**. The Tor bridge the
  proxy connects to is a fixed set of Tor relays. Snowflake
  protects the user's first hop; bridge identity / blocklisting
  is Tor's separate problem.

## Wire Format

```
Censored Tor client                     Volunteer Snowflake proxy                Tor bridge
       │                                          │                                  │
       │  Domain-fronted HTTPS to broker          │                                  │
       │   (or AMP cache / Amazon SQS)            │                                  │
       │   exchange SDP Offer/Answer              │                                  │
       │ ──────────────────────────────────────►  │                                  │
       │  (broker independently signals proxy     │                                  │
       │   via long-poll or SQS queue)            │                                  │
       │                                          │                                  │
       │  WebRTC DataChannel established          │                                  │
       │   ICE: STUN reflexive candidates         │                                  │
       │   (no TURN by default in upstream)       │                                  │
       │   DTLS handshake — fingerprint either    │                                  │
       │   pion-default (older), browser-mimic,   │                                  │
       │   or randomized (newer)                  │                                  │
       │ ◄────────── WebRTC ───────────────────►  │                                  │
       │                                          │                                  │
       │  Tor cells flow inside the DataChannel.  │                                  │
       │  Optional: SmuxNet/Turbo Tunnel layer    │                                  │
       │  preserves a single Tor session across   │                                  │
       │  multiple successive proxy connections.  │                                  │
       │                                          │  WebSocket to bridge             │
       │                                          │ ──────────────────────────────►  │
       │                                          │  Bytes relayed verbatim          │
       │                                          │ ◄──────────────────────────────  │
       │                                          │                                  │
       │  Tor cells reach the bridge; standard    │                                  │
       │  Tor circuit construction proceeds.      │                                  │
```

### Rendezvous channels

Three documented options, each with different CDN / cloud-provider
dependencies:

- **AMP cache**: client sends offer encoded into a URL on Google's
  AMP cache; broker reads it via the cache's HTTP API. Front
  domain is ampproject.org / google.com.
- **HTTPS rendezvous** (the original): client makes a
  domain-fronted HTTPS POST to a CDN edge (Cloudflare, Fastly,
  Microsoft Azure) where the Host header routes to the broker.
- **Amazon SQS rendezvous** (newer, per `doc/rendezvous-with-sqs.md`):
  client and broker exchange SDP messages through a shared SQS
  queue in a configured region. Broker creates a per-client queue
  named `snowflake-client + clientID` for replies. Sidesteps CDN
  domain-fronting entirely; depends on AWS instead.

### Broker → proxy signaling

The broker maintains a pool of available proxies (which long-poll
the broker to advertise availability). When a client offer arrives,
the broker pairs it with an available proxy and returns the proxy's
SDP answer to the client.

## Cover Protocol

The data path is WebRTC — looks like a peer-to-peer media session
(DTLS over UDP, ICE setup before that). The rendezvous channel is
either domain-fronted HTTPS to a popular CDN front, AMP-cache HTTP
GET, or SQS API call.

## Authentication

Out-of-band, via the broker. The broker's job is matchmaking, not
authenticating individual users; clients with a working rendezvous
channel get matched. Bridge-level authentication (Tor's own
mechanism) lives downstream of the proxy.

Volunteer proxies are anonymous — they don't carry long-term
identities (unlike `psiphon-inproxy`'s Ed25519 proxy IDs).
"Standalone", "webext", and "badge" proxy types are tracked in
broker metrics for capacity planning, not for authentication.

## Probe Resistance

- **Proxy endpoints aren't listening on a public port** — they're
  NAT'd peers reachable only via the WebRTC ICE candidates the
  broker exchanged. There's nothing for a censor to scan.
- **Rendezvous channel** is a domain-fronted (or SQS) request to
  a major cloud provider; the censor either has to block the
  whole front (collateral damage) or do TLS-MITM to inspect the
  Host header.
- **WebRTC DataChannel** doesn't accept random connections; once
  the SDP exchange has happened, only the matched peer can connect.

The remaining attack surface is the rendezvous (block all known
channels in a region) and the DTLS-fingerprint passive
classifier (now mitigated by post-March-2026 builds).

## Implementation

Two implementation pins to know about:

- **Tor canonical**: `gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake`. Pure Go. Web extension is the separate `snowflake-webext` repo.
- **Active GitHub fork**: [`tgragnato/snowflake`](https://github.com/tgragnato/snowflake) main @ [`22ee6ec`](https://github.com/tgragnato/snowflake/commit/22ee6ec). Has explicit hardening on top of upstream:
  - Custom DTLS fingerprint different from popular WebRTC stacks
  - Custom broker-negotiation transport: TLS 1.3 with hand-selected ciphersuites + supported groups, optional MultiPath TCP
  - Setting Engine tweaks to reduce MulticastDNS noise
  - Context-aware `io.Reader` that closes on errors in `copyLoop` (avoids stuck WebRTC connections)
  - Client padding to evade "TLS-in-DTLS" detection
  - `coder/websocket` instead of `gorilla/websocket`

License: BSD-3-Clause.

Layout (per the README):

- `client/` — Tor pluggable-transport client + library code
- `proxy/` — Go standalone proxy
- `broker/` — broker server (matchmaking)
- `server/` — Tor pluggable-transport server (the bridge-side endpoint)
- `common/` — shared libraries
- `dtls/` — the DTLS fingerprint-resistance integration (in tgragnato fork)
- `probetest/` — NAT probetesting service
- `doc/` — `broker-spec.txt`, `rendezvous-with-sqs.md`, manpages

Sister repo `snowflake-webext` (gitlab.torproject.org) — the
Chrome/Firefox extension that lets a volunteer turn their browser
tab into a snowflake proxy. This is the deployment surface
Lantern's Unbounded approximates with `<browsers-unbounded>`
embeds.

## Known Weaknesses

- **DTLS ClientHello fingerprint is the historical Achilles' heel.**
  pion-WebRTC's default ClientHello has been blocked by TSPU
  starting 2026-03-30 (net4people/bbs#603). Recent upstream and
  the tgragnato fork ship per-connection DTLS fingerprint
  randomization / browser-mimicry, but a deployment running an
  older build is exposed. **This is the central operational
  hardening item for any WebRTC-based PT** as of 2026.
- **Centralized broker** is the rendezvous bottleneck. AMP-cache,
  HTTPS-to-CDN, and SQS each have CDN/cloud dependencies a censor
  can attack — the system needs at least one usable rendezvous
  per region.
- **No Turbo-Tunnel by default**: a Snowflake proxy disconnect
  ends the data flow, requiring Tor to recover. Some forks add
  Turbo-Tunnel-style persistent sessions; upstream's been
  conservative about it. (Lantern's Unbounded ships persistent
  QUIC over WebRTC by default.)
- **Brwoser-extension volunteer fingerprintability**: a censor
  observing a region's outbound WebRTC could in principle correlate
  short-lived peer connections to known snowflake-extension
  signatures (extension version, ICE timing). Not seen in
  production but a foreseeable long-tail attack.
- **Asymmetric volunteer bandwidth**: residential uplinks limit
  per-volunteer throughput; high-bandwidth Tor circuits bottleneck.

## Deployment Notes

- Bundled with Tor Browser as a default pluggable transport since
  ~2021. The most-deployed WebRTC PT in production by user count.
- Web-extension volunteer mode is a real and active deployment
  surface — distinct from `psiphon-inproxy` (which excludes
  browser-extension proxies by design) and similar in spirit to
  Lantern's Unbounded (which adds embeddable widgets).
- Three rendezvous channels is the operational reality: AMP cache
  has been less reliable as Google deprecates AMP, HTTPS-to-CDN
  is the workhorse, SQS is the experimental escape hatch.
- The tgragnato fork is the most direct reference for "Snowflake
  with the post-March-2026 hardening already integrated"; Tor
  upstream tracks similar changes on a slower cadence.

## Cross-References

- Related protocols (this catalog):
  - `unbounded` — Lantern's WebRTC P2P design. Differences:
    Unbounded centers persistent Turbo-Tunnel QUIC over WebRTC
    (Snowflake doesn't), Unbounded supports embeddable browser
    widgets (Snowflake supports the dedicated webext but not
    arbitrary site embeds), Unbounded vendors Psiphon's
    `covert-dtls` while Snowflake's tgragnato fork rolls its own.
  - `psiphon-inproxy` — Psiphon's WebRTC 1st-hop. Differences:
    Psiphon-inproxy carries any underlying tunnel protocol (it's
    a 1st-hop layer), Snowflake's data channel always carries
    Tor cells; Psiphon-inproxy excludes browser-extension proxies
    explicitly, Snowflake centers them; Psiphon-inproxy adds a
    Noise-protocol session on top of the broker channel.
  - (TBD) `webtunnel` — Tor's other modern PT, HTTPS-mimicking.
    Snowflake and webtunnel are both shipping in Tor Browser as
    of 2026; webtunnel's design is "look like normal HTTPS", a
    very different family from Snowflake's WebRTC P2P.
  - `obfs4` — Tor's older PT. obfs4 is the canonical
    look-like-nothing pattern that FET defeated; Snowflake is
    the WebRTC alternative the Tor Project shipped to fill that
    gap.
