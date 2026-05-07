# Unbounded (Broflake)

## TL;DR

Lantern's WebRTC P2P swarm. Volunteer **widgets** running in
browsers (or as native binaries) on residential IPs in uncensored
regions proxy short-lived WebRTC connections to **desktop clients**
in censored regions; an **egress** server handles the final hop to
the open internet. A user's session is held together by a
**Turbo-Tunnel-style** persistent QUIC connection that rides on top
of the ephemeral WebRTC peer connections, so any individual widget
dropping out doesn't break the user. Discovery / signaling is
brokered by **freddie**. DTLS ClientHello fingerprint randomization
+ browser-mimicry (Psiphon's `covert-dtls`, vendored in
`common/covertdtls/`) defeats the GFW / TSPU DTLS-fingerprint
attacks that started blocking Snowflake's pion-default fingerprint
in March 2026.

The internal package path and module name is still `broflake` for
historical reasons; the user-facing project name is "Unbounded."

## Threat Model

- **Datacenter-IP blocklists**: by serving residential IPs (the
  widget endpoints), Unbounded sidesteps the GFW's wholesale
  blocklists of cloud / VPS ranges.
- **TLS / SNI fingerprinting on the user's side**: the censored
  user is talking WebRTC, not TLS-to-a-named-cloud-host. There's no
  SNI to extract.
- **DTLS ClientHello fingerprinting** (the March 2026 attack on
  Snowflake): defeated by `covertdtls.Config{ Mimic: true,
  Randomize: true }` — picks a random real-browser fingerprint per
  connection, with optional shuffle of cipher suites / extensions.
- **Active probing of fixed proxy IPs**: the censor doesn't get a
  fixed proxy IP to scan because the widget endpoints are
  short-lived volunteer browsers behind NATs. There's no public
  proxy-listening port to probe.
- **Volunteer churn / unreliable peers**: handled by the
  Turbo-Tunnel persistent QUIC layer — sessions are not bound to
  any single widget.
- **Per-volunteer-IP exposure ceiling**: N:M multiplexing means a
  single censored user's traffic is spread across N volunteer IPs,
  and a single volunteer IP serves M users — so the censor's
  observation per IP is a fraction of the user's full session.

Does **not** address:

- The egress server has a fixed IP and a static identity — it's
  reachable by a censored user's traffic only via the WebRTC swarm,
  not directly, but a determined adversary can still target the
  egress out-of-band. The system is defense-in-depth on the access
  hop, not end-to-end IP hiding for the egress.
- Volunteer's IP is visible to its peer's destination(s) (mostly:
  the egress, which is the immediate downstream peer, not arbitrary
  internet endpoints — see "compartmentalization" below).
- UPnP availability (~60-70% of home routers per the
  internal-docs `2026-04-residential-peer-proxies` analysis); CGNAT
  on mobile networks is a hard block. Unbounded is desktop-first
  for that reason.

## Wire Format

```
Censored user's apps                                                                           Open internet
        |                                                                                          ^
        v                                                                                          |
        |--- HTTP/SOCKS5 ----> Desktop client (clientcore)                                         |
                                       |                                                           |
                              [N WebRTC peer connections, ephemeral]                               |
                                       |                                                           |
                              ┌────────┴────────┬────────┬─...                                     |
                              v                 v        v                                         |
                        Widget #1            Widget #2  Widget #N (browser or native, residential) |
                              |                 |        |                                         |
                              └────────┬────────┴────────┘                                         |
                                       |                                                           |
                                  WebSocket  (one widget per WS pair to egress)                    |
                                       v                                                           |
                                  Egress server (egress/cmd) ────── HTTP CONNECT ───────────────────
                                       
                          Discovery / signaling: Freddie  (HTTP, separate from data path)
                          DTLS handshakes inside WebRTC: covertdtls (Mimic + Randomize)
                          QUIC session  rides over the multi-WebRTC-peer transport so the user's
                          session persists across peer drops and additions ("Turbo Tunnel")
```

The wire layering, top to bottom:

1. **Application** — user's apps speak HTTP or SOCKS5 to the
   desktop client.
2. **Turbo-Tunnel QUIC** — `clientcore/quic.go` wraps a
   `*quic.Transport` over a `BroflakeConn` (custom `net.Conn` shim
   that demultiplexes onto N current WebRTC peers). One persistent
   QUIC connection per user session.
3. **WebRTC data channels** — N concurrent peer connections;
   `BroflakeConn` schedules QUIC datagrams onto whichever peers are
   currently up.
4. **DTLS** — WebRTC's data-channel transport. The DTLS ClientHello
   from each widget is generated by `covertdtls` either as a real
   browser replay (Mimic mode) or with shuffled fields (Randomize
   mode). `Mimic + Randomize` is the default and matches Snowflake's
   own choice.
5. **ICE / STUN** — standard WebRTC discovery, no TURN.
6. **Underneath, between widget and egress**: a separate WebSocket
   connection to the egress server. Widget is the only path from
   browser-side WebRTC to internet TCP.

## Cover Protocol

WebRTC. To a passive observer, an Unbounded user's traffic looks
like a peer-to-peer WebRTC media session — UDP datagrams with DTLS
inside, the same wire shape as Google Meet, Discord, video calls.
With covert-dtls Mimic+Randomize, the DTLS ClientHello byte
fingerprint is per-connection different and matches a real Chrome
or Firefox.

## Authentication

Out-of-band, via the Freddie matchmaker:

- Desktop clients and widgets each have a session identifier
  presented to Freddie during signaling.
- Freddie pairs them via SDP exchange.
- After WebRTC connects, the channel is mutually authenticated by
  the DTLS handshake (standard WebRTC behavior — fingerprint-pinned
  certificates exchanged over the SDP offer / answer).

Volunteer widgets have no concept of "who" they're proxying for —
they relay opaque QUIC over WebRTC to the egress on behalf of any
peer Freddie sends. Compartmentalization between users happens at
the QUIC session layer, not at the WebRTC peer layer.

## Probe Resistance

- **Widget endpoints are not externally probable.** Widgets sit
  behind home NATs and only accept WebRTC connections via ICE
  candidates exchanged through Freddie. There's no listening TCP
  port a censor can scan.
- **Egress endpoints could be probed in principle**, but they're
  not the user's first hop — censored users never connect to the
  egress directly. A censor that finds the egress IP can block it,
  but that doesn't reveal the user-facing structure.
- **Freddie is reachable** (it's a discovery server) and could be
  probed / blocked. Freddie deployment is centralized; if Freddie
  is blocked, Unbounded as a whole stops working in that region.
  This is a known centralization point that the design accepts —
  it's the same trade Snowflake makes with its broker.

## Implementation

Pinned at upstream commit
[`bf64bc1`](https://github.com/getlantern/unbounded/commit/bf64bc1)
(2026-04-22).

Repo: `github.com/getlantern/unbounded` (Apache-2.0). Pure Go core
(clientcore + freddie + egress + netstate); UI is React; the same
clientcore engine compiles to native binary (desktop / Raspberry
Pi) and to WASM for browser-resident widgets, so one engine runs
everywhere.

Module structure (per the README and the `clientcore/` package):

- [`clientcore/broflake.go`](https://github.com/getlantern/unbounded/blob/bf64bc1/clientcore/broflake.go) — top-level `BroflakeEngine` orchestrator; manages two `WorkerTable`s (consumer + producer pools).
- [`clientcore/protocol.go`](https://github.com/getlantern/unbounded/blob/bf64bc1/clientcore/protocol.go) — `WorkerFSM` Mealy-machine framework; each worker independently manages one connection slot.
- [`clientcore/quic.go`](https://github.com/getlantern/unbounded/blob/bf64bc1/clientcore/quic.go) — `QUICLayer` wraps a `quic.Transport` over a `BroflakeConn`; provides the Turbo-Tunnel persistent session.
- [`clientcore/consumer.go`](https://github.com/getlantern/unbounded/blob/bf64bc1/clientcore/consumer.go), [`producer.go`](https://github.com/getlantern/unbounded/blob/bf64bc1/clientcore/producer.go), [`egress_consumer.go`](https://github.com/getlantern/unbounded/blob/bf64bc1/clientcore/egress_consumer.go), [`jit_egress_consumer.go`](https://github.com/getlantern/unbounded/blob/bf64bc1/clientcore/jit_egress_consumer.go) — the role-specific worker implementations.
- [`clientcore/webrtc_api.go`](https://github.com/getlantern/unbounded/blob/bf64bc1/clientcore/webrtc_api.go) / [`webrtc_api_js.go`](https://github.com/getlantern/unbounded/blob/bf64bc1/clientcore/webrtc_api_js.go) — same API, two implementations: pion-WebRTC (native) and the browser's WebRTC (WASM).
- [`common/covertdtls/covertdtls.go`](https://github.com/getlantern/unbounded/blob/bf64bc1/common/covertdtls/covertdtls.go) — wraps Psiphon-Labs's `theodorsm/covert-dtls` to randomize / mimic DTLS ClientHello. The doc comment specifically calls out `net4people/bbs#603` (the March 2026 Russia DTLS-fingerprint attack on Snowflake) as the motivating threat.
- [`freddie/`](https://github.com/getlantern/unbounded/tree/bf64bc1/freddie) — discovery / signaling server (HTTP, distinct from data path).
- [`egress/`](https://github.com/getlantern/unbounded/tree/bf64bc1/egress) — egress server (final hop). Speaks WebSocket to widgets and HTTP CONNECT to the open internet.
- [`netstate/`](https://github.com/getlantern/unbounded/tree/bf64bc1/netstate) — observability tool (network topology visualization).

## Known Weaknesses

- **Centralized matchmaker.** Freddie is a single point of
  control / failure. If Freddie is blocked at the network layer or
  legally compelled to stop matching users in a given region,
  Unbounded effectively stops working there. Snowflake has the same
  shape and is solving it gradually with multiple broker rendezvous
  options; Unbounded inherits the same problem.
- **Egress IP exposure.** Unlike pure-P2P designs, Unbounded's
  egress server is a fixed IP that handles the open-internet hop.
  The egress is "behind" the swarm from the user's perspective,
  but it's still a finite set of IPs that censors can target.
- **UPnP / CGNAT availability.** Per the internal-docs analysis
  `2026-04-residential-peer-proxies`, ~60-70% of home routers
  support UPnP and CGNAT on mobile is an outright block. The
  desktop-first deployment story is partly because of this.
- **DTLS fingerprint freshness.** covert-dtls's bundled browser
  fingerprints have to track real Chrome/Firefox releases. Stale
  fingerprints become anachronistic — a censor that fingerprints by
  Chrome version (rare) could distinguish a stale Unbounded build
  from current real Chrome.
- **Widget-side bandwidth asymmetry.** Residential uplinks are
  asymmetric (typically 10× slower than downlinks); high-bandwidth
  use cases (HD video) saturate the volunteer's uplink quickly.
  N:M multiplexing helps but doesn't eliminate the asymmetry.
- **No browser extension**. Unbounded explicitly supports browser-
  resident widgets, but there's no install-once Chrome/Firefox
  extension — operators run the React widget in a tab. Snowflake's
  browser extension fits a different deployment niche.

## Deployment Notes

- **Browser-widget volunteer mode** is the design's signature
  feature relative to Psiphon's inproxy (which intentionally
  excludes browser-extension and website-widget proxies). Lantern
  partners can embed `<browsers-unbounded>` on their website and
  visitors become volunteers for the duration of the page view.
- Lantern's main `unbounded.lantern.io` page is itself a giant
  embedded widget — every visit contributes some volunteer time.
- Native binary widgets are also supported; intended for
  longer-running deployments (Raspberry Pi as always-on volunteer).
- The egress server is the natural integration point for Lantern's
  bandit — egress assignment and volunteer pool selection can both
  be EXP3-driven.
- The internal `2026-04-residential-peer-proxies` doc is the
  highest-impact recommendation in `2026-04-non-protocol-evasion`
  (R1.1) — it argues for **moving up the stack from "WebRTC P2P
  with separate egress" (Unbounded today) to "full lantern-box on
  residential IPs" (Unbounded's successor design)**. Unbounded is
  the foundation that work builds on.

## Cross-References

- Internal: `2026-04-residential-peer-proxies` — the design
  evolution beyond Unbounded's current shape.
- Internal: `2026-04-non-protocol-evasion` (R1.1).
- Related protocols (this catalog):
  - (TBD) `snowflake` — the closest technical sibling. Both are
    flash-proxy descendants; both use WebRTC; both pair pion-WebRTC
    with covert-dtls. Differences: persistent Turbo-Tunnel
    QUIC layer (Unbounded), N:M multiplexing emphasis, browser-
    widget-first deployment.
  - `psiphon-inproxy` — Psiphon's analogous WebRTC 1st-hop
    mechanism. Shares the WebRTC + covert-dtls building blocks
    (Lantern's covertdtls package even comments "API mirrors the
    equivalent package in Snowflake v2.13.1"). Big differences:
    Psiphon-inproxy's brokers run a Noise session inside a
    domain-fronted CDN tunnel; Unbounded's Freddie is plain HTTP
    discovery. Psiphon-inproxy excludes browser-extension proxies
    by design; Unbounded centers them.
