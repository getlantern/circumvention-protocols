# Conjure (Refraction Networking)

## TL;DR

Don't run proxies at endpoint IPs — run them at **ISP backbone
routers** as packet-inspection stations. A Conjure-using client
connects to a randomly-chosen "phantom" IP in a station-controlled
subnet, with a tag that only the station can detect; the station
DNAT-redirects the tagged flow to a local handler that speaks the
client's chosen wrapping transport (Min / Obfs4 / Prefix / DTLS).
Untagged flows to the same phantom IP look unrouted (the IP isn't
actually serving anything end-to-end). The censor sees TCP traffic
to a normal IP in some ISP's subnet — to enumerate proxies it
would have to enumerate every IP in the subnet, every flow, every
moment.

ACM CCS 2019 paper: [`2019-frolov-conjure`](../circumvention-corpus/corpus/papers/2019-frolov-conjure.yaml).
Recent measurement work using Conjure as a vantage point in Iran:
[`2025-alaraj-iran-refraction`](../circumvention-corpus/corpus/papers/2025-alaraj-iran-refraction.yaml).

## Threat Model

Conjure addresses a different problem from the rest of the
catalog. Where TLS-mimicry / WebRTC / fronting protocols all
preserve "the proxy is at this IP, just disguise the wire," Conjure
removes the fixed proxy IP entirely:

- **IP-blocklist enumeration**: defeated by phantom-IP rotation.
  Each connection uses a different phantom. To block Conjure a
  censor has to block whole ISP subnets — which costs collateral
  reachability (the rest of those subnets).
- **Active probing of proxy IPs**: defeated because phantom IPs
  aren't actually proxy IPs. A probe that connects to a phantom
  without the right registration tag gets either no response (the
  IP genuinely isn't serving anything) or a default ISP response.
- **DPI of proxy traffic**: addressed by the **transport
  protocol** chosen at registration time:
  - `min`: minimal wrapping (closest to look-like-nothing; intended
    for low-bandwidth low-detection environments).
  - `obfs4`: obfs4-style XSalsa20+Poly1305 wrapping inside the
    Conjure tunnel.
  - `prefix`: configurable byte-prefix transforms (looks like an
    arbitrary protocol's first packet) — same idea as Psiphon's
    OSSH prefix layer.
  - `dtls`: DTLS-wrapped (UDP). Used to carry e.g. DTLS-OSSH and
    other UDP-friendly inner protocols.

Does **not** address:

- **ISP cooperation requirement**. Conjure only works on flows
  that traverse a cooperating ISP. Deployment partners are scarce;
  Refraction Networking's documented partnerships are with a
  small number of research/academic ISPs (e.g. Merit Network).
  This is the central operational scaling problem.
- **Inbound IP filtering by the censor's edge**. If the censor
  blocks routes to a station's announced subnets at the BGP / IXP
  level, Conjure stops working in that region.
- **Registration channel availability**. The DNS-registrar /
  decoy-registrar each have CDN / DNS dependencies that a censor
  can attack independently.

## Wire Format

Three logical phases.

### 1) Registration (out-of-band-ish)

Client tells the station "I want to connect; expect a flow with
this tag, this transport, this phantom IP." Two registration
channels in the canonical implementation:

- **Decoy registrar**: client opens a TLS connection to an
  unrelated benign destination ("decoy") on the path through the
  station. Embedded in that TLS exchange (in a way the station
  can detect via traffic inspection) is the registration message.
  The station extracts it. Decoy registration is the original
  TapDance-style mechanism.
- **DNS registrar**: client sends a registration request to a
  DNS server that the station is configured to read.

### 2) Phantom-IP connection

Client opens a TCP (or UDP, for `dtls`) connection to a phantom
IP — chosen by the registration mutually as a random IP in one of
the station's `phantom_subnets.toml` ranges (e.g.
`192.122.190.0/24`). The connection's first packet carries the
**tag** the station registered to expect; the station matches the
flow against its registered set.

```
Client                Censor's network                  Station (at ISP backbone)            Phantom IP
  |                          |                                    |                               |
  | TCP SYN to phantom IP -->|                                    |                               |
  |                          |  in-line PF_RING zero-copy ----->  |                               |
  |                          |                                    |  Detector inspects flow.      |
  |                          |                                    |  Match against registered     |
  |                          |                                    |  tags?                        |
  |                          |                                    |                               |
  |                          |                                    |  - Yes -> DNAT-redirect to    |
  |                          |                                    |          local handler        |
  |                          |                                    |          on this station      |
  |                          |                                    |                               |
  |                          |                                    |  - No  -> let the packet      |
  |                          |                                    |          continue toward      |
  |                          |                                    |          phantom (which       |
  |                          |                                    |          drops it; nobody is  |
  |                          |                                    |          actually listening)  |
```

To the censor's DPI, the connection looks like a normal TCP open
to some IP in some ISP subnet. The redirection happens at the
IP/router layer, transparently to anything between the client and
the station.

### 3) Transport-wrapped tunnel

Once the station has accepted the flow, client and station speak
the registered wrapping transport (Min / Obfs4 / Prefix / DTLS).
Inside that wrapping, any inner protocol can ride — Tor, Psiphon's
OSSH (`psiphon-conjure-ossh`), or anything else.

## Cover Protocol

To a passive observer: a TCP connection to an IP in some ISP's
subnet. No SNI, no domain — that IP isn't running TLS. Whatever
bytes the connection contains depend on the transport:

- `min`: high-entropy wrapped bytes. Vulnerable to FET (USENIX
  2023) — same look-like-nothing problem as obfs4.
- `obfs4`: same FET concerns; obfs4-shaped wire.
- `prefix`: the first packet matches a configurable protocol shape
  (HTTP, DNS, etc.); steady-state is wrapped bytes.
- `dtls`: looks like a DTLS session in unannounced UDP — also
  FET-class vulnerable but on UDP.

The point of Conjure isn't strong wire-level cover (any of the
TLS-mimicry protocols in this catalog do that better). The point
is **the IP itself isn't a proxy IP**, so wire-level fingerprinting
is one of several layers a censor would have to crack to identify
the connection as circumvention.

## Authentication

In-band, via the registration tag.

- Client and station share a long-lived public key (the station's
  key, distributed via a `ClientConf` that ships with clients).
- Registration messages contain client-derived material that
  proves possession of the registration capability. The exact
  format depends on the registration channel.
- Station detector (PF_RING-fed C+Rust hot path) checks every
  flow's first packets against the registered tag set.

The station authenticates the client; there's no real-time
end-user identity at the station layer (refraction is access
control by capability, not by user identity).

## Probe Resistance

The phantom-IP design is itself the probe-resistance story:

- A scanner that probes every IP in the station's subnet sees
  most of them as unresponsive (because they are — the phantom is
  unused address space until the station catches a registered
  flow).
- A scanner that connects to a phantom without the registered tag
  sees the connection silently fail (the station doesn't capture
  it; the IP genuinely doesn't have anything listening).
- A scanner that knows about Conjure and tries replayed tags is
  rejected; the registration step is one-shot and replays don't
  match a live registered flow.

The wire-level transports themselves vary in probe resistance
(Min/Obfs4/Prefix/DTLS) but the phantom-IP layer makes it expensive
to even *find* a connection to probe.

## Implementation

Pinned at conjure master @
[`3d8b86c`](https://github.com/refraction-networking/conjure/commit/3d8b86c).

Repos:

- [`refraction-networking/conjure`](https://github.com/refraction-networking/conjure) (Apache-2.0) — station code. Polyglot: Go for the application logic, Rust for the registration server, C for the PF_RING-fed packet detector (`detect.c`, `libtapdance/`).
- [`refraction-networking/gotapdance`](https://github.com/refraction-networking/gotapdance) — pure-Go client library, supports both Conjure and the older TapDance protocol. Pin master @ [`a8e3647`](https://github.com/refraction-networking/gotapdance/commit/a8e3647).

Conjure repo layout (per `pkg/`):

- [`pkg/transports/`](https://github.com/refraction-networking/conjure/tree/3d8b86c/pkg/transports) — wire-wrapping protocols.
  - [`wrapping/min/`](https://github.com/refraction-networking/conjure/tree/3d8b86c/pkg/transports/wrapping/min)
  - [`wrapping/obfs4/`](https://github.com/refraction-networking/conjure/tree/3d8b86c/pkg/transports/wrapping/obfs4)
  - [`wrapping/prefix/`](https://github.com/refraction-networking/conjure/tree/3d8b86c/pkg/transports/wrapping/prefix)
  - [`connecting/dtls/`](https://github.com/refraction-networking/conjure/tree/3d8b86c/pkg/transports/connecting/dtls)
- [`pkg/registrars/`](https://github.com/refraction-networking/conjure/tree/3d8b86c/pkg/registrars) — registration channels.
  - [`decoy-registrar/`](https://github.com/refraction-networking/conjure/tree/3d8b86c/pkg/registrars/decoy-registrar)
  - [`dns-registrar/`](https://github.com/refraction-networking/conjure/tree/3d8b86c/pkg/registrars/dns-registrar)
- [`pkg/phantoms/`](https://github.com/refraction-networking/conjure/tree/3d8b86c/pkg/phantoms) — phantom-IP selection (subnet-weighted, per-generation).
- [`pkg/station/`](https://github.com/refraction-networking/conjure/tree/3d8b86c/pkg/station) — the station orchestrator.
- [`pkg/dtls/`](https://github.com/refraction-networking/conjure/tree/3d8b86c/pkg/dtls) — DTLS handler shared by the dtls transport.
- [`detect.c`, `libtapdance/`, `loadkey.c`, `pfutils.c`](https://github.com/refraction-networking/conjure/tree/3d8b86c) — the C/Rust hot path for PF_RING zero-copy packet capture. The detector reads zero-copy from the network tap interface and writes match notifications to the application via ZMQ IPC.
- [`paper/paper.tex`](https://github.com/refraction-networking/conjure/blob/3d8b86c/paper/paper.tex) — the LaTeX source of the ACM CCS 2019 paper, in-tree.

## Known Weaknesses

- **ISP cooperation scaling.** Conjure only works on traffic that
  traverses a cooperating ISP backbone. The set of cooperating
  ISPs is small in practice; coverage is therefore patchy. This
  is the central limitation of refraction networking as a family
  and predates Conjure (TapDance had the same issue, USENIX
  2014).
- **Inner-transport FET exposure.** The Min and Obfs4 transports
  produce look-like-nothing wire, which fully-encrypted-traffic
  detection (USENIX 2023) blocks. The Prefix and DTLS variants
  give better cover but inherit each cover protocol's own
  weaknesses.
- **Registration-channel availability.** Decoy and DNS registrars
  each depend on infrastructure (TLS decoys / cooperative DNS)
  the censor can attack separately from the data-plane stations.
- **Heavy operational footprint.** Stations need PF_RING / kernel
  DNAT / multi-gigabit packet capture; this is not a "any
  volunteer can run a station" deployment — it's "an ISP runs a
  station." This is by design but limits scaling to traditional
  volunteer-operator models.
- **Phantom-IP subnets are public.** A censor that learns the
  station's `phantom_subnets.toml` ranges can blocklist them
  wholesale; the design relies on collateral-damage cost to deter
  this. Iran-era measurement work (`2025-alaraj-iran-refraction`)
  characterises how hostile state-level adversaries respond.

## Deployment Notes

- The Refraction Networking project's primary station deployment
  has historically been at Merit Network and other research-ISP
  partners. End-to-end use is via clients that ship the station's
  ClientConf — gotapdance is the canonical client library.
- Psiphon integrates Conjure as a delivery mechanism for OSSH:
  `psiphon-conjure-ossh` (with sub-transport variants `Min-OSSH`,
  `Prefix-OSSH`, `DTLS-OSSH`). Tor has historically not shipped
  Conjure as a default PT but has experimented with refraction-
  flavored transports.
- Conjure replaces TapDance (the predecessor: USENIX Security 2014,
  same research line) as the active deployment target. TapDance
  station code is still maintained for backwards compatibility but
  Conjure is what new deployments use.
- The 2025 ASIA-CCS measurement paper from the same research
  group (Alaraj + Wustrow) uses Conjure as a vantage point inside
  Iran to characterise censorship — useful corroboration that
  Conjure's deployment posture is real even in heavily-censored
  regions.

## Cross-References

- Public corpus papers: `2019-frolov-conjure` (the design paper),
  `2025-alaraj-iran-refraction` (recent measurement using Conjure
  as a vantage point), `2017-frolov-isp-scale`,
  `2020-frolov-httpt` (related refraction-networking lineage).
- Related protocols (this catalog):
  - `psiphon-conjure-ossh` — Psiphon's wire-protocol that rides on
    Conjure stations. Carries Psiphon's OSSH inside one of the
    Conjure transports (Min / Prefix / DTLS).
  - (TBD) `tapdance` — the predecessor refraction protocol. Still
    in production via `gotapdance` for legacy clients.
  - `obfs4` — used as one of Conjure's wrapping transports.
    Conjure inherits obfs4's FET vulnerability when that transport
    is selected.
  - All TLS-mimicry / WebRTC siblings — Conjure is in a different
    family entirely. Where they say "disguise the wire to a fixed
    proxy IP," Conjure says "make the proxy IP go away."
