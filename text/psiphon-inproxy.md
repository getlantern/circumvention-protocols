# Psiphon Inproxy (Conduit)

## TL;DR

A WebRTC **1st-hop transport** that prepends to any Psiphon tunnel
protocol — e.g. `INPROXY-WEBRTC-OSSH` is OSSH carried inside a
WebRTC peer connection from the censored client to a volunteer
proxy. The volunteer (Conduit user, in-unblocked-or-partially-
blocked region) relays the bytes to a real Psiphon server, where
the underlying tunnel protocol terminates normally. Brokers
(Psiphon-run) match clients to proxies, exchange ICE candidates,
and authenticate proxies by Ed25519 identity; the broker channel
itself is a Noise-protocol session running inside a domain-fronted
CDN tunnel. WebRTC DTLS uses `covert-dtls` for ClientHello
randomization or browser-mimicry, defeating the March 2026
Russia/TSPU pion-DTLS-fingerprint attack.

The user-facing volunteer app is **Conduit**
(`github.com/Psiphon-Inc/conduit`). The canonical protocol
implementation lives in `psiphon-tunnel-core`'s
`psiphon/common/inproxy/` package.

## Threat Model

Per the upstream `inproxy/doc.go`:

- **Datacenter-IP / static-proxy-IP blocklists**: defeated by using
  ephemeral residential IPs (the Conduit users' devices).
- **DTLS fingerprinting** (the March 2026 attack on Snowflake):
  defeated by `covert-dtls` Mimic / Randomize on the WebRTC
  ClientHello.
- **Active probing of proxy endpoints**: proxies are behind NATs,
  not externally-listening on a stable port. If the censor does
  send a stray packet to a candidate IP, the response should "look
  like common WebRTC stacks that receive packets from invalid
  peers" (per doc).
- **Broker observation by CDN / fronting provider**: the
  client/proxy↔broker channel is **Noise-encrypted inside the
  domain-fronted transport**, so even the CDN can't see the
  broker handshake.
- **Replay of broker handshake messages**: the Noise session has
  explicit replay defense + adds random padding.
- **Proxy enumeration**: clients can only target Psiphon servers
  with explicit in-proxy capability (broker enforces); proxies
  can't be misused to relay arbitrary destinations.
- **Misreporting of client IP / proxy ID**: neither the client nor
  the proxy is trusted; the broker signs an attestation containing
  both, and that attestation is **piggybacked on the client→server
  handshake** (no new broker→server connection needed).

What it does **not** address:

- The underlying Psiphon tunnel protocol on the 2nd hop (proxy →
  Psiphon server) is responsible for everything past the 1st hop —
  inproxy is an orthogonal layer. Pair it with a hardened tunnel
  protocol like `psiphon-tls-ossh` or `psiphon-conjure-ossh` for
  end-to-end resistance.
- Browser-extension and website-widget proxies are explicitly
  **out of scope**: doc says "Proxies are expected to be run for
  longer periods, on desktop computers." Distinct from Lantern's
  Unbounded which centers browser widgets.

## Wire Format

Two distinct connections:

### 1) Client/proxy ↔ Broker (control plane)

```
Client / Proxy                                      Psiphon broker
     |                                                    |
     | Domain-fronted HTTPS request to a CDN edge ------> |
     | (SNI = chosen fronting domain; Host header points  |
     |  to the broker's actual hostname)                  |
     |                                                    |
     | Inside the TLS body: a Noise framework session     |
     |   - mutual authentication (Ed25519 + Curve25519)   |
     |   - random padding                                 |
     |   - replay defense (per-message)                   |
     |   - additional obfuscation layer renders messages  |
     |     as fully random (suitable for plaintext)       |
     |                                                    |
     | Messages: discovery requests, ICE candidate        |
     | exchange, broker-signed attestations to relay to   |
     | the destination Psiphon server.                    |
```

The "additional obfuscation layer" (`obfuscation.go`) wraps Noise
records with HKDF-derived keystream + random padding so the
ciphertext looks like uniform random bytes. Useful when
encapsulating the session in plaintext transports beyond
domain-fronting.

### 2) Client ↔ Proxy ↔ Server (data plane)

```
Censored client                                  Volunteer proxy                            Psiphon server
       |                                                |                                          |
       | WebRTC peer connection (ICE + STUN)            |                                          |
       | DTLS handshake (covert-dtls Mimic+Randomize)   |                                          |
       | <-------- WebRTC data channel ----------->     |                                          |
       |                                                |                                          |
       |  Within the data channel: bytes of the         |                                          |
       |  underlying Psiphon tunnel protocol            |                                          |
       |  (e.g. OSSH, TLS-OSSH, MEEK-OSSH, ...)         |                                          |
       |                                                |                                          |
       |                                                |  Proxy relays bytes byte-for-byte         |
       |                                                |  to the Psiphon server using the          |
       |                                                |  inproxy-listener-side transport          |
       |                                                |  (TCP or UDP depending on tunnel).        |
       |                                                |                                          |
       |  ........................................................  (now full tunnel from client) |
       |  The full Psiphon tunnel protocol runs end-to-end (client to server) over the relay path. |
```

The proxy is intentionally **payload-blind**: it sees encrypted
tunnel-protocol bytes and forwards them. It can't decrypt and
can't tell which destination the client is reaching beyond what the
broker has authorized.

ICE candidate gathering uses host candidates (IPv4/IPv6), STUN
server-reflexive candidates, and **port-mapping candidates from
UPnP-IGD / NAT-PMP / PCP injected as host candidates**. TURN
candidates are not used. Mobile networks may skip discovery (CGNAT
assumed) for a faster dial.

### Tunnel-protocol naming

Per `protocol.go` in psiphon-tunnel-core, the constant
`INPROXY_PROTOCOL_WEBRTC = "INPROXY-WEBRTC"` and protocol IDs are
formed by `INPROXY-WEBRTC-` + the underlying-tunnel name:

```
INPROXY-WEBRTC-OSSH
INPROXY-WEBRTC-TLS-OSSH
INPROXY-WEBRTC-SHADOWSOCKS-OSSH
INPROXY-WEBRTC-UNFRONTED-MEEK-OSSH
INPROXY-WEBRTC-FRONTED-MEEK-OSSH
INPROXY-WEBRTC-QUIC-OSSH
INPROXY-WEBRTC-CONJURE-OSSH
... (for any TunnelProtocolIsCompatibleWithInproxy(p) protocol)
```

All in-proxy variants are **default disabled** in the upstream
config — they're enabled per-deployment via Psiphon's tactics
system.

## Cover Protocol

Two cover stories:

- **Client / proxy ↔ broker**: domain-fronted HTTPS to a popular
  CDN. The TLS handshake is to the CDN edge for a popular front
  domain; only the Host header (encrypted inside TLS) routes the
  request to the broker. Noise inside the TLS body — invisible to
  the CDN.
- **Client ↔ proxy data channel**: WebRTC. Looks like a
  peer-to-peer media session — DTLS over UDP, preceded by ICE STUN
  exchange. With covert-dtls, the DTLS ClientHello is per-
  connection randomized or matches a real browser.

## Authentication

Layered.

### Proxy identity: Ed25519

- Each proxy generates a long-lived Ed25519 keypair on first run.
- Public key (or Curve25519-derived twin used in Noise) is the
  **proxy ID**.
- Used for:
  - Noise handshake with the broker (ECDH on the Curve25519
    representation).
  - Out-of-band registration: an operator can prove ownership of
    a proxy via challenge/response signature.
  - Reputation tracking by Psiphon (well-performing proxies can
    be assigned higher utility).

Proxy IDs are revealed only to brokers and to Psiphon servers
(via the broker's relayed attestation). Clients never see them.

### Broker authentication

Broker-issued attestations are signed; the destination Psiphon
server validates the signature before granting traffic rules,
tactics, OSL progress, or tunneling.

### Client identity: compartment IDs

- **Personal**: out-of-band shared between a proxy operator and
  their friends/family. Limits the proxy to that group.
- **Common**: assigned by Psiphon, distributed via targeted tactics
  or embedded in OSLs.

## Probe Resistance

- **Broker channel** is invisible (domain-fronted TLS to a popular
  CDN, Noise inside, all messages padded and obfuscated to look
  like uniform random).
- **Proxy endpoints** aren't externally listening — WebRTC endpoint
  is announced via ICE, behind a NAT. A stray packet gets a
  generic-WebRTC-stack response (per doc: "should look like common
  WebRTC stacks that receive packets from invalid peers").
- **Server endpoints** are protected by the broker-issued
  attestation requirement: a Psiphon server with in-proxy
  capability won't grant any traffic rules until it gets a valid
  broker message identifying the proxy + client IP.

## Implementation

Pinned at psiphon-tunnel-core master @
[`2b144a4`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/commit/2b144a4)
and Conduit master @
[`2ef9809`](https://github.com/Psiphon-Inc/conduit/commit/2ef9809).

License: psiphon-tunnel-core is GPL-3.0; Conduit is GPL-3.0.
Pure Go for the protocol implementation; Conduit is React Native
(JS) wrapping the Go library.

Key files in `psiphon-tunnel-core`:

- [`psiphon/common/inproxy/doc.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/inproxy/doc.go) — package-level architecture doc; the canonical reference for the design rationale.
- [`psiphon/common/inproxy/broker.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/inproxy/broker.go) — broker matching, ICE-candidate exchange, Noise-session orchestration.
- [`psiphon/common/inproxy/proxy.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/inproxy/proxy.go) — proxy-role implementation (the volunteer side).
- [`psiphon/common/inproxy/client.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/inproxy/client.go) — client-role implementation (the censored-user side).
- [`psiphon/common/inproxy/coordinator.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/inproxy/coordinator.go) — top-level coordination (which keys, which broker, which destination).
- [`psiphon/common/inproxy/obfuscation.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/inproxy/obfuscation.go) — the additional obfuscation layer over Noise (HKDF-derived AES-CTR keystream + bloom-filter replay defense).
- [`psiphon/common/inproxy/dtls/dtls.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/inproxy/dtls/dtls.go) — DTLS-fingerprint-resistance integration (uses `Psiphon-Labs/covert-dtls`, the same library Lantern's Unbounded vendors in its `common/covertdtls/`).
- [`psiphon/common/inproxy/discovery.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/inproxy/discovery.go) / [`discoverySTUN.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/inproxy/discoverySTUN.go) — NAT topology discovery + STUN reflexive-candidate gathering.
- [`psiphon/common/inproxy/portmapper.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/inproxy/portmapper.go) — UPnP-IGD / NAT-PMP / PCP candidate injection.
- [`psiphon/common/inproxy/matcher.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/inproxy/matcher.go) — broker-side client/proxy matchmaking.
- [`psiphon/common/protocol/protocol.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/protocol/protocol.go) — `INPROXY_PROTOCOL_WEBRTC` constant; `TunnelProtocolPlusInproxyWebRTC()` builds composite protocol IDs.

Conduit-side bindings: the React Native app wraps the Go library
via expo / native modules; Android and Mac (Catalyst) are released,
iOS is "not currently released due to technical limitations."

## Known Weaknesses

- **Broker is centralized**. Like Snowflake's broker and
  Unbounded's Freddie, this is an inherent single-point-of-failure
  for the matchmaking step. The domain-fronted + Noise design
  makes the broker hard to identify and observe, but if the CDN
  itself is blocked region-wide, in-proxy stops matching there.
- **Domain-fronting availability**. Major CDNs have variously
  cracked down on domain fronting (Google 2018, Amazon shortly
  after). Inproxy depends on at least one usable fronting CDN per
  deployment region.
- **DTLS fingerprint freshness**. covert-dtls's bundled browser
  fingerprints have to track real Chrome/Firefox releases. Same
  caveat as Unbounded.
- **Browser-extension / website-widget proxies are unsupported**.
  Where Lantern's Unbounded centers browser widgets as a
  deployment surface, inproxy intentionally excludes that mode —
  Conduit is desktop-first. Coverage in browser-only environments
  is left to other tools.
- **2nd-hop tunnel protocol still has to defend itself**. Inproxy
  fixes the 1st-hop fingerprint; if `INPROXY-WEBRTC-OSSH` is paired
  with bare OSSH that gets fingerprinted on the proxy→server side,
  the censor can still detect the connection from observation
  points downstream of the proxy. (Less relevant when the proxy is
  in an unblocked region.)

## Deployment Notes

- All `INPROXY-WEBRTC-*` variants are default-disabled in
  `SupportedTunnelProtocols`; Psiphon enables them per-region via
  the tactics system. This means Conduit users only relay traffic
  for clients whose tactics permit it.
- Conduit is on Google Play (Android) + GitHub releases (Mac, CLI).
  iOS is shelved per the README.
- Designed to bundle with `tunnel-core`; integrates with Psiphon's
  tactics, datastore, and logging systems. Operators of forks
  (e.g. anyone building atop psiphon-tunnel-core) get inproxy
  capability "for free" subject to broker availability.
- The broker, in turn, "is designed to be bundled with the Psiphon
  server, psiphond, and, like tactics requests, run under
  MeekServer." So a single Psiphon server can play both roles.

## Cross-References

- Related protocols (this catalog):
  - `unbounded` — Lantern's analogous WebRTC P2P system. Big-
    picture similar (volunteer 1st-hop, WebRTC, covert-dtls);
    different on broker design (Unbounded's Freddie is plain HTTP
    discovery, inproxy uses Noise-inside-domain-fronted-CDN) and
    on browser-widget support (Unbounded yes, inproxy no).
  - (TBD) `snowflake` — the design reference for both inproxy and
    Unbounded. Tor's WebRTC pluggable transport.
  - (TBD) `psiphon-ossh` / `psiphon-tls-ossh` — the underlying
    tunnel protocols inproxy carries. Inproxy is a 1st-hop
    transport; the actual tunnel cryptography and authentication
    happen at the underlying-protocol layer.
