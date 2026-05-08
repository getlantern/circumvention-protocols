# QUIC

## TL;DR

The IETF's UDP transport with TLS 1.3 inside. RFC 9000 (May 2021)
core, RFC 9001 maps TLS onto it, RFC 9114 (June 2022) is HTTP/3
on top. **Wire-distinct from TLS-over-TCP** — UDP transport,
Connection-ID session identity, distinctive Initial-packet header
structure — but **everything else that rides on QUIC subsumes to
this single cover entry**: HTTP/3, MASQUE, WebTransport, MoQ,
SMB-over-QUIC, DoQ, gRPC-over-HTTP/3 all look identical at the
censor's vantage point because the wire is just QUIC. Collateral
cost of a wholesale block is **critical** — and the censor's
practical lever is throttling UDP/443 rather than blocking it,
forcing clients to fall back to HTTP/2 over TCP at measurable
performance cost.

## Standardization

Core specification, all IETF Standards Track:

- **RFC 9000** (May 2021) — *QUIC: A UDP-Based Multiplexed and
  Secure Transport*. Versioned protocol; v1 = `0x00000001`.
- **RFC 9001** (May 2021) — *Using TLS to Secure QUIC*. Maps
  TLS 1.3's handshake protocol onto QUIC frame types; defines
  Initial / Handshake / 1-RTT key separation.
- **RFC 9002** (May 2021) — *QUIC Loss Detection and Congestion
  Control*. NewReno default; CUBIC and BBR widely deployed.
- **RFC 9114** (June 2022) — *HTTP/3*. The headline application.
- **RFC 9204** (June 2022) — QPACK header compression.
- **RFC 9221** (March 2022) — *An Unreliable Datagram Extension
  to QUIC*. The DATAGRAM frame, used by WebTransport, MASQUE,
  Media-over-QUIC.
- **RFC 9298** (Aug 2022) — *Proxying UDP in HTTP* (CONNECT-UDP
  for MASQUE).
- **RFC 9484** (Oct 2023) — *Proxying IP in HTTP* (CONNECT-IP for
  MASQUE).
- **RFC 9250** (May 2022) — *DNS over Dedicated QUIC Connections*
  (DoQ).
- **RFC 9369** (May 2024) — *QUIC Version 2*. Largely a forced-
  version-negotiation exercise; minimal deployment, but defines
  `0x6b3343cf` as the v2 wire constant.
- **RFC 9701** (Apr 2025) — IPv6 flow label use with QUIC for
  ECN / flow identification.

In active progress as of 2026:

- `draft-ietf-quic-multipath` — Multipath QUIC; in IESG queue.
- `draft-ietf-masque-quic-proxy` — QUIC-aware proxying.
- `draft-ietf-masque-connect-ethernet` — Ethernet over MASQUE.
- `draft-schinazi-masque-obfuscation` — relay traffic
  indistinguishable from normal web traffic.
- `draft-ietf-tls-svcb-ech` — ECH discovery via SVCB.
- Post-quantum hybrid key shares (X25519MLKEM768) deployed in
  production by Cloudflare + Chrome since late 2024.

Working group: **IETF QUIC WG** in the Web and Internet Transport
area, with adjacent working groups (MASQUE, MOQ, HTTPbis, TLS)
all driving QUIC-relevant output.

## Wire Format

Per RFC 9000 §17 (packet formats).

### Long-header packets (handshake phase)

```
+-+-+-+-+-+-+-+-+
|1|1|T|T|X|X|X|X|       1B header byte; high bit = long-form (1)
+-+-+-+-+-+-+-+-+       T = packet type (0=Initial, 1=0-RTT, 2=Handshake, 3=Retry)
| Version (32)  |       4B version (0x00000001 for v1)
+---------------+
| DCID Len (8)  |
+---------------+
| DCID (...)    |       Destination Connection ID (0-160 bits)
+---------------+
| SCID Len (8)  |
+---------------+
| SCID (...)    |       Source Connection ID (0-160 bits)
+---------------+
| Token Len (i) |       (Initial only; varint)
| Token (...)   |       (Initial only; bytes)
+---------------+
| Length (i)    |       Remaining packet length (varint)
+---------------+
| Pkt Number    |       1-4 bytes (length encoded in high bits of header byte)
+---------------+
| Payload       |       Header-protected; payload encrypted with Initial / 0-RTT / Handshake keys
+---------------+
```

The **Initial packet** is critical for fingerprinting: its keys
are derived from a publicly-known salt + the Destination
Connection ID. Anyone (including a passive observer) can compute
the Initial keys and decrypt the inner CRYPTO frames carrying
the **TLS 1.3 ClientHello and ServerHello**.

That means: **at the Initial-packet layer, the inner TLS-1.3
ClientHello is observable to any DPI that wants to spend the CPU.**
SNI, ALPN, JA3/JA4-equivalent fingerprints, supported groups —
all visible. The wire-shape difference from TLS-over-TCP is the
*envelope* (UDP datagram + QUIC headers), not the cryptographic
opacity of the handshake itself.

ECH applies to the inner ClientHello the same as on TCP; with
ECH on, the inner SNI / ALPN are encrypted and the outer SNI
is the publishable cover.

### Short-header packets (1-RTT)

```
+-+-+-+-+-+-+-+-+
|0|1|S|R|R|K|P P|       1B header byte; high bit = long-form (0)
+-+-+-+-+-+-+-+-+       S = spin bit; R = reserved; K = key phase; P P = pkt-num length
| DCID (...)    |       Destination Connection ID; length is connection-state, not on-wire
+---------------+
| Pkt Number    |       1-4 bytes
+---------------+
| Payload       |       Header-protected; payload 1-RTT-encrypted
+---------------+
```

Once 1-RTT keys are established, **every byte of payload is
encrypted with AEAD** (AES-128-GCM by default; ChaCha20-Poly1305
selectable). The DCID is the only persistent identifier across
packets in a connection — **and a server can rotate it via
NEW_CONNECTION_ID frames** to break linkability.

### Frames inside encrypted payload

QUIC's payload is a sequence of frames. Notable frame types from
the censor's perspective:

- `STREAM` — bidirectional or unidirectional byte stream; carries
  HTTP/3 framing, MASQUE Capsule data, etc.
- `DATAGRAM` (RFC 9221) — unreliable datagram; carries WebTransport
  datagrams, MASQUE forwarded UDP, MoQ low-latency objects.
- `CRYPTO` — TLS handshake bytes.
- `NEW_CONNECTION_ID` / `RETIRE_CONNECTION_ID` — connection-ID
  rotation for migration / privacy.
- `PATH_CHALLENGE` / `PATH_RESPONSE` — path validation for
  connection migration across IP changes.

All of these are inside the encrypted payload and invisible to a
passive observer.

### Connection migration

QUIC's `Connection ID` is independent of the (IP, port) tuple.
A client can move from cellular to Wi-Fi, change IPs, and the
session continues — packets just arrive on the same DCID. This
is **a structural difference from TLS-over-TCP** that mimicry
designs need to handle: implementing QUIC convincingly means
implementing migration credibly, including the
PATH_CHALLENGE / PATH_RESPONSE handshake.

## Traffic Patterns

- **Initial flight is small but distinctive.** Client sends one
  Initial packet (sized typically 1200B per the RFC's minimum
  PMTU), server responds with Handshake + Initial packets
  totaling typically 2-6 KB. Connection establishment is 1-RTT
  for fresh connections, 0-RTT for resumed.
- **0-RTT data** is encrypted under early-data keys derived from
  resumption tickets; it lets a client send application data in
  the first flight.
- **Steady state**: bidirectional 1-RTT packets sized close to
  path MTU (1200-1500B typical). Modern stacks coalesce small
  application writes into single QUIC packets.
- **Connection migration events** are detectable behaviorally:
  one DCID receives packets from two distinct IP addresses in
  rapid succession.
- **Long-lived connections** are typical for HTTP/3 (one QUIC
  connection carries many HTTP/3 streams across a session) and
  for MASQUE (the relay connection lives as long as the user
  device is online).
- **Idle timeout** default ~30s if both peers configure it; many
  stacks send a PING frame to keep the connection live for
  longer.

## Encryption Surface

| Layer | Visible | Encrypted |
| --- | --- | --- |
| IP / UDP | client IP, server IP, UDP source port (ephemeral), UDP dest port (commonly 443) | n/a |
| QUIC long header | version, DCID, SCID, token (Initial), packet number, length | header bits behind header protection |
| Initial payload | inner TLS ClientHello / ServerHello (decryptable via spec-published Initial keys) | n/a until ECH is on |
| Handshake / 0-RTT / 1-RTT payload | sizes + timings of packets and packet trains | every byte of payload |
| Connection migration | observation that the same DCID is seen from a new IP | PATH_CHALLENGE / RESPONSE contents |

The critical implication: **the inner TLS ClientHello in the
Initial packet is observable to any DPI** willing to compute the
Initial keys. So all TLS-fingerprinting attacks (SNI, JA3/JA4,
extension order, supported groups, post-quantum-key-share-shape)
apply to QUIC the same way. ECH closes the inner-CH visibility
when deployed.

## Common Implementations

| Stack | Vendor | Scope |
| --- | --- | --- |
| Chromium QUIC | Google | Chrome, Edge (Chromium), Android WebView; the dominant client-side stack by population |
| msquic | Microsoft | Windows network stack, IIS, SMB-over-QUIC server side |
| quiche | Cloudflare | Cloudflare's edge for HTTP/3, WARP MASQUE, DoH / DoQ resolvers |
| mvfst | Meta | Facebook, Instagram, WhatsApp production traffic |
| s2n-quic | AWS | AWS CloudFront, several managed services |
| Apple's QUIC (Network framework) | Apple | macOS / iOS / iPadOS / visionOS — iCloud, App Store, Apple Push, MASQUE relay client |
| ngtcp2 + nghttp3 | ngtcp2 project | curl, IETF interop reference, many CDN testbeds |
| quic-go | quic-go project | Caddy, sing-box, lantern-box, hysteria2 (apernet's fork), most Go HTTP/3 servers |
| picoquic | Christian Huitema | Research / IETF interop reference |
| neqo | Mozilla | Firefox |

The browser-population concentrates in Chromium QUIC + neqo +
Apple QUIC, exactly as TLS browser-population concentrates in
BoringSSL + NSS + Schannel + Apple SecureTransport. Implementation-
fingerprint diversity is high but the *common-cover* fingerprints
are dominated by Chromium / Apple / Cloudflare client-side.

## Prevalence

- HTTP/3 served roughly **30-40% of all HTTP requests** through
  Cloudflare's network in 2026 (Cloudflare Radar). W3Techs reports
  HTTP/3 deployed by **~39% of all websites** in May 2026.
- Top properties are HTTP/3 by default: Google, YouTube, Facebook /
  Meta family, Instagram, Apple, Microsoft properties, Cloudflare,
  LinkedIn, Live, Amazon, ChatGPT.
- All major browsers ship HTTP/3 by default since 2022 (Chrome 87+,
  Firefox 88+, Safari 14+, Edge).
- iOS / macOS use HTTP/3 for App Store, iCloud, Apple Music, Apple
  ID. Apple Network Relay / iCloud Private Relay use HTTP/3
  whenever the path supports UDP/443.
- DoQ and MASQUE add lower-volume but high-collateral QUIC traffic.
- WebTransport flipped to Baseline 2026 (March 2026 — every major
  browser now ships it).

## Collateral Cost

**Critical, and concentrated in a fixed handful of vendors with
huge user bases.** A wholesale block of UDP/443 breaks
**simultaneously**:

- HTTP/3 traffic to Google, YouTube, Meta family, Apple,
  Cloudflare-fronted properties, Microsoft properties, Amazon,
  LinkedIn, ChatGPT, X / Twitter — i.e. virtually all top-100
  properties.
- iCloud Private Relay (via MASQUE on UDP/443), default-on for
  hundreds of millions of iCloud+ subscribers; clients see
  outright connectivity loss until they degrade out of Private
  Relay (which is itself observable user pain).
- Cloudflare WARP (consumer + Zero Trust enterprise via MASQUE).
- Apple Private Cloud Compute traffic for Apple Intelligence;
  Apple device telemetry.
- App Store / Mac App Store / iCloud / Apple Music / Apple Push
  Notifications when those have negotiated HTTP/3.
- Chrome IP Protection (rolling out for non-EU Chrome users).
- SMB-over-QUIC (the Microsoft-recommended remote-file-share
  transport for Windows Server 2022+ / 2025).

Because every one of these vendors has built confidence that
UDP/443 is reachable, blocking it produces visible product
failures rather than silent degradation. Censors that have tried
in practice (parts of Russia 2024 and Iran 2024-2025) **throttle**
UDP/443 rather than wholesale-block it, with the result that
clients fall back to HTTP/2 over TCP and users experience worse
performance but not broken services. The throttling strategy is
itself a tell that wholesale blocking is off the table.

The collateral set is **growing**, not shrinking. MoQ's expected
2026-2028 production deployment by Twitch / Meta Live / cloud
gaming will add live-video traffic to the QUIC umbrella; the
SMB-over-QUIC roll-out continues; MASQUE is entering more
enterprise SASE products.

## Common Ports & Collateral Cost

QUIC's port story is much more concentrated than TLS-over-TCP.
**UDP/443 is the overwhelming default**, which makes port-as-cover
strategies for QUIC mostly degenerate to "the same port everyone
else uses."

| Port | Cover service | Collateral of port-block |
| --- | --- | --- |
| **UDP/443** | Generic HTTP/3 + MASQUE + WebTransport + MoQ + SMB-over-QUIC + most DoH-over-QUIC | The Internet, on UDP. Censors throttle rather than block. |
| **UDP/853** | DNS-over-QUIC (DoQ) per RFC 9250, ALPN `doq` | Modest — most DoH-using clients fall back to TCP/443 silently |
| **UDP/784** | Earlier DoQ experimental allocation; now superseded by 853 | Negligible, almost no live traffic |
| **UDP/8443** | Alt-HTTPS / management; some QUIC test deployments | Niche enterprise cover |
| **UDP/3478, 3479** | STUN / TURN; some implementations multiplex QUIC for fallback | WebRTC / VoIP collateral if blocked, but the QUIC-on-this-port deployment is rare |

The single-port concentration on UDP/443 is itself a censorship
property: **a censor blocking UDP/443 is taking out the whole QUIC
substrate at once**, which raises the collateral bar high enough
that no major censor has done it durably. Targeted-port mimicry
(running QUIC-shaped traffic on a non-443 UDP port) is a much
weaker move than the analogous strategy on TLS-over-TCP — you'd
be running on a port where there's no QUIC cover traffic, which
is a fingerprint by itself.

## Mimicry Considerations

Most TLS mimicry concerns transpose directly onto QUIC, with some
QUIC-specific additions:

1. **Inner-TLS-ClientHello fingerprinting** is the same problem
   as on TCP — JA3/JA4-equivalent (sometimes called QSF /
   QUIC-fingerprint) tracking, supported-group ordering, GREASE
   placement, post-quantum X25519MLKEM768 hybrid key share. Mimics
   shipping classic-X25519-only against current Cloudflare /
   Chrome traffic are anachronistic.
2. **Initial packet structure** — the Connection ID lengths, the
   token field shape, the packet number length encoding. Different
   QUIC implementations have different defaults; matching the
   target population means matching their stack's defaults.
3. **Connection migration credibility.** If a mimic claims to be
   browser HTTP/3, sustained sessions need to demonstrate
   migration-handling behavior (or at least not break under it).
4. **Path MTU discovery** — RFC 9000 mandates a minimum 1200B
   maximum packet size on Initial packets; subsequent packets
   probe larger MTUs via PATH_MTU frames or DPLPMTUD heuristics.
   Deviation from typical browser-stack PMTU rhythms is an
   observable.
5. **0-RTT replay handling** — a mimic that claims to accept 0-RTT
   has to demonstrate the replay-protection behavior the spec
   requires; sloppy implementations are a fingerprint.
6. **Spin bit (RFC 8899 §17.4)** — when both peers opt in, the
   spin bit on 1-RTT packets reveals end-to-end latency. Browser
   stacks default to enabled; some implementations disable.
7. **Connection-ID rotation patterns** — Cloudflare, Apple, and
   Google all rotate DCIDs differently. A long-lived connection
   that *never* rotates its DCID is a fingerprint.
8. **ECH applies symmetrically**. A mimic shipping ECH against a
   non-ECH-deploying cover population is anachronistic; one
   *not* shipping ECH against a cover-set that increasingly does
   is anachronistic the other direction.

The classic browser-fingerprint-freshness problem from TLS is
amplified on QUIC because the cover-stack population is even
more concentrated (Chromium QUIC, Apple's, Cloudflare's quiche,
Mozilla's neqo) and each ships per-version fingerprint shifts
that mimics need to track.

## Censor Practice

History (selective):

- **2018-2020 — GFW** does selective UDP/443 throttling under
  high traffic conditions; clients silently fall back to TCP.
- **2022 — TSPU / Russia** brief trials of dropping QUIC packets
  with specific Initial-packet token fields; rolled back when
  collateral became visible.
- **2024 — Russia (TSPU)** sustained UDP/443 throttling in
  several regions during periods of unrest. Clients on Apple
  devices report iCloud Private Relay degraded; falling back to
  HTTP/2 over TCP works.
- **2024-2025 — Iran** intermittent UDP/443 throttling; observable
  drops on YouTube / Cloudflare-fronted properties; consistent
  with throttle-rather-than-block strategy.
- **GFW 2024-2026** continues per-flow UDP throttling; aggressive
  on Apple Private Relay endpoints specifically (DNS-poisoning
  the two specific hostnames `mask.icloud.com` and `mask-h2.icloud.com`,
  which is the Apple-documented path for "blocking" Private Relay).
- **No major censor has wholesale-blocked QUIC.** The collateral
  set has grown faster than blocking-ROI calculations have moved.

The throttle-not-block pattern is the durable equilibrium as of
2026: QUIC has too much collateral cost to drop, but censors
extract enough utility from making it slow that clients fall back
to TCP, where DPI is cheaper.

## Used as Cover By

(Catalog cross-references intentionally not populated yet — the
cover catalog is a survey of mimicry candidates, not a back-
reference index of existing circumvention designs. Will fill in
when there's a deliberate decision to wire the two together.)

In practice, every protocol that runs over QUIC subsumes to this
entry by the wire-distinctness criterion: if a censor sees it
and it's QUIC, the censor's options are the same as for any
other QUIC traffic. The major substrates riding on QUIC — and
therefore drawing collateral cover from this entry's
properties — are:

- **HTTP/3** (RFC 9114) — the headline. ~30-40% of HTTP requests
  in 2026. Substrate for almost everything below.
- **MASQUE** (RFC 9298, 9484, 9729) — proxy traffic via
  CONNECT-UDP / CONNECT-IP / CONNECT-Ethernet. iCloud Private
  Relay (default-on, hundreds of millions of devices), Cloudflare
  WARP, Cisco Secure Access, Apple Private Cloud Compute, Chrome
  IP Protection. Wire is HTTP/3.
- **WebTransport** (W3C + IETF, Baseline 2026) — Extended-CONNECT
  over HTTP/3. Browser-side default since Chrome 97 (2022),
  Firefox 114 (2023), Safari 18.2 (Dec 2024).
- **Media-over-QUIC (MoQ)** (IETF WG, ~2026-2027 RFC) — pre-
  standards but Meta / Google / Apple / Cisco / Cloudflare /
  Fastly / Twitch are at every interop. **No production
  blocking infrastructure exists today** because no major consumer
  product has shipped it yet — the strongest single fit to a
  "new IETF protocols, no censor fingerprints yet" thesis.
- **SMB-over-QUIC** — Microsoft enterprise file share via
  TLS-1.3-over-UDP/443. Windows Server 2022 Datacenter: Azure
  Edition + Server 2025. Microsoft positions it as an "SMB VPN
  for telecommuters."
- **DNS-over-QUIC (DoQ)** (RFC 9250) — encrypted DNS on UDP/853.
  AdGuard, NextDNS, dnsdist, PowerDNS, Unbound, Knot Resolver
  ship; modest deployment relative to DoH.
- **gRPC-over-HTTP/3** — emerging; CNCF gRPC supports HTTP/3
  transport with `application/grpc` content-type unchanged.

Each of these would be its own entry only if its wire shape were
distinguishable from generic QUIC. None are.

## Cross-References

- Sibling cover protocol: [`cover-tls-1-3`](cover-tls-1-3.md) —
  same cryptographic design, different transport envelope.
  Many of the fingerprint-tracking concerns on this entry are
  inherited from there.
- Public corpus papers worth eventually attaching: any new MoQ
  / MASQUE / HTTP/3-deployment measurement study (none currently
  in the corpus as of writing).
- Internal docs (TBD): when Lantern internal QUIC deployment
  notes (e.g. hysteria2 production observations) are added to
  `circumvention-corpus-private`, link them from here.
