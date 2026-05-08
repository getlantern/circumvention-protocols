# TURN

## TL;DR

Traversal Using Relays around NAT — RFC 8656 (Feb 2020,
obsoletes RFC 5766). The WebRTC fallback when ICE direct-
connect and STUN-port-prediction both fail; the call relays
through a TURN server instead. **Wire-distinct** from generic
UDP / TCP because every TURN control message carries the
fixed STUN magic cookie `0x2112A442` at offset 4, and
steady-state ChannelData frames sit in the distinctive
`0x4000-0x7FFF` channel-number range. **Yet not blocked**
because of WebRTC substrate position — wholesale-blocking
UDP/3478 + TCP/3478 + 5349 breaks Twilio Video, Vonage,
Cloudflare Calls, Microsoft Teams' relay fallback, every
video-conferencing vendor's hostile-NAT path. The cover
candidacy is unusual: a fingerprintable protocol that's
unblockable because of its collateral surface.

## Standardization

- **RFC 8656** (Feb 2020, Standards Track) — *Traversal Using
  Relays around NAT (TURN): Relay Extensions to Session
  Traversal Utilities for NAT (STUN)*. The current spec.
- **RFC 5766** (Apr 2010) — original TURN. Obsoleted by
  RFC 8656 but lots of deployed-2020 implementations still
  match its profile.
- **RFC 8489** (Feb 2020) — *Session Traversal Utilities for
  NAT (STUN)*. The substrate message format TURN extends.
- **RFC 6062** (Nov 2010) — *TURN Extensions for TCP
  Allocations*. Lets the relayed transport between the TURN
  server and the peer be TCP rather than UDP. Less common in
  WebRTC but relevant in some enterprise deployments.
- **RFC 6156** (Apr 2011) — IPv6 extensions.
- **RFC 7635** (Aug 2015) — third-party authorization
  (OAuth-style ephemeral credentials). The mechanism Twilio
  NTS / Vonage / etc. use to issue per-session creds without
  long-term shared secrets.
- **RFC 8155** (Apr 2017) — DNS-based STUN/TURN URI / SRV-
  record discovery.
- **RFC 8657** (Nov 2019) — `turn:` and `turns:` URI scheme.
- **RFC 5928** (Aug 2010) — TURN resolution mechanism.
- **RFC 5780** (May 2010) — NAT behavior discovery using STUN.

Working group: **IETF TRAM** (Turn Revised And Modernized) —
chartered around the 8656 / 8489 refresh cycle, now closed.
TURN is currently maintained mostly via individual drafts in
the broader RTCWEB / WISH / etc. ecosystem.

## Wire Format

### STUN message header (RFC 8489 §5)

Every TURN control-plane message begins with a STUN header:

```
+----+---------+--------------+------------+------------+
|2b  |   14b   |     16b      |     32b    |    96b     |
|0b00| msgtype |  msg length  | magic      | transaction|
|    |(class+  |  (excluding  | cookie     | id (random)|
|    | method) |  header)     | 0x2112A442 |            |
+----+---------+--------------+------------+------------+
```

The fixed `0x2112A442` magic cookie is **the unmistakable
wire fingerprint**. Any DPI that reads the first 8 bytes of
a UDP packet on UDP/3478 (or the framed payload on TCP/3478)
sees this exact sequence — no decryption required, no
heuristics. The leading `0b00` at the very first 2 bits of
the message type field also distinguishes STUN from RTP
(`0b10`), DTLS (`0b00010100` first byte), and other UDP
real-time protocols.

Method codes relevant to TURN:

| Method | Class | Purpose |
| --- | --- | --- |
| 0x003 | Request / Indication | Allocate |
| 0x004 | Request | Refresh (extend allocation lifetime) |
| 0x008 | Request | CreatePermission (authorize a peer IP) |
| 0x009 | Request | ChannelBind (associate a channel number with a peer) |
| 0x016 | Indication | Send (relay UDP datagram to peer) |
| 0x017 | Indication | Data (relay UDP datagram from peer to client) |
| 0x001 | Request / Response | Binding (vanilla STUN; sometimes appears within TURN flows) |

### Allocate flow

```
Client                                                Server

Allocate Request (no creds yet)
  REQUESTED-TRANSPORT (UDP=17 / TCP=6)
  ----- STUN message, magic cookie visible ----->

                      <--- 401 Unauthorized + REALM + NONCE ---

Allocate Request (with creds)
  USERNAME, REALM, NONCE, MESSAGE-INTEGRITY (HMAC-SHA1)
  REQUESTED-TRANSPORT, LIFETIME (e.g. 3600 s)
  ----- STUN message ------------------------------>

                      <--- Allocate Success Response ---
                      XOR-RELAYED-ADDRESS (the public IP+port
                                            allocated for this
                                            client to receive
                                            from peers on)
                      LIFETIME, MAPPED-ADDRESS
```

Then the client uses one of two data-plane patterns:

1. **Send / Data Indications** — every relayed datagram is
   wrapped in a STUN message. High overhead per packet but
   simple.
2. **Channels** — client binds a 16-bit channel number to a
   peer with ChannelBind, then exchanges **ChannelData**
   frames:

```
+--------+--------+----------+
|  16b   |  16b   |   N B    |
| ch num | length |  data    |
|0x4000- |        |          |
| 0x7FFF |        |          |
+--------+--------+----------+
```

The `0x4000-0x7FFF` range for the channel-number field is
distinctively non-STUN (which starts with `0b00`). Channel
data has 4 bytes of overhead instead of ~36 for Send/Data
indications, so it's the production WebRTC pattern.

### TCP framing (RFC 8656 §2.1)

On TCP/3478 plain TURN, STUN messages are length-prefixed
with their 16-bit length field already in the STUN header,
making framing self-delimiting. ChannelData on TCP rounds
length up to a multiple of 4 bytes for alignment.

### TURNS — TURN-over-TLS / TURN-over-DTLS

- TCP/5349: TURN-over-TLS — wire shape becomes
  [`cover-tls-1-3`](cover-tls-1-3.md), TURN messages encrypted inside
- UDP/5349: TURN-over-DTLS — wire shape becomes
  [`cover-dtls`](cover-dtls.md), TURN messages encrypted inside

For mimicry purposes, TURNS subsumes to its outer crypto
layer. Plain TURN on 3478 keeps its own wire shape.

### FINGERPRINT attribute

RFC 8489 §14.7 — optional CRC-32 of the message XOR'd with
the constant `0x5354554e` ("STUN" in ASCII). Some
implementations always include it (to disambiguate STUN
from other protocols multiplexed on the same UDP 5-tuple,
notably DTLS in WebRTC). The XOR constant is itself a
distinctive wire marker.

## Traffic Patterns

- **Allocate burst** at session start: 2-4 STUN messages in
  ~50-200ms (Allocate request, 401-with-NONCE, Allocate
  request with creds, Allocate success). Distinctive opening
  shape.
- **Permission / ChannelBind setup**: a few CreatePermission
  / ChannelBind requests, one per peer the client is
  connecting to (in WebRTC mesh sessions, can be N-1 peers).
- **Steady-state relay**: ChannelData frames sized close to
  the inner SRTP / DTLS-SRTP packet size (typically
  100-1300 bytes for video, 60-200 for audio). Sustained
  packet rate matching the inner media flow.
- **Refresh** every LIFETIME seconds (commonly 600 or 3600).
  Periodic STUN-shaped requests stand out behaviorally.
- **Idle / keepalive**: TURN doesn't require constant
  keepalives at the relay layer — the peer-to-relay UDP
  path stays alive as long as ChannelData flows. If the
  call ends, traffic stops abruptly.
- **TCP TURN** has the same control flow but with TCP
  congestion / ACK shape on the wire — distinguishable
  from UDP TURN at flow level.

## Encryption Surface

| Layer | Visible | Encrypted |
| --- | --- | --- |
| IP / UDP or TCP | client IP, server IP, ports | n/a |
| STUN header | message type, length, magic cookie 0x2112A442, transaction ID | nothing — header is always cleartext |
| STUN attributes | USERNAME (cleartext!), REALM, NONCE, ERROR-CODE, REQUESTED-TRANSPORT, LIFETIME, XOR-RELAYED-ADDRESS, XOR-MAPPED-ADDRESS | MESSAGE-INTEGRITY HMAC value (random-looking but the HMAC tag itself, not encryption) |
| Send / Data indications | DATA attribute length and structure | DATA attribute payload bytes (when peer-side packets are themselves encrypted, e.g. SRTP) |
| ChannelData frames | channel number, length | data payload (when the inner stream is SRTP / DTLS-SRTP / generic peer-encrypted) |
| TURNS outer wrapper (5349) | TLS / DTLS handshake, ALPN, SNI | the entire inner TURN exchange |

The control plane is **fully observable** on plain TURN.
Crucially: USERNAME is plaintext. RFC 8656 acknowledges this
and suggests TURNS (TURN-over-TLS) for credential
confidentiality, but production deployments overwhelmingly
run plain TURN on 3478 because the data-plane payload is
already encrypted (SRTP within ChannelData) and the
USERNAME on managed TURN providers is an ephemeral OAuth-
style token, not a stable identifier.

## Common Implementations

| Stack | Vendor | Scope |
| --- | --- | --- |
| **coturn** | coturn project | The open-source dominant. Powers Twilio NTS reference deployments, Jitsi Meet bundled TURN, Matrix.org bundled TURN, Nextcloud Talk, Slack Calls (legacy), most self-hosted WebRTC |
| pion/turn | Pion | Go TURN client + server. LiveKit, Daily.co components, Go-native WebRTC stacks. Same project family as pion/dtls — inherits some of the same fingerprint lessons |
| aiortc / aioice | Jeremy Lainé | Python WebRTC; academic / research |
| Twilio Network Traversal Service | Twilio (commercial) | Commercial TURN-as-a-service market leader |
| Xirsys | Xirsys (commercial) | Multi-region anycast TURN |
| Vonage NTS | Vonage (commercial) | Behind Vonage Video / TokBox |
| Cloudflare Calls TURN | Cloudflare | Free-tier TURN within Cloudflare Calls |
| Microsoft Teams TURN fleet | Microsoft | Global multi-region behind Teams calling — proprietary |
| Google Meet TURN fleet | Google | Global multi-region behind Meet — proprietary |
| Zoom relay nodes | Zoom | TURN-adjacent media relay (not strictly RFC) |
| AWS Kinesis Video Streams Signaling+TURN | AWS | Managed TURN inside Kinesis WebRTC |

The dominant population on the public Internet is
coturn (self-hosted long tail) + the proprietary
fleet of Twilio / Cloudflare / Microsoft / Google / Zoom.

## Prevalence

TURN is the WebRTC fallback path; estimates vary on what
fraction of WebRTC sessions need it:

- Industry rule-of-thumb: **15-20% of WebRTC sessions use
  a TURN relay** (the rest succeed with direct ICE / STUN-
  predicted ports). Higher in mobile-NAT-heavy regions and
  enterprise NATs.
- Twilio published in 2018-2020 customer-success material
  that ~10-15% of their Video sessions traversed TURN; this
  was on a global mix.
- Cloudflare Calls launched 2023 with free-tier TURN; their
  marketing material claims "millions of sessions/day"
  through their TURN fleet.
- Microsoft Teams operates a global Anycast TURN fleet;
  Teams has ~320M MAU (Microsoft 2024 filing). A double-digit
  percent fraction of those calls relay.

So the order-of-magnitude is: **billions of WebRTC sessions
per day across the major vendors, with on the order of
hundreds of millions traversing a TURN relay.**

Plain port 3478 / 5349 traffic is easily measurable in
ISP NetFlow data — it's a known, published port.

## Collateral Cost

**High.** A wholesale UDP/3478 + TCP/3478 + 5349 block
breaks the WebRTC relay fallback for every session whose
peers can't direct-connect. Concrete consequences:

- Hostile-NAT users (mobile carrier-grade NAT, enterprise
  egress NAT, double-NAT home routers) lose the ability to
  participate in any browser-based video call: Microsoft
  Teams, Zoom, Google Meet, Discord voice, Cloudflare Calls,
  Twilio-Video customers, every Daily.co / LiveKit
  application.
- B2B SaaS depending on TURN: Twilio, Vonage, Xirsys,
  Cloudflare Calls — these are sold to thousands of
  customer applications. Block breaks their products at
  the operator layer simultaneously.
- Telehealth, e-learning, and remote-interview workflows
  rely on WebRTC and degrade visibly under TURN block.
- Carrier-grade SIP trunking that uses ICE / TURN for
  WebRTC interconnect breaks for some operators.

The story matches [`cover-dtls`](cover-dtls.md): TURN is
WebRTC substrate, and WebRTC is universal video-call
infrastructure in 2026. **Wholesale-block is operationally
hostile**; censors avoid it.

The realistic block strategies are:

1. **Targeted TURN-server-IP blocking** — block the
   specific TURN endpoints used by a circumvention tool,
   leaving the rest of the TURN ecosystem alone. Works only
   if the circumvention tool advertises its TURN endpoints
   stably enough for the censor to enumerate them.
2. **Behavioral correlation** — TURN-shape traffic
   sustained for hours to a single relay (vs. typical
   call-duration patterns) might be flagged. But the
   protocol shape itself is fine.
3. **Authentication challenge** — coturn / Twilio /
   Cloudflare all require authentication. A censor can
   silently block flows that don't authenticate as a
   legitimate vendor's customer (i.e. drop flows whose
   401-NONCE-then-creds dance doesn't go through). This is
   close to active probing, expensive at scale.

## Common Ports & Collateral Cost

TURN has well-defined IANA ports; deviating from them is
a fingerprint of its own.

| Port | Variant | Collateral of port-block |
| --- | --- | --- |
| **UDP/3478** | Plain TURN over UDP — the dominant production port | High — all WebRTC TURN fallback traffic |
| **TCP/3478** | Plain TURN over TCP — used when UDP is blocked | High — covers networks that pre-block UDP for VPNs |
| **UDP/5349** | TURNS — TURN over DTLS | High — used when payload-encryption is required (regulated industries, healthcare) |
| **TCP/5349** | TURNS — TURN over TLS | High — same |
| **non-canonical port** | Some private TURN deployments | Low collateral, but **flow on a non-canonical port that performs the STUN magic-cookie handshake is a strong fingerprint of "circumvention TURN, not real WebRTC TURN"** — the absence of a realistic vendor is itself the signal |
| **UDP/3479-3489** | RFC 8656 §2.5 says clients MAY try a small range; some coturn deployments listen on adjacent ports | Modest — niche |

The wire shape and the port pair go together: TURN's
collateral-freedom protection comes from being on
3478/5349 with the magic cookie. Putting TURN on a random
high port surfaces the magic cookie on a port where no
legitimate consumer-product TURN ever runs, giving the
censor an unambiguous block target.

## Mimicry Considerations

Mimicking TURN convincingly is unusually constrained because
the wire format is rigid:

1. **The magic cookie `0x2112A442` is mandatory** in every
   STUN-formatted message. There's no obfuscation room
   here. A "TURN-like" protocol that omits or randomizes
   the magic cookie is no longer TURN; it's an obvious
   custom protocol on UDP/3478.
2. **Allocate / 401-NONCE / Allocate-with-creds is a
   required two-round-trip dance**. Skipping it (jumping
   straight to ChannelData) is anachronistic — real WebRTC
   stacks always negotiate.
3. **USERNAME / REALM / NONCE values must look realistic.**
   Twilio NTS issues per-session ephemeral credentials that
   look like `<unix_timestamp>:<random_id>`; coturn
   long-term creds use plain usernames. A circumvention
   server returning a static, distinctive USERNAME is
   fingerprintable.
4. **MESSAGE-INTEGRITY HMAC must verify** under the SASLprep
   prep of the password. A mimic that forwards arbitrary
   bytes here breaks correctness — a censor doesn't need
   to break the HMAC to detect this; just observe the 401
   loop never reaching success.
5. **ChannelData payload sizes must match WebRTC media
   reality** — audio frames ~60-200 bytes at 50pps, video
   frames sized close to MTU. Steady throughput patterns
   that don't match a real call are behaviorally
   distinctive.
6. **FINGERPRINT attribute discipline** — different stacks
   include it consistently or not. coturn always includes
   it on outgoing messages by default; some custom stacks
   don't. The presence/absence pattern leaks the
   implementation.
7. **Relayed-transport selection** — REQUESTED-TRANSPORT=17
   (UDP) is the WebRTC norm; REQUESTED-TRANSPORT=6 (TCP, RFC
   6062) is rarer and more enterprise. Consistently
   requesting TCP relays on a "WebRTC mimic" is anachronistic.
8. **Backing service requirement** — convincing TURN cover
   essentially requires a real TURN server (coturn) on the
   server side; running a custom binary that *emulates*
   TURN is far easier to detect than running coturn and
   tunneling through it.

The hardest mimicry case is **pretending to be a Twilio /
Cloudflare TURN customer** — those vendors have published
auth-flow contracts, anycast IP ranges, and TLS cert chains
that a clone can't easily reproduce. The easier mimicry case
is **running your own coturn instance** as a real service,
which works if the IP doesn't get enumerated.

## Censor Practice

History (selective):

- **2018-2020 — Iran / GFW** intermittent UDP/3478
  throttling during periods of unrest. Targeted UDP shape
  rather than TURN specifically; collateral on WebRTC was
  sometimes acknowledged in user-reported quality drops.
- **2020 — pandemic-era ramp** of consumer video calling
  raised the visibility of TURN-block side effects. Most
  major censors visibly *avoided* WebRTC blocks during this
  window because of remote-work / education impact.
- **2022 — Russia** TURN-shape behavioral fingerprinting
  research surfaced in net4people / OONI but no known
  large-scale block.
- **2024 — Iran** intermittent UDP/3478 + UDP/5349 blocks
  reported on Iranian-mobile networks during specific
  protest periods; rolled back after a few hours due to
  Skype/Teams complaints.
- **March 2026 — TSPU/Russia** blocked pion-DTLS
  fingerprint (cover-dtls's canonical event); plain TURN
  control-plane was not the focus, but TURN-over-DTLS
  flows on UDP/5349 inherited the impact.
- **2026 — Cloudflare Calls** has been suggested as
  circumvention cover in informal channels, but the
  international-infra-broadly-blocked-in-Iran reality
  (Cloudflare unreachable from many Iranian ASNs in early
  2026) limits this in practice.

The pattern: **TURN itself is virtually never wholesale-
blocked**. Censors block specific TURN endpoints (IP /
ASN-based) when those endpoints are demonstrably running
circumvention. The wire fingerprint is irrelevant when
collateral protects the protocol and the circumvention
tool is identified by destination instead.

## Used as Cover By

(Catalog cross-references intentionally sparse — TURN is
underused as cover for circumvention.)

The pattern that has been *proposed* (in discussion / in
research) but has limited deployed examples:

- A circumvention server running real coturn, with the
  client speaking real TURN to allocate, then tunneling
  application traffic through ChannelData frames sized
  to look like SRTP. The collateral-freedom story is
  strong; the behavioral story is harder (sustained TURN
  flows from a single client to a single relay over hours
  don't look like calls).
- Snowflake **uses STUN** (the substrate of TURN) for ICE
  candidate gathering but doesn't relay through TURN
  proper — once Snowflake establishes a peer connection,
  data goes via WebRTC DataChannel over DTLS-SRTP, not
  TURN ChannelData. So Snowflake is more accurately a
  **cover-dtls** consumer than a **cover-turn** consumer.

Empty `used_as_cover_by` is the honest current answer.

## Cross-References

- Sibling cover protocols:
  - [`cover-dtls`](cover-dtls.md) — TURNS-over-DTLS uses
    DTLS as outer wrapper. WebRTC ICE setup multiplexes
    STUN (TURN's substrate) and DTLS on the same UDP
    5-tuple — they coexist but are wire-distinguishable
    by leading byte (0b00 STUN vs 0b00010100 DTLS).
  - [`cover-tls-1-3`](cover-tls-1-3.md) — TURNS-over-TLS
    on TCP/5349 inherits this wrapper.
  - [`cover-quic`](cover-quic.md) — there have been
    proposals for TURN-over-QUIC but nothing IETF-
    standardized as of 2026.
- Public corpus: STUN/TURN measurement papers from the
  IMC / PAM / NDSS communities; specific paper IDs TBD as
  the corpus grows.
- Internal docs (TBD): `circumvention-corpus-private` is
  the natural home for any Lantern-internal TURN-cover
  experiments.
- Catalog circumvention entries that **could** mimic TURN
  but currently don't: this is the underutilized-cover
  story. A Lantern variant that runs over coturn with
  ChannelData-shaped framing is a clean candidate; it
  inherits WebRTC collateral and adds a wire shape no
  current Lantern protocol uses.
