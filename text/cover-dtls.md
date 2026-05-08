# DTLS

## TL;DR

TLS over UDP. RFC 9147 (DTLS 1.3, April 2022) derives its
cryptographic core from TLS 1.3; RFC 6347 (DTLS 1.2, 2012) is
still the dominant production version. **Wire is materially
distinct from both TLS-over-TCP and QUIC** — 13-byte record
header (vs TLS's 5), explicit epoch + sequence number,
distinctive HelloVerifyRequest cookie round trip, no QUIC-style
packet-number encryption. The dominant deployment is **WebRTC's
DTLS-SRTP** (RFC 5764) carrying every browser-based video / voice
call on the public Internet. The canonical 2026 censor attack
against any DTLS-using circumvention is **TSPU/Russia's March
2026 ClientHello-fingerprint match against pion-DTLS defaults**
(net4people/bbs#603), which broke Snowflake until pion-using
projects adopted fingerprint randomization (Psiphon's covert-dtls,
also vendored by Lantern Unbounded).

## Standardization

- **RFC 9147** (Apr 2022, Standards Track) — *The Datagram
  Transport Layer Security (DTLS) Protocol Version 1.3*. The
  current spec.
- **RFC 6347** (Jan 2012, Standards Track) — *DTLS 1.2*. Older
  but still the production majority because DTLS 1.3 deployment
  is slower than its TLS-1.3-over-TCP sibling.
- **RFC 9146** (Apr 2022) — *Connection Identifier for DTLS 1.2*.
- **RFC 9145** (Apr 2022) — Same idea for DTLS 1.3.
- **RFC 5764** (May 2010) — *Datagram Transport Layer Security
  (DTLS) Extension to Establish Keys for the Secure Real-time
  Transport Protocol (SRTP)*. The DTLS-SRTP spec — every WebRTC
  data channel and media flow runs through this.
- **RFC 7252** (Jun 2014) — *The Constrained Application Protocol
  (CoAP)*. CoAP-over-DTLS is the canonical secure CoAP profile;
  RFC 9147 update extends it for DTLS 1.3.
- **RFC 5246 § B.2** (historical) — TLS / DTLS shared cipher-suite
  registry.
- **RFC 8094** (Feb 2017) — *DNS over Datagram Transport Layer
  Security (DTLS)*. Largely superseded by DoQ in production but
  defined.
- DTLS 1.0 (RFC 4347, 2006) is historic; treat as out-of-scope.

Working group: **IETF TLS WG** (the same WG that owns TLS 1.3).
DTLS evolves in lockstep with TLS — 1.3 followed 1.3, etc.

## Wire Format

### Record header

```
+----+----------+--------+-----------+------------+----------+----------+
| 1B |   2B     |   2B   |    6B     |     2B     |   N B    |   ≤16B   |
| ty | version  | epoch  | seq num   | length     | payload  | (AEAD    |
|    | (0xfeff  | counter| (mono inc | of payload | enc with | tag if   |
|    |  / fefd  |        |  per      |            | record   | DTLS 1.3 |
|    |  / fefc) |        |  epoch)   |            | keys)    | / 1.2    |
+----+----------+--------+-----------+------------+----------+----------+
```

- `type` = 0x14 ChangeCipherSpec, 0x15 Alert, 0x16 Handshake,
  0x17 ApplicationData, 0x18 Heartbeat (RFC 6520).
- `version` legacy field: `0xfeff` DTLS 1.0, `0xfefd` DTLS 1.2,
  `0xfefc` DTLS 1.3. Real version negotiated via `supported_versions`
  extension as in TLS 1.3.
- `epoch` increments on key changes; `seq` resets at each epoch.
- DTLS 1.3 added optional **header protection** (16-byte
  pseudo-random mask XORed onto sequence-number bits), distinct
  from TLS but with similar privacy effect.

The 13-byte record header (vs TLS's 5) is the **most reliable
on-wire discriminator** between DTLS and other UDP traffic.

### Handshake — and the cookie round trip

```
Client                                                 Server

ClientHello (version, random, session_id, cipher_suites,
             extensions including key_share, ALPN, SNI, ECH...)
       -------- record(handshake, epoch=0, seq=0) -------->

                                                        On first contact, server may reply:
                <-- record(handshake, epoch=0, seq=0) --
                                                        HelloVerifyRequest{ cookie }

ClientHello { same fields, with cookie echoed }
       -------- record(handshake, epoch=0, seq=1) -------->

                <-- record(handshake, ...) -- ServerHello, EncryptedExtensions,
                                              Certificate*, CertificateVerify*, Finished
                                              (DTLS 1.3 — handshake records protected
                                              under handshake-traffic key from packet 2 onward)
... Finished ... ApplicationData ...
```

The HelloVerifyRequest cookie exchange is **DTLS-distinctive**.
DTLS 1.3 keeps this option available (servers can demand cookies
for DoS protection) and defines a one-shot stateless reply
mechanism in §5.1; DTLS 1.2 servers commonly enforce cookies.

Handshake messages can be larger than the path MTU, so the spec
defines explicit fragmentation:

```
HandshakeMessage {
    msg_type (1B),
    length (3B),
    message_seq (2B),
    fragment_offset (3B),
    fragment_length (3B),
    body (fragment_length bytes),
}
```

The `message_seq` + `fragment_offset` fields don't appear in
TLS-over-TCP. They're an unambiguous DTLS marker for any DPI
that decodes the inner handshake bytes.

### Connection ID (RFC 9146 / 9145)

Optionally negotiated; carried in records as a header-extension.
Lets the same DTLS session survive client IP/port changes —
analogous to QUIC's Connection ID.

### DTLS-SRTP (RFC 5764)

The dominant cover use:

1. ICE/STUN binding requests and responses set up the path.
2. DTLS handshake runs in-band on the same UDP 5-tuple.
3. Both endpoints derive SRTP master keys from the DTLS exporter
   (RFC 5705) using the label `EXTRACTOR-dtls_srtp`.
4. Subsequent media packets on the same 5-tuple use **SRTP**
   (RFC 3711) — not DTLS — keyed by the derived material.

So in a real WebRTC session: a few DTLS records of handshake,
then a long stream of SRTP packets. SRTP records have a different
header (no DTLS record-header bytes) and would deserve their own
catalog entry if they had wire-distinctness from generic UDP
encrypted traffic — but SRTP's encrypted payload is essentially
opaque UDP after the SRTP header, so it subsumes operationally
to "encrypted UDP with WebRTC ports."

## Traffic Patterns

- **Short handshake burst** at session start: 4-8 DTLS records
  in 1-2 RTTs, then transition to either DTLS application data
  or SRTP media.
- **WebRTC media flow**: high-rate UDP packets sized close to
  path MTU, sustained over the call duration. **Most observed
  DTLS traffic on the wire is the handshake; the bulk of the
  session bytes are SRTP.**
- **CoAP-over-DTLS** sessions are short and bursty — IoT devices
  wake up, exchange a few records, sleep.
- **Cisco AnyConnect DTLS data plane** is sustained encrypted UDP
  on UDP/443 with periodic keepalive frames; a censor watching
  UDP/443 sees a DTLS-shaped flow that looks neither like QUIC
  nor like generic VPN.
- **Connection ID** rebinding events are detectable behaviorally
  if the censor watches the same DTLS session move between IPs.

## Encryption Surface

| Layer | Visible | Encrypted |
| --- | --- | --- |
| IP / UDP | client IP, server IP, ports | n/a |
| DTLS record header | type, version, epoch, sequence number, length | (in DTLS 1.3 with header protection: sequence-number bits are masked) |
| DTLS handshake (first records) | full handshake messages including ClientHello (SNI, JA3/JA4-equivalent fingerprint, supported groups, ALPN), HelloVerifyRequest, ServerHello | (in DTLS 1.3) handshake-traffic-key-protected from EncryptedExtensions onward |
| DTLS Application Data | record sizes + timing | record contents |
| DTLS-SRTP-keyed media | SRTP header (length, SSRC, sequence), packet sizes, timing | SRTP payload (the actual media) |

Crucially: **the inner ClientHello in the first DTLS Handshake
record is observable**. DTLS doesn't have QUIC's Initial-keys
obfuscation. SNI / ALPN / cipher-suites / extension order / JA3D
or JA4D fingerprint — all visible to any passive observer that
parses DTLS records. ECH closes the inner-CH visibility when
deployed (the same draft applies; deployment lags TLS-over-TCP
ECH because the WebRTC ecosystem moves slower).

## Common Implementations

| Stack | Vendor | Scope |
| --- | --- | --- |
| OpenSSL DTLS | OpenSSL Foundation | The Linux-server default; Cisco AnyConnect server, OpenVPN-DTLS, Asterisk DTLS-SRTP |
| BoringSSL DTLS | Google | Chrome / Android WebRTC, Google Meet |
| NSS DTLS | Mozilla | Firefox WebRTC |
| Apple Security framework DTLS | Apple | FaceTime, iOS / macOS WebRTC, CallKit-backed apps |
| Schannel DTLS | Microsoft | Microsoft Teams native client DTLS-SRTP, Windows IPsec |
| **pion/dtls** | Pion project | Snowflake (pre-covert-dtls), Lantern Unbounded, Psiphon Inproxy, every Go-WebRTC project — **the most-circumvention-fingerprinted DTLS implementation in existence** |
| **covert-dtls** | Psiphon-Labs | Fingerprint-randomization wrapper around pion/dtls. Consumed by Lantern Unbounded (`common/covertdtls/`), Psiphon Inproxy, post-March-2026 Snowflake forks |
| mbedTLS DTLS | Trusted Firmware | Embedded / IoT — DTLS-CoAP devices (LwM2M) |
| wolfSSL DTLS | wolfSSL | Embedded; industrial DTLS |

The browser cluster is BoringSSL + NSS + Apple Security framework
+ Schannel — these define the legitimate WebRTC fingerprint
population. Production WebRTC is overwhelmingly served from this
set.

The **circumvention cluster** is pion/dtls + covert-dtls. As of
2026, every catalog circumvention design that uses DTLS (Snowflake,
Lantern Unbounded, Psiphon Inproxy) sits on this cluster — which
is exactly why TSPU's March 2026 fingerprint matched.

## Prevalence

DTLS volume is dominated by WebRTC. Concrete order-of-magnitude
indicators:

- Microsoft Teams: ~320M monthly active users (Microsoft 2024
  filing); voice / video calls run over DTLS-SRTP on the
  Teams-native client path.
- Zoom: ~300M+ daily meeting participants pre-2025 publishings.
- Google Meet: built into Workspace; tens of millions of daily
  users.
- Discord: ~150M MAU (2024); voice channels run over DTLS-SRTP.
- Apple FaceTime: hundreds of millions of devices ship it.
- Snapchat / Instagram Direct video: WebRTC-based, hundreds of
  millions MAU each.
- LwM2M / CoAP-over-DTLS: billions of constrained-device
  connections (Open Mobile Alliance LwM2M deployment numbers).

DTLS itself is invisible in W3Techs / Cloudflare-Radar style
measurements (those count HTTP-traffic shape; DTLS doesn't show
up there) but the carrier protocols above are easily multi-billion
interactions per day.

## Collateral Cost

**High.** A wholesale DTLS block breaks WebRTC across every major
video-conferencing product simultaneously: Microsoft Teams (~320M
MAU), Zoom (~300M+ DAU), Google Meet, Discord voice, FaceTime,
Snapchat / Instagram Direct video. The video-call-broken-everywhere
result is exactly the kind of visible product failure censors
avoid.

Targeted DTLS blocking (specific implementation fingerprints, or
specific destination IPs) is the operational pattern censors use
instead. The TSPU March 2026 attack is the canonical example —
**not "block all DTLS"** but "block traffic whose DTLS ClientHello
matches pion-default fingerprint." That has near-zero collateral
because pion-DTLS is rarely embedded in production consumer
products outside Snowflake.

Other collateral concerns:

- Cisco AnyConnect on UDP/443 — telework / corporate-VPN backbone
  for thousands of enterprises. Blocked-broadly would be visible.
- LwM2M / CoAP-over-DTLS — IoT fleets (cellular telematics,
  smart-meter telemetry). Blocking breaks IoT operators' SLAs.
- DTLS-SRTP for SIP carrier interconnect — in some deployments;
  blocking would impact carrier-grade voice.

So a censor's calculus is: **DTLS in browser stacks =
unblockable; DTLS in pion-default = freely blockable**. The
fingerprint differentiates.

## Common Ports & Collateral Cost

DTLS doesn't have a single dominant port — it inherits the port
of whatever carrier protocol uses it. The relevant port surface:

| Port | Cover service | Collateral of port-block |
| --- | --- | --- |
| **UDP/443** | Cisco AnyConnect data plane (DTLS); also QUIC | High — see [`cover-quic`](cover-quic.md). Cisco AnyConnect is enterprise VPN backbone. |
| **UDP/3478** | STUN binding (often in same flow as DTLS-SRTP) | High — every WebRTC NAT-traversal attempt |
| **UDP/5349** | TURNS (TURN over TLS / DTLS) | High — WebRTC media-relay fallback for hostile-NAT clients |
| **UDP/4500** | IPsec NAT-T (sometimes DTLS-adjacent / IKEv2) | Modest — IPsec is censor-friendly to block (consumer-VPN territory) |
| **UDP/5684** | CoAP-over-DTLS | LwM2M IoT fleets; blocking breaks smart-meter / fleet-telematics |
| **WebRTC ephemeral high ports** (10000-65535) | DTLS-SRTP media path | These are ephemeral per session; port-blocking the entire range breaks all WebRTC media |
| **UDP/853** | DNS-over-DTLS (RFC 8094, niche) | Negligible — production DoT/DoH/DoQ have largely won |
| **UDP/500** | IKEv2 (handshake; technically not DTLS but related family) | Modest |

The strongest cover ports are UDP/443 (Cisco AnyConnect) and the
WebRTC pair (UDP/3478 + ephemeral). Both inherit the WebRTC /
enterprise-VPN collateral cost story. Targeted-port mimicry of
DTLS on, say, UDP/12345 is exactly the kind of fragile move
called out in [`cover-tls-1-3`](cover-tls-1-3.md) §Common Ports —
the absence of legitimate DTLS traffic on a non-canonical UDP
port is itself a fingerprint.

## Mimicry Considerations

DTLS mimicry inherits everything from TLS mimicry, plus
DTLS-specific concerns:

1. **ClientHello fingerprint discipline** is **the** critical
   axis. The pion-DTLS default fingerprint was matched and
   blocked by TSPU in March 2026. Any DTLS-using mimic post-2026
   must either (a) randomize the ClientHello fields per-connection
   (the **covert-dtls Randomize mode**) or (b) replay a real
   browser fingerprint exactly (**Mimic mode**). Static custom
   fingerprints are immediately fingerprintable.
2. **HelloVerifyRequest cookie response** is DTLS-distinctive.
   A mimic that doesn't honor cookies (always sends the same
   ClientHello regardless of cookie request) is anachronistic
   relative to real WebRTC stacks.
3. **Handshake fragmentation behavior** — real DTLS stacks
   adapt to path MTU and use the `fragment_offset` fields. A
   mimic that always sends in one record (or always uses
   default fragment thresholds) is fingerprintable.
4. **Connection ID** — RFC 9146/9145 connection IDs are
   negotiated by real implementations on hostile NATs. A long-
   lived mimic that never advertises CIDs looks unlike real
   browser DTLS.
5. **DTLS 1.2 vs 1.3** — production WebRTC is gradually moving
   to DTLS 1.3 but most browser stacks still default to 1.2 in
   2026. Mimics shipping 1.3-only against a 1.2-dominated cover
   population are anachronistic; mimics shipping 1.2 against a
   1.3-deploying cover are anachronistic the other way. Track
   the population.
6. **DTLS-SRTP transition** — a full WebRTC mimic must complete
   the DTLS handshake and then **switch to SRTP-on-the-same-5-tuple**
   for steady-state media. A mimic that keeps sending DTLS
   ApplicationData records after the handshake is wire-shape-
   wrong for DTLS-SRTP cover; it looks like Cisco AnyConnect or
   bare DTLS-VPN, which is a different cover with different
   collateral cost.
7. **STUN binding precedes the handshake** in WebRTC. A mimic
   claiming WebRTC cover that skips STUN (just opens a UDP
   connection and starts DTLS) is anachronistic. STUN's
   `0x2112A442` magic + transaction ID are observable.
8. **Path MTU + fragmentation patterns** — pion-DTLS used to
   produce distinctive fragmentation timing. covert-dtls's
   randomize mode normalizes this; bare pion does not.

The historical lesson is unusually concrete here: **TSPU built
DTLS-fingerprint-blocking on top of pion's default ClientHello
in early 2026, and the entire WebRTC-using circumvention
ecosystem (Snowflake, Unbounded, inproxy) had to pivot to
randomization or browser-mimicry within weeks.** The fingerprint-
freshness budget for DTLS-using mimics is materially tighter
than for TLS-over-TCP mimics because of this established
attack capability.

## Censor Practice

History (selective):

- **2018 — early GFW** experiments with UDP-over-3478 throttling
  during Tor's first Snowflake trials. Throttle, not block.
- **2022 — Iran** sustained WebRTC throttling during periods of
  unrest; targeted UDP traffic patterns rather than DTLS
  specifically.
- **2024 — TSPU / Russia** initial DTLS-fingerprint trials
  against Snowflake; rolled back.
- **March 30, 2026 — TSPU / Russia** sustained block of pion-DTLS
  default ClientHello fingerprint (net4people/bbs#603). Snowflake
  Tor users in Russia lost connectivity. The Tor Project, Lantern
  Unbounded, and Psiphon Inproxy all responded within ~2 weeks
  by adopting Psiphon-Labs/covert-dtls fingerprint randomization
  or browser-mimicry. **This is the canonical 2026 DTLS
  fingerprint-attack event.**
- **2026 ongoing** — TSPU and adjacent censors track
  DTLS-fingerprint diversity; pion-default-fingerprinted traffic
  continues to be blocked. Browser-fingerprinted traffic
  (Chromium / Firefox / Apple WebKit) is unblocked.

The pattern: DTLS-fingerprint-matching is a **deployed,
operational censor capability** in at least one major
jurisdiction, with no observed wholesale-block of DTLS itself
(which would break WebRTC universally and is operationally
hostile).

## Used as Cover By

(Catalog cross-references intentionally not populated yet.)

The application-layer protocols that ride inside DTLS today:

- **WebRTC DTLS-SRTP** for media — Zoom, Microsoft Teams (native
  client), Google Meet, Discord voice, Snapchat / Instagram
  Direct video, FaceTime, every browser RTCPeerConnection.
- **Cisco AnyConnect** data-plane VPN.
- **OpenVPN-DTLS** variants (legacy).
- **CoAP-over-DTLS** for IoT (LwM2M, smart meters, telematics).
- **DNS-over-DTLS** (RFC 8094) — niche.
- **EAP-TLS over DTLS** for 802.1X in some enterprise deployments.

Each is a distinct application but all subsume to this entry by
the wire-distinctness criterion: a censor sees DTLS records and
cannot distinguish among the carriers without much deeper
observation.

## Cross-References

- Sibling cover protocols:
  - [`cover-tls-1-3`](cover-tls-1-3.md) — same cryptographic
    family; DTLS 1.3 inherits TLS 1.3's handshake design. Most
    fingerprint concerns transpose.
  - [`cover-quic`](cover-quic.md) — also UDP-based but with its
    own cryptographic envelope (Initial keys, header protection,
    Connection ID baked in). DTLS and QUIC are siblings on UDP
    but wire-distinct.
- Public corpus: no DTLS-specific paper in the corpus as of
  writing. The pion-DTLS-fingerprint attack should land as a
  measurement note when net4people / Tor metrics reports
  formalize the March 2026 event.
- Internal docs (TBD): `circumvention-corpus-private` is the
  natural home for Lantern's covertdtls deployment notes.
- Existing circumvention catalog entries that mimic DTLS (and
  therefore inherit this cover): `unbounded`, `psiphon-inproxy`,
  `snowflake` — each via pion/dtls + covert-dtls.
