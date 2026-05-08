# TLS 1.3

## TL;DR

The IETF's transport-encryption standard. Virtually every
HTTPS request, encrypted-DNS query, modern email session, and a
huge slice of UDP traffic (via DTLS and QUIC's TLS-1.3 inner
handshake) rides on TLS 1.3. **Collateral cost of a wholesale
block is critical** — banking, e-commerce, government services,
software updates, employee remote access, the entire SaaS
economy stop working. Censors therefore attack TLS surgically
(SNI extraction, JA3/JA4 fingerprinting, FET on post-handshake
records, CA profiling) rather than wholesale-block it. This is
the textbook example of the collateral-freedom frame and the
most-mimicked cover protocol in the catalog by an order of
magnitude.

## Standardization

- **RFC 8446** (Aug 2018) — TLS 1.3 base specification. Replaced
  TLS 1.2 (RFC 5246) with a redesigned handshake (1-RTT default,
  optional 0-RTT), AEAD-only ciphers, simplified cipher-suite
  enumeration (no separate KEX / sig / cipher columns), forward
  secrecy by default.
- **RFC 8447** — IANA registry consolidation for TLS parameters.
- **RFC 8448** — example handshake traces (good debugging
  reference).
- **RFC 8449** — `record_size_limit` extension (lets a peer
  advertise a smaller-than-default record size).
- **RFC 8470** — using TLS 1.3 0-RTT data with HTTP.
- **RFC 8773** — raw-public-key authentication (alternative to
  full X.509 cert chains).
- **RFC 8879** — TLS Certificate Compression.
- **draft-ietf-tls-esni** (now **draft-ietf-tls-encrypted-client-hello**,
  "ECH") — encrypts the inner ClientHello's SNI / ALPN / inner
  certs; deployed by Cloudflare, partial Firefox, partial Chrome.
  As of 2026 still in partial deployment; the catalog should
  treat ECH as opt-in by the server, not a baseline.

Working group: **IETF TLS WG**. Most-active since the late
1990s; the WG essentially defines what "encrypted" means on
the modern Internet.

## Wire Format

Per RFC 8446 §5 (record layer) and §4 (handshake protocol).

### Record layer

Each TLS record on the wire:

```
+--------+---------+--------+--------------------+
| 1 B    | 2 B     | 2 B    | length bytes       |
| type   | version | length | payload (encrypted |
|        | (0x0303 |        |  except handshake  |
|        |  legacy |        |  records before    |
|        |  marker)|        |  Finished)         |
+--------+---------+--------+--------------------+
```

`type`:
- `0x16` Handshake (visible up to ServerHello, then encrypted)
- `0x17` ApplicationData (always encrypted)
- `0x14` ChangeCipherSpec (legacy compat, ignored in TLS 1.3 logic)
- `0x15` Alert (encrypted post-handshake)

Note: RFC 8446 specifies the version field on the wire is
**always `0x0303`** ("legacy_record_version"), regardless of
which TLS version is actually negotiated. The real version is
inside the handshake's `supported_versions` extension.

### ClientHello (the part DPI cares about most)

Per §4.1.2:

```
[2B legacy_version = 0x0303]
[32B random]
[1B legacy_session_id length] [up to 32B legacy_session_id]
[2B cipher_suites length] [N×2B cipher suites]
[1B legacy_compression_methods length] [N×1B compression methods]
[2B extensions length] [extensions...]
```

Notable extensions whose presence / order is JA3 / JA4-relevant:

- `server_name` (SNI) — usually plaintext; encrypted only with
  ECH.
- `supported_versions` — contains the actual TLS version (0x0304
  for TLS 1.3).
- `key_share` — ephemeral ECDHE keys for the post-quantum
  X25519MLKEM768 hybrid or the classic X25519 / secp256r1.
- `signature_algorithms` — ordered list defining server-cert
  validation preferences.
- `application_layer_protocol_negotiation` (ALPN) — `h2` /
  `http/1.1` / `h3-29` etc.
- `pre_shared_key` (resumption / 0-RTT).
- `padding`, `record_size_limit`, `extended_master_secret`.

### Handshake summary

```
Client                                 Server
  ClientHello -------------------->
  (key_share, ...)
                                    <-- ServerHello
                                        (key_share, ...)
                                        EncryptedExtensions
                                        Certificate*
                                        CertificateVerify*
                                        Finished
                                        [Application Data*]
  Finished        -->
  Application Data <-> Application Data
```

The unencrypted span is **everything from byte 0 of ClientHello
through the start of EncryptedExtensions on the server side**.
After that, all handshake records are encrypted under the
handshake-traffic key derived from ECDHE.

### Post-quantum: X25519MLKEM768

Recent (2024-2026) deployment: `key_share` carries an X25519
share concatenated with an ML-KEM-768 (Kyber) share, both
contributing to the shared secret. Deployed by Cloudflare /
Chrome / Firefox in production. Mimics targeting the cover
protocol post-2024 should pick whichever variant the cover
implementation actually sends — different fingerprint than
classic X25519-only.

## Traffic Patterns

- **Handshake**: 1-RTT typical (ClientHello → ServerHello-and-rest →
  Finished). 0-RTT mode shaves a round trip but is not the default.
- **First flight is small** (~512-2048 byte ClientHello, depending
  on extensions and post-quantum).
- **Server flight in record fragments**: cert chain can push
  the response to several KB, sometimes split across multiple TCP
  segments / records — RFC 8879's certificate-compression and
  RFC 8773's raw-public-keys both shrink this.
- **Steady state**: bidirectional ApplicationData records, sized
  ≤ negotiated `max_fragment_length` (default 16384). Real
  browsers tend to coalesce small writes; many server stacks
  flush more aggressively. Different timing / size profiles per
  implementation are themselves fingerprintable.
- **Long-lived connections** under HTTP/2 multiplexing: one TLS
  session can carry hundreds of HTTP/2 streams over hours.
  Different shape from HTTP/1.1's many-short-connection pattern.

## Encryption Surface

| Layer | Visible | Encrypted |
| --- | --- | --- |
| TCP/IP | client IP, server IP, port pair, TCP flags | n/a |
| TLS record header | content type, legacy version, record length per record | n/a |
| ClientHello | full message (without ECH); inner CH fields encrypted to outer "GREASEy" CH (with ECH) | inner CH (ECH-only) |
| ServerHello | full message (selected version + cipher suite, server_random, session_id_echo, key_share) | n/a |
| EncryptedExtensions onward | Certificate + CertificateVerify + Finished sizes (record-length leaks) | message contents |
| ApplicationData | record sizes + timing | record contents |

ECH (when deployed) closes the SNI / ALPN / inner-Certificate
visibility on the **inner** ClientHello but the **outer** CH still
exists with its own SNI (the cover-domain). Visible ALPN on the
outer CH is whatever the ECH config specifies.

## Common Implementations

| Stack | Vendor | Scope |
| --- | --- | --- |
| BoringSSL | Google | Chrome, Android system TLS, gRPC, much of Google's server fleet |
| NSS | Mozilla | Firefox |
| Schannel | Microsoft | Windows-native TLS — Edge, IE, Office, Windows network APIs |
| Secure Transport / Network.framework | Apple | Safari, macOS / iOS system TLS |
| OpenSSL | OpenSSL Foundation | The de-facto Linux-server library — nginx, HAProxy, OpenSSH, OpenVPN, much of Apache |
| LibreSSL | OpenBSD | OpenBSD-derived hardened fork of OpenSSL |
| rustls | Rustls / ISRG | Increasingly the new-default for Rust + Go-via-cgo replacement of OpenSSL; Cloudflare ships it |
| Go `crypto/tls` | Go Project | Caddy, the bulk of Go HTTP / RPC servers, lantern-box on the proxy side |
| Java JSSE | OpenJDK / vendor JDKs | Java app servers, Android system-side |

JA3 / JA4 fingerprint diversity in the wild is therefore high
across these — but real **client** traffic concentrates heavily
in BoringSSL (Chrome+Android+much of Google), NSS (Firefox),
and Schannel (Windows / Office). Mimicking the long-tail
implementations rarely buys cover; mimicking the dominant ones
demands per-release fingerprint freshness.

## Prevalence

- HTTPS ≈ overwhelming majority of all bytes on the public
  Internet by 2026. Cloudflare Radar consistently reports
  >95% of HTTPS traffic on TLS 1.3 across the past several
  years.
- Encrypted DNS (DoH, RFC 8484) rides on TLS 1.3 — Chrome,
  Firefox, Safari, and several major OS resolvers default to
  DoH for upstream queries.
- QUIC (RFC 9000) carries a TLS 1.3 inner handshake; HTTP/3
  (RFC 9114) traffic is therefore TLS-1.3 traffic at the
  cryptographic layer even though the wire is UDP.
- DTLS 1.3 (RFC 9147) reuses TLS 1.3's handshake and AEAD
  framing in datagram form; WebRTC, IKEv2, and SIP TLS sessions
  draw from this layer.

A cleanly-blocked-everywhere TLS 1.3 is nowhere — the protocol
is the substrate of the modern Internet, full stop.

## Collateral Cost

**Critical.** A wholesale block of TLS 1.3 implies blocking:

- Online banking and payment-processor backends (every PCI-DSS
  compliant pipe).
- E-commerce: every checkout flow.
- Cloud-based productivity (Microsoft 365, Google Workspace,
  Salesforce, Slack, Notion, every SaaS).
- Software updates: macOS / iOS / Windows / Android / Linux
  package signing, Chrome / Firefox auto-update.
- Government services that have moved online.
- Most outbound email through SMTPS / IMAPS.
- Modern API integrations between any two business systems.
- Domestic economy's own digital infrastructure: virtually no
  national censor wholesale-blocks the country's own banks
  from each other.

In practice, even the most aggressive censors (GFW, TSPU,
Iran's filter) attack TLS by **selective inspection**, not
wholesale block. China's 2012 real-name VPN registration law
(documented in `2013-robinson-collateral`) is the policy-level
attempt to maintain the corporate / consumer split that
collateral freedom would otherwise erase — let business TLS
flow, segment-and-block consumer TLS-tunneling.

The censor's selective attacks are the actual operating
constraint:

- **SNI extraction** to apply domain-level allow / deny lists
  (USENIX Security 2025: GFW SNI inspection at 100Gbps scale).
- **JA3 / JA4 fingerprinting** to flag "non-browser" TLS clients.
- **Fully encrypted traffic detection** on post-handshake records
  for protocols that are essentially TLS-shaped but not real
  TLS — and on inner-TLS-over-outer-TLS structural signatures.
- **Certificate / CA profiling** — flagging Let's Encrypt-
  issued certs on small server-IPs as proxy candidates.
- **Active probing** of TLS endpoints — replaying ClientHellos,
  sending Trojan-style auth headers, observing the response.

These are the surfaces a mimic has to reproduce.

## Common Ports & Collateral Cost

Wire-shape mimicry is one collateral-freedom axis; **port choice is a
separate one**. A TLS-shaped circumvention service running on a port
other than 443 inherits the collateral-cost properties of whatever
high-value service is canonical on that port — censors who try to
block by port hit the cover service first.

| Port | Cover service | What blocks if a censor wholesale-drops the port |
| --- | --- | --- |
| **443** | HTTPS / HTTP/3 | The Internet |
| **853** | DNS-over-TLS (DoT) | Encrypted DNS for Android Private DNS, several OS-default resolvers; clients fall back to plaintext or DoH |
| **993** | IMAPS | Inbound mail clients globally — Outlook, Apple Mail, Thunderbird, every mobile mail app |
| **995** | POP3S | Inbound POP3; smaller user base, mostly legacy enterprise |
| **587** | Submission with STARTTLS | Outbound mail from clients — the dominant submission port |
| **465** | SMTPS (implicit TLS submission) | Outbound mail from clients (alternative to 587) |
| **636** | LDAPS | Active Directory binds, virtually every SSO / Group-Policy refresh in any AD environment |
| **5061** | SIPS | Microsoft Teams Phone (~80M users), Zoom Phone, every IP-PBX, every carrier SIP trunk |
| **5223** | Apple APNS | The persistent push channel every iOS / macOS / iPadOS / watchOS device keeps open 24/7 — blocking 5223 disables push notifications globally for the Apple device population |
| **2083** | RadSec | Eduroam global Wi-Fi roaming federation (~10,000 institutions in 100+ countries); WBA OpenRoaming carrier consortium |
| **8883** | MQTTS | AWS IoT Core, Azure IoT Hub, HiveMQ, Tesla vehicle telemetry, IIoT brokers |
| **8443** | alt-HTTPS / management consoles | Most enterprise admin UIs (Cisco, VMware, Citrix NetScaler / Gateway, Horizon, BIG-IP, Splunk) |
| **2087, 2096** | cPanel WHM / webmail | Mass-market web-hosting control panels |
| **4843** | OPC UA over HTTPS | Industrial-automation cloud profiles (factory floors → cloud analytics) |
| **5671** | AMQPS | Enterprise event-driven backbones (RabbitMQ, IBM MQ, Azure Service Bus, AWS Amazon MQ) |

The censor's calculus differs per port. Port 443 is essentially
unblockable; port 5223 is unblockable for any economy where iPhones
are deployed; port 5061 is unblockable wherever knowledge-worker
voice calling happens. The long-tail ports (cPanel, Splunk admin)
have lower individual collateral but blocking enterprise admin
ports tends to be politically visible because IT staff notice
immediately.

A circumvention design choosing a port has therefore three knobs:

1. **Generic high-volume cover** (443) — best wire-anonymity, but the
   single most-fingerprinted port on the Internet.
2. **Targeted high-value cover** (5061, 5223, 8883, 636, ...) —
   smaller traffic baseline so the design must look behaviorally
   plausible (real SIPS handshake patterns, real APNS keepalive
   timings, real LDAP search rates), but the censor's per-port
   collateral cost is much sharper.
3. **Off-port mimicry** (running TLS-shaped traffic on an
   unconventional port) — fragile; censors cheaply block
   unfamiliar destinations first. Don't.

The bullet (2) targeted-port strategy is under-explored relative
to (1) generic-443 strategies in the existing circumvention
catalog — none of the entries currently in `circumvention-protocols`
use port-targeting as their collateral-freedom story.

## Mimicry Considerations

The hardest things about convincing TLS 1.3 mimicry:

1. **JA3 / JA4 fingerprint freshness.** Browser TLS stacks roll
   forward continuously — extension order, GREASE values,
   supported groups, signature algorithms all drift release to
   release. uTLS-based mimicry has to track these explicitly;
   "match Chrome from a year ago" is a fingerprint that doesn't
   match current Chrome.
2. **Post-quantum hybrid key-share** (X25519MLKEM768) is now
   default in production Chrome / Cloudflare. Mimics that ship
   only the classic X25519 share are anachronistic against
   contemporary cover. Mimics that ship the hybrid have to
   implement the actual ML-KEM math (the public-key bytes are
   verifiable against the math; you can't fake-pad it).
3. **ECH is real but partial.** A mimic that ships ECH support
   has to match an ECH-using server / client population. A
   mimic that doesn't is consistent with the majority of cover
   traffic but anachronistic relative to a Cloudflare-fronted
   tail. Either choice is defensible; conflating them inside one
   deployment is not.
4. **Certificate authentication** — a real TLS server presents a
   real cert chain. A mimic either (a) terminates TLS itself
   with a real cert (Trojan, naiveproxy), (b) relays a real
   TLS handshake to a real cover server (REALITY, tlsmasq), or
   (c) forges an in-handshake-derived ephemeral cert (REALITY's
   inner path). Each choice has trade-offs; "no cert at all" is
   not an option for credible mimicry.
5. **Behavioral patterns of cert chains and record sizes.** Real
   server cert chains are usually 2-4 certs and sized 2-6 KB.
   Real ApplicationData records bunch around HTTP-2-frame-aligned
   sizes, not arbitrary lengths. A mimic that emits suspiciously
   small or suspiciously huge records is detectable on the
   record-size histogram.
6. **CT log audit trail.** Every server cert issued by a public
   CA is logged in Certificate Transparency. A mimic that owns
   a cert leaves a permanent audit trail in CT — a censor that
   periodically scans CT for "small / new / low-traffic
   domains" can build candidate proxy lists. REALITY's
   relay-the-real-handshake design avoids this; Trojan's
   own-the-cert design doesn't.
7. **MTU / packet-size leakage on QUIC and DTLS.** When TLS 1.3
   rides over UDP (QUIC, DTLS), the path MTU constrains record
   sizes, which leaks information about the underlying network
   even when the records are encrypted.

## Censor Practice

History (selective; not exhaustive):

- **2012 onward — GFW** does SNI extraction and selective
  domain-blocking; TLS itself is never wholesale-blocked.
- **2015 — China** real-name VPN registration law passes,
  designed to segment consumer-VPN TLS from business-VPN TLS
  (per `2013-robinson-collateral`).
- **2018 — Iran / Russia** experiments with TLS-version-
  blocking; rolled back after collateral damage to commerce.
- **2022 — GFW** deploys fully-encrypted-traffic detection in
  production (USENIX Security 2023 paper documents the
  classifier as deployed since at least early 2022).
- **2023 — TSPU / Russia** rolls out TLS-fingerprint-based
  blocking against specific JA3 fingerprints associated with
  circumvention tools.
- **2024-2025 — GFW** SNI extraction at 100Gbps scale (USENIX
  Security 2025).
- **2025-2026 — partial deployment of ECH-blocking** — early
  experiments in several censor jurisdictions, by classifying
  any ClientHello with the ECH extension as suspicious. As of
  2026 not yet a deployed wholesale block.

Throughout, the wholesale-block-TLS scenario has not happened
anywhere. The censor's strategy is to attack the cover from
inside (visible-surface inspection) rather than from outside
(blocking the protocol).

## Used as Cover By

(Catalog cross-references intentionally not populated yet —
this catalog is being built as a *survey of cover candidates*,
independent of the existing circumvention-protocol catalog.
The cross-reference field will be filled in when there's a
deliberate decision to wire the two together.)

## Cross-References

- Public corpus: `2013-robinson-collateral` (the source of the
  collateral-freedom frame). Also relevant for TLS-related
  measurement: `2023-niere-poster` (TLS record fragmentation
  for SNI evasion).
- Sibling cover protocols (when added):
  - **(TBD) cover-quic** — TLS 1.3 over UDP via QUIC. Same
    cryptography, very different wire shape; many of the
    fingerprinting concerns above transpose with twists.
  - **(TBD) cover-doh** — DNS-over-HTTPS; rides on TLS 1.3.
    Browser-default since 2020-ish. The DNS layer's collateral
    cost is its own story.
  - **(TBD) cover-dtls** — TLS-1.3-derived datagram protocol;
    WebRTC's transport. The pion-DTLS-fingerprint attack of
    March 2026 is a TLS-1.3-family event.
- Internal docs (TBD): `2026-04-non-protocol-evasion`'s discussion
  of TLS-side hardening recommendations is the right Lantern-
  internal cross-link.
