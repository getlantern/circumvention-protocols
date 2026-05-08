# Oblivious HTTP (OHTTP)

## TL;DR

Two-hop privacy-preserving HTTP transport. RFC 9458 (Jan 2024).
A client HPKE-encapsulates an HTTP request using a target
gateway's published public key, POSTs the encrypted blob to a
**relay** over normal HTTPS, and the relay forwards to the
**gateway** for decryption + processing + reply. Relay sees the
client IP but never decrypts; gateway decrypts but never learns
the IP. **Wire is generic HTTPS to a passive on-path observer**,
but several discriminators differentiate it from arbitrary HTTPS
to a TLS-decrypting DPI: the `message/ohttp-req` / `message/ohttp-res`
content-types, HPKE-encapsulated bodies with uniform-random
entropy distributions distinct from typical JSON / protobuf API
shapes, two-hop fanout patterns, and a small canonical set of
production relay hostnames. **The collateral cost story is who
runs the relays** — Apple Private Cloud Compute, WhatsApp Private
Processing, Chrome Safe Browsing, Mozilla telemetry, Cloudflare
Privacy Gateway, ISRG.

## Standardization

- **RFC 9458** (Jan 2024, Standards Track) — *Oblivious HTTP*. The
  core spec. Authors: Mozilla + Cloudflare + Apple.
- **RFC 9540** (Feb 2024, Standards Track) — *Discovery of
  Oblivious Services via Service Binding Records*. Defines the
  `ohttpgw` SvcParamKey for SVCB / HTTPS DNS records.
- **RFC 9614** (Jul 2024) — *Partitioning as an Architecture for
  Privacy*. Architectural framing document for the OHTTP / MASQUE /
  ECH / ODoH family — the broader IETF "split the trust between
  endpoint and identity" theme.
- **RFC 9180** (Feb 2022) — *Hybrid Public Key Encryption (HPKE)*.
  The cryptographic primitive OHTTP encapsulates with. Default
  suite: X25519 + HKDF-SHA256 + AES-128-GCM (DHKEM_X25519_HKDF_SHA256
  / HKDF-SHA256 / AES-128-GCM).
- Working group: `ohai` (Oblivious HTTP Application Intermediation),
  IETF Security Area.

In progress as of 2026:

- `draft-ietf-ohai-ohttp-pq` — post-quantum HPKE for OHTTP.
- `draft-ietf-ohai-chunked-ohttp` — streaming responses (large
  payloads delivered as a sequence of HPKE-sealed chunks).

## Wire Format

```
                               TLS 1.3                   TLS 1.3
   Client  ────────────────────►  Relay  ──────────────────►  Gateway  ───►  Origin
            POST /ohttp                    POST /…/encapsulate
            Content-Type:                  Content-Type:
              message/ohttp-req              message/ohttp-req
            Body: HPKE(req)                Body: HPKE(req)         (decrypted; decrypts
                                                                    request, runs origin
                                                                    HTTP, encrypts response)
            ◄────────────────────  Relay  ◄────────────────────  Gateway
            HTTP/200                       HTTP/200
            Content-Type:                  Content-Type:
              message/ohttp-res              message/ohttp-res
            Body: HPKE(resp)               Body: HPKE(resp)
```

Two TLS hops, both regular HTTPS (and increasingly HTTP/3 — see
[`cover-quic`](cover-quic.md)). The headers visible
*post-TLS* on each hop:

```
POST /ohttp HTTP/1.1
Host: relay.example.com
Content-Type: message/ohttp-req
Accept: message/ohttp-res
Content-Length: <bytes>

[binary HPKE encapsulation per RFC 9458 §4]
```

The HPKE encapsulation in the body has the format (RFC 9458 §4.1):

```
Encapsulated Request {
    Key Identifier (8),                    // identifies (KEM, KDF, AEAD) suite
    HPKE KEM Identifier (16),
    HPKE KDF Identifier (16),
    HPKE AEAD Identifier (16),
    Encapsulated KEM Shared Secret (Nenc * 8),
    HPKE-Protected Request (..),
}
```

For the default suite (X25519 + SHA-256 + AES-128-GCM):

- 1 byte Key ID
- 2+2+2 bytes for KEM/KDF/AEAD identifiers (0x0020, 0x0001, 0x0001)
- 32 bytes encapsulated X25519 public key
- variable-length AEAD-sealed inner request

So the body is **at minimum 39 bytes of header + the inner
request size + 16 bytes of AEAD tag**. The inner request itself is
binary HTTP (RFC 9292) — a compact framing distinct from text-form
HTTP.

The **gateway-side** unwraps, runs the inner HTTP request (against
its own configured origin), and seals the response under the
ephemeral key from the request. Symmetric on the way back.

### Gateway discovery (RFC 9540)

A client learns where to find a gateway via DNS:

```
example.com.   3600   IN   HTTPS   1 . alpn=h2 ohttpgw=https://relay.example/ohttp
```

The `ohttpgw=` SvcParamKey carries the relay URL. Discovery is
**observable in plaintext DNS** unless DoH/DoT is used; censors
that strip / rewrite SVCB records can break the discovery layer
without touching the data plane.

## Traffic Patterns

- **Per-request connections** are common. A client typically opens
  a TLS connection to the relay, POSTs the encrypted request,
  reads the response, and closes (or pools the connection across
  multiple requests). The session-lifetime profile is more like
  short-lived API calls than long-lived browsing.
- **Two-hop fanout**: from the relay's perspective, each incoming
  client request triggers an outgoing request to the gateway.
  Observable from a vantage point that sees both legs (e.g. a
  hosting provider running the relay, or a censor on the relay's
  upstream link).
- **Body sizes** cluster around the underlying inner-request
  sizes plus HPKE overhead (~39B + 16B AEAD tag). Telemetry-style
  use (Mozilla, WhatsApp Private Processing) sends small bodies
  (~hundreds of bytes); ML-inference use (Apple Intelligence)
  sends larger ones (KBs).
- **No persistent state at the relay**: relays don't keep per-
  client state, so a client's request volume to a relay produces
  a flat-uniform request distribution rather than browser-style
  bursty patterns.

## Encryption Surface

| Layer | Visible | Encrypted |
| --- | --- | --- |
| IP / TCP-or-UDP | client IP, relay IP, port pair | n/a |
| TLS 1.3 (outer) | SNI of relay (unless ECH is on), JA3/JA4-equivalent fingerprint, record-size + timing | the entire HTTP request including content-type and body |
| HTTP request to relay | (post-TLS only) method, path, Host header, Content-Type, Accept, body length | inner HTTP request itself, which is HPKE-sealed |
| HPKE encapsulation | (post-decrypt) HPKE suite identifiers, encapsulated KEM share | inner HTTP request method, path, headers, body |
| Relay → Gateway leg | (to anyone observing the relay's egress) gateway IP, gateway TLS SNI, body size | HPKE-sealed body forwards verbatim |

The discriminator a censor would ideally match on is the
**Content-Type `message/ohttp-req`** in the HTTP request line,
which is **only visible if the censor terminates / decrypts TLS**.
For a **passive on-path** observer with no TLS-MITM capability,
OHTTP and arbitrary HTTPS POST traffic are wire-indistinguishable.

A censor with TLS-MITM (e.g. a corporate network with installed
CA, or a state-level adversary with mass TLS-interception
infrastructure) can match on Content-Type and block trivially.

## Common Implementations

| Stack | Vendor | Scope |
| --- | --- | --- |
| swift-nio-oblivious-http | Apple | Private Cloud Compute, Apple Intelligence request path, Enhanced Visual Search (Photos, 2025) |
| ohttp (Rust) | Cloudflare | Privacy Gateway — first commercial OHTTP relay (2022). Used by Flo Anonymous Mode and as relay hop for Apple PCC |
| Fastly OHTTP relay | Fastly (open source) | Mozilla Firefox telemetry (Oct 2023), Google Privacy Sandbox FLEDGE *k*-anonymity, Google Chrome Safe Browsing real-time URL checks (Mar 2024), Meta WhatsApp Private Processing (Apr 2025) |
| bhttp + ohttp Rust crates | Mozilla | Firefox telemetry client side |
| Divvi Up OHTTP gateway | ISRG | ISRG-operated OHTTP gateway service for privacy-preserving telemetry |
| Google's relay impl | Google | Privacy Sandbox internal infrastructure |

The implementation set is small (handful of vendors) but each
implementation carries massive scale through its operator:
Apple PCC alone routes a substantial fraction of Apple Intelligence
requests; Chrome Safe Browsing is a default-on Chrome feature for
billions of Chrome installs.

## Prevalence

OHTTP traffic volume is hard to measure precisely (because it's
indistinguishable from generic HTTPS to public measurement points),
but the **deployment claims** are substantial:

- **Apple Private Cloud Compute** — every Apple Intelligence
  request from iOS 18 / macOS Sequoia onward when the device
  decides server-side compute is needed. Two-hop via Cloudflare
  and Fastly relays.
- **Apple Photos Enhanced Visual Search** (Dec 2024 / 2025) —
  per-photo OHTTP request when the feature performs landmark /
  scene recognition. Default-on in iOS / macOS.
- **Google Chrome Safe Browsing real-time URL checks** — since
  March 2024, default for users not opted out. Every URL-check
  query rides OHTTP through a Fastly relay.
- **Mozilla Firefox telemetry** — since October 2023, Firefox
  ships its telemetry pings via OHTTP through Fastly's relay.
- **Meta WhatsApp Private Processing** — since April 2025, certain
  AI / contextual features in WhatsApp route via OHTTP through
  Fastly.
- **Cloudflare Privacy Gateway** — multi-tenant relay; published
  customers include Flo (period tracker), enterprise privacy
  startups, several research projects.
- **Google Privacy Sandbox FLEDGE / Topics k-anonymity service** —
  via Fastly OHTTP relay, since 2023.

Aggregate request volume is substantial — billions of OHTTP
requests per day across these deployments.

## Collateral Cost

**High, and concentrated in a small list of identifiable relays.**

Wholesale-blocking OHTTP requires either:

1. **Identifying OHTTP traffic by Content-Type** — needs TLS
   termination / DPI-with-decryption. Most state-level adversaries
   don't do this at population scale, though some do for specific
   endpoints.
2. **Blocking the relay hostnames** — works because the production
   relay set is small and well-known:
   - Cloudflare Privacy Gateway (a Cloudflare subdomain)
   - Fastly's `ohttp-relay.fastly.net` (Mozilla / Google / Meta
     all use this)
   - Apple-controlled relay hostnames (within iCloud / Apple
     domains)
   - Divvi Up gateway

   Blocking these takes out: Apple Intelligence, WhatsApp Private
   Processing, Chrome Safe Browsing, Firefox telemetry, FLEDGE
   *k*-anonymity, several smaller services. The visible-product-
   breakage list is large.

3. **Identifying OHTTP traffic by body-entropy heuristic** —
   possible but high false-positive rate. HPKE-encapsulated
   bodies are uniform-random; so are TLS-resumption-derived
   tickets, encrypted file uploads, and most encrypted-content
   bodies. False positives crash legitimate API traffic.

The censor's blocking-cost calculation:

- Cost (1) is high because the censor must run TLS-decrypting
  DPI everywhere.
- Cost (2) is moderate but produces visible product failures
  Apple, Google, Mozilla, and Meta will all notice and react to.
- Cost (3) is low to deploy but high in collateral false
  positives.

In practice, the most-likely censor strategy is endpoint-blocking
specific relay hostnames after observing widespread use. **No
major censor has wholesale-blocked OHTTP as of 2026**; selective
blocks of specific relays have been observed in some contexts
(e.g. Privacy-Gateway-blocked corporate networks for specific
compliance reasons, not state-level censorship).

## Common Ports & Collateral Cost

OHTTP runs over HTTP, so its port story is identical to
[`cover-tls-1-3`](cover-tls-1-3.md) and increasingly to
[`cover-quic`](cover-quic.md):

| Port | Cover service | Collateral of port-block |
| --- | --- | --- |
| **TCP/443** | OHTTP over HTTPS (default for all current deployments) | Generic HTTPS / TCP-Internet — see TLS entry |
| **UDP/443** | OHTTP over HTTP/3 (rolling out at Apple, Cloudflare) | Generic HTTP/3 / QUIC — see QUIC entry |

OHTTP doesn't introduce its own port. Port-as-cover for OHTTP
collapses into the underlying transport's port story.

## Mimicry Considerations

A circumvention design that mimics OHTTP gets unusually clean
cover because of the heavyweight architecture:

1. **Two-hop deployment is the mimicry tax**. To look credibly
   like OHTTP, a circumvention service needs **a relay** (IP-
   stripping front) **and** **a gateway** (HPKE-decrypting
   back). The single-hop deployments common in existing
   circumvention designs are not OHTTP-shaped.
2. **HPKE is mandatory and gives the body shape**. Bodies must
   be uniform-random (HPKE ciphertext) at the right minimum
   sizes (~39B header + AEAD tag). A mimic carrying JSON or
   protobuf in cleartext is not OHTTP.
3. **Content-Type discipline**. Relay-side requests must carry
   `Content-Type: message/ohttp-req` and accept `message/ohttp-res`.
   Generic POST without the content-type signature is not OHTTP
   to a TLS-decrypting DPI.
4. **Discovery via SVCB is the natural deployment story**. A
   well-formed OHTTP service publishes an `ohttpgw` SvcParamKey
   in its DNS; a circumvention design that doesn't publish
   discovery looks like an out-of-band-configured private OHTTP
   service (which exists, but isn't the headline pattern).
5. **Behavioral plausibility**. OHTTP traffic patterns are
   request-response with no long-lived state at the relay. A
   mimic carrying long-lived multiplexed proxy traffic violates
   that profile.
6. **Relay fronting via known CDN hostnames** strengthens the
   cover dramatically — running a relay at a Cloudflare /
   Fastly-style domain inherits the production-relay hostname
   set's collateral cost. Self-hosting on a small-IP, low-traffic
   domain is much weaker cover.
7. **The content-type signature is a load-bearing fingerprint**.
   A censor's cheapest detection is matching `Content-Type:
   message/ohttp-req` post-TLS. Mimics that get DPI'd by such a
   censor either need to actually be OHTTP (full HPKE round-
   tripping with a real gateway) or hide inside a lower-layer
   cover (run inside generic HTTPS, which loses the OHTTP
   collateral story).

The first three points compose into a meaningful design
constraint: an OHTTP-mimicking circumvention service is a
**federation of relay-and-gateway pairs**, where each relay-IP
strips client identity and forwards to a gateway-IP that
HPKE-decrypts. That's an architecturally novel deployment for
circumvention compared to most catalog entries.

## Censor Practice

History (selective; OHTTP is recent enough that the deployment
record is short):

- **2024-2025 — corporate / compliance environments** sometimes
  block specific relay hostnames (e.g. Apple PCC relay) for
  compliance reasons; not state-level censorship but
  fingerprinted as "blocking specific OHTTP services."
- **No state-level wholesale OHTTP block** as of mid-2026.
- **Iran (briefly, 2025)** — observed selective blocks of
  Cloudflare Privacy Gateway endpoints during specific
  geopolitical events; reverted.
- **Russia (TSPU)** — has blocked certain Apple iCloud subdomains
  at various points; this hits MASQUE-via-iCloud-Private-Relay
  and OHTTP-via-iCloud-PCC simultaneously, but the public framing
  has been "blocking iCloud" not "blocking OHTTP."

The pattern that's emerging: censors that move against OHTTP
move against **specific relay hostnames** (cheap to identify, low
DPI cost) and accept the visible-product-breakage. As the relay
set grows beyond the current handful (Apple, Cloudflare, Fastly,
Mozilla, ISRG, Google) the whack-a-mole math gets worse for
censors.

## Used as Cover By

(Catalog cross-references intentionally not populated yet — the
cover catalog is a survey of mimicry candidates, not a back-
reference index of existing circumvention designs.)

The headline application-layer protocols that **ride inside**
OHTTP today:

- **Apple Private Cloud Compute** — Apple Intelligence, Photos
  Enhanced Visual Search.
- **Chrome Safe Browsing** real-time URL checks.
- **Mozilla Firefox telemetry**.
- **Google Privacy Sandbox** FLEDGE / Topics *k*-anonymity.
- **Meta WhatsApp Private Processing**.
- **Flo (period tracker)** Anonymous Mode.

These are **applications running over OHTTP**, not separate cover
protocols — they all subsume to this entry by the wire-distinctness
test.

## Cross-References

- Sibling cover protocols: [`cover-tls-1-3`](cover-tls-1-3.md)
  (the outer hop's transport), [`cover-quic`](cover-quic.md)
  (when OHTTP runs over HTTP/3 — increasingly).
- (Not yet in catalog) [`cover-dtls`](cover-dtls.md) — the
  WebRTC family is unrelated; OHTTP is HTTP-shaped end to end.
- Public corpus: no OHTTP-specific paper in the corpus as of
  writing; HPKE itself (RFC 9180) and the privacy-partitioning
  framing (RFC 9614) are the key reading.
- Internal docs (TBD): worth tracking when Lantern internal
  notes on OHTTP-style two-hop architecture land.
