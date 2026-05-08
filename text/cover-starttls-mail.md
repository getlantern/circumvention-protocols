# STARTTLS — SMTP / IMAP / POP3

## TL;DR

The mail STARTTLS family — SMTP STARTTLS (RFC 3207),
IMAP STARTTLS (RFC 2595 / 9051), and POP3 STLS (RFC 2595).
One umbrella entry because all three share the cover
shape: cleartext ASCII line-protocol prelude on a fixed
port (TCP/25 SMTP relay, TCP/587 SMTP submission, TCP/143
IMAP, TCP/110 POP3), capability advertisement, client
sends `STARTTLS` / `STLS`, server acks, then **inline TLS
handshake on the same TCP connection**. **Wire-distinct
from generic TLS** — a cleartext `220 ESMTP` / `* OK` /
`+OK` banner before the TLS handshake is unmistakably mail.
**Critical collateral cost** — email is fundamental; no
censor in 2026 wholesale-blocks the standard mail ports.
Implicit-TLS siblings (TCP/465 SMTPS, TCP/993 IMAPS,
TCP/995 POP3S) subsume to [`cover-tls-1-3`](cover-tls-1-3.md)
and are out of scope for this entry. **Cover candidacy**:
underutilized; gives a circumvention mimic a different
wire shape than plain TLS with even higher collateral
protection than RDP.

## Standardization

Mail core specs:

- **RFC 5321** (Oct 2008) — *Simple Mail Transfer Protocol*.
  The current SMTP base spec (obsoletes RFC 2821 / 821).
- **RFC 6409** (Nov 2011) — *Message Submission for Mail*.
  Defines TCP/587 as the canonical client-to-MSA submission
  port.
- **RFC 9051** (Aug 2021) — *Internet Message Access
  Protocol — Version 4rev2*. Current IMAP base spec
  (obsoletes RFC 3501).
- **RFC 1939** (May 1996) — *POP3*. Stable spec.

STARTTLS specs:

- **RFC 3207** (Feb 2002) — *SMTP Service Extension for
  Secure SMTP over Transport Layer Security*. The SMTP
  STARTTLS spec.
- **RFC 2595** (Jun 1999) — *Using TLS with IMAP, POP3 and
  ACAP*. Defines IMAP STARTTLS and POP3 STLS.
- **RFC 7817** (Mar 2016) — *Updated Transport Layer
  Security (TLS) Server Identity Check Procedure for Email-
  Related Protocols*. Updated cert-validation expectations.
- **RFC 8314** (Jan 2018) — *Cleartext Considered Obsolete:
  Use of Transport Layer Security (TLS) for Email
  Submission and Access*. **Recommends implicit-TLS over
  STARTTLS for new MUA deployments**, but explicitly does
  not deprecate STARTTLS — the existing deployment
  remains. This is the deployment-trend driver.

MTA-to-MTA TLS enforcement (relevant to TCP/25 cover):

- **RFC 8461** (Sep 2018) — *SMTP MTA Strict Transport
  Security (MTA-STS)*. HTTPS-published TXT records that
  let an MTA promise TLS-required to its peers. Major
  providers (Gmail, Microsoft, Yahoo, Mailgun, SendGrid)
  publish MTA-STS policies.
- **RFC 7672** (Oct 2015) — *DANE-SMTP*. DNSSEC-anchored
  TLSA records as an alternative to MTA-STS. Heavier
  deployment in Europe / .nl and operator-grade mail.
- **RFC 8689** (Nov 2019) — *SMTP Require TLS Option*.
  Per-message TLS-or-bounce control.

Working group: **IETF UTA** (Using TLS in Applications),
which has been the home for mail-protocol-and-TLS
guidance since the late 2010s.

## Wire Format

### SMTP STARTTLS exchange (RFC 3207, on TCP/25 or TCP/587)

```
S: 220 mail.example.com ESMTP Postfix (Debian/GNU)\r\n

C: EHLO client.example.com\r\n

S: 250-mail.example.com Hello client.example.com [203.0.113.5]\r\n
S: 250-PIPELINING\r\n
S: 250-SIZE 52428800\r\n
S: 250-VRFY\r\n
S: 250-ETRN\r\n
S: 250-STARTTLS\r\n
S: 250-ENHANCEDSTATUSCODES\r\n
S: 250-8BITMIME\r\n
S: 250 DSN\r\n

C: STARTTLS\r\n

S: 220 2.0.0 Ready to start TLS\r\n

[TLS handshake begins on the same TCP connection]

C: <TLS ClientHello>
S: <TLS ServerHello, Certificate, ...>
C: <Finished, ApplicationData...>

[Post-handshake the SMTP exchange repeats from EHLO under TLS]
C: EHLO ...
...
C: AUTH ...
C: MAIL FROM:<...>
C: RCPT TO:<...>
C: DATA
...
```

After STARTTLS, the SMTP server forgets prior state and
the client sends a fresh EHLO under TLS — RFC 3207 §4.2
explicitly requires this.

### IMAP STARTTLS (RFC 9051, on TCP/143)

```
S: * OK [CAPABILITY IMAP4rev2 SASL-IR LITERAL+ ENABLE IDLE STARTTLS LOGINDISABLED] mail.example.com IMAP4 ready\r\n

C: a001 STARTTLS\r\n

S: a001 OK Begin TLS negotiation now\r\n

[TLS handshake begins on the same TCP connection]

[Post-handshake the IMAP capability exchange typically repeats]
C: a002 CAPABILITY\r\n
S: * CAPABILITY IMAP4rev2 SASL-IR LITERAL+ ENABLE IDLE AUTH=PLAIN ...\r\n
S: a002 OK CAPABILITY completed\r\n

C: a003 LOGIN <user> <pass>\r\n
...
```

Real implementations advertise `LOGINDISABLED` before TLS
upgrade (RFC 9051 §11.1) so MUAs know auth is forbidden in
cleartext — STARTTLS is required before LOGIN.

### POP3 STLS (RFC 2595, on TCP/110)

```
S: +OK POP3 server ready\r\n

C: STLS\r\n

S: +OK Begin TLS negotiation now\r\n

[TLS handshake begins on the same TCP connection]

[Post-handshake POP3 commands]
C: USER <user>\r\n
S: +OK\r\n
C: PASS <pass>\r\n
S: +OK <mailbox>\r\n
C: STAT\r\n
...
```

POP3 doesn't have IMAP-style numbered tags or SMTP-style
status codes; it's the simplest line-protocol of the
three.

### Common structural pattern

All three share:

1. Server-first banner.
2. Cleartext capability negotiation listing STARTTLS / STLS.
3. Client-issued `STARTTLS` or `STLS` command.
4. Server-acked TLS-ready response.
5. Inline TLS handshake on the same TCP socket.
6. Post-handshake repeat of capability + auth exchange.

The byte-shape of the prelude differs across the three
(SMTP is 3-digit-numeric-coded, IMAP is tagged-line-protocol,
POP3 is `+OK`/`-ERR`-prefixed) — but the *structural*
shape is identical. This umbrella entry treats them as one
cover-population because the censor's blocking calculus
(wholesale block breaks email) applies equally.

### Implicit-TLS siblings (out of scope)

These are NOT this entry:

- **SMTPS** TCP/465 — TLS at byte 0; modern Microsoft / Gmail
  client submission default per RFC 8314
- **IMAPS** TCP/993 — TLS at byte 0
- **POP3S** TCP/995 — TLS at byte 0

They subsume to [`cover-tls-1-3`](cover-tls-1-3.md) because
their wire shape is plain TLS on a known mail port.
The wire-distinct cover candidacy here is the
**STARTTLS-prelude variants only**.

## Traffic Patterns

- **Banner exchange**: 1-3 small server-to-client lines
  immediately on TCP connect (~100-300 bytes total).
- **Capability negotiation**: a handful of small lines in
  each direction, ~few hundred bytes.
- **STARTTLS / STLS upgrade**: 2 cleartext lines (command +
  ack), then the TLS handshake bytes flow.
- **TLS handshake**: standard TLS 1.2 / 1.3 handshake.
  Modern Postfix + Dovecot + Exchange Online prefer
  TLS 1.2 (still the production majority on TCP/25 MTA-MTA
  flows in 2026 per published mail-server distros and SaaS
  defaults), with TLS 1.3 increasingly available.
- **Steady state — SMTP**: bursty bidirectional, dominated
  by message DATA bodies (kilobytes to megabytes per
  message). Sessions typically transmit 1-10 messages then
  QUIT.
- **Steady state — IMAP**: highly variable. IMAP IDLE
  sessions stay open for **tens of minutes** between
  notifications, with periodic small CAPABILITY / NOOP
  pings to keep NAT mappings alive (~every 9 minutes per
  RFC 9051 §7.1.2 guidance). FETCH / SELECT bursts size
  with mailbox content. **The long-idle nature of IMAP IDLE
  is its most distinctive behavioral fingerprint** —
  unlike most other long-lived TLS flows (HTTPS, RDP) it
  has long, near-zero-traffic gaps.
- **Steady state — POP3**: short sessions. Client connects,
  authenticates, downloads new mail (LIST + RETR loop),
  optionally DELE, then QUIT. Sessions typically last
  seconds to a minute.
- **MTA-to-MTA on TCP/25**: connections are short-lived
  per message; multiple messages may pipeline within one
  session before QUIT. Sustained traffic comes from
  high-volume relays (Gmail, Microsoft Exchange Online,
  SendGrid, Mailgun) where one TLS session on TCP/25
  carries dozens of messages over a few minutes.

For mimicry: SMTP and POP3 patterns are bursty-and-short;
IMAP IDLE is the one with the long-quiescent property.
A circumvention mimic must pick a sub-protocol whose
behavioral pattern matches its actual traffic shape.

## Encryption Surface

| Layer | Visible | Encrypted |
| --- | --- | --- |
| IP / TCP | client IP, server IP, ports | n/a |
| SMTP/IMAP/POP3 cleartext prelude | server banner (incl. server software + version), client EHLO/CAPABILITY/USER, capability list (incl. STARTTLS / STLS marker), STARTTLS / STLS command, server's TLS-ready ack | nothing — prelude is fully cleartext |
| TLS handshake (inline upgrade) | TLS ClientHello (SNI when present, ALPN, cipher suites, JA3/JA4 fingerprint), ServerHello, server cert chain | (with ECH, draft) inner SNI |
| Post-upgrade mail-protocol layer | TLS record sizes + timing | the entire post-upgrade exchange — AUTH credentials (PLAIN, LOGIN, OAUTHBEARER, GSSAPI), MAIL FROM / RCPT TO, DATA bodies, IMAP LOGIN / SELECT / FETCH / IDLE responses, POP3 USER / PASS / RETR / DELE responses, all message content + attachments |

The cleartext prelude exposes:

- **Server software + version** in the banner — Postfix
  versions, Dovecot versions, Exchange version strings,
  proprietary mail server signatures
- **Capability list** — supported AUTH mechanisms, IMAP
  extensions, SMTP extensions
- **The STARTTLS/STLS marker itself** — a censor sees the
  STARTTLS upgrade explicitly negotiated

Server cert subject is visible in the TLS handshake (no ECH
in production for mail STARTTLS as of 2026 — there is a
draft-margolis-uta-tls-ech-mail or similar in the IETF
pipeline).

## Common Implementations

| Stack | Vendor | Scope |
| --- | --- | --- |
| **Postfix** | Wietse Venema / IBM Research | Dominant open-source SMTP server. ~30%+ of Internet-exposed SMTP MTAs |
| **Exim** | Exim project | cPanel / WHM hosting bundles; large self-hosted SMTP. Big share on shared-hosting platforms |
| Sendmail | Sendmail consortium | Legacy SMTP — Unix systems, commercial mail appliances |
| **Microsoft Exchange / Exchange Online** | Microsoft | Enterprise + cloud SMTP / IMAP / EWS; hundreds of millions of mailboxes |
| **Dovecot** | Dovecot project | Dominant open-source IMAP / POP3 server. Postfix + Dovecot is the canonical Linux mail stack |
| Cyrus IMAP | CMU Cyrus project | University / ISP-scale IMAP |
| Courier-IMAP | Sam Varshavchik | Older alternative; smaller footprint |
| **Gmail** | Google | World's largest mail provider; ~1.8B accounts |
| **Outlook.com / Microsoft 365 mail** | Microsoft | Hundreds of millions of accounts; `smtp.office365.com:587` requires STARTTLS |
| **Apple iCloud Mail** | Apple | iCloud mailboxes; `smtp.mail.me.com:587` STARTTLS public endpoint |
| ProtonMail Bridge | Proton | Local STARTTLS endpoints to standard MUAs |
| **Mozilla Thunderbird** | Mozilla | Dominant open-source desktop MUA |
| **Apple Mail** (macOS / iOS) | Apple | Built-in MUA on every Mac / iPhone |
| **Microsoft Outlook** (Windows / Mac / Mobile) | Microsoft | Built-in MUA across Microsoft platforms |
| K-9 Mail / FairEmail (Android) | K-9 / FairEmail | Open-source Android MUAs |

The fingerprint diversity is **very high**:

- Server-side: Postfix vs. Exim vs. Sendmail vs. Exchange
  vs. Dovecot vs. Cyrus produce subtly different banners,
  capability lists, and TLS stacks (OpenSSL vs. GnuTLS vs.
  Schannel vs. NSS).
- Client-side: Outlook Schannel vs. Thunderbird NSS vs.
  Apple Security framework vs. Postfix relay vs. Gmail
  fetcher all have distinct ClientHello fingerprints.

A mimic that wants to look like, say, "Outlook on Windows
talking to Microsoft 365 SMTP" has a specific known-good
target fingerprint to copy. A mimic posing as "MTA-to-MTA
SMTP between Gmail and Postfix" has a different one.

## Prevalence

Email is universal:

- ~4.5B email users worldwide (Statista 2024 estimates).
- ~330B+ emails sent per day (Radicati Group, 2023).
- Gmail alone: ~1.8B accounts.
- Microsoft 365 commercial: ~400M+ paid seats (Microsoft
  earnings disclosures; consumer Outlook.com adds more).
- Apple iCloud Mail: hundreds of millions of accounts.

Port-level prevalence on the public Internet (Censys /
Shodan-style):

- TCP/25 — millions of MTAs publicly listening (every
  domain that receives email)
- TCP/587 — large public exposure for hosting providers,
  SaaS senders, ISP submission endpoints
- TCP/143 — large but shrinking; many providers have moved
  consumer MUAs to TCP/993 implicit-TLS
- TCP/110 — shrinking faster; POP3 is legacy

The **TCP/25 MTA-to-MTA traffic pattern is the most
abundant STARTTLS surface**: every email sent between
domains traverses STARTTLS-required (per MTA-STS / DANE)
SMTP between MTAs. This is sustained, high-volume,
universal traffic.

The 2026 trend — RFC 8314 implicit-TLS recommendation —
is shrinking the *consumer-MUA-to-MSA* STARTTLS surface
on TCP/143 and TCP/110, but the *MTA-to-MTA* surface on
TCP/25 remains intact and large because there is no
"implicit-TLS" deployment on TCP/25 (MTA-to-MTA always
opportunistically STARTTLSes).

## Collateral Cost

**Critical**. Email is the most fundamental Internet
service after web and DNS. A wholesale block of any of:

- TCP/25 — breaks **inbound email for every domain
  worldwide** that receives mail. Universally
  catastrophic; no censor has ever done this.
- TCP/587 — breaks **client mail submission** for every
  user using ISP / Microsoft 365 / Gmail SMTP submission.
  Effectively breaks consumer email-sending.
- TCP/143 — breaks **IMAP-based mail reading** for every
  MUA configured for STARTTLS-on-143 (still a large set;
  many self-hosted mail server deployments default this
  way).
- TCP/110 — breaks POP3 mail downloads (smaller but real
  user base, especially mobile / legacy clients).

Even a censor that's willing to break consumer mail can't
realistically break MTA-to-MTA email; that breaks
businesses' inbound email, breaks MFA password resets,
breaks every transactional notification — collateral
damage at the level of "rendering modern web services
inoperable."

The realistic block strategies censors use:

1. **TCP/25 outbound block from residential ranges** —
   universal at ISPs to prevent residential spam (this is
   operations, not censorship). Doesn't apply to data-
   center / business ranges where MTA-to-MTA happens.
2. **Destination-IP / ASN-based blocks** of specific mail
   providers known to evade local content controls (e.g.
   ProtonMail has been intermittently blocked in
   authoritarian jurisdictions).
3. **Content inspection** post-handshake (impossible
   without TLS interception, which requires the censor to
   be a CA the user trusts — a separate problem).

The cover-protection budget is **higher than RDP** — RDP
breaks Microsoft enterprise; mail breaks everything.

## Common Ports & Collateral Cost

| Port | Protocol | Collateral of port-block |
| --- | --- | --- |
| **TCP/25** | SMTP relay (MTA-to-MTA) — STARTTLS opportunistic | Critical — wholesale-blocking destroys inter-domain email |
| **TCP/587** | SMTP submission — STARTTLS-required (RFC 6409) | Critical — wholesale-blocking destroys client mail submission |
| **TCP/143** | IMAP — STARTTLS for cleartext-then-upgrade | High — many self-hosted MUAs use this; declining due to RFC 8314 |
| **TCP/110** | POP3 — STLS for cleartext-then-upgrade | Moderate-to-high — legacy but real user base |
| **TCP/465** | SMTPS (implicit TLS) | Out of scope — subsumes to [`cover-tls-1-3`](cover-tls-1-3.md) |
| **TCP/993** | IMAPS (implicit TLS) | Out of scope — same |
| **TCP/995** | POP3S (implicit TLS) | Out of scope — same |
| **non-canonical** | Some private deployments relocate STARTTLS-mail | **Strong fingerprint of circumvention** — cleartext `220 ESMTP` banner on a non-25/587 port has no legitimate cover-population |

Cover-population coupling: the wire shape and the port
go together. STARTTLS-pattern on TCP/25 has a **very large
legitimate population** (every MTA on the Internet);
STARTTLS-pattern on TCP/9999 has zero legitimate
population. As with cover-rdp, port-relocation breaks the
cover.

The **TCP/587 client submission** is probably the
strongest cover candidate from a client-running-on-a-
residential-ISP perspective: outbound from a residential
client to a public SMTP submission endpoint is normal
traffic, and the cleartext-then-STARTTLS prelude looks
like Outlook / Thunderbird / Apple Mail talking to its
configured MSA.

## Mimicry Considerations

Mimicking mail STARTTLS realistically:

1. **Banner format must match the chosen server software
   and version.** Postfix banners look different from Exim
   banners look different from Exchange banners.
   Real-world banner string examples:
   - Postfix: `220 mail.example.com ESMTP Postfix (Debian/GNU)\r\n`
   - Exim: `220 mail.example.com ESMTP Exim 4.95 ...\r\n`
   - Microsoft Exchange: `220 mail.example.com Microsoft ESMTP MAIL Service ready ...\r\n`
   - Dovecot: `* OK [CAPABILITY IMAP4rev1 SASL-IR LITERAL+ ENABLE IDLE STARTTLS LOGINDISABLED] Dovecot ready.\r\n`
   Pick one and copy a real version's banner exactly.
2. **Capability list must be coherent.** SMTP capability
   list ordering and exact extension set varies between
   servers. A capability list that mixes Postfix-only and
   Exchange-only extensions is anachronistic.
3. **Inline TLS ClientHello fingerprint must match the
   chosen client.** Outlook Schannel TLS != Thunderbird
   NSS TLS != Apple Mail Security framework TLS. Picking
   the wrong fingerprint for the asserted client is a
   tell.
4. **EHLO / CAPABILITY repeat after STARTTLS.** RFC 3207
   requires re-issuing EHLO under TLS in SMTP; RFC 9051
   recommends re-issuing CAPABILITY in IMAP. A mimic that
   skips this is anachronistic.
5. **Behavioral pattern must match the asserted protocol.**
   IMAP IDLE long-quiescence vs. SMTP message-then-QUIT
   vs. POP3 download-then-disconnect are all different.
   A mimic claiming to be IMAP but sustaining 1Mbps
   traffic for 30 minutes doesn't look like real IDLE.
6. **AUTH mechanism**: SMTP submission (TCP/587) requires
   AUTH; the censor sees the TLS-encrypted AUTH exchange
   but can fingerprint timing. A mimic that skips AUTH
   then immediately starts data is wrong-shaped.
7. **MAIL FROM / RCPT TO realism**: in a full SMTP cover,
   the (encrypted) message envelope addresses should be
   plausible — a circumvention server returning literal
   `MAIL FROM:<no-reply@server.invalid>` with random
   RCPTs has anomalous patterns relative to real mail.
   This is post-TLS so harder to detect, but not
   impossible.
8. **Cert chain**: a mail server's TLS cert is normally
   from a public CA matching the FQDN — mail.example.com.
   Self-signed certs on public-Internet mail are rare
   except in poorly-configured deployments; Let's Encrypt
   is the dominant CA for self-hosted mail in 2026.

The **easiest realistic cover** is **running real Postfix
or real Dovecot** as the backing service and tunneling
through a custom SASL mechanism or virtual-channel
extension. Active probing the server should get a real
mail-server response. Harder: emulate the prelude only —
detectable through banner fuzzing.

## Censor Practice

History (selective):

- **2014-present — every ISP** blocks outbound TCP/25
  from residential IP ranges as a spam-prevention
  measure. This is operational policy, not censorship,
  but constrains where STARTTLS-on-25 cover can be
  initiated from.
- **2018 — Iran** intermittently blocked specific mail
  providers (ProtonMail) at the IP / DNS layer.
  STARTTLS-on-standard-ports was not the target.
- **2019 — Russia** blocked ProtonMail SMTP submission
  at one point; ProtonMail rotated IPs and the block
  decayed.
- **2021 — China / GFW** has been observed to interfere
  with cleartext SMTP/IMAP/POP3 traffic during specific
  high-tension periods (slowing or selectively dropping
  traffic, particularly to specific overseas providers).
  No documented wholesale port block.
- **2022-2023 — multiple jurisdictions** sporadic
  STARTTLS-stripping attacks at the network layer have
  been documented — censor injects `STARTTLS` advertisement
  removal so client falls back to cleartext (then
  intercepts content). RFC 8461 MTA-STS and RFC 7672 DANE
  exist specifically to defend against this. Modern MUAs
  also enforce STARTTLS without falling back.
- **2024-2026 — no documented wholesale port-25 / 587 /
  143 / 110 blocks** by any major censor. Specific
  destination-IP blocks of specific providers continue.
  STARTTLS-stripping attacks continue but are mitigated
  by MTA-STS / DANE / MUA-side enforcement.

The pattern: **mail ports are universally permitted**.
The cover-protection here is unusually durable because
email is too foundational to risk wholesale disruption.

## Used as Cover By

(Catalog cross-references intentionally sparse — STARTTLS-
mail is **substantially underutilized as cover for
circumvention**.)

The scarcity reflects:

1. Most circumvention research focuses on TLS / QUIC /
   DTLS cover. STARTTLS-pattern cover is mostly absent
   from the literature.
2. The cleartext banner + capability prelude gives a
   mimic a *different wire shape than plain TLS*,
   defeating "TLS at byte 0" detection.
3. The collateral cost is critical and durable — email
   isn't going anywhere.
4. Backing-service plumbing is comparatively mature:
   Postfix, Dovecot, Exim are all easy to run; running a
   real mail server alongside a circumvention service is
   straightforward.

Empty `used_as_cover_by` is the honest current answer.

A circumvention design specifically positioned on
**TCP/587 with realistic SMTP submission STARTTLS prelude
and a real Postfix backing instance** is a concrete
underexplored candidate. Similarly TCP/143 with Dovecot
(IMAP IDLE pattern as a long-lived tunnel cover).

## Cross-References

- Sibling cover protocols:
  - [`cover-tls-1-3`](cover-tls-1-3.md) — implicit-TLS mail
    siblings (SMTPS 465, IMAPS 993, POP3S 995) subsume
    here. The choice between STARTTLS-on-587 vs. SMTPS-on-
    465 is a deliberate cover decision; STARTTLS gives a
    different wire shape, SMTPS gives a different port
    shape.
  - [`cover-rdp`](cover-rdp.md) — sibling STARTTLS-pattern
    entry. Both share "cleartext prelude on a fixed port,
    then inline TLS upgrade." Mimicry techniques transpose
    between them.
- Public corpus: STARTTLS-stripping attack measurement work
  exists (Durumeric et al., USENIX Security 2015 — *Neither
  Snow Nor Rain Nor MITM... An Empirical Analysis of Email
  Delivery Security*). Specific paper IDs as the corpus
  grows.
- Internal docs (TBD): no Lantern-internal experiments
  with mail-STARTTLS cover have been documented; this
  entry exists in part to surface that gap to the
  protocol-designer agent.
- Catalog circumvention entries that **could** mimic mail
  STARTTLS but currently don't: this is the underutilized-
  cover story. A Lantern variant on TCP/587 with a real
  Postfix backing instance + custom AUTH SASL mechanism is
  the obvious candidate; on TCP/143 with Dovecot, an IMAP
  IDLE-shaped long-lived tunnel.
