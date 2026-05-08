# RDP

## TL;DR

Microsoft Remote Desktop Protocol — the native Windows-and-
Azure remote-desktop protocol. **Wire-distinct at byte 0**:
every TCP/3389 connection begins with a TPKT version-3
header (`03 00 LEN_HI LEN_LO`, RFC 1006), then an X.224 /
ITU-T X.224 ConnectionRequest PDU (TPDU type `0xE0`)
carrying a cleartext `Cookie: mstshash=<username>\r\n`
line. **RDP is a STARTTLS-pattern protocol** — the X.224
prelude is unencrypted, then a TLS handshake (or CredSSP /
HYBRID_EX) negotiates inline on the same TCP connection.
This makes RDP wire-distinct from generic TLS (a TLS
handshake at byte 0 is plain TLS; a TLS handshake at byte
~36 preceded by `03 00 ... E0 ... mstshash=...` is RDP).
**Collateral cost is high**: RDP is the Microsoft enterprise
admin path — Azure Virtual Desktop, Windows 365, Microsoft
Dev Box, Windows Server RDS, every cloud Windows VM.
**Note**: RD Gateway tunnels RDP inside HTTPS on TCP/443
and subsumes to [`cover-tls-1-3`](cover-tls-1-3.md). This
entry covers **native RDP on TCP/3389** specifically.

## Standardization

RDP is **Microsoft-controlled**, not IETF-controlled. The
authoritative documents are Microsoft's open-specification
series under the Microsoft Open Specifications Promise:

- **[MS-RDPBCGR]** — *Remote Desktop Protocol: Basic
  Connectivity and Graphics Remoting*. The core RDP wire
  format. Versioned alongside Windows releases; current
  spec covers RDP 10.x.
- **[MS-RDPEDC]** — Dynamic Channels.
- **[MS-RDPEMT]** — Multitransport Extensions (RDP-UDP, the
  UDP/3389 path used for media bursts since Windows
  Server 2012).
- **[MS-RDPELE]** — License extensions.
- **[MS-RDPRFX]** — RemoteFX codec.
- **[MS-CSSP]** — Credential Security Support Provider
  (CredSSP), the auth handshake used by HYBRID security
  modes.

Substrate specs (open ITU-T / IETF):

- **ITU-T X.224 / ISO 8073** — *Connection-oriented
  Transport Protocol*. The PDU types (0xE0
  ConnectionRequest, 0xD0 ConnectionConfirm, 0xF0 Data) are
  inherited from this standard.
- **ITU-T T.125** — *Multipoint Communication Service
  Protocol Specification*. The MCS layer that rides above
  X.224 in RDP.
- **ITU-T T.124** — *Generic Conference Control*. Used at
  the GCC Conference Create exchange.
- **RFC 1006** — *ISO Transport Service on top of TCP*.
  Defines the TPKT version-3 framing — the literal
  `03 00 LEN_HI LEN_LO` bytes. (Yes, RDP-on-TCP runs the
  ITU OSI transport on top of TCP, with RFC 1006 acting as
  glue. This is the historical reason RDP looks the way it
  does on the wire.)

There is no IETF working group for RDP; protocol evolution
happens via Microsoft updating the [MS-*] documents and
shipping the updated implementation in Windows Server
releases. Microsoft has a track record of publishing wire
specs early enough that FreeRDP keeps pace.

## Wire Format

### Bytes 0-3 — TPKT version-3 header

```
+------+------+----------+----------+
|  1B  |  1B  |    1B    |    1B    |
| 0x03 | 0x00 |  LEN_HI  |  LEN_LO  |
+------+------+----------+----------+
```

`LEN_HI:LEN_LO` is the total TPKT length including these
4 bytes, big-endian. Every RDP message on TCP/3389 begins
this way — it's RFC 1006 framing of OSI-layer PDUs over
TCP. **No other widely-deployed protocol on TCP/3389 emits
this prefix**, so byte-0-prefix matching is sufficient
identification.

### Bytes 4+ — X.224 PDU

```
+------+----------+--------+--------+--------+
|  1B  |    1B    |   2B   |   2B   |   1B   |
|  LI  | TPDU type| DST-REF| SRC-REF| class  |
+------+----------+--------+--------+--------+
```

`LI` = length indicator (X.224 header length minus 1).

`TPDU type` codes:

| Type | Meaning |
| --- | --- |
| `0xE0` | ConnectionRequest — **the canonical RDP marker** |
| `0xD0` | ConnectionConfirm |
| `0xF0` | Data |
| `0x80` | Disconnect Request |

The first packet from client to server **always starts with
TPDU type `0xE0`**. From that fixed byte plus the TPKT
prefix, a DPI engine has the RDP session pinned with
zero ambiguity.

### RDP NEG REQ inside the X.224 ConnectionRequest

After the X.224 header, RDP 5.x+ stuffs an extension into
the user-data area:

```
Cookie: mstshash=<username>\r\n
RDP_NEG_REQ {
    type = 0x01
    flags = 0x00
    length = 8
    requestedProtocols = 0x00000003 // PROTOCOL_RDP | PROTOCOL_SSL | PROTOCOL_HYBRID | ...
}
```

The `Cookie: mstshash=` line is **plaintext**. Many real
clients fill in the Windows username here (mstsc.exe does
by default). FreeRDP populates from `--username` flag.
Censors / DPI can read it without effort.

`requestedProtocols` is a 32-bit bitfield announcing which
security layers the client is willing to speak:

| Value | Name | Meaning |
| --- | --- | --- |
| `0x00000000` | PROTOCOL_RDP | Legacy "Standard RDP Security" — own bespoke crypto, deprecated since Windows Server 2012 R2 |
| `0x00000001` | PROTOCOL_SSL | TLS-protected RDP — Windows authenticates with TLS cert; user creds in RDP layer |
| `0x00000002` | PROTOCOL_HYBRID | TLS + CredSSP / NLA — user creds authenticated via SPNEGO (Kerberos / NTLM) before any RDP message; the Microsoft default since Windows 8 / Server 2012 |
| `0x00000008` | PROTOCOL_HYBRID_EX | HYBRID + Early-User-Authorization Result PDU — Azure Virtual Desktop / Windows 365 default |

The server replies with X.224 ConnectionConfirm (TPDU type
`0xD0`) carrying RDP_NEG_RSP that selects exactly one
protocol via `selectedProtocol`.

### Inline TLS handshake — the STARTTLS pattern

If `selectedProtocol` is PROTOCOL_SSL or higher, the next
bytes on the SAME TCP/3389 connection are a TLS
ClientHello — i.e. **TLS as inline upgrade**. From this
point on the connection is encrypted: TLS handshake
completes, then RDP MCS / Erect Domain / etc. flows under
TLS, and a CredSSP exchange runs on top in HYBRID mode.

For mimicry / detection purposes:

- A DPI watching TCP/3389 sees the TPKT + X.224 prelude
  cleartext, then a TLS handshake. The presence of a TLS
  handshake at byte ~36 (after the TPKT and X.224 headers)
  rather than byte 0 is itself a discriminator: this is
  STARTTLS-shaped, not plain TLS.
- ECH applies to the inline TLS handshake but only protects
  the inner SNI from byte 36 onward; the X.224 prelude
  before it (including `mstshash=`) is always cleartext.
- Server cert in the TLS handshake is typically a
  self-signed cert from the Windows machine (`CN=<machine
  name>`) for ad-hoc deployments, or a real cert from
  Azure / customer infrastructure for AVD / Windows 365.

### MCS / RDP application layer (post-handshake)

After TLS / CredSSP completes, the protocol becomes
ITU-T T.125 MCS multiplexing of multiple "channels"
(input, output, virtual channels for clipboard / drives /
audio / RemoteApp). The application layer is highly
distinctive to RDP but invisible under TLS — relevant to
mimicry of behavioral patterns, not to byte-shape
fingerprinting.

### RDP-UDP transport (UDP/3389)

Windows Server 2012+ added [MS-RDPEMT] Multitransport: a
UDP transport for the same RDP session, used for high-
bandwidth media (video). The UDP path uses DTLS internally
for encryption — wire shape on UDP/3389 looks like DTLS,
which subsumes to [`cover-dtls`](cover-dtls.md). The
canonical wire-distinct cover here is **TCP/3389 only**.

## Traffic Patterns

- **Connection prelude**: a single ~4-byte TPKT + ~30-byte
  X.224 ConnectionRequest from client, ~20-byte
  ConnectionConfirm from server. Tiny, distinctive opening
  packet.
- **TLS handshake**: standard TLS 1.2 / 1.3 handshake
  (Windows Server 2025 supports TLS 1.3 for RDP since
  Windows 11 24H2 client; Windows Server 2022 still
  TLS 1.2 by default). Cert exchange, ServerHello, etc.
- **CredSSP exchange** (HYBRID mode): SPNEGO tokens
  (Kerberos or NTLM) traverse over the TLS-protected
  channel.
- **Capability exchange**: a burst of small messages as
  client + server negotiate display resolution, color
  depth, virtual-channel set.
- **Steady state**: bursty bidirectional traffic. **Server-
  to-client dominates** — bitmap updates / RemoteFX /
  RDP Graphics Pipeline carry screen updates at
  whatever frame rate the user's activity drives. Client-
  to-server is mostly mouse + keyboard input (low
  bandwidth, bursty around user activity).
- **Long-lived sessions**: RDP sessions routinely last
  hours to days. TCP-keepalive shape stays alive.
- **Idle behavior**: when the user is idle, traffic drops
  to near zero — no constant keepalives at the RDP layer
  beyond TCP-keepalive defaults. A circumvention mimic
  generating constant-rate traffic on TCP/3389 would
  stand out behaviorally.
- **Reconnect**: RDP supports session reconnect; on network
  blips, mstsc.exe transparently re-establishes the TCP
  connection and re-runs the prelude. Reconnect bursts
  are visible.

## Encryption Surface

| Layer | Visible | Encrypted |
| --- | --- | --- |
| IP / TCP | client IP, server IP, ports | n/a |
| TPKT header | `03 00 LEN_HI LEN_LO` | nothing — fixed prefix |
| X.224 ConnectionRequest | LI, TPDU=0xE0, refs, RDP_NEG_REQ structure including **`Cookie: mstshash=<username>` cleartext**, `requestedProtocols` bitfield | nothing — header is always cleartext |
| X.224 ConnectionConfirm | LI, TPDU=0xD0, RDP_NEG_RSP structure with `selectedProtocol` | nothing |
| TLS handshake (inline upgrade) | TLS ClientHello (SNI when present, ALPN, cipher suites, JA3/JA4 fingerprint), ServerHello, server cert chain | (with ECH) inner SNI |
| Post-handshake RDP/MCS layer | record sizes + timing | the entire RDP application stream — MCS, Erect Domain, capability negotiation, virtual channels, GUI bitmap updates, audio redirection, clipboard, drive redirection, RemoteApp |
| CredSSP (HYBRID) | nothing distinctive — runs inside TLS | username / domain / NTLM-or-Kerberos auth tokens |

The cleartext `mstshash=` username is RDP's most
distinctive privacy leak. Microsoft has documented this
for years; the cover-population just lives with it because
RDP is an enterprise-trusted-network protocol historically.

## Common Implementations

| Stack | Vendor | Scope |
| --- | --- | --- |
| Microsoft mstsc.exe | Microsoft | Built-in Windows Remote Desktop Connection client; ships on every Windows 10 / 11 / Server install |
| Microsoft Remote Desktop (Mac / iOS / Android) | Microsoft | First-party clients on non-Windows |
| Windows Server RDS | Microsoft | Server-side RDP terminal-server stack |
| **Azure Virtual Desktop (AVD)** | Microsoft | Azure-managed multi-session RDP — flagship cloud VDI |
| **Windows 365 Cloud PC** | Microsoft | Cloud-hosted personal Windows desktops |
| **Microsoft Dev Box** | Microsoft | Developer-focused cloud workstations |
| **FreeRDP** | FreeRDP project | Dominant open-source RDP client + library; powers Remmina, GNOME-Boxes, KRDC, Devolutions RDM, Apache Guacamole's RDP backend |
| **xrdp** | xrdp project | Open-source RDP server for Linux — canonical way to RDP into a Linux desktop |
| rdesktop | rdesktop project | Older OSS client (FreeRDP predecessor); legacy |
| Apache Guacamole | Apache Software Foundation | Browser-based RDP-over-HTTPS gateway (Guacamole proxies real RDP on the backend, so the wire-to-server is still native RDP) |
| Devolutions RDM | Devolutions | Windows admin / MSP RDP client suite |
| AWS WorkSpaces (RDP variants) | AWS | Some configurations use native RDP, others PCoIP / WSP |

The **fingerprint diversity is high**: mstsc.exe + FreeRDP
+ Microsoft Remote Desktop Mac/mobile each produce
different ClientHello fingerprints when negotiating the
inline TLS, plus distinct X.224 ConnectionRequest cookie
patterns. A circumvention mimic has multiple legitimate
profiles to copy from.

The **server-side population** is more concentrated:
Windows Server's Schannel TLS, plus FreeRDP / xrdp on the
Linux long tail.

## Prevalence

Order-of-magnitude:

- Microsoft reports 18M+ Azure Virtual Desktop users (FY24
  earnings call, paraphrased — exact public numbers vary).
- Windows 365 (Cloud PC) has been Microsoft's fastest-
  growing enterprise SaaS line per their disclosures.
- Every Azure Windows VM, every AWS Windows EC2 instance,
  every GCP Windows VM is administered by RDP by default
  unless the customer explicitly disables port 3389. AWS
  alone has hundreds of thousands of Windows EC2
  instances; the same scale on Azure.
- Microsoft Dev Box has been adopted by major dev orgs.
- Apache Guacamole-based deployments power thousands of
  enterprise self-hosted bastion hosts.
- Self-hosted Windows Server RDS deployments at small +
  mid-market enterprises number in the low millions.

In Censys / Shodan-style scans, port 3389 has consistently
ranked among the **top 20 most-exposed TCP ports
on the public Internet**, with millions of IPv4 hosts
listening. Most are enterprise admin endpoints, often
behind RD Gateway nowadays but with the native port still
exposed.

The cover-population on TCP/3389 is dominated by:
Azure Windows VMs (cloud-VM admin), AWS Windows EC2 (same),
on-prem Windows Server RDS, and self-hosted Windows
desktops with RDP enabled.

## Collateral Cost

**High** at the wholesale level. A wholesale TCP/3389 block
breaks:

- Azure Virtual Desktop access for users not routed through
  RD Gateway
- Windows 365 Cloud PC access on default configurations
- Microsoft Dev Box default access path
- Every Azure / AWS / GCP Windows VM admin connection that
  wasn't deliberately moved to a non-default port
- Enterprise bastion-host RDP into corporate networks
- Helpdesk remote-support sessions
- Self-hosted Windows Server RDS deployments
- Linux-via-xrdp setups in some research / hosting
  environments

The constituency hurt is **Microsoft enterprise customers
worldwide** — the demographic most likely to have
political clout to push back on a censor's wholesale block.
The only sensible operational pattern is **destination-IP-
based blocking** (block specific hosts known to run
circumvention RDP servers) rather than port-based.

There's an additional twist: **many enterprise networks
already block outbound TCP/3389 at their own egress** for
security reasons (RDP brute-force is a major ransomware
vector). This means the port is *less* available as cover
for a circumvention client running on a corporate network
than on a residential network — collateral cost depends on
the client environment.

## Common Ports & Collateral Cost

| Port | Variant | Collateral of port-block |
| --- | --- | --- |
| **TCP/3389** | Native RDP — the dominant production port | High — see above. Microsoft enterprise admin path. |
| **UDP/3389** | RDP-UDP (Multitransport, [MS-RDPEMT]) | Low-to-modest — RDP-UDP is bandwidth optimization only; sessions silently fall back to TCP/3389 if UDP is blocked |
| **TCP/443** | RD Gateway tunnels RDP inside HTTPS / WebSocket | n/a — wire is plain HTTPS, subsumes to [`cover-tls-1-3`](cover-tls-1-3.md). The native-RDP wire shape is gone here. |
| **TCP/3391** | Connection Broker (in RDS deployments) | Negligible — admin-only |
| **non-canonical** | Some private deployments relocate RDP to 13389 / 33389 / similar | **Strong fingerprint of circumvention** — TPKT+X.224 prelude on a non-3389 port has no legitimate cover-population. The absence of real RDP traffic on that port is the signal. |

The collateral-freedom story holds *only* on TCP/3389. A
Lantern-style circumvention design that uses the RDP wire
shape on a non-canonical port loses the cover protection
entirely; the X.224 prelude becomes a tag for the censor
rather than camouflage.

## Mimicry Considerations

RDP mimicry is a STARTTLS-pattern problem:

1. **Reproduce the TPKT + X.224 + RDP_NEG_REQ prelude
   exactly.** The byte sequence is fixed; small length-
   field errors are catastrophic. mstsc.exe and FreeRDP
   produce subtly different `requestedProtocols` bitfields
   and cookie formats — pick one and copy it byte-for-byte.
2. **`Cookie: mstshash=` value should look realistic.**
   mstsc.exe defaults to the Windows username; FreeRDP
   populates from the `--username` flag. A static or
   distinctive cookie value is fingerprintable.
3. **Inline TLS ClientHello fingerprint must match the
   chosen client family.** Windows Schannel ClientHello
   on RDP differs from a vanilla Windows browser because
   the cipher-suite list and extension set are RDP-tuned.
   FreeRDP uses OpenSSL by default with its own cipher
   list. **Don't** copy Chrome's ClientHello and serve it
   inside an RDP prelude — that's an immediate
   anachronism (Chrome doesn't speak RDP).
4. **Server cert must be plausible** — either a self-
   signed `CN=<machine_name>` (the Windows-on-prem
   default) or a real cert from Azure / AVD pattern. A
   Let's Encrypt cert behind RDP is anachronistic.
5. **CredSSP / HYBRID negotiation** — if you advertise
   PROTOCOL_HYBRID, you need to actually run a CredSSP
   handshake. Skipping it after advertising it is a
   protocol violation an active prober will flag. Easier
   path: advertise PROTOCOL_SSL only (TLS without
   CredSSP) — still legitimate for older clients.
6. **Steady-state behavioral shape**: real RDP has bursty
   server-to-client dominant traffic driven by user
   activity. A constant-rate tunnel running through an
   RDP cover is behaviorally distinct.
7. **Session length distribution**: RDP sessions are
   long-lived but go idle; circumvention sessions
   sustained at full throughput for hours stand out.
8. **Server-side identity**: the censor can fingerprint
   the server via active probing — mstsc.exe probing your
   server should get a real RDP response with realistic
   capability advertisement, not a rejection or
   suspicious behavior. The hardest path is **running real
   xrdp** as the backing service and tunneling through a
   virtual channel; the easier-but-fingerprintable path is
   **emulating** the prelude only.

The strongest cover story is **xrdp on TCP/3389 with a
hidden virtual-channel tunnel** — the wire shape is
fully real RDP because xrdp actually answers, and the
circumvention payload rides one of the [MS-RDPBCGR]
virtual channels (or a custom one). Fingerprint diversity
is naturally provided by xrdp's TLS stack vs. mstsc.exe's
Schannel.

## Censor Practice

History (selective):

- **2017-2019 — China / GFW** sporadic TCP/3389 throttling
  during high-tension periods. Generally rolled back
  because of cloud-VM-admin disruption complaints from
  operators of Chinese cloud providers.
- **2019-2021 — Iran** intermittent TCP/3389 blocking
  during specific protest periods. RDP outbound from Iran
  to international cloud providers is sometimes
  unreliable; inbound from international clients to
  domestic Iranian VMs is generally permitted.
- **2020+ — multiple jurisdictions** corporate-egress
  policies (security guidance from CISA, NCSC, etc.) push
  enterprises to block outbound TCP/3389 for ransomware
  prevention. **This narrows the residential / corporate
  cover-population asymmetry** — TCP/3389 is more
  available as cover from a residential ISP than from a
  corporate-policy-managed network.
- **2024 — RDP brute-force / ransomware visibility** at
  the cloud-provider level (AWS, Azure, GCP) led to
  default-block recommendations and Network Security Group
  defaults that block 3389 unless explicitly enabled. The
  cover-population on cloud-VM internet-exposed 3389 has
  shrunk; the cover-population on domestic Windows admin
  networks remains large.
- **2026 — no documented wholesale-block of TCP/3389 by
  any major censor**. Targeted blocks of specific RDP
  endpoints (when known to host circumvention) have been
  reported anecdotally on Iranian + Chinese networks.

The pattern: **port 3389 itself is generally permitted**
(censors trade the small population of RDP-using
circumvention against the large enterprise admin
population). Specific destination-IP blocks happen.
Active probing of port 3389 to detect non-RDP behavior is
plausible but not widely documented.

## Used as Cover By

(Catalog cross-references intentionally sparse — RDP is
**underutilized as cover for circumvention**.)

The scarcity is the interesting part:

- Most circumvention research focuses on TLS / QUIC / DTLS
  cover and ignores STARTTLS-pattern protocols.
- The cleartext `mstshash=` and TPKT + X.224 prelude give
  a circumvention mimic a *different wire shape than
  plain TLS*, breaking pattern-matching that targets only
  "TLS at byte 0" flows.
- The Microsoft enterprise admin collateral cost is real
  and durable.

Empty `used_as_cover_by` is the honest current answer.

A circumvention design **specifically positioned on
TCP/3389 with realistic RDP wire shape and an xrdp backing
server** is a reasonable, underexplored candidate.

## Cross-References

- Sibling cover protocols:
  - [`cover-tls-1-3`](cover-tls-1-3.md) — RD Gateway
    subsumes here (RDP-over-HTTPS on TCP/443 looks like
    plain TLS; no STARTTLS pattern). The choice between
    RDP-on-3389 vs. RD-Gateway-on-443 is a deliberate
    cover decision.
  - [`cover-dtls`](cover-dtls.md) — RDP-UDP / Multitransport
    on UDP/3389 inherits this wire shape because
    [MS-RDPEMT] uses DTLS internally.
  - [`cover-starttls-mail`](cover-starttls-mail.md) — sibling
    STARTTLS-pattern entry. SMTP / IMAP / POP3 STARTTLS and
    RDP share the structural property of "cleartext prelude
    on a fixed port, then inline TLS upgrade." Mimicry
    techniques transpose between them.
- Public corpus: RDP-targeted circumvention papers are rare;
  STARTTLS-pattern measurement work is mostly mail-protocol-
  centric. The cover-rdp body-pattern entry is an open
  research opportunity.
- Internal docs (TBD): no Lantern-internal experiments using
  RDP as cover have been documented; this entry exists in
  part to surface that gap to the protocol-designer agent.
- Catalog circumvention entries that **could** mimic RDP
  but currently don't: this is the underutilized-cover
  story. A Lantern variant on TCP/3389 with a real xrdp
  backing instance + virtual-channel tunneling is the
  obvious candidate.
