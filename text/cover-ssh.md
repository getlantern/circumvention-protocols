# SSH

## TL;DR

The IETF SSH-2 protocol family. RFC 4250-4256 (Jan 2006); refreshed
through RFC 8308 / 8709 / 8731 / 8732 / 9142 across 2018-2022.
**Wire-distinctness is unusually strong** — the first bytes are
the plaintext banner `SSH-2.0-<software_version>\r\n`, with no
DPI required to identify the protocol or the exact server
software version. **And yet SSH is virtually unblocked at the
censor's port-22 layer** because of collateral cost: every Linux
server, every cloud-provisioned VM, every developer's daily
workflow (git push, scp, Ansible, VS Code Remote-SSH, JetBrains
Gateway), every network-device admin path. Wholesale-blocking
port 22 breaks the administration plane of the modern Internet.

This is the textbook collateral-freedom case: **wire fingerprint
is plaintext, and yet the protocol survives** because the censor
can't afford to block it.

## Standardization

The SSH-2 family. All Standards Track unless noted.

- **RFC 4250** (Jan 2006) — *Assigned Numbers*. Algorithm names,
  message-type codes.
- **RFC 4251** (Jan 2006) — *Architecture*. Three-protocol stack
  (transport / authentication / connection).
- **RFC 4252** (Jan 2006) — *Authentication Protocol*. Public-key,
  password, host-based, GSS-API.
- **RFC 4253** (Jan 2006) — *Transport Layer Protocol*. **The
  wire spec.** Banner, KEX, encryption, MAC, packet format.
- **RFC 4254** (Jan 2006) — *Connection Protocol*. Channels,
  port forwarding, agent forwarding, X11 forwarding.
- **RFC 4255** (Jan 2006) — *SSHFP DNS Records* (host-key
  fingerprints in DNS).
- **RFC 4256** (Jan 2006) — *Generic Message Exchange
  Authentication* (interactive auth).

Maintenance and modernization across 2018-2022:

- **RFC 8268** (Dec 2017) — More MODP DH groups.
- **RFC 8308** (Mar 2018) — *Extension Negotiation* (the
  `ext-info-c`/`ext-info-s` negotiation).
- **RFC 8332** (Mar 2018) — RSA-SHA-256 / RSA-SHA-512 host keys.
- **RFC 8709** (Feb 2020) — *Ed25519 and Ed448 Public Key
  Algorithms*.
- **RFC 8731** (Feb 2020) — *Curve25519 / Curve448 KEX*.
- **RFC 8732** (Feb 2020) — *GSS-API Key Exchange* refresh.
- **RFC 9142** (Jan 2022) — Consolidates KEX-algorithm
  recommendations and deprecates SHA-1-based KEX.

In progress / deployed-not-yet-RFC:

- **`sntrup761x25519-sha512@openssh.com`** — OpenSSH's hybrid
  post-quantum KEX (Streamlined NTRU Prime + X25519). **Default
  since OpenSSH 9.0 (April 2022).** The deployed cover-population
  default in 2026.
- `mlkem768x25519-sha256` — IETF-track post-quantum hybrid; in
  draft, several implementations adopting.
- `draft-ietf-curdle-ssh-pq-ke` — IETF post-quantum hybrid KEX
  consolidation.
- Working group: **IETF CURDLE WG** for crypto refreshes; the
  classical SSH-2 protocol's WG (SECSH) is closed, with CURDLE
  carrying maintenance.

## Wire Format

### Banner exchange (plaintext)

The first bytes on every SSH connection, in both directions:

```
Client → Server:  SSH-2.0-OpenSSH_9.7p1 Ubuntu-2\r\n
Server → Client:  SSH-2.0-OpenSSH_9.6\r\n
```

Format: `SSH-<protoversion>-<softwareversion>[ <comments>]\r\n`,
ASCII, terminated by CRLF. RFC 4253 §4.2.

This banner is **not encrypted**. A passive observer reads the
exact server software version (often including OS
distribution + patch level) from the wire. There is no defense
against this in the protocol; it is by design (RFC 4253 §4.2
explicitly states the banner is for compatibility detection).

The banner is the most reliable on-wire SSH discriminator and
the strongest argument for SSH's collateral-freedom story —
**every censor capable of port-22 inspection can identify SSH
trivially, and they don't block it anyway.**

### KEX_INIT and key exchange

After banners, both sides exchange `SSH_MSG_KEXINIT` messages
listing supported algorithms in preference order:

```
SSH_MSG_KEXINIT = 20 (1B)
cookie (16B)
kex_algorithms (name-list)
server_host_key_algorithms (name-list)
encryption_algorithms_client_to_server (name-list)
encryption_algorithms_server_to_client (name-list)
mac_algorithms_client_to_server (name-list)
mac_algorithms_server_to_client (name-list)
compression_algorithms_client_to_server (name-list)
compression_algorithms_server_to_client (name-list)
languages_client_to_server (name-list)
languages_server_to_client (name-list)
first_kex_packet_follows (1B)
reserved (4B)
```

Algorithm names are ASCII strings: `curve25519-sha256`,
`sntrup761x25519-sha512@openssh.com`,
`chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`,
`ssh-ed25519`, `rsa-sha2-512`, etc. **The exact algorithm-list
ordering is the SSH equivalent of a JA3/JA4 fingerprint** — every
implementation has its preferred order, and a mimic that uses
the wrong order is trivially detectable.

OpenSSH 9.x default offer (client side) approximately:

```
kex:    sntrup761x25519-sha512@openssh.com,
        curve25519-sha256, curve25519-sha256@libssh.org,
        diffie-hellman-group-exchange-sha256,
        diffie-hellman-group16-sha512,
        diffie-hellman-group18-sha512,
        diffie-hellman-group14-sha256
hostkey: ssh-ed25519-cert-v01@openssh.com,
         ecdsa-sha2-nistp256-cert-v01@openssh.com,
         rsa-sha2-512-cert-v01@openssh.com,
         ssh-ed25519, ecdsa-sha2-nistp256, rsa-sha2-512
cipher:  chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr,
         aes256-ctr, aes128-gcm@openssh.com, aes256-gcm@openssh.com
mac:     umac-64-etm@openssh.com, umac-128-etm@openssh.com,
         hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com,
         hmac-sha1-etm@openssh.com, ...
```

After KEX_INIT both sides compute the actual key exchange
(X25519 or sntrup761x25519 hybrid in current OpenSSH); the
server signs the exchange hash with its host private key
(commonly Ed25519); both sides derive session keys via HKDF
(or RFC 4253's prescriptive KDF for older modes); they exchange
`SSH_MSG_NEWKEYS` and switch to encrypted records.

### Encrypted-record format

After NEWKEYS, every packet has the format:

```
encrypted({
    packet_length (4B; sometimes encrypted, depending on cipher)
    padding_length (1B)
    payload (packet_length - padding_length - 1)
    padding (padding_length bytes; ≥4 bytes; random-content)
})
mac (16-32 bytes; outside the encryption envelope for CTR/CBC modes; AEAD-integrated for GCM / chacha20-poly1305)
```

ChaCha20-Poly1305 (`chacha20-poly1305@openssh.com`) and AES-GCM
modes encrypt the entire packet (including length field),
producing genuinely opaque steady-state traffic. Older
CTR-mode-with-HMAC connections leak packet length in the
clear.

### Channels (post-handshake)

Real SSH connections multiplex one or more channels:

- `session` — interactive shell or `exec` command
- `direct-tcpip` — `LocalForward` / `-L` (client-to-server tunnel)
- `forwarded-tcpip` — `RemoteForward` / `-R`
- `x11` — X11 forwarding
- `auth-agent@openssh.com` — agent forwarding

Channel multiplexing produces predictable behavioral patterns
(small interactive-shell packets, large bulk SCP/SFTP packets,
small ACK-shaped frames) that a sophisticated DPI can match on
even though the bytes are encrypted.

## Traffic Patterns

- **Connection establishment is small and fast**: banners (~50B
  each) + KEX_INIT (~1KB each) + key exchange (~few hundred
  bytes) + auth (~few KB) — typically 5-15 round trips,
  completing in <1 second on a healthy network.
- **Steady state varies by carrier**:
  - Interactive shell: small (<200B) packets keystroke-paced;
    server echoes keystrokes immediately.
  - SCP / SFTP bulk transfer: full-MSS packets at line rate.
  - Port forwarding: shape mirrors the inner protocol.
  - Idle: keepalive (`ServerAliveInterval`) at 60-300 second
    intervals.
- **Long-lived sessions** are typical for development workflows
  (a developer's `ssh server` session may last hours).
- **Reconnection patterns**: high reconnect rate from CI / CD
  systems; lower from human users. The reconnect cadence is
  itself a behavioral signature.

## Encryption Surface

| Layer | Visible | Encrypted |
| --- | --- | --- |
| TCP/IP | client IP, server IP, port pair | n/a |
| **Banner** | full software version + OS distribution + patch level (plaintext) | n/a — by design |
| KEX_INIT | algorithm-list ordering, cookie | n/a |
| Key exchange | DH / X25519 / sntrup761 ephemeral public values; host-key signature; host pubkey | n/a |
| Server host pubkey | visible in plaintext during KEX | n/a |
| Authentication exchange | (encrypted under handshake-traffic key) usernames, signatures, password-auth bytes | the actual passwords / signatures |
| Channel data | (encrypted under session keys) packet sizes + timing | bytes themselves |

The three plaintext-visible items are unusually rich for a
"secure" protocol: server software version (banner), KEX
algorithm-list ordering (KEX_INIT), and host public key (KEX
reply). All three are the SSH equivalents of TLS's JA3/JA4
fingerprint — and SSH's are even more identifying because the
banner explicitly states version.

ECH-equivalent encryption of the banner / KEX_INIT has not been
standardized for SSH and is not on any deployment roadmap as of
2026. The community consensus is that SSH's collateral-freedom
properties are strong enough that opportunistic banner
randomization isn't a priority.

## Common Implementations

| Stack | Vendor | Scope |
| --- | --- | --- |
| **OpenSSH** | OpenBSD project | The dominant implementation. Default on every Linux distribution, macOS, recent Windows (Microsoft OpenSSH-Server since Win10 1709, native), every cloud-provisioned VM (AWS EC2, GCP, Azure, DigitalOcean, Linode, ...), every Cisco / Juniper / Arista network device's SSH server-side. **The cover-population default.** |
| PuTTY | Simon Tatham et al. | Windows interactive client; still widely used despite Microsoft's native OpenSSH |
| libssh | libssh project | C library — curl, qemu, KDE / GNOME file managers' SFTP support |
| libssh2 | libssh2 project | Different C library — git's libgit2, Mercurial, hosting-control-panel SSH |
| Tectia | SSH Communications Security (commercial) | Enterprise / regulated-industry SSH |
| Bitvise SSH Server | Bitvise (commercial) | Windows commercial server |
| Dropbear | Matt Johnston | Embedded / OpenWrt / busybox systems — the dominant SSH for resource-constrained deployments |
| wolfSSH | wolfSSL | IoT / industrial |
| AsyncSSH | Ron Frederick | Python asyncio SSH — orchestration / automation |
| go SSH | Go project (`golang.org/x/crypto/ssh`) | Tailscale, Caddy admin, Hashicorp tooling, lots of cloud orchestration code |
| Tailscale SSH | Tailscale | Tailscale-overlay SSH; rides on Tailscale tunnel rather than over the open Internet |

The implementation diversity is real, but **OpenSSH's banner
population dominates by orders of magnitude**. A cover-population
fingerprint of "OpenSSH_9.x" matches the great majority of
public-facing SSH servers; PuTTY / Tectia / Bitvise show up in
client-side mixes more than server-side.

## Prevalence

- Shodan facet for port 22 reports approximately **22 million
  publicly exposed SSH listeners** (May 2026). Top countries
  US, China, Germany, France, UK. This counts only the publicly-
  exposed subset; behind enterprise NAT the installed base is
  vastly larger — every Linux server in a private network, every
  cloud-VM administrative path, every container-orchestration
  bastion.
- Every git host of consequence offers SSH access — GitHub,
  GitLab (`.com` and self-hosted), Bitbucket, Codeberg, sourcehut,
  AWS CodeCommit. Git pushes / pulls over SSH are a daily-
  workflow constant for tens of millions of developers.
- Every cloud provider's "SSH into your VM" path is the default
  administrative entry point.
- Configuration management tools (Ansible, Salt, Chef, Puppet
  agentless modes) all run over SSH at scale.
- Editor remote-development workflows: VS Code Remote-SSH,
  Cursor Remote, JetBrains Gateway, Vim/Emacs over `ssh -X` or
  Mosh — millions of developer-hours daily.
- Mosh (mobile shell) bootstraps via SSH, then switches to UDP.

SSH traffic doesn't show up in W3Techs / Cloudflare Radar
measurements (those count HTTP-shape traffic), but the protocol
is the single most-deployed remote-administration path in
existence.

## Collateral Cost

**High.** Wholesale-blocking SSH (port 22 or fingerprinted by
banner) breaks **simultaneously**:

- Every Linux server administration path globally.
- Every git push / pull from developers using `git@github.com`,
  `git@gitlab.com`, etc.
- Every cloud provider's customer-VM access path.
- Every Ansible / Salt / Chef / Puppet configuration-management
  run.
- Every CI / CD agent that uses SSH for deployment.
- Every developer's `ssh prod-server` workflow.
- Every network-device administrative session (Cisco, Juniper,
  Arista, F5, Palo Alto).
- Mosh, VS Code Remote-SSH, Cursor Remote, JetBrains Gateway,
  every editor remote-development product.

Censors that have flirted with SSH-blocking historically:

- **GFW**: never wholesale-blocked SSH. Has periodically blocked
  *specific destination IPs* known to be running circumvention
  SSH endpoints. Does not block port 22 itself.
- **TSPU / Russia**: similarly, no wholesale port-22 block.
  Periodic targeting of specific server IPs.
- **Iran**: same pattern.

The pattern is clear: **port-22 SSH is a high-value cover
because nobody can afford to clean-block it, but specific
destination IPs that look "circumvention-y" do get IP-blocked**.
The IP-reputation game (rotate IPs, prefer cloud-provider IPs
shared with legitimate customers) is the durable strategy for
SSH-shaped circumvention.

## Common Ports & Collateral Cost

SSH has a relatively concentrated port story — TCP/22 dominates,
but operators rebind to other ports for security-through-obscurity
or to evade enterprise firewalls.

| Port | Cover service | Collateral of port-block |
| --- | --- | --- |
| **TCP/22** | Default SSH everywhere — Linux servers, cloud VMs, network devices, git hosts | Critical for developers / admins; blocking breaks the global administration plane |
| **TCP/443** | SSH-over-443 — common manual evasion of enterprise firewalls; some hosting providers expose SSH here | Inherits TLS / HTTPS collateral cost (see [`cover-tls-1-3`](cover-tls-1-3.md)) |
| **TCP/2222** | Common alternate when port 22 is restricted (security through obscurity); GitLab / GitHub Enterprise alternative | Modest; long-tail |
| **TCP/8022** | Another common alternate | Modest |
| **TCP/7822** | GitHub's documented `ssh.github.com` alternate | Some — GitHub-specific |

A circumvention SSH service running on TCP/443 inherits the
TLS-port collateral story (no censor wholesale-blocks 443) but
is fingerprintable as "non-TLS traffic on TLS port" by any
DPI that parses the first bytes — the SSH banner gives the game
away in milliseconds. To actually hide SSH inside HTTPS, you
need an obfuscation layer (Psiphon's OSSH wraps an obfuscation
layer around SSH; this is the canonical move). Naive
SSH-on-port-443 is a low-quality cover because port and wire
disagree.

The right way to use SSH-port collateral is to run **on TCP/22
itself**, accept that the wire is identifiable as SSH, and
rely on the censor's port-22-block-cost calculation.

## Mimicry Considerations

SSH is unusual in this catalog because the wire is plaintext-
identifiable. A mimic isn't trying to hide *that* it's SSH —
it's trying to look like *real* SSH (a normal OpenSSH
deployment with normal-looking traffic) rather than something
obviously circumvention-shaped.

1. **Banner discipline** — the mimic must serve a real OpenSSH
   banner string for the version it claims to be. `SSH-2.0-OpenSSH_9.7p1`
   should match an actual OpenSSH 9.7 release; mismatched
   versions (banner says 9.7, KEX_INIT defaults match 8.9) are
   a tell.
2. **KEX_INIT algorithm-list ordering** — must match the chosen
   OpenSSH version's defaults exactly. The list order is the
   "JA3 of SSH" — every OpenSSH minor release has its own
   canonical ordering, and mimics that ship a stale ordering
   are anachronistic.
3. **Post-quantum KEX**: `sntrup761x25519-sha512@openssh.com`
   is the OpenSSH default since 9.0 (April 2022). A mimic in
   2026 that claims to be modern OpenSSH but doesn't offer
   `sntrup761x25519-sha512@openssh.com` first is anachronistic
   relative to the cover population. Conversely, a mimic that
   ships only `sntrup761x25519-sha512@openssh.com` and refuses
   classical X25519 fallback is anachronistic the other way.
4. **Host-key type and signature** — Ed25519 is the modern
   default; mimics shipping only RSA-2048 host keys look like
   ancient OpenSSH installs. Mixed Ed25519 + RSA-SHA-512
   matches modern reality.
5. **Authentication realism** — real SSH servers usually accept
   publickey + password (and refuse passwords from public-IP
   internet servers if hardened). A mimic that immediately
   accepts any credential looks fake.
6. **Channel-data plausibility** — a real SSH session has
   either interactive-shell traffic (small packets, keystroke-
   paced) or bulk-file traffic (full-MSS at line rate) or
   port-forward traffic (shape mirrors inner protocol). A mimic
   that produces only random-shaped opaque blobs after handshake
   is unusual; real channel data has structure.
7. **Connection lifetime + reconnect cadence** — production
   SSH-using workloads (CI / CD, orchestration, developer
   sessions) have characteristic timing. Long-lived idle
   connections with periodic keepalives match developer use;
   short-burst high-volume reconnect floods match CI / CD.
8. **Server fingerprint stability** — real SSH servers don't
   rotate host keys per connection. A mimic that uses a fresh
   host key on every connection is observable as "non-real
   server."

## Censor Practice

History (selective):

- **Pre-2010** — broad SSH availability worldwide; no major
  censor wholesale-blocked the protocol.
- **GFW (multiple incidents 2010-2018)** — selective IP-blocking
  of specific SSH servers used by circumvention services
  (commercial SSH tunnels, some VPS providers). No port-22
  wholesale block.
- **2017 — Iran experiments** — brief throttling of port-22
  during specific events, reverted.
- **TSPU / Russia 2022-2024** — selective IP blocks of known
  circumvention SSH endpoints; consistent with SSH-IP-reputation
  game. No wholesale port-22 block.
- **2018 — Egypt during specific events** — temporary port-22
  blocks during protests, reverted within days.
- **2025-2026** — **status quo: no major censor wholesale-blocks
  SSH at the port or banner layer.** All known censor activity
  against SSH-using circumvention is at the destination-IP layer.

The pattern fits the collateral-freedom prediction precisely:
the protocol's wire is a dead giveaway, but the censor's
blocking calculus rejects the wholesale-block path.

## Used as Cover By

(Catalog cross-references intentionally not populated — the
cover catalog is a survey of mimicry candidates.)

Existing circumvention catalog entries that ride on SSH:

- `psiphon-ossh` — Psiphon's RC4-obfuscated SSH. The obfuscation
  layer is over the SSH banner exchange; once past obfuscation,
  it's bog-standard OpenSSH.
- `psiphon-tls-ossh` — wraps OSSH inside TLS 1.3.
- `psiphon-conjure-ossh` — OSSH delivered via Conjure refraction.
- `psiphon-inproxy` (when carrying OSSH variants) — OSSH inside
  WebRTC-relayed paths.

All of these ride on SSH at the application-protocol layer; the
cover catalog entry here documents the substrate they're hiding
inside / above.

## Cross-References

- Public corpus: no SSH-specific paper in the corpus as of
  writing. The collateral-freedom paper (`2013-robinson-collateral`)
  doesn't analyse SSH but predicts exactly its survival pattern.
- Internal docs (TBD): when Lantern internal notes on SSH-shaped
  cover land, link them here.
- Sibling cover protocols:
  - [`cover-tls-1-3`](cover-tls-1-3.md) — when SSH is wrapped in
    TLS (e.g. SSH-over-443-with-stunnel), the outer wire is TLS,
    not SSH; this entry's cover claims don't transfer.
  - [`cover-quic`](cover-quic.md) — SSH-over-QUIC is not a
    standardized thing. Niche / experimental.
- Existing circumvention catalog entries that mimic SSH:
  `psiphon-ossh` and its variants. See the §Used as Cover By
  section above.
