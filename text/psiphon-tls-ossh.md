# Psiphon TLS-OSSH

## TL;DR

OSSH wrapped inside a real TLS 1.3 session. The outer TLS uses
Psiphon's `CustomTLSConfig` (uTLS-based, with either a fixed or
per-connection-randomized fingerprint, optional ClientHello record
fragmentation, RFC-7685 TLS padding). Authentication is embedded
in the **TLS ClientHello's 32-byte `client_random` field**: 16-byte
nonce + 16-byte HMAC-SHA256 truncated tag, HKDF-keyed from a
shared "obfuscated key" with an optional 20-minute time-window
factor for replay defense. Servers that recognize the message
strip the wrapper and run OSSH→SSH inside; servers that don't fall
through to a configured passthrough HTTPS host (e.g. a real
website on the same IP) — that's the probe-resistance design.

## Threat Model

The modern Psiphon variant for TLS-friendly threat profiles. Designed
to address everything OSSH-alone leaves on the table:

- **Fully encrypted traffic detection** (USENIX 2023). The wire is
  real TLS 1.3 from the first byte; first-packet entropy is exactly
  what FET classifiers expect from real TLS, so they don't flag it.
- **JA3 / JA4 fingerprinting**. uTLS is in use; profile is either
  pinned to a real browser (e.g. Chrome) or randomized per-conn.
- **SNI extraction**. The `SNIServerName` is configurable per
  server entry — operators choose a domain that's high-collateral
  to block. Optional `FragmentClientHello` ([Niere et al. ACM CCS
  2023 — `2023-niere-poster`](../circumvention-corpus/corpus/papers/2023-niere-poster.yaml)) splits the ClientHello across multiple TLS records to defeat single-record SNI matchers.
- **TLS record-size fingerprinting**. RFC-7685 TLS padding extension
  used to randomize ClientHello length (`TLSPadding` field, capped
  at 65535).
- **Active probing**. A probe that connects with a random `client_
  random` doesn't pass HMAC verification → server treats the
  connection as a passthrough (forwards bytes to a configured real
  HTTPS host). Probes get a real HTTPS response from a real site.
- **Replay**. The HMAC includes the current 20-minute time epoch
  (`TLS_PASSTHROUGH_TIME_PERIOD = 20 * time.Minute`); server-side
  history cache (`TLS_PASSTHROUGH_HISTORY_TTL = 60 min`) rejects
  reused messages.

What it does **not** address:

- **The OSSH layer inside is still RC4-obfuscated**. Once a censor
  has decrypted the outer TLS (e.g. via a man-in-the-middle CA),
  the inner RC4 obfuscator carries OSSH's known weaknesses. Mitre
  in practice: cert pinning + client-side trust store hygiene
  prevents the MITM from happening; the outer TLS isn't expected
  to leak the inner stream.
- **Behavioral profiling**. A long-lived TLS connection to one
  server with high throughput is a behavioral signature distinct
  from typical browsing. Like every other TLS-mimicry protocol,
  this is out of scope.

## Wire Format

```
Client                                        Psiphon TLS-OSSH server
   |                                                  |
   |  TLS 1.3 ClientHello (uTLS profile, real or       |
   |  randomized fingerprint)                          |
   |    SNI = chosen cover domain                      |
   |    extensions in profile-prescribed order         |
   |    client_random[32]:                             |
   |       [0:16]  random nonce                        |
   |       [16:32] HMAC-SHA256(passthroughKey,         |
   |                            nonce)[:16]            |
   |    optional: padding (RFC 7685) randomizes        |
   |    record length; ClientHello record-             |
   |    fragmented across N TLS records.               |
   |  --------------------------------------------->   |
   |                                                  |
   |                                              Server peels client_random.
   |                                              Compute HMAC over nonce
   |                                              with passthroughKey =
   |                                              HKDF-SHA256(obfuscatedKey,
   |                                                          time_period?,
   |                                                          "tls-passthrough")
   |                                              Compare in constant time.
   |                                              If invalid: byte-relay to
   |                                              configured passthrough host.
   |                                              If valid: continue TLS.
   |  <----- ServerHello + cert + Finished -----     |
   |  TLS 1.3 handshake completes                    |
   |                                                  |
   |  Inside the encrypted TLS records:               |
   |    [16B OSSH seed | 4B magic 0x0BF5CA7E |        |
   |     4B pad-length | random padding | OSSH-       |
   |     wrapped SSH session]                         |
   |  <-----  bidirectional TLS app data  ----->     |
```

The 32 bytes that conventional TLS treats as the "client random"
are repurposed here as the auth tag. Real TLS clients fill these
with random bytes; statistically, an HMAC-tagged 16+16 layout is
indistinguishable from random.

The OSSH layer inside the TLS stream is bare OSSH — same RC4-keyed
preamble + magic + SSH session described in the
[`psiphon-ossh`](psiphon-ossh.md) entry. The TLS wrapper provides
modern cover; OSSH provides the inner authentication and SSH key
exchange.

## Cover Protocol

Real TLS 1.3 to whatever domain the server entry's `SNIServerName`
specifies. uTLS-driven ClientHello matches a real browser at the
byte level; `RandomizedTLSProfileSeed` cycles between profiles so
even repeat connections to the same server look like different
clients. With `FragmentClientHello` enabled, the ClientHello is
split across multiple TLS records — defeats the class of TCP-DPI
implementations that match SNI in a single TLS record (the niere-
2023 result).

## Authentication

In `client_random`. Construction (per
[`psiphon/common/obfuscator/passthrough.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/obfuscator/passthrough.go)):

```
passthroughKey = HKDF-SHA256(
    IKM    = obfuscatedKey,
    salt   = ASCII("tls-passthrough"),
    info   = optional 20-minute current-time epoch,
    length = TLS_PASSTHROUGH_KEY_SIZE = 32 bytes,
)

message[0:16]  = crypto/rand bytes
message[16:32] = HMAC-SHA256(passthroughKey, message[0:16])[:16]
```

Constants from `passthrough.go`:

```
TLS_PASSTHROUGH_NONCE_SIZE   = 16
TLS_PASSTHROUGH_KEY_SIZE     = 32
TLS_PASSTHROUGH_TIME_PERIOD  = 20 * time.Minute
TLS_PASSTHROUGH_HISTORY_TTL  = 60 * time.Minute   (3 × time period)
TLS_PASSTHROUGH_MESSAGE_SIZE = 32                   (= client_random size)
```

The optional time factor (passed as `useTimeFactor=true` for modern
clients) means the same `obfuscatedKey` produces a different
`passthroughKey` each 20 minutes. A captured ClientHello stops
verifying after at most one full time period, and the server's
replay-history cache catches re-use within the active window. The
flag exists so legacy clients/servers that don't yet implement the
time factor can still interoperate (`useTimeFactor=false` mode is
documented as supported but not preferred).

The OSSH `obfuscatedKey` is **shared** between the outer TLS-
passthrough HMAC and the inner OSSH RC4 derivation. That's the
single per-server secret distributed by Psiphon to each client.

After the TLS handshake, OSSH's own SSH key exchange runs end-to-
end; that's where session-level authentication of the server
identity is finalized.

## Probe Resistance

The TLS-passthrough mechanism is the canonical Psiphon design pattern
for TLS-based protocols. A probe:

1. Opens TCP, sends a normal TLS ClientHello with a random
   `client_random`.
2. Server peels the 32-byte `client_random`, computes the expected
   HMAC tag, compares — fails (probe doesn't know the obfuscated
   key).
3. Server falls into **passthrough mode**: forwards the bytes
   verbatim to a configured passthrough HTTPS upstream (typically
   a real website hosted on the same IP).
4. Probe completes a normal TLS handshake with the upstream's real
   cert and gets real HTTP responses.

This is the same design philosophy as REALITY's relay-by-default
and tlsmasq's masquerade — Psiphon implemented its version
independently around the same time. The big difference vs. REALITY
is that Psiphon's TLS-OSSH server **terminates** TLS itself with
its own cert; REALITY relays the entire TLS handshake to a real
cover site. The Psiphon server has to host both the proxy stack
and a passthrough service on the same IP.

## Implementation

Pinned at psiphon-tunnel-core master @
[`2b144a4`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/commit/2b144a4).

License: GPL-3.0. Pure Go. Outer TLS uses Psiphon's fork of utls
(`Psiphon-Labs/utls`).

Key files:

- [`psiphon/tlsTunnelConn.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/tlsTunnelConn.go) — `TLSTunnelConn`, `DialTLSTunnel`, padding parameter handling.
- [`psiphon/tlsDialer.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/tlsDialer.go) — `CustomTLSConfig` (the uTLS wrapper), `NewCustomTLSDialer`. Supports `TLSProfile` (named profile), `RandomizedTLSProfileSeed` (per-conn randomization), `FragmentClientHello`, `TLSPadding`, `NoDefaultTLSSessionID`, etc.
- [`psiphon/common/obfuscator/passthrough.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/obfuscator/passthrough.go) — `MakeTLSPassthroughMessage`, `VerifyTLSPassthroughMessage`, `derivePassthroughKey`. The complete spec for the in-`client_random` HMAC.
- [`psiphon/common/protocol/customTLSProfiles.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/protocol/customTLSProfiles.go) — bundled real-browser TLS profiles for uTLS-mode.
- [`psiphon/common/obfuscator/obfuscator.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/obfuscator/obfuscator.go) — the inner OSSH layer, see [`psiphon-ossh`](psiphon-ossh.md) for full details.
- [`psiphon/common/protocol/protocol.go`](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/2b144a4/psiphon/common/protocol/protocol.go) — `TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH = "TLS-OSSH"`.

## Known Weaknesses

- **Inner OSSH is still RC4-obfuscated**. The TLS layer protects
  the inner stream from passive observation, but if a censor
  performs a TLS man-in-the-middle (e.g. via a deployed root CA
  in a censored region's enterprise MITM box), the inner OSSH
  exposes RC4's known weaknesses. Mitigation: client-side cert
  pinning is the standard defense.
- **Server has to host a real passthrough site**. The probe-
  resistance story requires the same IP serve a credible HTTPS
  service (the "passthrough host" the failed-auth path forwards
  to). Operators have to maintain that site.
- **Time-factor clock drift**. The 20-minute time period requires
  client and server clocks to be roughly synchronized. The history
  TTL of 3× the period (`60 min`) gives some tolerance, but a
  client with a wildly wrong clock can fail to authenticate even
  with the right key.
- **TLS profile aging**. Like every uTLS-based protocol, the
  bundled TLS profiles must track real-browser releases or the
  fingerprint becomes anachronistic. `Psiphon-Labs/utls` is a
  separate fork that the Psiphon team maintains, parallel to
  refraction-networking/utls.
- **Throughput at the TLS layer**. RFC-7685 padding adds bytes
  to every connection; in high-throughput scenarios the overhead
  is non-trivial. Operators tune `tlsOSSHMinTLSPadding` /
  `MaxTLSPadding` per region.

## Deployment Notes

- Default-enabled for in-proxy variants: `INPROXY-WEBRTC-TLS-OSSH`
  is selected by Psiphon tactics in regions where TLS-based
  censorship is the primary concern.
- Recommended over bare `OSSH` in any deployment context where
  the network supports stable TLS connections (i.e. virtually all
  modern threats).
- Composes naturally with `psiphon-inproxy` — the inproxy
  WebRTC 1st hop carries TLS-OSSH bytes from the volunteer proxy
  to the Psiphon server.

## Cross-References

- Public corpus: `2023-niere-poster` — TLS record fragmentation;
  the technique implemented as the optional
  `FragmentClientHello` parameter.
- Related protocols (this catalog):
  - `psiphon-ossh` — the inner layer.
  - `psiphon-inproxy` — the orthogonal 1st-hop transport.
  - `vless-reality` — the closest design analog from the Xray
    family. Both use in-handshake auth + a relay-on-failure
    probe-resistance design. Differences: REALITY relays the
    entire TLS handshake to a real cover site; TLS-OSSH
    terminates TLS itself and passes through to a real site only
    on auth failure.
  - `tlsmasq` — Lantern's older relay-based design; same
    family of probe-resistance philosophy.
  - `samizdat` — Lantern's modern in-handshake-auth TLS protocol.
    Auth in `SessionID` (HMAC) vs. TLS-OSSH's auth in
    `client_random` (HMAC); HTTP/2 multiplexing on top vs.
    SSH-over-TLS.
