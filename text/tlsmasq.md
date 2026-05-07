# tlsmasq

## TL;DR

Lantern protocol with a two-phase design:
**(1) the listener proxies an entire TLS handshake to a real origin
TLS server** so both peers see the real cert chain and pick a real
version + cipher suite (no proxy-controlled cert anywhere); **(2) the
client sends a TLS-formatted "completion signal" using a pre-shared
52-byte secret as the per-record key** — a real signal turns the
already-handshaken connection into a relay for a *second* fresh TLS
handshake whose records ride on the original session's wire format.
Probes that don't know the secret never trigger phase 2 and get a
real conversation with the real origin.

**Still in production** via the older flashlight-based Lantern stack;
not yet ported to the newer `lantern-box` / sing-box-integrated stack.
The team's `samizdat` docs explicitly cite tlsmasq as inspiration —
samizdat reuses the masquerade-on-fail idea with simpler in-band auth
— and `vless-reality` later realized the same relay-by-default pattern
deeper inside the TLS state machine.

## Threat Model

The same TLS-cert-reputation / SNI / active-probing problems that
later motivated REALITY and samizdat:

- **Cert reputation**: any cert the proxy presents itself is a
  per-server signal that ages and gets blocked. Solution: relay the
  *real* origin's cert through the handshake.
- **Active probing**: a censor that connects to the proxy IP and
  speaks normal TLS expects to see the cert/behavior of whatever the
  cover domain advertises. Solution: when the probe doesn't send the
  completion signal, just keep proxying to the real origin until it
  closes — the probe sees a real microsoft.com (or whoever) end to
  end.
- **In-handshake injection / MITM**: a censor could inject garbage
  bytes during the proxied handshake to test whether the connection
  is "real" (a real origin would error; a tlsmasq listener might
  recover and continue). Solution: the server's completion signal
  carries an HMAC over the entire proxied-handshake transcript —
  any injection breaks the HMAC and a real client refuses to proceed.

It does **not** address SNI extraction by itself — the proxied
ClientHello carries whatever SNI the client/origin negotiate, so
operators must pick a cover domain whose SNI is OK to expose.

## Wire Format

```
Client (tlsmasq dialer)             Listener                          Origin (real TLS server, e.g. microsoft.com)
  |                                    |                                          |
  |  TCP connect                       |                                          |
  |  TLS ClientHello ----------------> |                                          |
  |                                    |  buffer + relay byte-for-byte ---------> |
  |                                    |                                          |
  |  <----------- TLS ServerHello + cert chain (REAL origin's real cert) -------- |
  |  ... full proxied TLS handshake bytes flow through the listener,              |
  |      both sides record an HMAC of the transcript with the pre-shared secret.  |
  |  Negotiated: version V, suite S (whatever the origin chose).                  |
  |                                    |                                          |
  |  Client signal: ONE TLS record,    |  Listener tries to decrypt every record  |
  |  encrypted with secret-derived     |  it sees from client using a connection  |
  |  keys, formatted to match V + S    |  state keyed by the SECRET. The first    |
  |  exactly. Contains a 32-byte       |  one that decrypts is the signal.        |
  |  nonce: 8B expiration (UTC ns)     |                                          |
  |  || 24B random.                    |  On signal:                              |
  |                                    |    - check nonce TTL + replay cache      |
  |                                    |    - verify HMAC over transcript         |
  |                                    |    - close origin connection             |
  |                                    |    - reply with own signal containing    |
  |                                    |      HMAC(transcript) for client to vfy  |
  |                                    |                                          |
  |  Hijack handshake (second TLS)     |  Both sides perform a NEW TLS handshake  |
  |  starts. New ClientHello, new      |  with fresh keys. The new handshake's    |
  |  ServerHello, new keys.            |  records are written using the disguised |
  |  Forced version V, suite S.        |  conn — bytes look like ongoing app data |
  |                                    |  of the original session.                |
  |                                    |                                          |
  |  Application data over the         |                                          |
  |  hijacked TLS connection.          |                                          |
```

## Cover Protocol

To a passive observer: a single TLS connection to `origin.example.com`
with the origin's real cert, then ongoing encrypted records. Records
during the second (hijacked) handshake are encrypted under the
*first* session's negotiated version + suite, so they're
record-format-identical to ordinary application data.

## Authentication

In-band, post-handshake.

- **Pre-shared secret**: 52 bytes (`ptlshs.Secret = [52]byte`).
- **Completion signal**: a single TLS record, formatted to match the
  proxied handshake's negotiated version V and cipher suite S, but
  encrypted with keys derived from the secret + parameters extracted
  from the proxied handshake (server random etc.). The plaintext
  contains a 32-byte nonce: `[0:8]` little-endian Unix-nano
  expiration timestamp, `[8:32]` random.
- **Replay protection**: server keeps a `nonceCache` (default sweep
  every 1 min, default nonce TTL 30 min). Replay → drop.
- **Transcript HMAC**: both sides feed every byte of the proxied
  handshake into `HMAC-SHA256(secret)`. The server's completion
  signal contains its HMAC; the client compares against its own.
  Mismatch → close. Prevents undetected mid-handshake byte
  injection.

A connection that never sends a completion signal — or sends one
that fails any of the checks above — is just a passive relay between
the dialer and the real origin until either side closes.

## Probe Resistance

By construction. The listener doesn't have a "is this a probe?"
branch — it has a "did this connection eventually send a valid
completion signal?" branch, and the default behavior is "keep
proxying to origin." So:

- A probe that connects and sends a normal ClientHello → handshake
  proxied to origin → probe finishes a real TLS session with origin
  → probe sees real cert, real ServerHello quirks, real HTTP after.
  Listener never reveals tlsmasq.
- A probe that injects garbage during the handshake → origin errors
  out → listener returns the error and tears down both sides; probe
  sees normal-looking origin error.
- A probe that finishes the handshake but doesn't send a valid
  signal → connection sits idle / continues to be relayed to origin
  → probe sees no anomaly.

This relay-by-default model is the same idea REALITY later
implemented with much tighter integration into the TLS state
machine. tlsmasq did it as a wrapper layer above any standard TLS
implementation, which is more portable but slightly more expensive
(extra MITM hooks on every connection).

## Implementation

Pinned at upstream commit
[`6e479a5`](https://github.com/getlantern/tlsmasq/commit/6e479a5)
(March 2023 — last commit on the repo).

Repo: `github.com/getlantern/tlsmasq` (Apache-2.0). Pure Go. ~700
lines core + a few hundred in `ptlshs/`.

Two layered packages:

- [`ptlshs/`](https://github.com/getlantern/tlsmasq/tree/6e479a5/ptlshs) — "Proxied TLS handshake" — the primitive: dial, relay handshake, watch for completion signal, enable secret-keyed record encryption.
- [`tlsmasq` (root)](https://github.com/getlantern/tlsmasq/tree/6e479a5) — wraps `ptlshs.Conn` and adds the "hijack" — a second TLS handshake whose bytes ride inside disguised records.

Key files / functions:

- [`ptlshs/ptlshs.go`](https://github.com/getlantern/tlsmasq/blob/6e479a5/ptlshs/ptlshs.go) — `DialerConfig` / `ListenerConfig`, `Secret [52]byte`, `Handshaker` interface (decouples the actual TLS implementation — the dialer can use a uTLS-fingerprinted handshaker).
- [`ptlshs/conn.go`](https://github.com/getlantern/tlsmasq/blob/6e479a5/ptlshs/conn.go) — `clientConn.handshake` (lines 168–226) writes the completion signal at line 214 and verifies the server's transcript HMAC at line 219; `serverConn.handshake` (lines 469–565) is the listener half, including the explicit fallback at line 506 (`proxyUntilClose`) when the client doesn't send a recognizable ClientHello.
- [`ptlshs/nonce.go`](https://github.com/getlantern/tlsmasq/blob/6e479a5/ptlshs/nonce.go) — `nonce [32]byte`, layout documented inline, replay cache.
- [`hijack.go`](https://github.com/getlantern/tlsmasq/blob/6e479a5/hijack.go) — `hijack` (line 34): runs the inner TLS handshake; `ensureParameters` (line 63) clamps the new `tls.Config` to the negotiated `Version` + `CipherSuite`; `disguise` (line 124) wraps the conn so handshake records use the secret-derived TLS connection state.
- [`conn.go`](https://github.com/getlantern/tlsmasq/blob/6e479a5/conn.go) — top-level `tlsmasq.Conn` that delegates handshake to `ptlshs` then `hijack`.

Defaults: `DefaultNonceTTL = 30 * time.Minute`,
`DefaultNonceSweepInterval = 1 * time.Minute`. The
`Handshaker` interface lets the dialer plug in uTLS for ClientHello
fingerprint mimicry — the standard library handshaker is provided as
`StdLibHandshaker` but documented as "fingerprintable" and not
recommended for circumvention use.

## Known Weaknesses

- **No SNI evasion**: the proxied ClientHello carries the cover
  domain's SNI in the clear (relayed to origin and back). Operators
  must accept that the cover domain is observable.
- **First-byte latency cost**: the proxied handshake is a *real*
  handshake to a real origin, so connection setup includes a full
  RTT to origin in addition to the client↔listener path. samizdat
  and REALITY both squeeze this latency by avoiding the round-trip
  to origin on the success path.
- **Listener load**: every probe completes a real handshake with
  the origin. If a censor scans heavily, the listener will hold
  open many origin connections. samizdat's design (drop-on-auth-fail
  before proxying) is cheaper for the proxy operator.
- **Origin server dependence**: if the origin (e.g. microsoft.com)
  changes behavior or rate-limits the proxy IP, the cover collapses.
- **Quiet upstream**: the repo hasn't taken commits since
  2023-03-01, so newer attacks (e.g. post-2023 TLS-record-fragmentation
  analyses, post-2023 FET refinements) haven't been engineered against
  in this codebase. Not deprecated — the protocol is still in
  production via flashlight — but lacks the active hardening loop
  that samizdat and reflex get.

## Deployment Notes

- **In production** via Lantern's flashlight-based stack. New
  Lantern features land in `lantern-box` (sing-box) where the
  default is `samizdat`; tlsmasq has not been ported into that
  stack but is not deprecated.
- Conceptually the closest sibling to `vless-reality`: both use
  relay-by-default + secret-keyed in-handshake authentication. The
  big mechanism difference is that REALITY *terminates* TLS itself
  (signing an ephemeral cert under a key derived from a TLS-
  ephemeral-key ECDH) while tlsmasq lets the *origin* terminate TLS
  and then opens a *second* TLS session inside the same wire.
- Inspiration trail (per the upstream samizdat README):
  tlsmasq → samizdat (in-band SessionID HMAC + masquerade-on-fail)
  → reflex (role reversal, no client-direction handshake at all).

## Cross-References

- Related protocols (this catalog):
  - `samizdat` — Lantern's successor. Combines tlsmasq's masquerade
    idea with simpler in-band SessionID auth and HTTP/2
    multiplexing.
  - `reflex` — Lantern's other successor. Different evasion family
    (TLS role reversal) but same probe-resistance philosophy.
  - `vless-reality` — independent realization of the same "relay
    by default, intercept on success" pattern, deeper into the
    TLS state machine.
