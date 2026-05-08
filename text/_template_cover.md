# Cover Protocol Name

## TL;DR

One or two sentences. What this protocol does, who uses it,
and why it might be a useful mimicry candidate (high collateral
cost? distinctive cover shape? underutilized?).

## Standardization

RFC numbers, IETF working group, current status (proposed /
draft / standard / historic), brief deployment history. If
the protocol is non-IETF (e.g. de-facto-standard or
vendor-controlled), say so explicitly and name the controlling
body.

## Wire Format

The bytes a passive observer sees on the wire. Concrete enough
that someone implementing a mimic could sketch the segments.
Point to the relevant RFC sections by number where applicable.

## Traffic Patterns

Timing, packet-size distributions, flow shapes, idle behavior,
session duration profiles. The behavioral signature beyond
just the byte shape — what would a behavioral DPI classifier
match on?

## Encryption Surface

Two lists:

- **Visible**: fields a passive observer can read in cleartext
  (SNI, ALPN, IP, port, version markers, ...).
- **Encrypted**: fields covered by the protocol's confidentiality
  layer (body, headers, payload, ...).

If the protocol has multiple layers (e.g. TCP/IP vs. TLS vs.
application data), describe each layer's surface separately.

## Common Implementations

Major real-world software that speaks this protocol — browsers,
OS network stacks, server stacks, libraries. Drives the JA3 / JA4
fingerprint diversity available to a mimic; "match Chrome" only
works if Chrome ships a recognizable implementation.

## Prevalence

How common is this on the wire? Cite measurement work where
possible — Cloudflare Radar, M-Lab, USENIX measurement papers,
public-corpus papers. Give numeric ranges where they're
defensible; otherwise be explicit that the claim is qualitative.

## Collateral Cost

What breaks if a censor wholesale-blocks this protocol? Be
specific:

- Which categories of users / businesses / services lose
  function?
- Are there already-deployed alternatives the censor could route
  to?
- Has the censor *attempted* a wholesale block in the past?
  What was the outcome?

The point is to characterise the censor's economic / political
budget for blocking this cover, which determines how durable
mimicry-based protection actually is.

## Mimicry Considerations

What's hard about mimicking this protocol convincingly:

- TLS-fingerprint freshness (if applicable).
- Behavioral patterns the mimic has to reproduce (timing,
  flow shape, packet sizes).
- Implementation diversity in the wild — does the censor see
  many implementations or a near-monopoly?
- Side-channel risks (DNS for SNI, server-cert audit trails
  in CT, etc.).
- Practical deployment constraints (need for a real backing
  service? Real cert? Cooperating CDN?).

## Censor Practice

History of what censors have actually done to this protocol —
blocking events, fingerprinting research, regulatory attacks.
Cite specific incidents and dates. If the protocol has *not*
been blocked, say that and characterise what would change the
calculus.

## Used as Cover By

Cross-references to circumvention entries in this catalog
that mimic / ride over this protocol. Empty for cover protocols
that haven't been used as cover yet (these are the *underutilized
candidates* — sometimes the most interesting entries).

## Cross-References

- Public corpus paper IDs (papers that measure / analyze this
  protocol).
- Internal docs IDs (Lantern-internal analyses).
- Sibling cover protocols in this catalog (e.g. TLS 1.3 ↔ QUIC
  share much of the design DNA).
