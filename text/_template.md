# Protocol Name

## TL;DR

One or two sentences. What it does, against which threat, in what cover.

## Threat Model

Which censors and which detection methods does this target? Be specific
(e.g. "GFW fully-encrypted-traffic detection [USENIX 2023]" not just
"DPI"). Note what it does *not* defend against.

## Wire Format

Handshake step-by-step + steady-state framing. Concrete enough that a
reader who knows TLS / QUIC / etc. can sketch the bytes on the wire.
Include nuances that distinguish this from look-alike protocols.

## Cover Protocol

What an observer sees on the wire. "Looks like X to a passive
observer because <specific reason>."

## Authentication

How peers prove identity / authorize the channel. Static key?
Cert-fingerprint? Embedded in TLS? Pre-handshake bytes?

## Probe Resistance

What happens when an attacker connects directly to the server /
replays a captured ClientHello? "Falls back to a real web server" /
"Closes after 30s of silence" / "No auth → indistinguishable from
real X."

## Implementation

Pin the upstream commit. Key files / functions. Permalinks where they
help. Implementation language(s).

## Known Weaknesses

Published or observed detection methods that work against this. Cite
papers from `circumvention-corpus` by ID where applicable.

## Deployment Notes

Where it's actually deployed (which apps, which censorship contexts).
Where it's been blocked. Operational caveats (e.g. "requires real
fronting domain", "needs UDP-friendly path").

## Cross-References

- public corpus paper IDs (papers that analyze this)
- internal docs IDs (Lantern-specific analyses)
- related protocol IDs in this catalog
