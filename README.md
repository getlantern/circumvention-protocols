# circumvention-protocols

A hand-curated catalog of deployed censorship-circumvention protocols,
distilled into a format the protocol-designer agent can consult
directly. One YAML metadata sidecar + one markdown body file per
protocol. Wrapped in a tiny MCP server so an LLM can ask "what's been
tried for active-probe resistance?" or "compare REALITY, naiveproxy,
and Cloak on TLS fingerprint matching" without re-reading the field
every conversation.

## Why this exists

There are excellent per-family READMEs (sing-box, Xray, V2Ray, lantern-
box, Psiphon, Outline, Tor pluggable transports), but no consolidated
catalog with a consistent structured schema and conventional summary
sections. This repo adds that one missing layer, focused on
**deployed protocols** (not papers — see
[`circumvention-corpus`](https://github.com/getlantern/circumvention-corpus)
for the academic literature).

Each entry is **carefully written, not auto-summarized from upstream
READMEs.** Many of these protocols have nuances that drive completely
different evasion properties (REALITY's borrowed real-cert vs Trojan's
TLS-to-real-server vs naiveproxy's identical-Chromium-stack are all
"TLS mimicry," but produce very different detection surfaces). A glib
summary that conflates the mechanisms will drive wrong design
recommendations downstream.

## Layout

```
schema/protocol.schema.json         JSON Schema for a single entry
protocols/<id>.yaml                 Metadata sidecar
text/<id>.md                        Rich body, FTS5 indexed
cmd/protocols-mcp/                  Go stdio MCP server
bin/                                (reserved)
```

## Entry shape

Each protocol has:

```yaml
id: vless-reality
name: "VLESS + REALITY"
family: xray              # xray | sing-box | lantern | psiphon | outline | tor-pt | wireguard | other
status: active            # active | deprecated | research-only | blocked-broadly
languages: [go]
upstream:
  repo: https://github.com/XTLS/Xray-core
  docs: https://xtls.github.io/...
  spec: https://github.com/XTLS/REALITY
implementations:          # other repos shipping the same wire protocol
  - {family: sing-box, repo: github.com/sagernet/sing-box, notes: "..."}
references: [reality-2023]            # IDs in circumvention-corpus
internal_refs: [2026-04-non-protocol-evasion]   # IDs in circumvention-corpus-private
tags: [tls-mimicry, anti-probe]
license: MPL-2.0
body_path: text/vless-reality.md
summary: |
  One-paragraph summary surfaced by list/search hits.
```

Markdown body uses conventional H2 sections so cross-protocol search
hits comparable spots:

```
## TL;DR              one or two sentences
## Threat Model       which censors / detection methods does this target?
## Wire Format        handshake step-by-step + steady-state framing
## Cover Protocol     what an observer sees on the wire
## Authentication     how peers prove identity
## Probe Resistance   what happens when an attacker connects directly?
## Implementation     key files / functions; permalinks to upstream
## Known Weaknesses   published or observed detection methods
## Deployment Notes   where deployed, where blocked, operational caveats
## Cross-References   public-corpus paper IDs, internal-docs IDs, related protocol IDs
```

## MCP tools

| Tool | Purpose |
| --- | --- |
| `search_protocols(query, family?, status?, tag?, limit?)` | FTS5 search over name + body |
| `get_protocol(id, include_body?=true)` | Full metadata + body |
| `list_protocols(family?, status?, tag?)` | Metadata only |
| `list_families()` / `list_tags()` | Corpus overview with counts |
| `compare_protocols(ids[])` | Pull metadata + summaries for N protocols at once |

## Authoring guidance

When adding a new entry:

1. **Read the upstream code at a specific commit.** Note the SHA in
   the `Implementation` section. Don't summarize from the README —
   READMEs are often marketing copy and miss the mechanism.
2. **Distinguish the wire protocol from its transports.** "vless over
   websocket-tls" is a transport stack composed from two entries
   (`vless-*` for the inner protocol; the websocket wrapping is a
   transport choice, not its own protocol entry).
3. **Cross-reference the public corpus** for any paper that analyzes
   this specific protocol — fill in `references:`. Prefer specific
   findings ("USENIX 2023 entropy detection only flags ~0.6% of
   real-world non-circumvention traffic, so this protocol's high-
   entropy first packet is a real liability") over vague ones.
4. **When in doubt, leave the section short and accurate** rather
   than confident-and-wrong.

## Pairs with

- `circumvention-corpus` (academic papers about detection / defense)
- `circumvention-corpus-private` (Lantern-internal analyses, partner
  drafts, leaked material)

The protocol-designer skill in `getlantern/claude-plugins` knows about
all three and is expected to consult them in order:
internal-docs → protocols → public corpus → the open web.
