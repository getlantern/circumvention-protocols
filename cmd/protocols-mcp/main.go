// protocols-mcp is a stdio MCP server over a local catalog of
// censorship-circumvention protocols. See ../../README.md for the
// schema and authoring guidance.
//
// At startup the server walks the corpus dir, parses every YAML in
// protocols/, reads the corresponding markdown body, and builds an
// in-memory SQLite FTS5 index. The repo is the source of truth — the
// index is rebuilt on every launch, no separate state file.
package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	_ "modernc.org/sqlite"

	"gopkg.in/yaml.v3"
)

const (
	serverName    = "protocols"
	serverVersion = "0.1.0"
	protocolRev   = "2024-11-05"
)

// Implementation is one entry in a protocol's implementations: list.
type Implementation struct {
	Family string `yaml:"family" json:"family"`
	Repo   string `yaml:"repo" json:"repo"`
	Notes  string `yaml:"notes,omitempty" json:"notes,omitempty"`
}

// Upstream is the canonical / originating implementation.
type Upstream struct {
	Repo string `yaml:"repo,omitempty" json:"repo,omitempty"`
	Docs string `yaml:"docs,omitempty" json:"docs,omitempty"`
	Spec string `yaml:"spec,omitempty" json:"spec,omitempty"`
}

// CryptoSurface is the visible-vs-encrypted breakdown for a cover protocol.
type CryptoSurface struct {
	Visible   []string `yaml:"visible,omitempty" json:"visible,omitempty"`
	Encrypted []string `yaml:"encrypted,omitempty" json:"encrypted,omitempty"`
}

// CommonImplementation is a real-world implementation of a cover protocol.
type CommonImplementation struct {
	Name   string `yaml:"name" json:"name"`
	Vendor string `yaml:"vendor,omitempty" json:"vendor,omitempty"`
	Scope  string `yaml:"scope,omitempty" json:"scope,omitempty"`
}

// Protocol mirrors schema/protocol.schema.json. Holds both circumvention and
// cover-protocol entries, distinguished by Kind.
type Protocol struct {
	ID              string           `yaml:"id" json:"id"`
	Name            string           `yaml:"name" json:"name"`
	Kind            string           `yaml:"kind,omitempty" json:"kind"`
	Family          string           `yaml:"family,omitempty" json:"family,omitempty"`
	Status          string           `yaml:"status,omitempty" json:"status,omitempty"`
	Languages       []string         `yaml:"languages,omitempty" json:"languages,omitempty"`
	Upstream        *Upstream        `yaml:"upstream,omitempty" json:"upstream,omitempty"`
	Implementations []Implementation `yaml:"implementations,omitempty" json:"implementations,omitempty"`
	References      []string         `yaml:"references,omitempty" json:"references,omitempty"`
	InternalRefs    []string         `yaml:"internal_refs,omitempty" json:"internal_refs,omitempty"`
	Tags            []string         `yaml:"tags,omitempty" json:"tags,omitempty"`
	License         string           `yaml:"license,omitempty" json:"license,omitempty"`
	BodyPath        string           `yaml:"body_path" json:"body_path"`
	Summary         string           `yaml:"summary" json:"summary"`

	// Cover-entry-specific fields.
	RFC                   []int                  `yaml:"rfc,omitempty" json:"rfc,omitempty"`
	Category              string                 `yaml:"category,omitempty" json:"category,omitempty"`
	CollateralCost        string                 `yaml:"collateral_cost,omitempty" json:"collateral_cost,omitempty"`
	CryptoSurface         *CryptoSurface         `yaml:"crypto_surface,omitempty" json:"crypto_surface,omitempty"`
	CommonImplementations []CommonImplementation `yaml:"common_implementations,omitempty" json:"common_implementations,omitempty"`
	UsedAsCoverBy         []string               `yaml:"used_as_cover_by,omitempty" json:"used_as_cover_by,omitempty"`

	// Circumvention-entry-specific field: which cover protocols this mimics.
	Mimics []string `yaml:"mimics,omitempty" json:"mimics,omitempty"`

	// Filled by load(); not in YAML.
	Body string `yaml:"-" json:"-"`
}

type store struct {
	mu        sync.RWMutex
	protos    map[string]*Protocol
	corpusDir string
	db        *sql.DB
}

func main() {
	var corpus string
	flag.StringVar(&corpus, "corpus", ".", "path to circumvention-protocols root")
	flag.Parse()

	abs, err := filepath.Abs(corpus)
	if err != nil {
		log.Fatalf("resolve --corpus: %v", err)
	}

	s, err := newStore(abs)
	if err != nil {
		log.Fatalf("load corpus: %v", err)
	}
	defer s.db.Close()

	log.Printf("protocols-mcp v%s ready: %d protocols from %s", serverVersion, len(s.protos), abs)
	if err := s.serve(os.Stdin, os.Stdout); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// ---- loader ----

func newStore(corpus string) (*store, error) {
	s := &store{
		protos:    map[string]*Protocol{},
		corpusDir: corpus,
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	s.db = db
	if _, err := db.Exec(`
		CREATE VIRTUAL TABLE protos USING fts5(
			id UNINDEXED,
			name,
			summary,
			body,
			tokenize = 'porter unicode61'
		);
	`); err != nil {
		return nil, fmt.Errorf("create fts table: %w", err)
	}

	dir := filepath.Join(corpus, "protocols")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read protocols dir %s: %w", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".yaml") || strings.HasPrefix(name, "_") {
			continue
		}
		full := filepath.Join(dir, name)
		raw, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", full, err)
		}
		p := &Protocol{}
		if err := yaml.Unmarshal(raw, p); err != nil {
			return nil, fmt.Errorf("parse %s: %w", full, err)
		}
		if p.ID == "" {
			return nil, fmt.Errorf("%s: missing id", full)
		}
		if p.BodyPath == "" {
			return nil, fmt.Errorf("%s: missing body_path", full)
		}

		bodyFull := filepath.Join(corpus, p.BodyPath)
		body, err := os.ReadFile(bodyFull)
		if err != nil {
			return nil, fmt.Errorf("read body %s: %w", bodyFull, err)
		}
		p.Body = string(body)

		if _, dup := s.protos[p.ID]; dup {
			return nil, fmt.Errorf("duplicate id %q", p.ID)
		}
		s.protos[p.ID] = p
		if _, err := db.Exec(
			`INSERT INTO protos (id, name, summary, body) VALUES (?, ?, ?, ?)`,
			p.ID, p.Name, p.Summary, p.Body,
		); err != nil {
			return nil, fmt.Errorf("index %s: %w", p.ID, err)
		}
	}
	return s, nil
}

// ---- MCP serve loop ----

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *store) serve(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1<<20), 64<<20)
	enc := json.NewEncoder(out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			log.Printf("bad request: %v", err)
			continue
		}
		resp := s.handle(req)
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("encode response: %w", err)
		}
	}
	return scanner.Err()
}

func (s *store) handle(req rpcRequest) rpcResponse {
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": protocolRev,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "version": serverVersion},
		}
	case "tools/list":
		resp.Result = map[string]any{"tools": tools}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &rpcError{Code: -32602, Message: err.Error()}
			return resp
		}
		text, err := s.callTool(p.Name, p.Arguments)
		if err != nil {
			resp.Error = &rpcError{Code: -32000, Message: err.Error()}
			return resp
		}
		resp.Result = map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
		}
	case "notifications/initialized":
		// no-op
	default:
		resp.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
	return resp
}

// ---- tools ----

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

var tools = []tool{
	{
		Name: "search_protocols",
		Description: "Full-text search over the catalog. The catalog holds two kinds of entries: deployed " +
			"CIRCUMVENTION protocols (sing-box, Xray, V2Ray, Lantern, Psiphon, Outline, Tor pluggable transports, ...) " +
			"and dominant-Internet COVER protocols (TLS, QUIC, DoH, WebRTC, etc.) that circumvention designs may mimic " +
			"to gain collateral-freedom protection. Use the kind filter to restrict to one or the other; default returns both.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query":  map[string]any{"type": "string", "description": "FTS5 query: bare words or phrases. Examples: 'tls mimicry probe resistance', '\"role reversal\"', 'quic salamander'."},
				"kind":   map[string]any{"type": "string", "description": "Restrict to one entry kind: 'circumvention' or 'cover'."},
				"family": map[string]any{"type": "string", "description": "Restrict to one originating family (lantern / sing-box / xray / v2ray / psiphon / outline / tor-pt / wireguard / openvpn / cover / other)."},
				"status": map[string]any{"type": "string", "description": "Restrict to one status (active / deprecated / research-only / blocked-broadly)."},
				"tag":    map[string]any{"type": "string", "description": "Restrict to protocols carrying this tag."},
				"limit":  map[string]any{"type": "integer", "description": "Max hits (default 20)."},
			},
			"required": []string{"query"},
		},
	},
	{
		Name:        "get_protocol",
		Description: "Return the full metadata + body for one protocol by id. Use after search_protocols / list_protocols to read the source.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":           map[string]any{"type": "string"},
				"include_body": map[string]any{"type": "boolean", "description": "Include the full markdown body (default true)."},
			},
			"required": []string{"id"},
		},
	},
	{
		Name:        "list_protocols",
		Description: "List protocols (metadata only). Filter by kind / family / status / tag. Default returns both circumvention and cover entries.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"kind":   map[string]any{"type": "string", "description": "'circumvention' or 'cover'"},
				"family": map[string]any{"type": "string"},
				"status": map[string]any{"type": "string"},
				"tag":    map[string]any{"type": "string"},
			},
		},
	},
	{
		Name:        "list_families",
		Description: "Distinct family values present in the catalog, with protocol counts.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	},
	{
		Name:        "list_tags",
		Description: "Distinct tags, sorted by protocol count.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	},
	{
		Name: "compare_protocols",
		Description: "Pull metadata + summaries for several protocols at once for side-by-side reasoning. " +
			"Body is omitted to keep the payload small — fetch individual bodies with get_protocol if needed.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"ids": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "Protocol IDs to compare. Typically 2-6.",
				},
			},
			"required": []string{"ids"},
		},
	},
}

func (s *store) callTool(name string, raw json.RawMessage) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch name {
	case "search_protocols":
		return s.toolSearch(raw)
	case "get_protocol":
		return s.toolGet(raw)
	case "list_protocols":
		return s.toolList(raw)
	case "list_families":
		return s.toolListFamilies()
	case "list_tags":
		return s.toolListTags()
	case "compare_protocols":
		return s.toolCompare(raw)
	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
}

func (s *store) toolSearch(raw json.RawMessage) (string, error) {
	var args struct {
		Query  string `json:"query"`
		Kind   string `json:"kind"`
		Family string `json:"family"`
		Status string `json:"status"`
		Tag    string `json:"tag"`
		Limit  int    `json:"limit"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", err
	}
	if strings.TrimSpace(args.Query) == "" {
		return "", errors.New("query is required")
	}
	if args.Limit <= 0 {
		args.Limit = 20
	}

	rows, err := s.db.Query(
		`SELECT id, snippet(protos, 3, '«', '»', ' … ', 32) AS snip, bm25(protos) AS rank
		 FROM protos
		 WHERE protos MATCH ?
		 ORDER BY rank
		 LIMIT ?`,
		sanitizeFTSQuery(args.Query), args.Limit*4,
	)
	if err != nil {
		return "", fmt.Errorf("fts query: %w", err)
	}
	defer rows.Close()

	type hit struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Kind    string   `json:"kind"`
		Family  string   `json:"family,omitempty"`
		Status  string   `json:"status,omitempty"`
		Tags    []string `json:"tags,omitempty"`
		Summary string   `json:"summary"`
		Snippet string   `json:"snippet"`
	}
	out := make([]hit, 0, args.Limit)
	for rows.Next() {
		var id, snip string
		var rank float64
		if err := rows.Scan(&id, &snip, &rank); err != nil {
			return "", err
		}
		p, ok := s.protos[id]
		if !ok {
			continue
		}
		if args.Kind != "" && protoKind(p) != args.Kind {
			continue
		}
		if args.Family != "" && p.Family != args.Family {
			continue
		}
		if args.Status != "" && p.Status != args.Status {
			continue
		}
		if args.Tag != "" && !contains(p.Tags, args.Tag) {
			continue
		}
		out = append(out, hit{
			ID: p.ID, Name: p.Name, Kind: protoKind(p), Family: p.Family, Status: p.Status,
			Tags: p.Tags, Summary: p.Summary, Snippet: snip,
		})
		if len(out) >= args.Limit {
			break
		}
	}
	return jsonString(out)
}

// protoKind returns the entry kind, defaulting to "circumvention" for entries
// that pre-date the kind field.
func protoKind(p *Protocol) string {
	if p.Kind == "" {
		return "circumvention"
	}
	return p.Kind
}

func (s *store) toolGet(raw json.RawMessage) (string, error) {
	var args struct {
		ID          string `json:"id"`
		IncludeBody *bool  `json:"include_body"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", err
	}
	p, ok := s.protos[args.ID]
	if !ok {
		return "", fmt.Errorf("no protocol with id %q", args.ID)
	}
	include := true
	if args.IncludeBody != nil {
		include = *args.IncludeBody
	}
	out := map[string]any{
		"id":                     p.ID,
		"name":                   p.Name,
		"kind":                   protoKind(p),
		"family":                 p.Family,
		"status":                 p.Status,
		"languages":              p.Languages,
		"upstream":               p.Upstream,
		"implementations":        p.Implementations,
		"references":             p.References,
		"internal_refs":          p.InternalRefs,
		"tags":                   p.Tags,
		"license":                p.License,
		"body_path":              p.BodyPath,
		"summary":                p.Summary,
		"rfc":                    p.RFC,
		"category":               p.Category,
		"collateral_cost":        p.CollateralCost,
		"crypto_surface":         p.CryptoSurface,
		"common_implementations": p.CommonImplementations,
		"used_as_cover_by":       p.UsedAsCoverBy,
		"mimics":                 p.Mimics,
	}
	if include {
		out["body"] = p.Body
	}
	return jsonString(out)
}

func (s *store) toolList(raw json.RawMessage) (string, error) {
	var args struct {
		Kind   string `json:"kind"`
		Family string `json:"family"`
		Status string `json:"status"`
		Tag    string `json:"tag"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
	}
	type row struct {
		ID             string   `json:"id"`
		Name           string   `json:"name"`
		Kind           string   `json:"kind"`
		Family         string   `json:"family,omitempty"`
		Status         string   `json:"status,omitempty"`
		Category       string   `json:"category,omitempty"`
		CollateralCost string   `json:"collateral_cost,omitempty"`
		Tags           []string `json:"tags,omitempty"`
		Summary        string   `json:"summary"`
	}
	out := []row{}
	for _, p := range s.protos {
		if args.Kind != "" && protoKind(p) != args.Kind {
			continue
		}
		if args.Family != "" && p.Family != args.Family {
			continue
		}
		if args.Status != "" && p.Status != args.Status {
			continue
		}
		if args.Tag != "" && !contains(p.Tags, args.Tag) {
			continue
		}
		out = append(out, row{
			ID: p.ID, Name: p.Name, Kind: protoKind(p),
			Family: p.Family, Status: p.Status,
			Category: p.Category, CollateralCost: p.CollateralCost,
			Tags: p.Tags, Summary: p.Summary,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Name < out[j].Name
	})
	return jsonString(out)
}

func (s *store) toolListFamilies() (string, error) {
	counts := map[string]int{}
	for _, p := range s.protos {
		counts[p.Family]++
	}
	type row struct {
		Family string `json:"family"`
		Count  int    `json:"count"`
	}
	out := make([]row, 0, len(counts))
	for k, v := range counts {
		out = append(out, row{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return jsonString(out)
}

func (s *store) toolListTags() (string, error) {
	counts := map[string]int{}
	for _, p := range s.protos {
		for _, t := range p.Tags {
			counts[t]++
		}
	}
	type row struct {
		Tag   string `json:"tag"`
		Count int    `json:"count"`
	}
	out := make([]row, 0, len(counts))
	for k, v := range counts {
		out = append(out, row{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Tag < out[j].Tag
	})
	return jsonString(out)
}

func (s *store) toolCompare(raw json.RawMessage) (string, error) {
	var args struct {
		IDs []string `json:"ids"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", err
	}
	if len(args.IDs) == 0 {
		return "", errors.New("ids is required")
	}
	type row struct {
		ID              string           `json:"id"`
		Name            string           `json:"name"`
		Family          string           `json:"family"`
		Status          string           `json:"status"`
		Languages       []string         `json:"languages,omitempty"`
		Upstream        *Upstream        `json:"upstream,omitempty"`
		Implementations []Implementation `json:"implementations,omitempty"`
		References      []string         `json:"references,omitempty"`
		InternalRefs    []string         `json:"internal_refs,omitempty"`
		Tags            []string         `json:"tags,omitempty"`
		Summary         string           `json:"summary"`
	}
	out := make([]row, 0, len(args.IDs))
	missing := []string{}
	for _, id := range args.IDs {
		p, ok := s.protos[id]
		if !ok {
			missing = append(missing, id)
			continue
		}
		out = append(out, row{
			ID: p.ID, Name: p.Name, Family: p.Family, Status: p.Status,
			Languages: p.Languages, Upstream: p.Upstream, Implementations: p.Implementations,
			References: p.References, InternalRefs: p.InternalRefs, Tags: p.Tags, Summary: p.Summary,
		})
	}
	resp := map[string]any{"protocols": out}
	if len(missing) > 0 {
		resp["missing"] = missing
	}
	return jsonString(resp)
}

// ---- helpers ----

func jsonString(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// sanitizeFTSQuery makes a free-form user query safe for FTS5's MATCH
// parser. The parser rejects punctuation like "." and ":" outside of
// column-qualifier syntax, so a query like "ok.ru" or "samizdat:auth"
// fails with a syntax error. We tokenize on whitespace, drop any chars
// that aren't word characters / quote / hyphen / asterisk (the FTS5
// special chars we want to preserve for phrase / NOT / prefix queries),
// drop empty tokens, and AND-join with spaces. That reduces "ok.ru"
// to "ok ru" — which still matches an indexed body containing "ok.ru"
// because the unicode61 tokenizer splits the indexed text on the same
// punctuation.
func sanitizeFTSQuery(q string) string {
	var out strings.Builder
	for _, tok := range strings.Fields(q) {
		var clean strings.Builder
		for _, r := range tok {
			switch {
			case r >= 'a' && r <= 'z',
				r >= 'A' && r <= 'Z',
				r >= '0' && r <= '9',
				r == '"', r == '-', r == '*', r == '_':
				clean.WriteRune(r)
			default:
				clean.WriteRune(' ')
			}
		}
		for _, sub := range strings.Fields(clean.String()) {
			if out.Len() > 0 {
				out.WriteByte(' ')
			}
			out.WriteString(sub)
		}
	}
	return out.String()
}
