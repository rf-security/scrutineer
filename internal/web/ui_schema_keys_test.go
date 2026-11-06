package web

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"scrutineer/internal/db"
)

// The SPA generates its types from openapi.yaml, so a key the server sends
// but the schema lacks is invisible to it. These tests fetch representative
// /api/v1/ui responses and require every JSON object key, at every depth the
// schema describes, to be a declared property.

type specSchemas map[string]map[string]any

func loadSpecSchemas(t *testing.T) specSchemas {
	t.Helper()
	raw, err := os.ReadFile("../../openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas specSchemas `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Components.Schemas
}

// resolve follows a $ref.
func (s specSchemas) resolve(sch map[string]any) map[string]any {
	for {
		ref, ok := sch["$ref"].(string)
		if !ok {
			return sch
		}
		next, ok := s[strings.TrimPrefix(ref, "#/components/schemas/")]
		if !ok {
			return map[string]any{}
		}
		sch = next
	}
}

func subSchemas(sch map[string]any, key string) []map[string]any {
	list, _ := sch[key].([]any)
	out := make([]map[string]any, 0, len(list))
	for _, v := range list {
		if m, ok := v.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// objectProps merges the properties of sch and its allOf members; open is
// true when the schema admits undeclared keys (additionalProperties) or
// declares no properties at all (a free-form object).
func (s specSchemas) objectProps(sch map[string]any) (props map[string]map[string]any, open bool) {
	props = map[string]map[string]any{}
	var walk func(map[string]any)
	walk = func(x map[string]any) {
		x = s.resolve(x)
		if ap, ok := x["additionalProperties"]; ok && ap != false {
			open = true
		}
		if p, ok := x["properties"].(map[string]any); ok {
			for k, v := range p {
				if m, ok := v.(map[string]any); ok {
					props[k] = m
				}
			}
		}
		for _, sub := range subSchemas(x, "allOf") {
			walk(sub)
		}
	}
	walk(sch)
	return props, open || len(props) == 0
}

// undeclaredKeys lists "path.key" for each object key in v that sch does not
// declare. oneOf/anyOf pass when any alternative does.
func (s specSchemas) undeclaredKeys(sch map[string]any, v any, path string) []string {
	sch = s.resolve(sch)
	if v == nil {
		return nil
	}
	if alts := append(subSchemas(sch, "oneOf"), subSchemas(sch, "anyOf")...); len(alts) > 0 {
		var best []string
		for i, alt := range alts {
			if !s.admitsKind(alt, v) {
				continue
			}
			bad := s.undeclaredKeys(alt, v, path)
			if len(bad) == 0 {
				return nil
			}
			if i == 0 || len(bad) < len(best) {
				best = bad
			}
		}
		return best
	}
	switch val := v.(type) {
	case map[string]any:
		props, open := s.objectProps(sch)
		var bad []string
		for k, child := range val {
			ps, ok := props[k]
			if !ok {
				if !open {
					bad = append(bad, path+"."+k)
				}
				continue
			}
			bad = append(bad, s.undeclaredKeys(ps, child, path+"."+k)...)
		}
		return bad
	case []any:
		items, ok := sch["items"].(map[string]any)
		if !ok {
			return nil
		}
		var bad []string
		for i, child := range val {
			bad = append(bad, s.undeclaredKeys(items, child, fmt.Sprintf("%s[%d]", path, i))...)
		}
		return bad
	}
	return nil
}

// admitsKind reports whether sch's type (when it states one) allows v's
// JSON kind, so a {type: null} oneOf branch does not swallow an object.
func (s specSchemas) admitsKind(sch map[string]any, v any) bool {
	sch = s.resolve(sch)
	var kinds []string
	switch t := sch["type"].(type) {
	case string:
		kinds = []string{t}
	case []any:
		for _, k := range t {
			if ks, ok := k.(string); ok {
				kinds = append(kinds, ks)
			}
		}
	default:
		return true
	}
	want := "scalar"
	switch v.(type) {
	case map[string]any:
		want = "object"
	case []any:
		want = "array"
	}
	for _, k := range kinds {
		if k == want || (want == "scalar" && k != "object" && k != "array") {
			return true
		}
	}
	return false
}

func requireSchemaCovers(t *testing.T, specs specSchemas, name string, v any) {
	t.Helper()
	sch, ok := specs[name]
	if !ok {
		t.Fatalf("schema %s not in openapi.yaml", name)
	}
	if bad := specs.undeclaredKeys(sch, v, name); len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("%s: JSON keys missing from openapi.yaml: %s", name, strings.Join(bad, ", "))
	}
}

// seedUISchemaFixture is one repo with a done scan, an open finding with
// every optional sub-record the row and detail project, and a label.
func seedUISchemaFixture(t *testing.T, s *Server) (db.Repository, db.Scan, db.Finding) {
	t.Helper()
	repo := seedUIRepo(t, s.DB, "schema")
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, deepDiveSkillName)
	s.DB.Model(&sc).Updates(map[string]any{"cost_usd": 1.25, "commit": "c0ffee", "input_tokens": 10})
	f := seedUIFinding(t, s.DB, sc, "schema finding", db.FindingNew)
	s.DB.Model(&f).Updates(map[string]any{
		"cwe": "CWE-79", "commit": "c0ffee", "location": "src/a.go:3-5 (x); also src/b.go:9",
		"missed_count": 1, "seen_count": 2, "confidence": "high", "breaking_change": "unknown",
		"release_tag": "v1", "disclosure_draft": "d",
	})
	label := db.FindingLabel{Name: "schema", Color: "#fff"}
	if err := s.DB.Create(&label).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&f).Association("Labels").Append(&label); err != nil {
		t.Fatal(err)
	}
	return repo, sc, f
}

func TestUISchemaKeysMatchServer(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	specs := loadSpecSchemas(t)
	repo, sc, f := seedUISchemaFixture(t, s)

	firstItem := func(path string) any {
		t.Helper()
		items, _ := getUI(t, s, path)["items"].([]any)
		if len(items) == 0 {
			t.Fatalf("%s: no items", path)
		}
		return items[0]
	}
	requireSchemaCovers(t, specs, "FindingRow", firstItem("/api/v1/ui/findings"))
	requireSchemaCovers(t, specs, "UIFindingDetail", getUI(t, s, fmt.Sprintf("/api/v1/ui/findings/%d", f.ID)))
	requireSchemaCovers(t, specs, "RepoRow", firstItem("/api/v1/ui/repositories"))
	requireSchemaCovers(t, specs, "RepoDetail", getUI(t, s, fmt.Sprintf("/api/v1/ui/repositories/%d", repo.ID)))
	requireSchemaCovers(t, specs, "ScanRow", firstItem("/api/v1/ui/scans"))
	requireSchemaCovers(t, specs, "UIScanDetail", getUI(t, s, fmt.Sprintf("/api/v1/ui/scans/%d", sc.ID)))
	requireSchemaCovers(t, specs, "Meta", getUI(t, s, "/api/v1/ui/meta"))
}

// The checker itself: an undeclared key fails, oneOf/allOf/$ref/items
// resolve, and additionalProperties opens an object.
func TestUISchemaKeysChecker(t *testing.T) {
	specs := specSchemas{
		"Leaf": {"type": "object", "properties": map[string]any{"a": map[string]any{"type": "string"}}},
		"Root": {"allOf": []any{
			map[string]any{"$ref": "#/components/schemas/Leaf"},
			map[string]any{"type": "object", "properties": map[string]any{
				"kids": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/Leaf"}},
				"maybe": map[string]any{"oneOf": []any{
					map[string]any{"$ref": "#/components/schemas/Leaf"}, map[string]any{"type": "null"},
				}},
				"bag": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
			}},
		}},
	}
	ok := map[string]any{"a": "x", "kids": []any{map[string]any{"a": "y"}}, "maybe": nil, "bag": map[string]any{"z": "1"}}
	if bad := specs.undeclaredKeys(specs["Root"], ok, "Root"); len(bad) != 0 {
		t.Fatalf("valid doc flagged: %v", bad)
	}
	wrong := map[string]any{"a": "x", "b": 1, "kids": []any{map[string]any{"c": 1}}, "maybe": map[string]any{"d": 1}}
	bad := specs.undeclaredKeys(specs["Root"], wrong, "Root")
	sort.Strings(bad)
	if strings.Join(bad, ",") != "Root.b,Root.kids[0].c,Root.maybe.d" {
		t.Fatalf("undeclared = %v", bad)
	}
}

// Every /api/v1/ui path parameter is a numeric id read by uiPathID except
// the few that are names; the spec must say integer so generated clients
// type them as numbers.
func TestUIPathParamsNumericIDs(t *testing.T) {
	raw, err := os.ReadFile("../../openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	stringParams := map[string]bool{"action": true, "commit": true, "path": true, "login": true}
	for p, ops := range doc.Paths {
		if !strings.HasPrefix(p, "/v1/ui/") {
			continue
		}
		for method, op := range ops {
			opMap, _ := op.(map[string]any)
			params, _ := opMap["parameters"].([]any)
			for _, v := range params {
				prm, _ := v.(map[string]any)
				name, _ := prm["name"].(string)
				if prm["in"] != "path" || stringParams[name] {
					continue
				}
				if sch, _ := prm["schema"].(map[string]any); sch["type"] != "integer" {
					t.Errorf("%s %s: path param %q is %v, want integer", method, p, name, sch["type"])
				}
			}
		}
	}
}
