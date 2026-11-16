package sharing

import (
	"bytes"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var updateGolden = flag.Bool("update", false, "rewrite openapi.portal.yaml from openapi.yaml and openapi_auth.yaml")

const (
	baseSpecPath   = "../../openapi.yaml"
	authSpecPath   = "openapi_auth.yaml"
	portalSpecPath = "../../openapi.portal.yaml"
	innerWebDir    = "../web"
)

func generatePortalSpec(t *testing.T) []byte {
	t.Helper()
	base, err := os.ReadFile(baseSpecPath)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := os.ReadFile(authSpecPath)
	if err != nil {
		t.Fatal(err)
	}
	out, err := buildPortalSpec(base, auth)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestPortalOpenAPIGolden keeps openapi.portal.yaml in step with openapi.yaml,
// openapi_auth.yaml and the allow-list. Run with -update to regenerate.
func TestPortalOpenAPIGolden(t *testing.T) {
	got := generatePortalSpec(t)
	if *updateGolden {
		if err := os.WriteFile(portalSpecPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(portalSpecPath)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/sharing -run TestPortalOpenAPIGolden -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("openapi.portal.yaml is stale; run: go test ./internal/sharing -run TestPortalOpenAPIGolden -update")
	}
}

type specDoc struct {
	Paths map[string]map[string]any `yaml:"paths"`
}

func loadPortalSpec(t *testing.T) specDoc {
	t.Helper()
	var doc specDoc
	if err := yaml.Unmarshal(generatePortalSpec(t), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestPortalOpenAPIHasNoWrites: the generated client types must contain no
// write operation except POST /auth/logout.
func TestPortalOpenAPIHasNoWrites(t *testing.T) {
	doc := loadPortalSpec(t)
	methods := []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}
	for path, item := range doc.Paths {
		for key := range item {
			if !contains(methods, key) || key == "get" {
				continue
			}
			if key == "post" && path == "/auth/logout" {
				continue
			}
			t.Errorf("portal spec has a write operation: %s %s", strings.ToUpper(key), path)
		}
	}
	if _, ok := doc.Paths["/auth/logout"]["post"]; !ok {
		t.Error("portal spec lacks POST /auth/logout")
	}
}

// TestAllowListExistsInInnerMuxAndSpec: every forwarded pattern is registered
// by the inner handler (so the allow-list never names a dead route) and is
// documented in the portal spec.
func TestAllowListExistsInInnerMuxAndSpec(t *testing.T) {
	registered := innerPatterns(t)
	doc := loadPortalSpec(t)
	all := append(append(append([]route{}, apiRoutes...), downloadRoutes...), legacyPageRoutes...)
	seen := map[string]bool{}
	for _, rt := range all {
		if seen[rt.pattern] {
			t.Errorf("duplicate allow-listed pattern %q", rt.pattern)
		}
		seen[rt.pattern] = true
		method, path, _ := strings.Cut(rt.pattern, " ")
		if method != "GET" {
			t.Errorf("allow-listed route %q is not GET", rt.pattern)
		}
		inner := path
		if strings.HasPrefix(path, "/api/v1/") {
			// exportHandler is mounted under StripPrefix("/api/v1").
			inner = strings.TrimPrefix(path, "/api/v1")
		}
		if !registered["GET "+inner] {
			t.Errorf("allow-listed route %q: inner mux has no %q", rt.pattern, "GET "+inner)
		}
		if strings.Contains(path, "{id}") && rt.kind != kindRepo && rt.kind != kindFinding && rt.kind != kindScan {
			t.Errorf("route %q has an {id} but no per-resource kind", rt.pattern)
		}
	}
	for _, rt := range append(append([]route{}, apiRoutes...), downloadRoutes...) {
		_, path, _ := strings.Cut(rt.pattern, " ")
		if _, ok := doc.Paths[path]["get"]; !ok {
			t.Errorf("allow-listed route %q missing from openapi.portal.yaml", rt.pattern)
		}
	}
}

// innerPatterns collects every string-literal pattern internal/web registers
// with Handle/HandleFunc.
func innerPatterns(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(innerWebDir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if v, err := strconv.Unquote(lit.Value); err == nil {
				out[v] = true
			}
			return true
		})
	}
	if len(out) < 100 {
		t.Fatalf("found only %d inner patterns in %s; the parser is not seeing the registrations", len(out), innerWebDir)
	}
	return out
}
