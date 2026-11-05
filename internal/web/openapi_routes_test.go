package web

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type openAPIPath map[string]any

type openAPIDoc struct {
	Paths map[string]openAPIPath `yaml:"paths"`
}

type registeredAPIRoute struct {
	Method string
	Path   string
}

func TestOpenAPICoversRegisteredAPIRoutes(t *testing.T) {
	doc := loadOpenAPIDoc(t)
	var missing []string
	for _, route := range registeredOpenAPIRoutes(t) {
		ops, ok := doc.Paths[route.Path]
		if !ok {
			missing = append(missing, route.Method+" "+route.Path)
			continue
		}
		if _, ok := ops[strings.ToLower(route.Method)]; !ok {
			missing = append(missing, route.Method+" "+route.Path)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("openapi.yaml is missing registered API routes:\n%s", strings.Join(missing, "\n"))
	}
}

func TestOpenAPIRepositoryPatchRequiresFork(t *testing.T) {
	doc := loadOpenAPIDoc(t)
	schema := openAPIRequestSchema(t, doc, "/repositories/{id}", "patch")
	if _, ok := schema["additionalProperties"]; ok {
		t.Fatal("PATCH /repositories/{id} schema should not reject unknown fields; the handler ignores them")
	}
	required, ok := schema["required"].([]any)
	if !ok {
		t.Fatal("PATCH /repositories/{id} schema missing required fields")
	}
	for _, field := range required {
		if field == "fork" {
			return
		}
	}
	t.Fatalf("PATCH /repositories/{id} required fields = %v, want fork", required)
}

func loadOpenAPIDoc(t *testing.T) openAPIDoc {
	t.Helper()
	data, err := os.ReadFile("../../openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc openAPIDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func openAPIRequestSchema(t *testing.T, doc openAPIDoc, path, method string) map[string]any {
	t.Helper()
	ops, ok := doc.Paths[path]
	if !ok {
		t.Fatalf("openapi path %s not found", path)
	}
	op := openAPIMap(t, ops[method], path+" "+method)
	requestBody := openAPIMap(t, op["requestBody"], path+" "+method+" requestBody")
	content := openAPIMap(t, requestBody["content"], path+" "+method+" content")
	jsonContent := openAPIMap(t, content["application/json"], path+" "+method+" application/json")
	return openAPIMap(t, jsonContent["schema"], path+" "+method+" schema")
}

func openAPIMap(t *testing.T, value any, label string) map[string]any {
	t.Helper()
	switch m := value.(type) {
	case map[string]any:
		return m
	case openAPIPath:
		return map[string]any(m)
	default:
		t.Fatalf("%s is %T, want map[string]any", label, value)
		return nil
	}
}

func TestRoutesInFunctionRecognizesHandleAndHandleFunc(t *testing.T) {
	src := `package web

func sample(mux interface {
	Handle(string, any)
	HandleFunc(string, any)
}) {
	mux.HandleFunc("GET /repositories", nil)
	mux.Handle("HEAD /repositories", nil)
}
`
	file, err := parser.ParseFile(token.NewFileSet(), "sample.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := routesInParsedFile(t, file, "sample.go", "sample", "/v1")
	want := []registeredAPIRoute{
		{Method: "GET", Path: "/v1/repositories"},
		{Method: "HEAD", Path: "/v1/repositories"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %#v, want %#v", got, want)
	}
}

func TestRoutesInFunctionRejectsUnmappableRegistrations(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "methodless handlefunc",
			body: `mux.HandleFunc("/repositories", nil)`,
			want: "method-qualified",
		},
		{
			name: "methodless handle",
			body: `mux.Handle("/repositories", nil)`,
			want: "method-qualified",
		},
		{
			name: "non literal handlefunc",
			body: `pattern := "GET /repositories"
	mux.HandleFunc(pattern, nil)`,
			want: "non-literal route pattern",
		},
		{
			name: "non literal handle",
			body: `pattern := "GET /repositories"
	mux.Handle(pattern, nil)`,
			want: "non-literal route pattern",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := `package web

func sample(mux interface {
	Handle(string, any)
	HandleFunc(string, any)
}) {
	` + tt.body + `
}
`
			file, err := parser.ParseFile(token.NewFileSet(), "sample.go", src, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = routesInParsedFileResult(file, "sample.go", "sample", "/v1")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestAPIRouteFromPatternRejectsUnsupportedMethod(t *testing.T) {
	for _, pattern := range []string{
		"BREW /coffee",
		"CONNECT /tunnel",
	} {
		if _, err := apiRouteFromPattern("", pattern); err == nil {
			t.Fatalf("apiRouteFromPattern accepted unsupported method-qualified pattern %q", pattern)
		}
	}
}

func registeredOpenAPIRoutes(t *testing.T) []registeredAPIRoute {
	t.Helper()
	routes := append(routesInFunction(t, "api.go", "apiHandler", ""), routesInFunction(t, "api_export.go", "exportHandler", "/v1")...)
	routes = append(routes, registeredUIRoutes(t)...)
	// claim-check is documented in openapi.yaml but registered on the root
	// browser mux, outside apiHandler/exportHandler.
	routes = append(routes, registeredAPIRoute{Method: "POST", Path: "/claim-check"})
	// GET /api/openapi.yaml is likewise registered on the root mux, so that
	// serving the spec does not sit behind the scan-token auth.
	routes = append(routes, registeredAPIRoute{Method: "GET", Path: "/openapi.yaml"})
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
	return routes
}

func routesInFunction(t *testing.T, filename, funcName, pathPrefix string) []registeredAPIRoute {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return routesInParsedFile(t, file, filename, funcName, pathPrefix)
}

func routesInParsedFile(t *testing.T, file *ast.File, filename, funcName, pathPrefix string) []registeredAPIRoute {
	t.Helper()
	routes, err := routesInParsedFileResult(file, filename, funcName, pathPrefix)
	if err != nil {
		t.Fatal(err)
	}
	return routes
}

func routesInParsedFileResult(file *ast.File, filename, funcName, pathPrefix string) ([]registeredAPIRoute, error) {
	var routes []registeredAPIRoute
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != funcName {
			continue
		}
		var extractErr error
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if !isRouteRegistration(call) {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				extractErr = fmt.Errorf("%s: non-literal route pattern in %s", filename, funcName)
				return false
			}
			pattern, err := strconv.Unquote(lit.Value)
			if err != nil {
				extractErr = fmt.Errorf("%s: unquote route pattern: %w", filename, err)
				return false
			}
			route, err := apiRouteFromPattern(pathPrefix, pattern)
			if err != nil {
				extractErr = fmt.Errorf("%s: unsupported route pattern %q: %w", filename, pattern, err)
				return false
			}
			routes = append(routes, route)
			return true
		})
		if extractErr != nil {
			return nil, extractErr
		}
		return routes, nil
	}
	return nil, fmt.Errorf("%s: function %s not found", filename, funcName)
}

func isRouteRegistration(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "Handle" || sel.Sel.Name == "HandleFunc"
}

func apiRouteFromPattern(pathPrefix, pattern string) (registeredAPIRoute, error) {
	fields := strings.Fields(pattern)
	switch len(fields) {
	case 1:
		return registeredAPIRoute{}, errors.New("route pattern must be method-qualified")
	case 2:
	default:
		return registeredAPIRoute{}, strconv.ErrSyntax
	}
	switch fields[0] {
	case "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE":
		return registeredAPIRoute{Method: fields[0], Path: pathPrefix + fields[1]}, nil
	default:
		return registeredAPIRoute{}, strconv.ErrSyntax
	}
}

// uiRouteRegistration names one /api/v1/ui registrar: the file it lives in,
// the function, and how its patterns map onto spec paths (prefix is added,
// trim removed first).
type uiRouteRegistration struct {
	file, fn, prefix, trim string
	// onRoot registrars are called from Handler on the root mux rather than
	// from exportHandler.
	onRoot bool
}

// uiRouteRegistrars lists every registerUI*Routes function. A new registrar
// must be added here (TestUIRouteRegistrarsAreListed enforces it) so its
// routes are held to openapi.yaml.
var uiRouteRegistrars = []uiRouteRegistration{
	{file: "ui.go", fn: "registerUICoreRoutes", prefix: "/v1"},
	{file: "ui_session.go", fn: "registerUISessionRoutes", trim: "/api", onRoot: true},
	{file: "ui_findings.go", fn: "registerUIFindingRoutes", prefix: "/v1"},
	{file: "ui_findings_actions.go", fn: "registerUIFindingActionRoutes", prefix: "/v1"},
	{file: "ui_repositories.go", fn: "registerUIRepositoryRoutes", prefix: "/v1"},
	{file: "ui_scans_detail.go", fn: "registerUIScanRoutes", prefix: "/v1"},
	{file: "ui_inventory.go", fn: "registerUIInventoryRoutes", prefix: "/v1"},
	{file: "ui_insights.go", fn: "registerUIInsightRoutes", prefix: "/v1"},
}

func registeredUIRoutes(t *testing.T) []registeredAPIRoute {
	t.Helper()
	var routes []registeredAPIRoute
	for _, reg := range uiRouteRegistrars {
		for _, route := range routesInFunction(t, reg.file, reg.fn, reg.prefix) {
			route.Path = strings.TrimPrefix(route.Path, reg.trim)
			// Go's {path...} wildcard is a plain {path} parameter in OpenAPI.
			route.Path = strings.ReplaceAll(route.Path, "...}", "}")
			routes = append(routes, route)
		}
	}
	return routes
}

// Every registerUI*Routes function must be listed in uiRouteRegistrars and
// actually called, otherwise its routes would ship unchecked or not at all.
func TestUIRouteRegistrarsAreListed(t *testing.T) {
	listed := map[string]uiRouteRegistration{}
	for _, reg := range uiRouteRegistrars {
		listed[reg.fn] = reg
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "registerUI") || !strings.HasSuffix(fn.Name.Name, "Routes") {
				continue
			}
			reg, ok := listed[fn.Name.Name]
			if !ok {
				t.Errorf("%s: %s is not listed in uiRouteRegistrars", name, fn.Name.Name)
				continue
			}
			if reg.file != name {
				t.Errorf("uiRouteRegistrars says %s lives in %s, found in %s", reg.fn, reg.file, name)
			}
		}
	}
	exportCalls := callsInFunction(t, "api_export.go", "exportHandler")
	rootCalls := callsInFunction(t, "server.go", "Handler")
	for _, reg := range uiRouteRegistrars {
		calls := exportCalls
		where := "exportHandler"
		if reg.onRoot {
			calls, where = rootCalls, "Handler"
		}
		if !calls[reg.fn] {
			t.Errorf("%s is not called from %s", reg.fn, where)
		}
	}
}

// callsInFunction returns the names of the methods/functions funcName calls.
func callsInFunction(t *testing.T, filename, funcName string) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != funcName {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					calls[sel.Sel.Name] = true
				}
			}
			return true
		})
	}
	return calls
}

// A registered /v1/ui route must not still be marked `x-status: planned`, and
// an operation the spec claims is implemented (no marker) must be registered.
func TestOpenAPIUIPlannedStatusMatchesRoutes(t *testing.T) {
	doc := loadOpenAPIDoc(t)
	registered := map[string]bool{}
	for _, route := range registeredUIRoutes(t) {
		registered[strings.ToLower(route.Method)+" "+route.Path] = true
	}
	var stale, phantom []string
	for path, ops := range doc.Paths {
		if !strings.HasPrefix(path, "/v1/ui/") {
			continue
		}
		for method, raw := range ops {
			op, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			key := method + " " + path
			planned := op["x-status"] == "planned"
			switch {
			case registered[key] && planned:
				stale = append(stale, key)
			case !registered[key] && !planned:
				phantom = append(phantom, key)
			}
		}
	}
	sort.Strings(stale)
	sort.Strings(phantom)
	if len(stale) > 0 {
		t.Errorf("implemented /v1/ui routes still marked x-status: planned:\n%s", strings.Join(stale, "\n"))
	}
	if len(phantom) > 0 {
		t.Errorf("/v1/ui operations without x-status: planned that no registrar serves:\n%s", strings.Join(phantom, "\n"))
	}
}
