package web

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func anonReq(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = testHost
	return r
}

// The SPA document is reachable without the operator token so a signed-out
// browser gets the login screen instead of a 401.
func TestUIServesPlaceholderWithoutOperator(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	t.Setenv(uiDirEnv, "")
	for _, path := range []string{"/ui/", "/ui/findings/123", "/ui/repositories/5?tab=scans"} {
		w := serveUI(t, s, anonReq(path))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `data-scrutineer-ui="placeholder"`) {
			t.Fatalf("%s = %d %q", path, w.Code, w.Body.String())
		}
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "img-src 'self' data: "+uiAvatarImgHost) || !strings.Contains(csp, "script-src 'self';") {
			t.Fatalf("%s CSP = %q", path, csp)
		}
		if w.Header().Get("Vary") != "Cookie" || w.Header().Get("Cache-Control") != cacheNoCache {
			t.Fatalf("%s headers = %v", path, w.Header())
		}
	}
	// /ui redirects to /ui/.
	if w := serveUI(t, s, anonReq("/ui")); w.Header().Get("Location") != uiBasePath {
		t.Fatalf("/ui = %d Location %q", w.Code, w.Header().Get("Location"))
	}
	// The loopback host check still applies.
	r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	r.Host = "evil.example"
	if w := serveUI(t, s, r); w.Code != http.StatusForbidden {
		t.Fatalf("non-local host = %d", w.Code)
	}
	// The template UI stays behind the operator token.
	if w := serveUI(t, s, anonReq("/")); w.Code != http.StatusUnauthorized {
		t.Fatalf("/ = %d", w.Code)
	}
}

// The embedded build may carry at most SvelteKit's boot script inline; any
// more means the CSP hash list is growing by accident.
func TestEmbeddedUIDocumentInlineScripts(t *testing.T) {
	sub, err := fs.Sub(uiDist, "ui/dist")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := fs.ReadFile(sub, uiIndexFile)
	if err != nil {
		t.Fatalf("embedded index.html: %v", err)
	}
	if n := len(inlineScriptHashes(doc)); n > 1 {
		t.Fatalf("embedded index.html has %d inline scripts, want at most 1", n)
	}
}

func TestUIServesBuildDirWithScriptHash(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	dir := t.TempDir()
	boot := "\n\t__sveltekit_x = { base: '/ui' };\n\timport('/ui/_app/immutable/entry.js');\n"
	doc := `<!doctype html><html><head><script type="module" src="/ui/_app/immutable/start.js"></script></head>` +
		`<body><div id="app"></div><script>` + boot + `</script></body></html>`
	mustWrite(t, filepath.Join(dir, uiIndexFile), doc)
	mustWrite(t, filepath.Join(dir, "_app", "immutable", "entry.js"), "export {}")
	mustWrite(t, filepath.Join(dir, "favicon.png"), "png")
	s.SetUIDir(dir)

	w := serveUI(t, s, anonReq("/ui/scans"))
	sum := sha256.Sum256([]byte(boot))
	want := "script-src 'self' 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "';"
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Security-Policy"), want) {
		t.Fatalf("doc = %d CSP = %q, want %q", w.Code, w.Header().Get("Content-Security-Policy"), want)
	}

	w = serveUI(t, s, anonReq("/ui/_app/immutable/entry.js"))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != cacheImmutable || w.Body.String() != "export {}" {
		t.Fatalf("asset = %d %q %q", w.Code, w.Header().Get("Cache-Control"), w.Body.String())
	}
	if csp := w.Header().Get("Content-Security-Policy"); csp != cspPolicy {
		t.Fatalf("asset CSP = %q, want the strict policy", csp)
	}
	w = serveUI(t, s, anonReq("/ui/favicon.png"))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != cacheNoCache {
		t.Fatalf("favicon = %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	// Path traversal stays inside the build dir.
	w = serveUI(t, s, anonReq("/ui/../../etc/passwd"))
	if strings.Contains(w.Body.String(), "root:") {
		t.Fatal("served a file outside the build dir")
	}
}

func TestUIDocumentCSP(t *testing.T) {
	csp := uiDocumentCSP([]string{"'sha256-a'", "'sha256-b'"})
	if !strings.Contains(csp, "script-src 'self' 'sha256-a' 'sha256-b';") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("csp = %q", csp)
	}
	if got := inlineScriptHashes([]byte(`<script src="/x.js"></script><SCRIPT>a</SCRIPT>`)); len(got) != 1 {
		t.Fatalf("hashes = %v", got)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
