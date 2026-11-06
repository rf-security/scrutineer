package web

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"io/fs"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
)

// Serving the Svelte SPA under /ui/ (02-api-plan.md section 5.3). The document
// and its assets carry no data, so they sit outside requireOperator: an
// unauthenticated browser reaches the SPA, which calls GET
// /api/v1/ui/session and shows its login screen on 401.

// uiDist is the built SPA. The committed placeholder index.html says the UI
// is not built; `npm run build` with outDir pointing here replaces it. `all:`
// keeps SvelteKit's `_app` directory, which embed would otherwise skip.
//
//go:embed all:ui/dist
var uiDist embed.FS

const (
	uiBasePath      = "/ui/"
	uiIndexFile     = "index.html"
	uiImmutableDir  = "_app/immutable/"
	uiDirEnv        = "SCRUTINEER_UI_DIR"
	testHooksEnv    = "SCRUTINEER_TEST_HOOKS"
	cacheImmutable  = "public, max-age=31536000, immutable"
	cacheNoCache    = "no-cache"
	uiAvatarImgHost = "https://avatars.githubusercontent.com"
)

// uiState is the Server's UI v2 state, kept in one field so server.go only
// grows by one line.
type uiState struct {
	mu           sync.Mutex
	queuePending bool
	// testHooks enables POST /api/v1/ui/_test/publish (development only).
	testHooks bool
	// dir, when set, serves the SPA from disk instead of the embedded build,
	// re-reading index.html per request so a rebuild needs no restart.
	dir string
	// liveLogs mirrors running scans' logs for GET /ui/scans/{id}/log
	// (ui_scans_log.go).
	liveLogs uiLiveLogs
}

// EnableTestHooks turns on the dev-only SSE publish seam. Call before
// serving; it is never enabled by default.
func (s *Server) EnableTestHooks() { s.ui.testHooks = true }

// TestHooksEnabled reports whether the dev-only seam is on.
func (s *Server) TestHooksEnabled() bool { return s.ui.testHooks }

// TestHooksFromEnv reports whether SCRUTINEER_TEST_HOOKS=1 asks for the seam.
func TestHooksFromEnv() bool { return os.Getenv(testHooksEnv) == "1" }

// SetUIDir serves the SPA from dir (a SvelteKit build output) instead of the
// embedded copy. Empty falls back to SCRUTINEER_UI_DIR, then the embed.
func (s *Server) SetUIDir(dir string) { s.ui.dir = dir }

func (s *Server) uiFS() fs.FS {
	dir := s.ui.dir
	if dir == "" {
		dir = os.Getenv(uiDirEnv)
	}
	if dir != "" {
		if st, err := os.Stat(path.Join(dir, uiIndexFile)); err == nil && !st.IsDir() {
			return os.DirFS(dir)
		}
	}
	sub, err := fs.Sub(uiDist, "ui/dist")
	if err != nil {
		return uiDist
	}
	return sub
}

// uiHandler serves /ui/: hashed assets are immutable, other files no-cache,
// and every unknown path falls back to index.html (SPA routing).
func (s *Server) uiHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fsys := s.uiFS()
		name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(r.URL.Path, uiBasePath)), "/")
		if name == "" || name == "." || name == uiIndexFile {
			serveUIDocument(w, r, fsys)
			return
		}
		if st, err := fs.Stat(fsys, name); err != nil || st.IsDir() {
			serveUIDocument(w, r, fsys)
			return
		}
		if strings.HasPrefix(name, uiImmutableDir) {
			w.Header().Set(cacheControlHeader, cacheImmutable)
		} else {
			w.Header().Set(cacheControlHeader, cacheNoCache)
		}
		http.ServeFileFS(w, r, fsys, name)
	})
}

func serveUIDocument(w http.ResponseWriter, r *http.Request, fsys fs.FS) {
	doc, err := fs.ReadFile(fsys, uiIndexFile)
	if err != nil {
		http.Error(w, "UI not built", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Security-Policy", uiDocumentCSP(inlineScriptHashes(doc)))
	w.Header().Set(cacheControlHeader, cacheNoCache)
	w.Header().Add("Vary", "Cookie")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(doc)
	}
}

// inlineScriptRE matches <script> elements; group 1 is the attributes, group
// 2 the body. External scripts (src=) are covered by 'self'.
var inlineScriptRE = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script\s*>`)

var scriptSrcAttrRE = regexp.MustCompile(`(?i)\bsrc\s*=`)

// inlineScriptHashes returns the CSP source expressions for every inline
// script in doc (SvelteKit's boot script), so the SPA document can run it
// without 'unsafe-inline'.
func inlineScriptHashes(doc []byte) []string {
	var out []string
	for _, m := range inlineScriptRE.FindAllSubmatch(doc, -1) {
		if scriptSrcAttrRE.Match(m[1]) {
			continue
		}
		sum := sha256.Sum256(m[2])
		out = append(out, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
	}
	return out
}

// uiDocumentCSP is cspPolicy with the inline script hashes added to
// script-src and GitHub avatars allowed in img-src. Assets keep cspPolicy.
func uiDocumentCSP(hashes []string) string {
	script := "script-src 'self'"
	if len(hashes) > 0 {
		script += " " + strings.Join(hashes, " ")
	}
	policy := strings.Replace(cspPolicy, "script-src 'self'", script, 1)
	return strings.Replace(policy, "img-src 'self' data:", "img-src 'self' data: "+uiAvatarImgHost, 1)
}

// registerUICoreRoutes registers the WP-API-0 routes on the operator mux
// (paths are relative to /api/v1, so the spec documents them as /v1/ui/...).
func (s *Server) registerUICoreRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui/meta", s.uiMeta)
	mux.HandleFunc("GET /ui/meta/dynamic", s.uiMetaDynamic)
	mux.HandleFunc("GET /ui/meta/cwe", s.uiMetaCWE)
	mux.HandleFunc("GET /ui/search", s.uiSearch)
	mux.HandleFunc("GET /ui/events", s.uiEvents)
	mux.HandleFunc("GET /ui/activity", s.uiActivityHandler)
	mux.HandleFunc("GET /ui/scans", s.uiScanList)
	mux.HandleFunc("POST /ui/_test/publish", s.uiTestPublish)
}
