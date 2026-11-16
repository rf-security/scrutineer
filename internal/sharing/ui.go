package sharing

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
)

// Serving the portal SPA at / (DESIGN §4). The document and its assets carry
// no data, so they are served without a session; the SPA asks
// GET /auth/session and shows its sign-in screen on 401. This mirrors
// internal/web's /ui/ handler (ui.go there).

// uiDist is the built portal UI (scrutineer-portal-ui, adapter-static with
// fallback index.html). The committed placeholder index.html says the UI is
// not built; `UI_OUT_DIR=<this dir> npm run build` replaces it. `all:` keeps
// SvelteKit's `_app` directory, which embed would otherwise skip.
//
//go:embed all:ui/dist
var uiDist embed.FS

const (
	uiIndexFile    = "index.html"
	uiImmutableDir = "_app/immutable/"
	// uiDirEnv serves the SPA from disk instead of the embed, re-reading
	// index.html per request so a rebuild needs no restart.
	uiDirEnv       = "SCRUTINEER_SHARING_UI_DIR"
	cacheImmutable = "public, max-age=31536000, immutable"
	cacheNoCache   = "no-cache"
	avatarImgHost  = "https://avatars.githubusercontent.com"
)

// uiCSP mirrors internal/web's cspPolicy (the document adds its inline
// script hashes and GitHub avatars).
const uiCSP = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self' data:; " +
	"connect-src 'self'; " +
	"base-uri 'self'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'; " +
	"object-src 'none'"

func uiFS() fs.FS {
	if dir := os.Getenv(uiDirEnv); dir != "" {
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

// serveSPA serves a built file, or the document for any other path (client
// routing). Hashed assets are immutable, everything else no-cache. A missing
// path shaped like a download 404s rather than coming back as HTML.
func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	fsys := uiFS()
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" || name == uiIndexFile {
		serveUIDocument(w, r, fsys)
		return
	}
	if st, err := fs.Stat(fsys, name); err == nil && !st.IsDir() {
		h := w.Header()
		h.Set("Content-Security-Policy", uiCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		if strings.HasPrefix(name, uiImmutableDir) {
			h.Set("Cache-Control", cacheImmutable)
		} else {
			h.Set("Cache-Control", cacheNoCache)
		}
		http.ServeFileFS(w, r, fsys, name)
		return
	}
	if hasDownloadSuffix(name) {
		http.NotFound(w, r)
		return
	}
	serveUIDocument(w, r, fsys)
}

func hasDownloadSuffix(name string) bool {
	for _, suf := range downloadSuffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

func serveUIDocument(w http.ResponseWriter, r *http.Request, fsys fs.FS) {
	doc, err := fs.ReadFile(fsys, uiIndexFile)
	if err != nil {
		http.Error(w, "UI not built", http.StatusNotFound)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", uiDocumentCSP(inlineScriptHashes(doc)))
	h.Set("Cache-Control", cacheNoCache)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	addVary(h, "Cookie")
	h.Set("Content-Type", "text/html; charset=utf-8")
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
// script in doc (SvelteKit's boot script), so the document can run it
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

func uiDocumentCSP(hashes []string) string {
	script := "script-src 'self'"
	if len(hashes) > 0 {
		script += " " + strings.Join(hashes, " ")
	}
	policy := strings.Replace(uiCSP, "script-src 'self'", script, 1)
	return strings.Replace(policy, "img-src 'self' data:", "img-src 'self' data: "+avatarImgHost, 1)
}
