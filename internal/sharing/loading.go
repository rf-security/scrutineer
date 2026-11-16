package sharing

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
)

// The progress page shown while a visitor's first GitHub repository lookup
// runs. It polls /auth/status and reloads the requested page once the lookup
// finishes, so a slow lookup reads as progress rather than a hung request.
var (
	//go:embed assets/loading.html
	loadingHTML []byte
	//go:embed assets/loading.js
	loadingJS []byte
	// accessWatchJS rides along on pages served from a partial repository list
	// and reloads them once the lookup completes.
	//go:embed assets/access-watch.js
	accessWatchJS []byte
)

// loadingCSP mirrors internal/web's policy: same-origin scripts only, with
// inline styles allowed for tailwindcss-browser.
const loadingCSP = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'; " +
	"object-src 'none'"

// wantsDocument reports whether r is a top-level page navigation, the only
// kind of request that can usefully be answered with the progress page. htmx
// swaps, fetches, and downloads keep waiting on the lookup instead.
func wantsDocument(r *http.Request) bool {
	if r.Method != http.MethodGet || isHX(r) {
		return false
	}
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
		return dest == "document"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func (s *Server) renderLoading(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", loadingCSP)
	_, _ = w.Write(loadingHTML)
}

func (s *Server) loadingScript(w http.ResponseWriter, _ *http.Request) {
	writeScript(w, loadingJS)
}

func (s *Server) accessWatchScript(w http.ResponseWriter, _ *http.Request) {
	writeScript(w, accessWatchJS)
}

func writeScript(w http.ResponseWriter, js []byte) {
	h := w.Header()
	h.Set("Content-Type", "text/javascript; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	_, _ = w.Write(js)
}

// accessStatus reports the visitor's repository lookup to the progress page.
// It never starts a fetch; the page reloads to do that.
func (s *Server) accessStatus(w http.ResponseWriter, r *http.Request) {
	st := accessStatus{State: accessUnauthorized}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if sess, err := s.cfg.open(c.Value); err == nil {
			st = s.access.status(sess.GitHubUserID, sess.Token)
		}
	}
	if st.State == accessUnauthorized {
		clearCookie(w, sessionCookie)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(st)
}
