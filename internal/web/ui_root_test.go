package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// newUIRootServer is a UIRoot server serving a one-file SPA build from disk.
func newUIRootServer(t *testing.T) *Server {
	t.Helper()
	s, cleanup := newTestServer(t)
	t.Cleanup(cleanup)
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, uiIndexFile), `<!doctype html><body data-spa="root"></body>`)
	mustWrite(t, filepath.Join(dir, "favicon.svg"), "svg")
	s.SetUIDir(dir)
	s.UIRoot = true
	return s
}

func TestUIRootServesSPAAtRoot(t *testing.T) {
	s := newUIRootServer(t)
	for _, p := range []string{"/", "/findings/12", "/repositories/5?tab=scans", "/login?next=/scans"} {
		w := serveUI(t, s, anonReq(p))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `data-spa="root"`) {
			t.Fatalf("%s = %d %q", p, w.Code, w.Body.String())
		}
	}
	if w := serveUI(t, s, anonReq("/favicon.svg")); w.Body.String() != "svg" {
		t.Fatalf("favicon = %d %q", w.Code, w.Body.String())
	}
	// Old /ui/ links land on the same route at the root.
	if w := serveUI(t, s, anonReq("/ui/findings/12?section=notes")); w.Code != http.StatusFound || w.Header().Get("Location") != "/findings/12?section=notes" {
		t.Fatalf("/ui/ redirect = %d %q", w.Code, w.Header().Get("Location"))
	}
	// Downloads stay on the operator mux at the root.
	if w := serveUI(t, s, anonReq("/findings/1/report.md")); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous download = %d", w.Code)
	}
	if w := serveUI(t, s, localReq(http.MethodGet, "/reporting/report.csv")); w.Code != http.StatusOK {
		t.Fatalf("operator download = %d", w.Code)
	}
	// The printed sign-in link still sets the cookie.
	w := serveUI(t, s, anonReq("/login?token="+testOperatorToken+"&next=/scans"))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/scans" || len(w.Result().Cookies()) == 0 {
		t.Fatalf("login = %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := serveUI(t, s, localReq(http.MethodGet, "/api/v1/ui/session")); !strings.Contains(w.Body.String(), `"ui_base":"/"`) {
		t.Fatalf("session = %q", w.Body.String())
	}
}

func TestUIRootServesLegacyUnderPrefix(t *testing.T) {
	s := newUIRootServer(t)
	if w := serveUI(t, s, anonReq("/legacy/")); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous legacy = %d", w.Code)
	}
	w := serveUI(t, s, localReq(http.MethodGet, "/legacy/"))
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `href="/legacy/findings`) || !strings.Contains(body, `src="/legacy/static/`) {
		t.Fatalf("legacy index = %d\n%s", w.Code, body)
	}
	for _, m := range legacyURLAttrRE.FindAllStringSubmatch(body, -1) {
		if !strings.HasPrefix(m[2], legacyPrefix+"/") && !strings.HasPrefix(m[2], "//") {
			t.Fatalf("legacy index still links %s%s", m[1], m[2])
		}
	}
	if w.Header().Get("Content-Length") != "" && w.Header().Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length %s for %d bytes", w.Header().Get("Content-Length"), len(body))
	}
	if w := serveUI(t, s, anonReq("/legacy/static/app.js")); w.Code != http.StatusOK {
		t.Fatalf("legacy static = %d", w.Code)
	}
	// Redirects after a form post stay inside /legacy/.
	r := localReq(http.MethodPost, "/legacy/settings/theme")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Body = io.NopCloser(strings.NewReader(url.Values{"theme": {"claude"}}.Encode()))
	if w := serveUI(t, s, r); w.Header().Get("Location") != "/legacy/settings" {
		t.Fatalf("legacy POST = %d Location %q", w.Code, w.Header().Get("Location"))
	}
	// Sign-in under /legacy/ lands back in the template UI.
	w = serveUI(t, s, anonReq("/legacy/login?token="+testOperatorToken))
	if w.Header().Get("Location") != "/legacy/" {
		t.Fatalf("legacy login Location %q", w.Header().Get("Location"))
	}
}

func TestUIRootOffKeepsTransitionLayout(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	if w := serveUI(t, s, localReq(http.MethodGet, "/legacy/")); w.Code != http.StatusNotFound {
		t.Fatalf("/legacy/ without UIRoot = %d", w.Code)
	}
	if w := serveUI(t, s, anonReq("/")); w.Code != http.StatusUnauthorized {
		t.Fatalf("/ without UIRoot = %d", w.Code)
	}
}

func TestRewriteLegacyHTML(t *testing.T) {
	in := `<a href="/findings/1">x</a><a href="//cdn.example/x"></a><a href="https://e.test/"></a>` +
		`<a href="/legacy/scans"></a><form action='/scans/1/retry'></form><div sse-connect="/events?scan=1" data-path="/src/a.rs"></div>`
	want := `<a href="/legacy/findings/1">x</a><a href="//cdn.example/x"></a><a href="https://e.test/"></a>` +
		`<a href="/legacy/scans"></a><form action='/legacy/scans/1/retry'></form><div sse-connect="/legacy/events?scan=1" data-path="/src/a.rs"></div>`
	if got := string(rewriteLegacyHTML([]byte(in))); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestLegacyRewriterStreamsSSE(t *testing.T) {
	h := legacyRewrite(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: scan-status\ndata: <a href=\"/scans/1\">1</a>\n\n"))
		w.(http.Flusher).Flush()
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/events", nil))
	if !w.Flushed || !strings.Contains(w.Body.String(), `href="/legacy/scans/1"`) {
		t.Fatalf("flushed=%v body=%q", w.Flushed, w.Body.String())
	}
}
