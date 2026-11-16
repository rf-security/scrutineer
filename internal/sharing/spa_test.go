package sharing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/web"
	"scrutineer/internal/worker"
)

// Tests for the SPA mode (default -ui=spa): DESIGN WP-B2 acceptance.

func spaConfig() *Config {
	c := testConfig()
	c.UI = UISPA
	return c
}

// recorder is an inner handler that records forwarded paths.
type recorder struct {
	hits  []string
	reply func(http.ResponseWriter, *http.Request)
}

func (rc *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rc.hits = append(rc.hits, r.Method+" "+r.URL.Path)
	if rc.reply != nil {
		rc.reply(w, r)
	}
}

type portalFixture struct {
	s      *Server
	inner  *recorder
	cookie *http.Cookie
	fetchN *atomic.Int32
	// inA/inB: repo A is in scope (WRITE on GitHub), B is not.
	repoA, repoB       db.Repository
	scanA, scanB       db.Scan
	findingA, findingB db.Finding
}

// newPortal builds an SPA-mode portal whose GitHub lookup reports repos
// immediately (or via fetch when set), with repo A in scope and repo B out.
func newPortal(t *testing.T, fetch func(context.Context, string, func([]githubRepo)) ([]githubRepo, error)) *portalFixture {
	t.Helper()
	gdb := openTestDB(t)
	f := &portalFixture{inner: &recorder{}, fetchN: &atomic.Int32{}}
	f.repoA = db.Repository{URL: "https://github.com/acme/a", Name: "a"}
	f.repoB = db.Repository{URL: "https://github.com/other/b", Name: "b"}
	for _, repo := range []*db.Repository{&f.repoA, &f.repoB} {
		if err := gdb.Create(repo).Error; err != nil {
			t.Fatal(err)
		}
	}
	f.scanA = db.Scan{RepositoryID: f.repoA.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	f.scanB = db.Scan{RepositoryID: f.repoB.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	for _, sc := range []*db.Scan{&f.scanA, &f.scanB} {
		if err := gdb.Create(sc).Error; err != nil {
			t.Fatal(err)
		}
	}
	f.findingA = db.Finding{ScanID: f.scanA.ID, RepositoryID: f.repoA.ID, Title: "a"}
	f.findingB = db.Finding{ScanID: f.scanB.ID, RepositoryID: f.repoB.ID, Title: "b"}
	for _, fd := range []*db.Finding{&f.findingA, &f.findingB} {
		if err := gdb.Create(fd).Error; err != nil {
			t.Fatal(err)
		}
	}
	f.s = New(spaConfig(), gdb, slog.New(slog.NewTextHandler(io.Discard, nil)), f.inner, EmptyGrantSource())
	if fetch == nil {
		fetch = func(context.Context, string, func([]githubRepo)) ([]githubRepo, error) {
			return []githubRepo{{FullName: "acme/a", HTMLURL: "https://github.com/acme/a", ViewerPermission: "WRITE"}}, nil
		}
	}
	f.s.access.fetch = func(ctx context.Context, tok string, p func([]githubRepo)) ([]githubRepo, error) {
		f.fetchN.Add(1)
		return fetch(ctx, tok, p)
	}
	sealed, err := f.s.cfg.seal(session{GitHubUserID: 7, Login: "octocat", Token: "tok", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	f.cookie = &http.Cookie{Name: sessionCookie, Value: sealed}
	return f
}

func (f *portalFixture) do(method, target string, withCookie bool, header map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "share.example.org"
	if withCookie {
		r.AddCookie(f.cookie)
	}
	for k, v := range header {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(w, r)
	return w
}

func (f *portalFixture) get(target string) *httptest.ResponseRecorder {
	return f.do(http.MethodGet, target, true, nil)
}

func decodeEnvelope(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want JSON", ct)
	}
	var env map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return env
}

func cookieCleared(w *httptest.ResponseRecorder) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func idFor(f *portalFixture, kind resourceKind, inScope bool) uint {
	switch kind {
	case kindRepo:
		if inScope {
			return f.repoA.ID
		}
		return f.repoB.ID
	case kindFinding:
		if inScope {
			return f.findingA.ID
		}
		return f.findingB.ID
	case kindScan:
		if inScope {
			return f.scanA.ID
		}
		return f.scanB.ID
	}
	return 0
}

func TestOutOfScopeIs404OnEveryKindRoute(t *testing.T) {
	f := newPortal(t, nil)
	for _, rt := range append(append([]route{}, apiRoutes...), downloadRoutes...) {
		if rt.kind != kindRepo && rt.kind != kindFinding && rt.kind != kindScan {
			continue
		}
		_, pattern, _ := strings.Cut(rt.pattern, " ")
		for _, tc := range []struct {
			name string
			id   string
		}{
			{"out of scope", strconv.Itoa(int(idFor(f, rt.kind, false)))},
			{"missing", "999999"},
			{"not a number", "abc"},
		} {
			f.inner.hits = nil
			w := f.get(strings.Replace(pattern, "{id}", tc.id, 1))
			if w.Code != http.StatusNotFound || len(f.inner.hits) != 0 {
				t.Errorf("%s %s: status %d, forwarded %v; want 404 not forwarded", rt.pattern, tc.name, w.Code, f.inner.hits)
				continue
			}
			if strings.HasPrefix(pattern, "/api/") {
				if env := decodeEnvelope(t, w); env["code"] != "not_found" {
					t.Errorf("%s %s: envelope %v", rt.pattern, tc.name, env)
				}
			}
		}
		f.inner.hits = nil
		target := strings.Replace(pattern, "{id}", strconv.Itoa(int(idFor(f, rt.kind, true))), 1)
		if f.get(target); len(f.inner.hits) != 1 || f.inner.hits[0] != "GET "+target {
			t.Errorf("%s in scope: forwarded %v, want %s", rt.pattern, f.inner.hits, target)
		}
	}
	// List and static routes forward with the visitor's scope attached.
	var seen web.ViewScope
	f.inner.reply = func(_ http.ResponseWriter, r *http.Request) {
		u, _ := userFrom(r.Context())
		seen = u.Scope
	}
	f.get("/api/v1/ui/findings")
	if _, ok := seen.RepoIDs[f.repoA.ID]; !ok || len(seen.RepoIDs) != 1 || !seen.ReadOnly {
		t.Fatalf("list scope = %+v, want read-only {A}", seen)
	}
}

func TestDeniedRoutesAndMethodsAreRefused(t *testing.T) {
	f := newPortal(t, nil)
	a := strconv.Itoa(int(f.repoA.ID))
	fa := strconv.Itoa(int(f.findingA.ID))
	sa := strconv.Itoa(int(f.scanA.ID))
	denied := []string{
		"/api/v1/ui/search?q=x", "/api/v1/ui/events", "/api/v1/ui/activity", "/api/v1/ui/meta/dynamic",
		"/api/v1/ui/session", "/api/v1/ui/labels", "/api/v1/ui/audit",
		"/api/v1/ui/orgs", "/api/v1/ui/maintainers", "/api/v1/ui/packages", "/api/v1/ui/advisories",
		"/api/v1/ui/sboms", "/api/v1/ui/skills", "/api/v1/ui/settings", "/api/v1/ui/usage",
		"/api/v1/ui/reporting", "/api/v1/ui/benchmark", "/api/v1/ui/investigations",
		"/api/v1/ui/conversations/1", "/api/v1/ui/repositories/branches",
		"/api/v1/ui/repositories/" + a + "/blob/abc/x.go", "/api/v1/ui/repositories/" + a + "/tree/abc/",
		"/api/v1/ui/repositories/" + a + "/workbench", "/api/v1/ui/repositories/" + a + "/scan-config",
		"/api/v1/ui/repositories/" + a + "/compliance", "/api/v1/ui/repositories/" + a + "/expected",
		"/api/v1/ui/repositories/" + a + "/conversations", "/api/v1/ui/repositories/" + a + "/subprojects/x",
		"/api/v1/ui/findings/" + fa + "/exposures", "/api/v1/ui/findings/" + fa + "/submissions",
		"/api/v1/ui/findings/" + fa + "/labels", "/api/v1/ui/findings/" + fa + "/vince",
		"/api/v1/ui/findings/" + fa + "/akrites", "/api/v1/ui/findings/" + fa + "/conversations",
		"/api/v1/ui/scans/" + sa + "/refusal-audit",
		"/api/v1/repositories", "/api/v1/findings/" + fa, "/api/v1/scans", "/api/openapi.yaml",
		"/api/repositories/" + a, "/api/v1/ui/", "/api/v1/ui",
		"/claim-check", "/static/app.css", "/events", "/settings",
		"/findings/" + fa + "/disclosure.md", "/advisories/1/certificate.json",
	}
	for _, p := range denied {
		f.inner.hits = nil
		w := f.get(p)
		// Outside /api/ a client-route-shaped path gets the data-free SPA
		// document (the SPA shows its own not-found); never the inner handler.
		spaDoc := w.Code == http.StatusOK && !strings.HasPrefix(p, "/api/") &&
			strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") && w.Header().Get("Vary") == "Cookie"
		if (w.Code != http.StatusNotFound && !spaDoc) || len(f.inner.hits) != 0 {
			t.Errorf("GET %s: status %d, forwarded %v; want 404", p, w.Code, f.inner.hits)
		}
		if strings.HasPrefix(p, "/api/") {
			if env := decodeEnvelope(t, w); env["code"] != "not_found" {
				t.Errorf("GET %s: envelope %v", p, env)
			}
		}
	}

	sameOrigin := map[string]string{"Sec-Fetch-Site": "same-origin"}
	writes := []string{
		"/api/v1/ui/findings/" + fa, "/api/v1/ui/findings/" + fa + "/status", "/api/v1/ui/findings/" + fa + "/notes",
		"/api/v1/ui/findings/" + fa + "/actions/patch", "/api/v1/ui/repositories/" + a + "/actions/scan",
		"/api/v1/ui/scans/" + sa + "/actions/cancel", "/api/v1/ui/session", "/api/v1/import",
		"/findings/" + fa + "/status", "/findings/" + fa + "/notes", "/repositories/" + a + "/delete",
		"/auth/session", "/auth/access",
	}
	for _, p := range writes {
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			f.inner.hits = nil
			if w := f.do(m, p, true, sameOrigin); w.Code != http.StatusNotFound || len(f.inner.hits) != 0 {
				t.Errorf("%s %s: status %d, forwarded %v; want 404", m, p, w.Code, f.inner.hits)
			}
		}
	}
	// Every allow-listed route refuses non-GET.
	for _, rt := range append(append([]route{}, apiRoutes...), downloadRoutes...) {
		_, p, _ := strings.Cut(rt.pattern, " ")
		p = strings.Replace(p, "{id}", "1", 1)
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
			f.inner.hits = nil
			if w := f.do(m, p, true, sameOrigin); w.Code != http.StatusNotFound || len(f.inner.hits) != 0 {
				t.Errorf("%s %s: status %d, forwarded %v; want 404", m, p, w.Code, f.inner.hits)
			}
		}
	}
	// CSRF: any non-GET/HEAD without Sec-Fetch-Site: same-origin is 403, even
	// the one write route.
	for _, site := range []string{"", "cross-site", "same-site", "none"} {
		for _, m := range []string{http.MethodPost, http.MethodDelete, http.MethodPatch} {
			if w := f.do(m, "/auth/logout", true, map[string]string{"Sec-Fetch-Site": site}); w.Code != http.StatusForbidden {
				t.Errorf("%s /auth/logout Sec-Fetch-Site=%q: status %d, want 403", m, site, w.Code)
			}
		}
	}
}

func TestCookielessAPIRequestIs401JSON(t *testing.T) {
	f := newPortal(t, nil)
	for _, p := range []string{"/api/v1/ui/findings", "/api/v1/ui/findings/" + strconv.Itoa(int(f.findingA.ID)), "/api/v1/ui/meta", "/auth/access", "/auth/session"} {
		w := f.do(http.MethodGet, p, false, map[string]string{"Sec-Fetch-Dest": "document", "Accept": "text/html"})
		if w.Code != http.StatusUnauthorized || w.Header().Get("Location") != "" {
			t.Fatalf("%s: status %d Location %q, want 401 without redirect", p, w.Code, w.Header().Get("Location"))
		}
		if env := decodeEnvelope(t, w); env["code"] != "unauthorized" || env["request_id"] != w.Header().Get("X-Request-Id") {
			t.Fatalf("%s: envelope %v", p, env)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: Cache-Control %q", p, w.Header().Get("Cache-Control"))
		}
	}
	// A tampered or expired cookie is cleared as well.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/ui/findings", nil)
	r.Host = "share.example.org"
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "garbage"})
	w := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || !cookieCleared(w) {
		t.Fatalf("bad cookie: status %d cleared %v", w.Code, cookieCleared(w))
	}
	if f.fetchN.Load() != 0 || len(f.inner.hits) != 0 {
		t.Fatal("an unauthenticated request reached GitHub or the inner handler")
	}
	// A download without a session redirects to sign-in carrying next.
	w = f.do(http.MethodGet, "/findings/1/report.md?audience=upstream", false, nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/auth/login?next="+url.QueryEscape("/findings/1/report.md?audience=upstream") {
		t.Fatalf("download without session: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestGitHubFailuresOnAPI(t *testing.T) {
	t.Run("outage is 503 and keeps the session", func(t *testing.T) {
		f := newPortal(t, func(context.Context, string, func([]githubRepo)) ([]githubRepo, error) {
			return nil, &githubHTTPError{StatusCode: http.StatusBadGateway, Endpoint: "/graphql"}
		})
		w := f.get("/api/v1/ui/findings")
		if w.Code != http.StatusServiceUnavailable || cookieCleared(w) || len(f.inner.hits) != 0 {
			t.Fatalf("status %d cleared %v forwarded %v", w.Code, cookieCleared(w), f.inner.hits)
		}
		if env := decodeEnvelope(t, w); env["code"] != "unavailable" {
			t.Fatalf("envelope %v", env)
		}
	})
	t.Run("rejected token is 401 and clears the session", func(t *testing.T) {
		f := newPortal(t, func(context.Context, string, func([]githubRepo)) ([]githubRepo, error) {
			return nil, &githubHTTPError{StatusCode: http.StatusUnauthorized, Endpoint: "/graphql"}
		})
		w := f.get("/api/v1/ui/findings")
		if w.Code != http.StatusUnauthorized || !cookieCleared(w) || w.Header().Get("Location") != "" {
			t.Fatalf("status %d cleared %v location %q", w.Code, cookieCleared(w), w.Header().Get("Location"))
		}
		if env := decodeEnvelope(t, w); env["code"] != "unauthorized" {
			t.Fatalf("envelope %v", env)
		}
	})
}

func TestSessionNeverStartsAFetch(t *testing.T) {
	f := newPortal(t, nil)
	w := f.get("/auth/session")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got sessionInfo
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Authenticated || got.Login != "octocat" || got.GitHubUserID != 7 || got.Access.State != accessIdle || got.ExpiresAt.IsZero() {
		t.Fatalf("session = %+v", got)
	}
	if f.fetchN.Load() != 0 || len(f.s.access.entries) != 0 {
		t.Fatalf("/auth/session started a lookup (fetches %d, entries %d)", f.fetchN.Load(), len(f.s.access.entries))
	}
	// The JSON carries every documented key, partial included.
	var raw map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &raw)
	for _, k := range []string{"authenticated", "login", "github_user_id", "expires_at", "access", "version"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("session JSON lacks %q: %s", k, w.Body)
		}
	}
	if _, ok := raw["access"].(map[string]any)["partial"]; !ok {
		t.Errorf("session access lacks partial: %s", w.Body)
	}
	// Once something reads access, the session reports it ready.
	f.get("/auth/access")
	_ = json.Unmarshal(f.get("/auth/session").Body.Bytes(), &got)
	if got.Access.State != accessReady || got.Access.Found != 1 {
		t.Fatalf("after lookup: access = %+v", got.Access)
	}
}

func TestAccessReflectsLists(t *testing.T) {
	f := newPortal(t, func(context.Context, string, func([]githubRepo)) ([]githubRepo, error) {
		return []githubRepo{
			{FullName: "acme/a", HTMLURL: "https://github.com/acme/a", ViewerPermission: "ADMIN"},
			{FullName: "acme/unscanned", HTMLURL: "https://github.com/acme/unscanned", ViewerPermission: "MAINTAIN"},
			{FullName: "acme/readonly", HTMLURL: "https://github.com/acme/readonly", ViewerPermission: "READ"},
		}, nil
	})
	f.s.grants = &StaticGrantSource{byUser: map[int64]grantEntry{7: {RepositoryIDs: map[uint]struct{}{f.repoB.ID: {}}}}, now: time.Now}
	w := f.get("/auth/access")
	if w.Code != http.StatusOK || w.Header().Get(portalScopeHeader) != "complete" {
		t.Fatalf("status %d scope %q", w.Code, w.Header().Get(portalScopeHeader))
	}
	var got accessInfo
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	ids := []uint{f.repoA.ID, f.repoB.ID}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if got.AuthorizedRepoCount != 3 || got.ScannedRepoCount != 2 || len(got.RepositoryIDs) != 2 ||
		got.RepositoryIDs[0] != ids[0] || got.RepositoryIDs[1] != ids[1] || got.Incomplete {
		t.Fatalf("access = %+v", got)
	}
	if len(got.Unscanned) != 1 || got.Unscanned[0] != (externalRepoJSON{Name: "acme/unscanned", URL: "https://github.com/acme/unscanned"}) {
		t.Fatalf("unscanned = %+v", got.Unscanned)
	}
	if len(got.Insufficient) != 1 || got.Insufficient[0] != (insufficientRepoJSON{Name: "acme/readonly", URL: "https://github.com/acme/readonly", Access: "Read access"}) {
		t.Fatalf("insufficient = %+v", got.Insufficient)
	}
	if !strings.Contains(w.Body.String(), `"authorized_repo_count":3`) {
		t.Fatalf("unexpected JSON keys: %s", w.Body)
	}
}

func TestPartialScopeIsMarked(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	f := newPortal(t, func(_ context.Context, _ string, progress func([]githubRepo)) ([]githubRepo, error) {
		progress([]githubRepo{{FullName: "acme/a", HTMLURL: "https://github.com/acme/a", ViewerPermission: "WRITE"}})
		<-release
		return nil, nil
	})
	f.s.access.loadingMax = 30 * time.Millisecond
	w := f.get("/api/v1/ui/findings")
	if w.Code != http.StatusOK || w.Header().Get(portalScopeHeader) != "partial" || len(f.inner.hits) != 1 {
		t.Fatalf("status %d scope %q forwarded %v", w.Code, w.Header().Get(portalScopeHeader), f.inner.hits)
	}
	var got accessInfo
	_ = json.Unmarshal(f.get("/auth/access").Body.Bytes(), &got)
	if !got.Incomplete || len(got.RepositoryIDs) != 1 {
		t.Fatalf("access while partial = %+v", got)
	}
	var sess sessionInfo
	_ = json.Unmarshal(f.get("/auth/session").Body.Bytes(), &sess)
	if sess.Access.State != accessLoading || !sess.Access.Partial || sess.Access.Found != 1 {
		t.Fatalf("session access while partial = %+v", sess.Access)
	}
}

func TestAPIResponsesAreNoStore(t *testing.T) {
	f := newPortal(t, nil)
	f.inner.reply = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Header().Set("Vary", "Accept-Encoding")
		_, _ = io.WriteString(w, "{}")
	}
	for _, p := range []string{"/api/v1/ui/meta", "/findings/" + strconv.Itoa(int(f.findingA.ID)) + "/report.md"} {
		w := f.get(p)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", p, w.Header().Get("Cache-Control"))
		}
		if v := strings.Join(w.Header().Values("Vary"), ","); !strings.Contains(v, "Cookie") || !strings.Contains(v, "Accept-Encoding") {
			t.Errorf("%s: Vary %q", p, v)
		}
	}
}

func TestJSONLogoutRevokesAndInvalidates(t *testing.T) {
	var revoked atomic.Bool
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/grant") {
			revoked.Store(true)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer gh.Close()
	old := githubAPI
	githubAPI = gh.URL
	defer func() { githubAPI = old }()

	f := newPortal(t, nil)
	f.get("/auth/access") // populate the cache
	if len(f.s.access.entries) != 1 {
		t.Fatal("access lookup was not cached")
	}
	w := f.do(http.MethodPost, "/auth/logout", true, map[string]string{"Sec-Fetch-Site": "same-origin", "Accept": "application/json"})
	if w.Code != http.StatusNoContent || w.Header().Get("Location") != "" || w.Body.Len() != 0 {
		t.Fatalf("logout: status %d location %q body %q", w.Code, w.Header().Get("Location"), w.Body)
	}
	if !revoked.Load() || !cookieCleared(w) || len(f.s.access.entries) != 0 {
		t.Fatalf("revoked %v cleared %v entries %d", revoked.Load(), cookieCleared(w), len(f.s.access.entries))
	}
	// Without Accept: application/json the redirect is unchanged.
	w = f.do(http.MethodPost, "/auth/logout", true, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/auth/login" {
		t.Fatalf("form logout: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestNextValidation(t *testing.T) {
	for next, want := range map[string]bool{
		"/":                                   true,
		"/findings/1":                         true,
		"/findings?severity=high":             true,
		"/a//b":                               true,
		"":                                    false,
		"findings":                            false,
		"//evil.example":                      false,
		"/\\evil.example":                     false,
		"/a\\b":                               false,
		"https://evil.example/":               false,
		"/a\nb":                               false,
		"/a\x00":                              false,
		"/" + strings.Repeat("a", maxNextLen): false,
	} {
		if got := validNext(next); got != want {
			t.Errorf("validNext(%q) = %v, want %v", next, got, want)
		}
	}

	// next rides the state cookie through GitHub and back.
	f := newPortal(t, nil)
	w := f.do(http.MethodGet, "/auth/login?next="+url.QueryEscape("/findings/12?section=patch"), false, nil)
	if w.Code != http.StatusFound {
		t.Fatalf("login: %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	var st *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == stateCookie {
			st = c
		}
	}
	if st == nil || !st.Secure || !st.HttpOnly {
		t.Fatalf("state cookie = %+v", st)
	}
	state, next := parseStateCookie(st.Value)
	if state == "" || state != loc.Query().Get("state") || next != "/findings/12?section=patch" {
		t.Fatalf("state %q (github %q) next %q", state, loc.Query().Get("state"), next)
	}
	// A hostile next is dropped at login and again at the callback.
	w = f.do(http.MethodGet, "/auth/login?next="+url.QueryEscape("//evil.example/x"), false, nil)
	for _, c := range w.Result().Cookies() {
		if c.Name == stateCookie {
			if _, next := parseStateCookie(c.Value); next != "/" {
				t.Fatalf("hostile next kept: %q", next)
			}
		}
	}
	if _, next := parseStateCookie("s." + base64.RawURLEncoding.EncodeToString([]byte("//evil"))); next != "/" {
		t.Fatalf("forged state cookie next kept: %q", next)
	}
	// The callback rejects a state that does not match the cookie's state part.
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state=other&code=x", nil)
	r.Host = "share.example.org"
	r.AddCookie(&http.Cookie{Name: stateCookie, Value: st.Value})
	w = httptest.NewRecorder()
	f.s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("callback with wrong state: %d", w.Code)
	}
}

func writeUIDir(t *testing.T, doc string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "_app/immutable/entry"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "_app/immutable/entry/start.js"), []byte("export{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "favicon.svg"), []byte("<svg/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(uiDirEnv, dir)
	return dir
}

func TestSPAFallback(t *testing.T) {
	writeUIDir(t, "<!doctype html><title>portal</title>")
	f := newPortal(t, nil)
	for _, p := range []string{"/", "/findings/1", "/findings", "/repositories/3?tab=scans", "/scans/9", "/login?next=%2F", "/index.html"} {
		w := f.do(http.MethodGet, p, false, nil)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<title>portal</title>") {
			t.Errorf("GET %s: %d %q, want the document", p, w.Code, w.Body)
		}
		if w.Header().Get("Cache-Control") != "no-cache" || !strings.Contains(w.Header().Get("Vary"), "Cookie") {
			t.Errorf("GET %s: caching headers %v", p, w.Header())
		}
	}
	if f.fetchN.Load() != 0 || len(f.inner.hits) != 0 {
		t.Fatal("serving the document touched GitHub or the inner handler")
	}
	for _, p := range []string{"/api/x", "/api/v1/ui/nope", "/auth/x", "/findings/1/disclosure.md", "/repositories/1/thing.json", "/static/app.css"} {
		if w := f.do(http.MethodGet, p, false, nil); w.Code == http.StatusOK {
			t.Errorf("GET %s: 200, want no SPA fallback", p)
		}
	}
	if w := f.do(http.MethodGet, "/api/x", false, nil); w.Code != http.StatusNotFound {
		t.Errorf("GET /api/x: %d", w.Code)
	}
	w := f.do(http.MethodGet, "/_app/immutable/entry/start.js", false, nil)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != cacheImmutable {
		t.Errorf("immutable asset: %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	w = f.do(http.MethodGet, "/favicon.svg", false, nil)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != cacheNoCache {
		t.Errorf("asset: %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
}

func TestSPAEmbeddedPlaceholderServes(t *testing.T) {
	t.Setenv(uiDirEnv, "")
	f := newPortal(t, nil)
	if w := f.do(http.MethodGet, "/", false, nil); w.Code != http.StatusOK {
		t.Fatalf("embedded document: %d", w.Code)
	}
}

func TestSPADocumentCSPHashesInlineScripts(t *testing.T) {
	boot := "\n\t\t\t__sveltekit_x = { base: \"\" };\n\t\t\timport('/_app/immutable/entry/start.js');\n\t\t"
	writeUIDir(t, `<!doctype html><html><head><script type="module" src="/_app/immutable/entry/start.js"></script></head>`+
		`<body><script>`+boot+`</script><script>second()</script></body></html>`)
	f := newPortal(t, nil)
	w := f.do(http.MethodGet, "/findings/1", false, nil)
	csp := w.Header().Get("Content-Security-Policy")
	for _, body := range []string{boot, "second()"} {
		sum := sha256.Sum256([]byte(body))
		if want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"; !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %s", csp, want)
		}
	}
	if n := strings.Count(csp, "'sha256-"); n != 2 {
		t.Errorf("CSP hashes %d scripts, want 2 (external src= scripts are covered by 'self')", n)
	}
	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'", "img-src 'self' data: " + avatarImgHost, "object-src 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline'; img") && strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("CSP allows inline scripts: %q", csp)
	}
}

// TestErrorEnvelopeMatchesWeb compares the portal's envelope with the one
// internal/web's writeUIError produces, byte for byte apart from the message
// and request id.
func TestErrorEnvelopeMatchesWeb(t *testing.T) {
	gdb := openTestDB(t)
	sqldb, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ws, err := web.New(gdb, queue.NewNoSchema(sqldb, log, 0, queue.SQLite), log, web.NewBroker(), &worker.Worker{DB: gdb})
	if err != nil {
		t.Fatal(err)
	}
	ws.OperatorToken = "operator"
	r := httptest.NewRequest(http.MethodGet, "/api/v1/ui/session", nil)
	r.Host = "127.0.0.1"
	webW := httptest.NewRecorder()
	ws.Handler().ServeHTTP(webW, r)
	if webW.Code != http.StatusUnauthorized {
		t.Fatalf("web 401 probe: %d %s", webW.Code, webW.Body)
	}

	f := newPortal(t, nil)
	portalW := f.do(http.MethodGet, "/api/v1/ui/findings", false, nil)

	idRE := regexp.MustCompile(`^[0-9a-f]{16}$`)
	normalize := func(w *httptest.ResponseRecorder) string {
		id := w.Header().Get("X-Request-Id")
		if !idRE.MatchString(id) {
			t.Fatalf("X-Request-Id %q", id)
		}
		body := strings.Replace(w.Body.String(), id, "ID", 1)
		var env map[string]any
		if err := json.Unmarshal([]byte(body), &env); err != nil {
			t.Fatal(err)
		}
		return strings.Replace(body, strconv.Quote(env["error"].(string)), `"MSG"`, 1)
	}
	if a, b := normalize(webW), normalize(portalW); a != b {
		t.Fatalf("envelopes differ:\nweb:    %s\nportal: %s", a, b)
	}
	for _, h := range []string{"Content-Type", "Cache-Control"} {
		if webW.Header().Get(h) != portalW.Header().Get(h) {
			t.Errorf("%s: web %q portal %q", h, webW.Header().Get(h), portalW.Header().Get(h))
		}
	}
}

func TestLegacyModeKeepsHTMLPortal(t *testing.T) {
	f := newPortal(t, nil)
	f.s.cfg.UI = UILegacy
	// SPA client routes are the legacy pages again, behind a redirect.
	if w := f.do(http.MethodGet, "/findings", false, nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/auth/login" {
		t.Fatalf("legacy /findings: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := f.do(http.MethodGet, "/findings/1", false, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("legacy /findings/1: %d", w.Code)
	}
	f.inner.hits = nil
	if f.do(http.MethodGet, "/static/app.css", false, nil); len(f.inner.hits) != 1 {
		t.Fatal("legacy mode should forward /static/")
	}
	// The JSON API keeps its 401 in legacy mode too.
	if w := f.do(http.MethodGet, "/api/v1/ui/findings", false, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("legacy API: %d", w.Code)
	}
	if w := f.do(http.MethodGet, "/no-such-page", false, nil); w.Code != http.StatusNotFound {
		t.Fatalf("legacy unknown page: %d", w.Code)
	}
}

func TestDevIdentity(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8081", ":8081", "share.example.org:443", "192.168.1.5:8081", "nonsense"} {
		if _, err := LoadDevConfig(addr, "", DevIdentity{Login: "dev", UserID: 1}); err == nil {
			t.Errorf("LoadDevConfig(%q) accepted a non-loopback address", addr)
		}
	}
	if _, err := LoadDevConfig("127.0.0.1:8081", "https://share.example.org", DevIdentity{Login: "dev", UserID: 1}); err == nil {
		t.Error("LoadDevConfig accepted a public base URL")
	}
	for _, addr := range []string{"127.0.0.1:8081", "localhost:8081", "[::1]:8081"} {
		if _, err := LoadDevConfig(addr, "", DevIdentity{Login: "dev", UserID: 1}); err != nil {
			t.Errorf("LoadDevConfig(%q): %v", addr, err)
		}
	}

	gdb := openTestDB(t)
	a := db.Repository{URL: "https://github.com/acme/a", Name: "a"}
	b := db.Repository{URL: "https://github.com/other/b", Name: "b"}
	c := db.Repository{URL: "https://github.com/other/c", Name: "c"}
	for _, repo := range []*db.Repository{&a, &b, &c} {
		if err := gdb.Create(repo).Error; err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := LoadDevConfig("127.0.0.1:8081", "", DevIdentity{
		Login: "dev-maintainer", UserID: 42,
		Repos:   []string{"acme/a", "acme/unscanned=WRITE", "acme/readonly=READ"},
		RepoIDs: []uint{b.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, gdb, slog.New(slog.NewTextHandler(io.Discard, nil)), &recorder{}, EmptyGrantSource())
	h := s.Handler()
	req := func(target, host string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Host = host
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := req("/auth/login", "evil.example", nil); w.Code != http.StatusForbidden {
		t.Fatalf("dev mode accepted a non-loopback Host: %d", w.Code)
	}
	w := req("/auth/login?next=%2Ffindings", "localhost:5173", nil)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/findings" {
		t.Fatalf("dev login: %d %q", w.Code, w.Header().Get("Location"))
	}
	var sess *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookie {
			sess = ck
		}
	}
	if sess == nil || sess.Secure || !sess.HttpOnly {
		t.Fatalf("dev session cookie = %+v (want HttpOnly, not Secure)", sess)
	}
	var got accessInfo
	if err := json.Unmarshal(req("/auth/access", "127.0.0.1:8081", sess).Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ScannedRepoCount != 2 || len(got.Unscanned) != 1 || len(got.Insufficient) != 1 {
		t.Fatalf("dev access = %+v", got)
	}
	var info sessionInfo
	_ = json.Unmarshal(req("/auth/session", "127.0.0.1:8081", sess).Body.Bytes(), &info)
	if info.Login != "dev-maintainer" || info.GitHubUserID != 42 {
		t.Fatalf("dev session = %+v", info)
	}
}
