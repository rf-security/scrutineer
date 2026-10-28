package sharing

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

// sentinel is a next-handler that records whether it was reached.
type sentinel struct{ hit bool }

func (s *sentinel) ServeHTTP(http.ResponseWriter, *http.Request) { s.hit = true }

// newServer builds a portal Server whose inner handler is a sentinel, so tests
// can assert whether a request would have been forwarded.
func newServer(t *testing.T) (*Server, *sentinel) {
	t.Helper()
	inner := &sentinel{}
	s := New(testConfig(), openTestDB(t), slog.New(slog.NewTextHandler(io.Discard, nil)), inner, EmptyGrantSource())
	return s, inner
}

func TestAuthorizeBlocksOutOfScopeFinding(t *testing.T) {
	s, inner := newServer(t)

	repo := db.Repository{URL: "https://github.com/o/r", Name: "r"}
	if err := s.db.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	if err := s.db.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "bug"}
	if err := s.db.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}

	call := func(scopeIDs map[uint]struct{}) int {
		inner.hit = false
		h := s.authorize(kindFinding, inner)
		r := httptest.NewRequest("GET", "/findings/1", nil)
		r.SetPathValue("id", strconv.FormatUint(uint64(finding.ID), 10))
		r = r.WithContext(context.WithValue(r.Context(), userKey{}, &user{Login: "x", RepoIDs: scopeIDs}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// Out of scope: 404 and never forwarded.
	if code := call(map[uint]struct{}{999: {}}); code != http.StatusNotFound {
		t.Fatalf("out-of-scope: want 404, got %d", code)
	}
	if inner.hit {
		t.Fatal("out-of-scope request was forwarded to inner handler")
	}
	// In scope: forwarded.
	if code := call(map[uint]struct{}{repo.ID: {}}); code == http.StatusNotFound {
		t.Fatalf("in-scope: unexpected 404")
	}
	if !inner.hit {
		t.Fatal("in-scope request was not forwarded")
	}
}

func TestAuthorizeBlocksOutOfScopeScan(t *testing.T) {
	s, inner := newServer(t)

	repo := db.Repository{URL: "https://github.com/o/r", Name: "r"}
	if err := s.db.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	if err := s.db.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}

	call := func(scopeIDs map[uint]struct{}) int {
		inner.hit = false
		h := s.authorize(kindScan, inner)
		r := httptest.NewRequest("GET", "/scans/1", nil)
		r.SetPathValue("id", strconv.FormatUint(uint64(scan.ID), 10))
		r = r.WithContext(context.WithValue(r.Context(), userKey{}, &user{Login: "x", RepoIDs: scopeIDs}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// A scan whose repository is out of scope: 404 and never forwarded.
	if code := call(map[uint]struct{}{999: {}}); code != http.StatusNotFound {
		t.Fatalf("out-of-scope: want 404, got %d", code)
	}
	if inner.hit {
		t.Fatal("out-of-scope scan was forwarded to inner handler")
	}
	// The scan's own repository is in scope: forwarded.
	if code := call(map[uint]struct{}{repo.ID: {}}); code == http.StatusNotFound {
		t.Fatalf("in-scope: unexpected 404")
	}
	if !inner.hit {
		t.Fatal("in-scope scan was not forwarded")
	}
}

func TestListRouteSkipsPerResourceCheck(t *testing.T) {
	s, inner := newServer(t)
	h := s.authorize(kindList, inner)
	r := httptest.NewRequest("GET", "/findings", nil)
	r = r.WithContext(context.WithValue(r.Context(), userKey{}, &user{RepoIDs: map[uint]struct{}{}}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !inner.hit {
		t.Fatal("list route should forward; the scoped query does the filtering")
	}
}

func TestHostAndRouteGuards(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()

	// Wrong host is rejected before anything else.
	r := httptest.NewRequest("GET", "/auth/login", nil)
	r.Host = "evil.example.net"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong host: want 403, got %d", w.Code)
	}

	// Correct host, unauthenticated protected route → redirect to login.
	r = httptest.NewRequest("GET", "/findings", nil)
	r.Host = s.cfg.host
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/auth/login" {
		t.Fatalf("protected route: want 303→/auth/login, got %d %q", w.Code, w.Header().Get("Location"))
	}

	// An htmx-driven request to a protected route must get an HX-Redirect (htmx
	// swallows ordinary 3xx), not a bare 303 it would silently fail to follow.
	r = httptest.NewRequest("GET", "/findings", nil)
	r.Host = s.cfg.host
	r.Header.Set("HX-Request", "true")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || w.Header().Get("HX-Redirect") != "/auth/login" {
		t.Fatalf("htmx protected route: want 204 + HX-Redirect /auth/login, got %d HX-Redirect=%q", w.Code, w.Header().Get("HX-Redirect"))
	}

	// A non-whitelisted path 404s at the portal (never reaches the inner app).
	r = httptest.NewRequest("GET", "/settings", nil)
	r.Host = s.cfg.host
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("non-whitelisted path: want 404, got %d", w.Code)
	}

	// Cross-site POST is rejected before routing.
	r = httptest.NewRequest("POST", "/auth/logout", nil)
	r.Host = s.cfg.host
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST: want 403, got %d", w.Code)
	}

	// The portal is read-only: the finding write routes are withheld, so even a
	// same-origin POST to them 404s at the portal and never reaches the inner
	// handler.
	for _, path := range []string{"/findings/1/status", "/findings/1/notes"} {
		r = httptest.NewRequest("POST", path, nil)
		r.Host = s.cfg.host
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("write route %s: want 404 (withheld), got %d", path, w.Code)
		}
	}
}

func TestRequireAuthGitHubFailureHandling(t *testing.T) {
	tests := []struct {
		name         string
		githubCode   int
		wantCode     int
		wantRedirect bool
		wantCleared  bool
	}{
		{
			name:         "invalid token clears session",
			githubCode:   http.StatusUnauthorized,
			wantCode:     http.StatusSeeOther,
			wantRedirect: true,
			wantCleared:  true,
		},
		{
			name:        "transient failure preserves session",
			githubCode:  http.StatusServiceUnavailable,
			wantCode:    http.StatusServiceUnavailable,
			wantCleared: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/graphql" {
					t.Errorf("path = %q, want /graphql", r.URL.Path)
				}
				if tt.githubCode == http.StatusServiceUnavailable {
					w.Header().Set("Retry-After", "0")
				}
				w.WriteHeader(tt.githubCode)
			}))
			defer srv.Close()
			old := githubAPI
			githubAPI = srv.URL
			defer func() { githubAPI = old }()

			s, inner := newServer(t)
			sealed, err := s.cfg.seal(session{
				GitHubUserID: 1,
				Login:        "octocat",
				Token:        "tok",
				ExpiresAt:    time.Now().Add(time.Hour).Unix(),
			})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sealed})
			w := httptest.NewRecorder()
			s.requireAuth(inner).ServeHTTP(w, r)

			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantCode)
			}
			if tt.wantRedirect && w.Header().Get("Location") != "/auth/login" {
				t.Fatalf("Location = %q, want /auth/login", w.Header().Get("Location"))
			}
			if inner.hit {
				t.Fatal("request reached inner handler after GitHub failure")
			}
			var cleared bool
			for _, c := range w.Result().Cookies() {
				if c.Name == sessionCookie && c.MaxAge < 0 {
					cleared = true
				}
			}
			if cleared != tt.wantCleared {
				t.Fatalf("session cleared = %v, want %v", cleared, tt.wantCleared)
			}
		})
	}
}

func TestRequireAuthAppliesGrantForExactNumericUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"viewer":{"repositories":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`)
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	gdb := openTestDB(t)
	repo := db.Repository{URL: "https://github.com/acme/manual", Name: "manual"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	grants := &StaticGrantSource{
		byUser: map[int64]grantEntry{
			583231: {RepositoryIDs: map[uint]struct{}{repo.ID: {}}},
		},
		now: time.Now,
	}
	inner := &sentinel{}
	s := New(testConfig(), gdb, slog.New(slog.NewTextHandler(io.Discard, nil)), inner, grants)

	call := func(userID int64) int {
		inner.hit = false
		sealed, err := s.cfg.seal(session{
			GitHubUserID: userID,
			Login:        "display-name-is-not-authority",
			Token:        "tok",
			ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "/repositories/1", nil)
		r.SetPathValue("id", strconv.FormatUint(uint64(repo.ID), 10))
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sealed})
		w := httptest.NewRecorder()
		s.requireAuth(s.authorize(kindRepo, inner)).ServeHTTP(w, r)
		return w.Code
	}

	if code := call(583231); code == http.StatusNotFound || !inner.hit {
		t.Fatalf("configured numeric user was denied: status %d, forwarded %v", code, inner.hit)
	}
	if code := call(583232); code != http.StatusNotFound || inner.hit {
		t.Fatalf("different numeric user inherited grant: status %d, forwarded %v", code, inner.hit)
	}
}

func TestFirstPageNavigationShowsProgressUntilLookupFinishes(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = io.WriteString(w, `{"data":{"viewer":{"repositories":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`)
	}))
	defer srv.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	s, inner := newServer(t)
	sealed, err := s.cfg.seal(session{GitHubUserID: 1, Login: "octocat", Token: "tok", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string, header map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = "share.example.org"
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sealed})
		for k, v := range header {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	status := func() accessStatus {
		var st accessStatus
		if err := json.NewDecoder(request("/auth/status", nil).Body).Decode(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}

	w := request("/", map[string]string{"Sec-Fetch-Dest": "document"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Loading your repositories") {
		t.Fatalf("first navigation: status %d, want the progress page", w.Code)
	}
	if inner.hit {
		t.Fatal("progress page should not reach the inner handler")
	}
	if got := status().State; got != accessLoading {
		t.Fatalf("status during lookup = %q, want loading", got)
	}
	if w := request("/auth/loading.js", nil); w.Code != http.StatusOK {
		t.Fatalf("loading.js: status %d", w.Code)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for status().State != accessReady {
		if time.Now().After(deadline) {
			t.Fatal("lookup never became ready")
		}
		time.Sleep(time.Millisecond)
	}
	w = request("/", map[string]string{"Sec-Fetch-Dest": "document"})
	if !inner.hit {
		t.Fatalf("navigation after lookup: status %d, want it forwarded", w.Code)
	}
}

func TestNonDocumentRequestWaitsForFirstLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(w, `{"data":{"viewer":{"repositories":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`)
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	s, inner := newServer(t)
	sealed, err := s.cfg.seal(session{GitHubUserID: 1, Login: "octocat", Token: "tok", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("HX-Request", "true")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sealed})
	s.requireAuth(inner).ServeHTTP(httptest.NewRecorder(), r)
	if !inner.hit {
		t.Fatal("htmx request should wait for the lookup and be forwarded, not get the progress page")
	}
}

func TestAccessStatusWithoutSessionIsUnauthorized(t *testing.T) {
	s, _ := newServer(t)
	r := httptest.NewRequest(http.MethodGet, "/auth/status", nil)
	w := httptest.NewRecorder()
	s.accessStatus(w, r)
	var st accessStatus
	if err := json.NewDecoder(w.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.State != accessUnauthorized {
		t.Fatalf("state = %q, want unauthorized", st.State)
	}
}

func TestNavigationPastLoadingWindowServesPartialScope(t *testing.T) {
	gdb := openTestDB(t)
	first := db.Repository{URL: "https://github.com/acme/first", Name: "first"}
	second := db.Repository{URL: "https://github.com/acme/second", Name: "second"}
	for _, repo := range []*db.Repository{&first, &second} {
		if err := gdb.Create(repo).Error; err != nil {
			t.Fatal(err)
		}
	}

	var seen *user
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen, _ = userFrom(r.Context()) })
	s := New(testConfig(), gdb, slog.New(slog.NewTextHandler(io.Discard, nil)), inner, EmptyGrantSource())
	s.access.loadingMax = 50 * time.Millisecond
	release := make(chan struct{})
	defer close(release)
	s.access.fetch = func(_ context.Context, _ string, progress func([]githubRepo)) ([]githubRepo, error) {
		page := []githubRepo{{FullName: "acme/first", HTMLURL: "https://github.com/acme/first", ViewerPermission: "WRITE"}}
		progress(page)
		<-release
		return append(page, githubRepo{FullName: "acme/second", HTMLURL: "https://github.com/acme/second", ViewerPermission: "WRITE"}), nil
	}

	sealed, err := s.cfg.seal(session{GitHubUserID: 1, Login: "octocat", Token: "tok", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	navigate := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Sec-Fetch-Dest", "document")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sealed})
		w := httptest.NewRecorder()
		s.requireAuth(inner).ServeHTTP(w, r)
		return w
	}

	if w := navigate(); !strings.Contains(w.Body.String(), "Loading your repositories") || seen != nil {
		t.Fatal("first navigation should get the progress page")
	}
	time.Sleep(60 * time.Millisecond)
	navigate()
	if seen == nil {
		t.Fatal("navigation past the loading window should be forwarded")
	}
	if _, ok := seen.RepoIDs[first.ID]; !ok {
		t.Fatal("partial scope is missing the repository from the first page")
	}
	if _, ok := seen.RepoIDs[second.ID]; ok {
		t.Fatal("partial scope includes a repository GitHub has not reported yet")
	}
}
