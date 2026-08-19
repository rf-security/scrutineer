package sharing

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	s := New(testConfig(), openTestDB(t), slog.New(slog.NewTextHandler(io.Discard, nil)), inner)
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
				w.WriteHeader(tt.githubCode)
			}))
			defer srv.Close()
			old := githubAPI
			githubAPI = srv.URL
			defer func() { githubAPI = old }()

			s, inner := newServer(t)
			sealed, err := s.cfg.seal(session{
				Login:     "octocat",
				Token:     "tok",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
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
