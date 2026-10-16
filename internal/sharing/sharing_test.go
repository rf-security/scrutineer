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
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

func testConfig() *Config {
	return &Config{
		Addr:         "127.0.0.1:8081",
		BaseURL:      "https://share.example.org",
		clientID:     "id",
		clientSecret: "secret",
		host:         "share.example.org",
		sessionKey:   sha256.Sum256([]byte("test-session-key")),
	}
}

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := db.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqldb, err := gdb.DB(); err == nil {
			_ = sqldb.Close()
		}
	})
	return gdb
}

func TestSessionRoundTrip(t *testing.T) {
	c := testConfig()
	in := session{Login: "octocat", Token: "ghp_test123", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	sealed, err := c.seal(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.open(sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if out.Login != in.Login || out.Token != in.Token {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestSessionExpired(t *testing.T) {
	c := testConfig()
	sealed, err := c.seal(session{Login: "x", ExpiresAt: time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.open(sealed); err == nil {
		t.Fatal("expected expired session to be rejected")
	}
}

func TestSessionTamperRejected(t *testing.T) {
	c := testConfig()
	sealed, err := c.seal(session{Login: "x", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the ciphertext (decode first so the mutation is not
	// lost in unused trailing bits of the last base64 character); the GCM tag
	// must then fail to authenticate.
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xFF
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := c.open(tampered); err == nil {
		t.Fatal("expected tampered session to be rejected")
	}
	// A session sealed under a different key must not open under ours.
	other := testConfig()
	other.sessionKey = sha256.Sum256([]byte("different-key"))
	otherSealed, _ := other.seal(session{Login: "x", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if _, err := c.open(otherSealed); err == nil {
		t.Fatal("expected foreign-key session to be rejected")
	}
}

func TestFetchMaintainedReposOwnedAndOrg(t *testing.T) {
	// Directly owned repositories are included unconditionally.
	owned := []githubRepo{{FullName: "me/owned", HTMLURL: "https://github.com/me/owned"}}

	orgs := []githubOrg{{Login: "acme"}}
	// Org repositories are filtered by the visitor's effective permission,
	// carried in each listing entry's permissions object.
	orgRepos := []githubRepo{
		{FullName: "acme/admin", HTMLURL: "https://github.com/acme/admin"},
		{FullName: "acme/maintain", HTMLURL: "https://github.com/acme/maintain"},
		{FullName: "acme/push", HTMLURL: "https://github.com/acme/push"},
		{FullName: "acme/readonly", HTMLURL: "https://github.com/acme/readonly"},
	}
	orgRepos[0].Permissions.Admin = true
	orgRepos[1].Permissions.Maintain = true
	orgRepos[2].Permissions.Push = true
	// orgRepos[3] has no elevated permission and must be dropped.

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// One short page per endpoint ends pagination.
		switch r.URL.Path {
		case "/user/repos":
			if aff := r.URL.Query().Get("affiliation"); aff != "owner" {
				t.Errorf("owned listing affiliation = %q, want owner", aff)
			}
			_ = json.NewEncoder(w).Encode(owned)
		case "/user/orgs":
			_ = json.NewEncoder(w).Encode(orgs)
		case "/orgs/acme/repos":
			_ = json.NewEncoder(w).Encode(orgRepos)
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	repos, err := fetchMaintainedRepos(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool, len(repos))
	for _, r := range repos {
		got[r.FullName] = true
	}
	for _, want := range []string{"me/owned", "acme/admin", "acme/maintain", "acme/push"} {
		if !got[want] {
			t.Errorf("expected %q in maintained set: %+v", want, repos)
		}
	}
	if got["acme/readonly"] {
		t.Fatal("read-only org repo leaked into maintained set")
	}
	if len(repos) != 4 {
		t.Fatalf("expected 4 maintained repos, got %d: %+v", len(repos), repos)
	}
}

func TestLogoutRevokesGrantAndClearsCookie(t *testing.T) {
	cfg := testConfig()
	cfg.clientID = "client-123"
	cfg.clientSecret = "shh"

	// A valid session cookie carrying a token to revoke.
	sealed, err := cfg.seal(session{Login: "octocat", Token: "ghp_tok", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}

	var (
		gotMethod, gotPath, gotAuthUser, gotAuthPass, gotToken string
		revoked                                                bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuthUser, gotAuthPass, _ = r.BasicAuth()
		var body struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotToken = body.AccessToken
		revoked = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	s := New(cfg, openTestDB(t), slog.New(slog.NewTextHandler(io.Discard, nil)), &sentinel{})
	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sealed})
	w := httptest.NewRecorder()
	s.logout(w, r)

	if !revoked {
		t.Fatal("logout did not call GitHub to revoke the grant")
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("revoke method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/applications/client-123/grant" {
		t.Errorf("revoke path = %q, want /applications/client-123/grant", gotPath)
	}
	if gotAuthUser != "client-123" || gotAuthPass != "shh" {
		t.Errorf("revoke basic auth = %q:%q, want client-123:shh", gotAuthUser, gotAuthPass)
	}
	if gotToken != "ghp_tok" {
		t.Errorf("revoked token = %q, want ghp_tok", gotToken)
	}

	// The response must clear the session cookie and redirect to login. A plain
	// form post gets a 303 the browser follows on its own.
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/auth/login" {
		t.Fatalf("logout: want 303→/auth/login, got %d %q", w.Code, w.Header().Get("Location"))
	}
	var cleared bool
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout did not clear the session cookie")
	}
}

func TestLogoutHTMXRedirects(t *testing.T) {
	cfg := testConfig()
	sealed, err := cfg.seal(session{Login: "octocat", Token: "ghp_tok", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	// Grant revocation is exercised elsewhere; here GitHub just accepts it so we
	// can focus on the htmx-aware redirect.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	s := New(cfg, openTestDB(t), slog.New(slog.NewTextHandler(io.Discard, nil)), &sentinel{})
	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sealed})
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.logout(w, r)

	// htmx swallows a 3xx, so the handler must signal navigation with HX-Redirect.
	if w.Code != http.StatusNoContent || w.Header().Get("HX-Redirect") != "/auth/login" {
		t.Fatalf("htmx logout: want 204 + HX-Redirect /auth/login, got %d HX-Redirect=%q", w.Code, w.Header().Get("HX-Redirect"))
	}
}

func TestResolveScopeIntersectsByURL(t *testing.T) {
	gdb := openTestDB(t)
	// scrutineer knows these two repos.
	owned := db.Repository{URL: "https://github.com/o/owned.git", Name: "owned", HTMLURL: "https://github.com/o/owned"}
	other := db.Repository{URL: "https://github.com/o/other", Name: "other"}
	if err := gdb.Create(&owned).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&other).Error; err != nil {
		t.Fatal(err)
	}

	// GitHub says the visitor maintains "owned" (different casing / .git) and a
	// repo scrutineer has never seen.
	gh := []githubRepo{
		{HTMLURL: "https://github.com/O/Owned", CloneURL: "https://github.com/o/owned.git"},
		{HTMLURL: "https://github.com/o/unknown", CloneURL: "https://github.com/o/unknown.git"},
	}
	scope, err := resolveScope(context.Background(), gdb, gh)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.ReadOnly {
		t.Fatal("scope must be read-only")
	}
	if _, ok := scope.RepoIDs[owned.ID]; !ok {
		t.Fatalf("expected owned repo %d in scope: %+v", owned.ID, scope.RepoIDs)
	}
	if _, ok := scope.RepoIDs[other.ID]; ok {
		t.Fatal("unmaintained repo leaked into scope")
	}
	if len(scope.RepoIDs) != 1 {
		t.Fatalf("expected exactly one repo in scope, got %d", len(scope.RepoIDs))
	}
}
