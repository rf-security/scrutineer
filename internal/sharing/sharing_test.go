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
	"strings"
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
	in := session{GitHubUserID: 1, Login: "octocat", Token: "ghp_test123", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	sealed, err := c.seal(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.open(sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if out.GitHubUserID != in.GitHubUserID || out.Login != in.Login || out.Token != in.Token {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestSessionExpired(t *testing.T) {
	c := testConfig()
	sealed, err := c.seal(session{GitHubUserID: 1, Login: "x", ExpiresAt: time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.open(sealed); err == nil {
		t.Fatal("expected expired session to be rejected")
	}
}

func TestSessionWithoutNumericIdentityRejected(t *testing.T) {
	c := testConfig()
	sealed, err := c.seal(session{Login: "legacy", Token: "tok", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.open(sealed); err == nil || !strings.Contains(err.Error(), "GitHub user ID") {
		t.Fatalf("open legacy session error = %v, want missing GitHub user ID", err)
	}
}

func TestSessionTamperRejected(t *testing.T) {
	c := testConfig()
	sealed, err := c.seal(session{GitHubUserID: 1, Login: "x", ExpiresAt: time.Now().Add(time.Hour).Unix()})
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
	otherSealed, _ := other.seal(session{GitHubUserID: 1, Login: "x", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if _, err := c.open(otherSealed); err == nil {
		t.Fatal("expected foreign-key session to be rejected")
	}
}

func TestFetchUserReturnsStableNumericIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Errorf("path = %q, want /user", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `{"id":583231,"login":"octocat"}`)
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	identity, err := fetchUser(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if identity.ID != 583231 || identity.Login != "octocat" {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestFetchUserRejectsMissingNumericIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"login":"octocat"}`)
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	if _, err := fetchUser(context.Background(), "tok"); err == nil || !strings.Contains(err.Error(), "user ID") {
		t.Fatalf("fetchUser error = %v, want invalid user ID", err)
	}
}

func TestFetchRepositoryAccess(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.URL.Path != "/graphql" {
			t.Errorf("request = %s %s, want POST /graphql", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		var body struct {
			Query     string `json:"query"`
			Variables struct {
				First int     `json:"first"`
				After *string `json:"after"`
			} `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode GraphQL request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Variables.First != githubPerPage {
			t.Errorf("first = %d, want %d", body.Variables.First, githubPerPage)
		}
		for _, fragment := range []string{
			"affiliations: [OWNER, COLLABORATOR, ORGANIZATION_MEMBER]",
			"ownerAffiliations: [OWNER, COLLABORATOR, ORGANIZATION_MEMBER]",
			"visibility: PUBLIC",
			"viewerPermission",
		} {
			if !strings.Contains(body.Query, fragment) {
				t.Errorf("query does not contain %q", fragment)
			}
		}

		switch requests {
		case 1:
			if body.Variables.After != nil {
				t.Errorf("first page after = %q, want null", *body.Variables.After)
			}
			_, _ = io.WriteString(w, `{
  "data": {"viewer": {"repositories": {
    "nodes": [
      {"nameWithOwner":"me/owned","url":"https://github.com/me/owned","viewerPermission":"ADMIN"},
      {"nameWithOwner":"acme/maintain","url":"https://github.com/acme/maintain","viewerPermission":"MAINTAIN"},
      {"nameWithOwner":"acme/readonly","url":"https://github.com/acme/readonly","viewerPermission":"READ"},
      {"nameWithOwner":"acme/triage","url":"https://github.com/acme/triage","viewerPermission":"TRIAGE"}
    ],
    "pageInfo":{"hasNextPage":true,"endCursor":"cursor-1"}
  }}}
}`)
		case 2:
			if body.Variables.After == nil || *body.Variables.After != "cursor-1" {
				t.Errorf("second page after = %v, want cursor-1", body.Variables.After)
			}
			_, _ = io.WriteString(w, `{
  "data": {"viewer": {"repositories": {
    "nodes": [
      {"nameWithOwner":"acme/write","url":"https://github.com/acme/write","viewerPermission":"WRITE"},
      {"nameWithOwner":"outside/collaborator","url":"https://github.com/outside/collaborator","viewerPermission":"WRITE"},
      {"nameWithOwner":"acme/none","url":"https://github.com/acme/none","viewerPermission":null}
    ],
    "pageInfo":{"hasNextPage":false,"endCursor":null}
  }}}
}`)
		default:
			t.Errorf("unexpected GraphQL request %d", requests)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	repos, err := fetchRepositoryAccess(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]githubRepo, len(repos))
	for _, r := range repos {
		got[r.FullName] = r
	}
	for _, want := range []string{"me/owned", "acme/maintain", "acme/write", "outside/collaborator"} {
		if repo, ok := got[want]; !ok || !repo.maintained() {
			t.Errorf("expected %q in findings-authorized set: %+v", want, repos)
		}
	}
	for _, insufficient := range []string{"acme/readonly", "acme/triage", "acme/none"} {
		if repo, ok := got[insufficient]; !ok || repo.maintained() {
			t.Errorf("expected %q in insufficient-permission set: %+v", insufficient, repos)
		}
	}
	if len(repos) != 7 {
		t.Fatalf("expected all 7 accessible repos, got %d: %+v", len(repos), repos)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestFetchRepositoryAccessRetriesTransientGraphQLResponse(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"viewer":{"repositories":{
  "nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}
}}}}`)
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	repos, err := fetchRepositoryAccess(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 0 {
		t.Fatalf("repos = %+v, want none", repos)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestFetchRepositoryAccessGraphQLErrors(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		want         string
		unauthorized bool
	}{
		{
			name:         "unauthorized",
			status:       http.StatusUnauthorized,
			body:         `{"message":"Bad credentials"}`,
			want:         "returned 401",
			unauthorized: true,
		},
		{
			name:   "graphql error",
			status: http.StatusOK,
			body:   `{"errors":[{"type":"RATE_LIMITED","message":"rate limit exceeded"}]}`,
			want:   "GraphQL error (RATE_LIMITED)",
		},
		{
			name:   "missing data",
			status: http.StatusOK,
			body:   `{"data":{}}`,
			want:   "omitted repository data",
		},
		{
			name:   "missing pagination cursor",
			status: http.StatusOK,
			body: `{"data":{"viewer":{"repositories":{
  "nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":null}
}}}}`,
			want: "another page but no end cursor",
		},
		{
			name:   "maintained repository missing URL",
			status: http.StatusOK,
			body: `{"data":{"viewer":{"repositories":{
  "nodes":[{"nameWithOwner":"acme/broken","url":"","viewerPermission":"WRITE"}],
  "pageInfo":{"hasNextPage":false,"endCursor":null}
}}}}`,
			want: "without a URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()
			old := githubAPI
			githubAPI = srv.URL
			defer func() { githubAPI = old }()

			_, err := fetchRepositoryAccess(context.Background(), "tok")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
			if got := isGitHubUnauthorized(err); got != tt.unauthorized {
				t.Fatalf("isGitHubUnauthorized = %v, want %v", got, tt.unauthorized)
			}
		})
	}
}

func TestFetchRepositoryAccessRejectsRepeatedCursor(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = io.WriteString(w, `{"data":{"viewer":{"repositories":{
  "nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":"same"}
}}}}`)
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	_, err := fetchRepositoryAccess(context.Background(), "tok")
	if err == nil || !strings.Contains(err.Error(), "repeated cursor") {
		t.Fatalf("error = %v, want repeated cursor", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestLogoutRevokesGrantAndClearsCookie(t *testing.T) {
	cfg := testConfig()
	cfg.clientID = "client-123"
	cfg.clientSecret = "shh"

	// A valid session cookie carrying a token to revoke.
	sealed, err := cfg.seal(session{GitHubUserID: 1, Login: "octocat", Token: "ghp_tok", ExpiresAt: time.Now().Add(time.Hour).Unix()})
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

	s := New(cfg, openTestDB(t), slog.New(slog.NewTextHandler(io.Discard, nil)), &sentinel{}, EmptyGrantSource())
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
	sealed, err := cfg.seal(session{GitHubUserID: 1, Login: "octocat", Token: "ghp_tok", ExpiresAt: time.Now().Add(time.Hour).Unix()})
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

	s := New(cfg, openTestDB(t), slog.New(slog.NewTextHandler(io.Discard, nil)), &sentinel{}, EmptyGrantSource())
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
		{FullName: "o/owned", HTMLURL: "https://github.com/O/Owned", CloneURL: "https://github.com/o/owned.git", ViewerPermission: "WRITE"},
		{FullName: "o/unknown", HTMLURL: "https://github.com/o/unknown", CloneURL: "https://github.com/o/unknown.git", ViewerPermission: "MAINTAIN"},
		{FullName: "o/other", HTMLURL: "https://github.com/o/other", CloneURL: "https://github.com/o/other.git", ViewerPermission: "READ"},
	}
	scope, err := resolveScope(context.Background(), gdb, gh, nil)
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
	if scope.AuthorizedRepoCount != 2 {
		t.Fatalf("authorized repo count = %d, want 2", scope.AuthorizedRepoCount)
	}
	if len(scope.UnscannedRepositories) != 1 {
		t.Fatalf("unscanned repositories = %+v, want one", scope.UnscannedRepositories)
	}
	unscanned := scope.UnscannedRepositories[0]
	if unscanned.Name != "o/unknown" || unscanned.URL != "https://github.com/o/unknown" {
		t.Errorf("unscanned repository = %+v, want o/unknown", unscanned)
	}
	if len(scope.InsufficientRepositories) != 1 {
		t.Fatalf("insufficient repositories = %+v, want one", scope.InsufficientRepositories)
	}
	insufficient := scope.InsufficientRepositories[0]
	if insufficient.Name != "o/other" || insufficient.Access != "Read access" {
		t.Errorf("insufficient repository = %+v, want o/other with read access", insufficient)
	}
}
