package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// seedRepoWithFinding creates a repository, a deep-dive scan, and one finding
// whose title is returned so tests can assert on its presence in list pages.
func seedRepoWithFinding(t *testing.T, s *Server, url, name, title string) uint {
	t.Helper()
	repo := db.Repository{URL: url, Name: name}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: title,
		Severity: "High", Location: "x.go:1", CWE: "CWE-79"}).Error; err != nil {
		t.Fatal(err)
	}
	return repo.ID
}

// wants pairs a list path with the substring that must (or must not) appear
// for the alpha/bravo fixtures: findings render titles, the repo list renders
// URLs.
var scopeProbes = map[string][2]string{
	"/findings": {"SSRF in alpha", "XSS in bravo"},
	"/":         {"example.com/a", "example.com/b"},
}

// TestViewScope_unsetIsNoop confirms the main app (no scope on the request)
// still sees every repository and finding — the seam must be inert by default.
func TestViewScope_unsetIsNoop(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedRepoWithFinding(t, s, "https://example.com/a", "alpha", "SSRF in alpha")
	seedRepoWithFinding(t, s, "https://example.com/b", "bravo", "XSS in bravo")

	for path, probe := range scopeProbes {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", path))
		if w.Code != 200 {
			t.Fatalf("%s status %d", path, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, probe[0]) || !strings.Contains(body, probe[1]) {
			t.Errorf("%s: expected both %q and %q", path, probe[0], probe[1])
		}
	}
}

// TestViewScope_restrictsListsAndSharingFlag confirms a restricted read-only
// scope limits both list pages to the allow-listed repository and turns on the
// Sharing template flag (admin nav hidden).
func TestViewScope_restrictsListsAndSharingFlag(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	a := seedRepoWithFinding(t, s, "https://example.com/a", "alpha", "SSRF in alpha")
	seedRepoWithFinding(t, s, "https://example.com/b", "bravo", "XSS in bravo")

	scope := ViewScope{RepoIDs: map[uint]struct{}{a: {}}, ReadOnly: true}

	for path, probe := range scopeProbes {
		r := localReq("GET", path)
		r = r.WithContext(WithViewScope(r.Context(), scope))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s status %d", path, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, probe[0]) {
			t.Errorf("%s: in-scope %q missing", path, probe[0])
		}
		if strings.Contains(body, probe[1]) {
			t.Errorf("%s: out-of-scope %q leaked", path, probe[1])
		}
		// Sharing flag hides the Settings gear (admin nav) in the layout.
		if strings.Contains(body, `href="/settings"`) {
			t.Errorf("%s: admin nav not hidden under read-only scope", path)
		}
	}
}

// TestViewScope_readOnlyRefusesWrites confirms the read-only scope refuses the
// mutating finding handlers at the write path itself (defense in depth behind
// the sharing portal's GET-only route whitelist): they return 403 and perform
// no write, rather than relying only on the UI hiding the controls.
func TestViewScope_readOnlyRefusesWrites(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repoID := seedRepoWithFinding(t, s, "https://example.com/a", "alpha", "SSRF in alpha")
	scope := ViewScope{RepoIDs: map[uint]struct{}{repoID: {}}, ReadOnly: true}

	for _, path := range []string{"/findings/1/status", "/findings/1/notes"} {
		r := localReq("POST", path)
		r = r.WithContext(WithViewScope(r.Context(), scope))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("%s under read-only scope: want 403, got %d", path, w.Code)
		}
	}

	// The finding's status must be untouched by the refused write (still the
	// "new" default it was created with).
	var f db.Finding
	if err := s.DB.First(&f).Error; err != nil {
		t.Fatal(err)
	}
	if f.Status != db.FindingNew {
		t.Errorf("read-only write mutated finding status to %q", f.Status)
	}
}

// TestViewScope_emptyScopeMatchesNothing confirms a present-but-empty scope
// (a maintainer with no known repos) hides everything rather than everything
// being visible.
func TestViewScope_emptyScopeMatchesNothing(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedRepoWithFinding(t, s, "https://example.com/a", "alpha", "SSRF in alpha")

	r := localReq("GET", "/findings")
	r = r.WithContext(WithViewScope(r.Context(), ViewScope{RepoIDs: map[uint]struct{}{}, ReadOnly: true}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "SSRF in alpha") {
		t.Errorf("empty scope leaked a finding")
	}
}

// TestViewScope_repositoryAccessExplainsUnscannedRepos confirms the shared
// repositories page distinguishes an authorized-but-unscanned GitHub repo from
// repositories the current login is not authorized to see.
func TestViewScope_repositoryAccessExplainsUnscannedRepos(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	scannedID := seedRepoWithFinding(t, s, "https://github.com/acme/scanned", "scanned", "visible finding")

	scope := ViewScope{
		RepoIDs:             map[uint]struct{}{scannedID: {}},
		AuthorizedRepoCount: 2,
		UnscannedRepositories: []ExternalRepository{{
			Name: "acme/not-scanned",
			URL:  "https://github.com/acme/not-scanned",
		}},
		InsufficientRepositories: []ExternalRepository{{
			Name:   "acme/read-only",
			URL:    "https://github.com/acme/read-only",
			Access: "Read access",
		}},
		ReadOnly: true,
	}
	r := localReq("GET", "/")
	r = r.WithContext(WithViewScope(r.Context(), scope))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"GitHub authorizes this account for 2 public",
		"Scrutineer has scanned 1; 1",
		"acme/not-scanned",
		"Not scanned",
		"acme/read-only",
		"Read access",
		"below the required level",
		"missing from every list",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("repository access explanation missing %q", want)
		}
	}
}

func TestViewScope_repositoryAccessExplainsEmptyAuthorization(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	r := localReq("GET", "/")
	r = r.WithContext(WithViewScope(r.Context(), ViewScope{
		RepoIDs: map[uint]struct{}{},
		InsufficientRepositories: []ExternalRepository{{
			Name:   "acme/triage-only",
			URL:    "https://github.com/acme/triage-only",
			Access: "Triage access",
		}},
		ReadOnly: true,
	}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "GitHub did not report any public repositories") {
		t.Errorf("empty authorization explanation missing")
	}
	if !strings.Contains(body, "No scanned repositories") {
		t.Errorf("sharing-specific empty state missing")
	}
	if !strings.Contains(body, "acme/triage-only") || !strings.Contains(body, "Triage access") {
		t.Errorf("insufficient-permission repository explanation missing")
	}
	if strings.Contains(body, "Add a git URL above") {
		t.Errorf("local add-repository guidance leaked into sharing view")
	}
}

// seedScannerFinding creates a repo with one scanner-skill (non-deep-dive)
// finding, which is what the /findings "scanner" badge counts.
func seedScannerFinding(t *testing.T, s *Server, url, name string) uint {
	t.Helper()
	repo := db.Repository{URL: url, Name: name}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "zizmor"}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
		Title: "scanner " + name, Severity: "Low", Status: db.FindingNew}).Error; err != nil {
		t.Fatal(err)
	}
	return repo.ID
}

// TestViewScope_findingToggleCountsRespectScope confirms the /findings badge
// counts (built via the raw-SQL findingIndexWhereSQL path) are restricted to
// the visitor's repositories, not counted across the whole dataset.
func TestViewScope_findingToggleCountsRespectScope(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	a := seedScannerFinding(t, s, "https://x/a", "a")
	seedScannerFinding(t, s, "https://x/b", "b")

	// No scope (local operator): both repos' scanner findings counted.
	if _, scanner := s.findingToggleCounts(localReq("GET", "/findings"), false); scanner != 2 {
		t.Fatalf("unscoped scannerTotal = %d, want 2", scanner)
	}
	// Scoped to repo a: repo b's finding must not be counted.
	ra := localReq("GET", "/findings")
	ra = ra.WithContext(WithViewScope(ra.Context(), ViewScope{RepoIDs: map[uint]struct{}{a: {}}, ReadOnly: true}))
	if _, scanner := s.findingToggleCounts(ra, false); scanner != 1 {
		t.Errorf("scoped scannerTotal = %d, want 1 (repo b leaked)", scanner)
	}
	// Empty scope: nothing counted.
	re := localReq("GET", "/findings")
	re = re.WithContext(WithViewScope(re.Context(), ViewScope{RepoIDs: map[uint]struct{}{}, ReadOnly: true}))
	if _, scanner := s.findingToggleCounts(re, false); scanner != 0 {
		t.Errorf("empty-scope scannerTotal = %d, want 0", scanner)
	}
}

// TestViewScope_distinctLanguagesRespectScope confirms the language facet on the
// repo list only reveals languages from repositories the visitor can see.
func TestViewScope_distinctLanguagesRespectScope(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	a := db.Repository{URL: "https://x/la", Name: "la", Languages: "Go, Python"}
	b := db.Repository{URL: "https://x/lb", Name: "lb", Languages: "Rust, Kotlin"}
	if err := s.DB.Create(&a).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&b).Error; err != nil {
		t.Fatal(err)
	}

	r := localReq("GET", "/")
	r = r.WithContext(WithViewScope(r.Context(), ViewScope{RepoIDs: map[uint]struct{}{a.ID: {}}, ReadOnly: true}))
	got := distinctLanguages(s.DB, r)
	want := []string{"Go", "Python"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("scoped languages = %v, want %v (repo b's Rust/Kotlin leaked)", got, want)
	}
}
