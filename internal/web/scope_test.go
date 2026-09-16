package web

import (
	"fmt"
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

// TestViewScope_scansListScopedAndDefaultsToDone confirms the /scans list is
// scoped to the visitor's repositories and defaults to completed scans under a
// read-only (portal) scope, while status=all clears that default and the local
// operator still sees every scan by default.
func TestViewScope_scansListScopedAndDefaultsToDone(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	mkScan := func(repoID uint, st db.ScanStatus) uint {
		sc := db.Scan{RepositoryID: repoID, Kind: "skill", SkillName: "security-deep-dive", Status: st}
		if err := s.DB.Create(&sc).Error; err != nil {
			t.Fatal(err)
		}
		return sc.ID
	}
	repoA := db.Repository{URL: "https://example.com/a", Name: "alpha"}
	repoB := db.Repository{URL: "https://example.com/b", Name: "bravo"}
	if err := s.DB.Create(&repoA).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&repoB).Error; err != nil {
		t.Fatal(err)
	}
	doneA := mkScan(repoA.ID, db.ScanDone)
	failedA := mkScan(repoA.ID, db.ScanFailed)
	doneB := mkScan(repoB.ID, db.ScanDone)

	row := func(id uint) string { return fmt.Sprintf(`id="scan-%d"`, id) }
	scope := ViewScope{RepoIDs: map[uint]struct{}{repoA.ID: {}}, ReadOnly: true}
	get := func(path string, sc *ViewScope) string {
		r := localReq("GET", path)
		if sc != nil {
			r = r.WithContext(WithViewScope(r.Context(), *sc))
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s status %d", path, w.Code)
		}
		return w.Body.String()
	}

	// Portal default: only repo a's DONE scan — its failed scan is hidden by the
	// Done default and repo b's scan is out of scope.
	def := get("/scans", &scope)
	if !strings.Contains(def, row(doneA)) {
		t.Errorf("portal default: in-scope done scan missing")
	}
	if strings.Contains(def, row(failedA)) {
		t.Errorf("portal default: failed scan shown, want Done-only default")
	}
	if strings.Contains(def, row(doneB)) {
		t.Errorf("portal default: out-of-scope scan leaked")
	}

	// status=all overrides the default: both of repo a's scans, still scoped.
	all := get("/scans?status=all", &scope)
	if !strings.Contains(all, row(doneA)) || !strings.Contains(all, row(failedA)) {
		t.Errorf("status=all: expected both of repo a's scans")
	}
	if strings.Contains(all, row(doneB)) {
		t.Errorf("status=all: out-of-scope scan leaked")
	}

	// Local operator (no scope): default shows every scan regardless of status.
	op := get("/scans", nil)
	if !strings.Contains(op, row(failedA)) || !strings.Contains(op, row(doneB)) {
		t.Errorf("operator default should list all scans, unfiltered")
	}
}

// TestViewScope_repoListPortalSortsByStatus confirms the sharing portal's
// default repository ordering is completed → queued → failed (by each repo's
// latest scan), overriding the operator's most-recently-updated default.
func TestViewScope_repoListPortalSortsByStatus(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	// Create oldest→newest as done, queued, failed so recency (updated_at desc)
	// would yield the REVERSE of the wanted status order — a pass proves the
	// status ordering won.
	mk := func(url, name string, st db.ScanStatus) uint {
		repo := db.Repository{URL: url, Name: name}
		if err := s.DB.Create(&repo).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill",
			SkillName: "security-deep-dive", Status: st}).Error; err != nil {
			t.Fatal(err)
		}
		return repo.ID
	}
	dID := mk("https://example.com/done", "d", db.ScanDone)
	qID := mk("https://example.com/queued", "q", db.ScanQueued)
	fID := mk("https://example.com/failed", "f", db.ScanFailed)

	order := func(body string) (int, int, int) {
		return strings.Index(body, "example.com/done"),
			strings.Index(body, "example.com/queued"),
			strings.Index(body, "example.com/failed")
	}

	// Portal (read-only scope over all three): done < queued < failed.
	scope := ViewScope{RepoIDs: map[uint]struct{}{dID: {}, qID: {}, fID: {}}, ReadOnly: true}
	r := localReq("GET", "/")
	r = r.WithContext(WithViewScope(r.Context(), scope))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	iD, iQ, iF := order(w.Body.String())
	if iD < 0 || iQ < 0 || iF < 0 {
		t.Fatalf("missing repos: done=%d queued=%d failed=%d", iD, iQ, iF)
	}
	if iD >= iQ || iQ >= iF {
		t.Errorf("portal order = done@%d queued@%d failed@%d; want done < queued < failed", iD, iQ, iF)
	}

	// Operator (no scope) keeps recency: newest-created (failed) first.
	wo := httptest.NewRecorder()
	s.Handler().ServeHTTP(wo, localReq("GET", "/"))
	oD, oQ, oF := order(wo.Body.String())
	if oF >= oQ || oQ >= oD {
		t.Errorf("operator order = done@%d queued@%d failed@%d; want recency failed < queued < done", oD, oQ, oF)
	}
}

// TestSharingTemplates_renderAllPortalPages renders every page the sharing
// portal can reach through the standalone templates/sharing/ set (parsed via
// WithTemplateGlob). html/template resolves {{template}} references statically
// during escaping — even in never-executed branches — so a missing sub-template
// surfaces here as a 500, guarding the portal's template set stays complete.
func TestSharingTemplates_renderAllPortalPages(t *testing.T) {
	s, done := newTestServerWith(t, WithTemplateGlob("templates/sharing/*.html"))
	defer done()

	repo := db.Repository{URL: "https://example.com/a", Name: "alpha", Languages: "Go"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "security-deep-dive", Status: db.ScanDone}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "SSRF in alpha",
		Severity: "High", Location: "x.go:1", CWE: "CWE-79"}
	if err := s.DB.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}

	scope := ViewScope{RepoIDs: map[uint]struct{}{repo.ID: {}}, ReadOnly: true}
	for _, p := range []string{
		"/", "/findings", "/scans",
		fmt.Sprintf("/repositories/%d", repo.ID),
		fmt.Sprintf("/findings/%d", finding.ID),
		fmt.Sprintf("/scans/%d", scan.ID),
	} {
		r := localReq("GET", p)
		r = r.WithContext(WithViewScope(r.Context(), scope))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Errorf("%s rendered %d via sharing templates (body: %.300s)", p, w.Code, w.Body.String())
		}
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
