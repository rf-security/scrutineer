package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// Marker test for the /api/v1/ui read surface under a sharing-portal
// ViewScope (DESIGN WP-B1). Repository A is in scope; every row belonging to
// repository B carries scopeLeakMarker, and A cross-references B (A depends on
// a package B publishes, B is one of A's dependents, A and B share a
// maintainer) so a payload that resolves those references would surface B.

const scopeLeakMarker = "zzleak"

// scopeFixture is the seeded A/B world.
type scopeFixture struct {
	repoA, repoB       db.Repository
	scanA, scanB       db.Scan
	findingA, findingB db.Finding
}

func mustCreate(t *testing.T, gdb *gorm.DB, v any) {
	t.Helper()
	if err := gdb.Create(v).Error; err != nil {
		t.Fatalf("create %T: %v", v, err)
	}
}

func seedScopeFixture(t *testing.T, gdb *gorm.DB) scopeFixture {
	t.Helper()
	var fx scopeFixture
	m := scopeLeakMarker
	// B first, so its ids are the low ones a careless default would hit.
	fx.repoB = db.Repository{URL: "https://github.com/acme/bravo", Name: m + "-bravo", FullName: "acme/" + m + "-bravo",
		Owner: "acme", Description: m + " description", Languages: "Go, " + m + "lang", Metadata: `{"` + m + `":1}`}
	mustCreate(t, gdb, &fx.repoB)
	fx.repoA = db.Repository{URL: "https://github.com/acme/alpha", Name: "alpha", FullName: "acme/alpha",
		Owner: "acme", Description: "alpha description", Languages: "Rust", Metadata: `{"alpha":1}`}
	mustCreate(t, gdb, &fx.repoA)

	mkScan := func(repo db.Repository, skill, text string, st db.ScanStatus) db.Scan {
		sc := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: st, StatusPriority: db.StatusPriorityFor(st),
			SkillName: skill, Model: text + "-model", Log: text + " log\n", Prompt: text + " prompt",
			Report: `{"summary":"` + text + ` report"}`, Commit: "c0ffee"}
		mustCreate(t, gdb, &sc)
		return sc
	}
	fx.scanB = mkScan(fx.repoB, deepDiveSkillName, m, db.ScanDone)
	mkScan(fx.repoB, m+"-queued", m, db.ScanQueued)
	mkScan(fx.repoB, m+"-running", m, db.ScanRunning)
	fx.scanA = mkScan(fx.repoA, deepDiveSkillName, "alpha", db.ScanDone)

	mkFinding := func(sc db.Scan, text string) db.Finding {
		f := db.Finding{ScanID: sc.ID, RepositoryID: sc.RepositoryID, Title: text + " finding", Severity: "High",
			Status: db.FindingNew, CWE: "CWE-79", Location: text + "/app.go:3", Commit: "c0ffee", Trace: text + " trace"}
		mustCreate(t, gdb, &f)
		return f
	}
	fx.findingB = mkFinding(fx.scanB, m)
	fx.findingA = mkFinding(fx.scanA, "alpha")

	for _, side := range []struct {
		repo db.Repository
		f    db.Finding
		sc   db.Scan
		text string
	}{{fx.repoB, fx.findingB, fx.scanB, m}, {fx.repoA, fx.findingA, fx.scanA, "alpha"}} {
		text := side.text
		mustCreate(t, gdb, &db.FindingNote{FindingID: side.f.ID, Body: text + " note", By: text})
		mustCreate(t, gdb, &db.FindingCommunication{FindingID: side.f.ID, Channel: "email", Direction: "outbound", Actor: text, Body: text + " comm"})
		mustCreate(t, gdb, &db.FindingReference{FindingID: side.f.ID, URL: "https://example.com/" + text, Summary: text + " ref"})
		mustCreate(t, gdb, &db.FindingReview{FindingID: side.f.ID, Verdict: "true_positive", Reason: text + " review", Reviewer: text})
		mustCreate(t, gdb, &db.FindingHistory{FindingID: side.f.ID, Field: "severity", OldValue: text + " old", NewValue: "High", By: text})
		mustCreate(t, gdb, &db.FindingObservation{FindingID: side.f.ID, ScanID: side.sc.ID, RepositoryID: side.repo.ID, Title: text + " observation", SkillName: side.sc.SkillName})
		mustCreate(t, gdb, &db.FindingVerification{FindingID: side.f.ID, ScanID: side.sc.ID, Status: "verified", Report: `{"note":"` + text + ` verification"}`})
		mustCreate(t, gdb, &db.FindingAttackPath{FindingID: side.f.ID, ScanID: side.sc.ID, ProductionViability: db.ProductionViabilityViable, Report: `{"note":"` + text + ` attack"}`})
		mustCreate(t, gdb, &db.Package{RepositoryID: side.repo.ID, Name: text + "-pkg", Ecosystem: "npm", PURL: "pkg:npm/" + text + "-pkg"})
		mustCreate(t, gdb, &db.Dependency{RepositoryID: side.repo.ID, Name: text + "-dep", Ecosystem: "npm", PURL: "pkg:npm/" + text + "-dep", DependencyType: "runtime", ManifestPath: "package.json"})
		mustCreate(t, gdb, &db.Dependent{RepositoryID: side.repo.ID, Name: text + "-dependent", Ecosystem: "npm", RepositoryURL: "https://github.com/other/" + text})
		mustCreate(t, gdb, &db.Advisory{RepositoryID: side.repo.ID, UUID: text + "-uuid", Title: text + " advisory", Severity: "high"})
		mustCreate(t, gdb, &db.PackageAlternative{RepositoryID: side.repo.ID, PURL: "pkg:npm/" + text + "-alt", Kind: db.PackageAlternativeFork, Note: text + " alt"})
		mustCreate(t, gdb, &db.Subproject{RepositoryID: side.repo.ID, Path: text + "/sub", Name: text + "-sub"})
		own := db.Maintainer{Login: text + "-maint", Name: text + " maint", Notes: text + " maint note"}
		mustCreate(t, gdb, &own)
		if err := gdb.Model(&own).Association("Repositories").Append(&side.repo); err != nil {
			t.Fatal(err)
		}
	}

	// Cross references from A to B, by non-marker identities so A's own rows
	// may legitimately name them.
	mustCreate(t, gdb, &db.Package{RepositoryID: fx.repoB.ID, Name: "shared-lib", Ecosystem: "npm", PURL: "pkg:npm/shared-lib"})
	mustCreate(t, gdb, &db.Dependency{RepositoryID: fx.repoA.ID, Name: "shared-lib", Ecosystem: "npm", PURL: "pkg:npm/shared-lib", DependencyType: "runtime", ManifestPath: "package.json"})
	mustCreate(t, gdb, &db.Dependent{RepositoryID: fx.repoA.ID, Name: "bravo", Ecosystem: "npm", RepositoryURL: fx.repoB.URL})
	shared := db.Maintainer{Login: "shared-maint", Name: "Shared", Notes: m + " shared maintainer note"}
	mustCreate(t, gdb, &shared)
	if err := gdb.Model(&shared).Association("Repositories").Append(&fx.repoA, &fx.repoB); err != nil {
		t.Fatal(err)
	}
	return fx
}

// scopedUIReq is a GET (or other method) carrying a sharing-portal scope and
// no operator credential, exactly as cmd/sharing forwards it.
func scopedUIReq(method, path string, sc *ViewScope) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = testHost
	if sc != nil {
		r = r.WithContext(WithViewScope(r.Context(), *sc))
	}
	return r
}

// scopeInPaths are every DESIGN §3.1 allow-listed /api/v1/ui GET, against A's
// ids, with the query variants that change what a handler loads.
func scopeInPaths(fx scopeFixture) []string {
	repo := fmt.Sprintf("/api/v1/ui/repositories/%d", fx.repoA.ID)
	finding := fmt.Sprintf("/api/v1/ui/findings/%d", fx.findingA.ID)
	scan := fmt.Sprintf("/api/v1/ui/scans/%d", fx.scanA.ID)
	paths := []string{
		"/api/v1/ui/meta", "/api/v1/ui/meta/cwe?q=79",
		"/api/v1/ui/repositories", "/api/v1/ui/repositories?sort=status", "/api/v1/ui/repositories?q=" + scopeLeakMarker,
		"/api/v1/ui/findings", "/api/v1/ui/findings?status=all&facets=status,severity,category",
		fmt.Sprintf("/api/v1/ui/findings?repository_id=%d", fx.repoB.ID), "/api/v1/ui/findings?scanners=1",
		"/api/v1/ui/scans", "/api/v1/ui/scans?status=queued", fmt.Sprintf("/api/v1/ui/scans?repository_id=%d", fx.repoB.ID),
		fmt.Sprintf("/api/v1/ui/scans?finding_id=%d", fx.findingB.ID),
		repo,
	}
	for _, sub := range []string{"findings", "findings?scanners=1&status=all", "scans", "scans?latest=0", "dependencies",
		"dependencies?all=1", "packages", "dependents", "advisories", "maintainers", "alternatives", "subprojects",
		"threat-model", "metadata"} {
		paths = append(paths, repo+"/"+sub)
	}
	paths = append(paths, finding)
	for _, sub := range []string{"history", "notes", "communications", "references", "reviews", "verifications",
		"observations", "attack-paths", "remediation", "migration-guide"} {
		paths = append(paths, finding+"/"+sub)
	}
	return append(paths, scan, scan+"/log", scan+"/prompt", scan+"/report")
}

// scopeOutPaths are the same id-bearing routes against B's ids.
func scopeOutPaths(fx scopeFixture) []string {
	var out []string
	repo := fmt.Sprintf("/api/v1/ui/repositories/%d", fx.repoB.ID)
	out = append(out, repo)
	for _, sub := range []string{"findings", "scans", "dependencies", "packages", "dependents", "advisories", "maintainers",
		"alternatives", "subprojects", "threat-model", "metadata"} {
		out = append(out, repo+"/"+sub)
	}
	finding := fmt.Sprintf("/api/v1/ui/findings/%d", fx.findingB.ID)
	out = append(out, finding)
	for _, sub := range []string{"history", "notes", "communications", "references", "reviews", "verifications",
		"observations", "attack-paths", "remediation", "migration-guide"} {
		out = append(out, finding+"/"+sub)
	}
	scan := fmt.Sprintf("/api/v1/ui/scans/%d", fx.scanB.ID)
	return append(out, scan, scan+"/log", scan+"/prompt", scan+"/report")
}

// findForeignIDs walks a decoded JSON body for any reference to B: a
// repository id (repository_id, known_repository_id, repository.id), B's
// finding or scan id under a finding/scan key.
func findForeignIDs(v any, fx scopeFixture, path string, out *[]string) {
	is := func(x any, id uint) bool { n, ok := x.(float64); return ok && n == float64(id) }
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			p := path + "." + k
			switch k {
			case "repository_id", "known_repository_id":
				if is(x, fx.repoB.ID) {
					*out = append(*out, p)
				}
			case "finding_id", "matched_finding_id", "disclosure_review_finding_id":
				if is(x, fx.findingB.ID) {
					*out = append(*out, p)
				}
			case "scan_id", "last_seen_scan_id", "last_missed_scan_id":
				if is(x, fx.scanB.ID) {
					*out = append(*out, p)
				}
			case uiKeyRepository:
				if obj, ok := x.(map[string]any); ok && is(obj["id"], fx.repoB.ID) {
					*out = append(*out, p)
				}
			}
			findForeignIDs(x, fx, p, out)
		}
	case []any:
		for i, x := range t {
			findForeignIDs(x, fx, fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

// writeGuard fails the test on any INSERT/UPDATE/DELETE (or non-SELECT raw
// statement) while armed: the portal runs on a read-only Postgres role, so a
// GET that writes would fail there.
type writeGuard struct {
	mu     sync.Mutex
	armed  bool
	writes []string
}

var readSQL = regexp.MustCompile(`(?is)^\s*(SELECT|WITH|PRAGMA|EXPLAIN)\b`)

func installWriteGuard(t *testing.T, gdb *gorm.DB) *writeGuard {
	t.Helper()
	g := &writeGuard{}
	record := func(kind string) func(*gorm.DB) {
		return func(tx *gorm.DB) {
			g.mu.Lock()
			defer g.mu.Unlock()
			if !g.armed {
				return
			}
			sql := tx.Statement.SQL.String()
			if kind == "raw" && readSQL.MatchString(sql) {
				return
			}
			g.writes = append(g.writes, kind+": "+sql)
		}
	}
	cb := gdb.Callback()
	for _, err := range []error{
		cb.Create().Before("gorm:create").Register("scope_ui_test:create", record("create")),
		cb.Update().Before("gorm:update").Register("scope_ui_test:update", record("update")),
		cb.Delete().Before("gorm:delete").Register("scope_ui_test:delete", record("delete")),
		cb.Raw().After("gorm:raw").Register("scope_ui_test:raw", record("raw")),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	return g
}

func (g *writeGuard) arm(on bool) {
	g.mu.Lock()
	g.armed = on
	g.mu.Unlock()
}

// TestUIScope_markerNoCrossRepoLeak calls every allow-listed GET under
// ViewScope{A, ReadOnly} and asserts no B marker or B id reaches any body,
// total, facet, languages or stats; every B id answers 404; and no GET
// writes to the database.
func TestUIScope_markerNoCrossRepoLeak(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedScopeFixture(t, s.DB)
	guard := installWriteGuard(t, s.DB)
	scope := ViewScope{RepoIDs: map[uint]struct{}{fx.repoA.ID: {}}, ReadOnly: true}

	guard.arm(true)
	defer guard.arm(false)
	for _, path := range scopeInPaths(fx) {
		w := serveUI(t, s, scopedUIReq(http.MethodGet, path, &scope))
		body := w.Body.String()
		optional := strings.HasSuffix(path, "/threat-model")
		if w.Code != http.StatusOK && (!optional || w.Code != http.StatusNotFound) {
			t.Errorf("GET %s = %d; body = %s", path, w.Code, body)
			continue
		}
		if strings.Contains(strings.ToLower(body), scopeLeakMarker) {
			t.Errorf("GET %s leaked a B marker: %s", path, body)
		}
		var decoded any
		if json.Unmarshal(w.Body.Bytes(), &decoded) == nil {
			var refs []string
			findForeignIDs(decoded, fx, "$", &refs)
			if len(refs) > 0 {
				t.Errorf("GET %s references repository B at %v", path, refs)
			}
		}
	}
	for _, path := range scopeOutPaths(fx) {
		w := serveUI(t, s, scopedUIReq(http.MethodGet, path, &scope))
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s (out of scope) = %d, want 404; body = %s", path, w.Code, w.Body.String())
		}
		if strings.Contains(strings.ToLower(w.Body.String()), scopeLeakMarker) {
			t.Errorf("GET %s 404 body leaked a B marker", path)
		}
	}
	guard.arm(false)
	if len(guard.writes) > 0 {
		t.Errorf("read-only GETs wrote to the database:\n%s", strings.Join(guard.writes, "\n"))
	}

	// Spot checks on what the scoped lists do return.
	get := func(path string) map[string]any {
		return decodeUIJSON[map[string]any](t, serveUI(t, s, scopedUIReq(http.MethodGet, path, &scope)), http.StatusOK)
	}
	repos := get("/api/v1/ui/repositories")
	if repos["total"] != float64(1) || len(repos["items"].([]any)) != 1 {
		t.Errorf("scoped repositories = %v", repos)
	}
	if langs := repos["languages"].([]any); len(langs) != 1 || langs[0] != "Rust" {
		t.Errorf("scoped languages = %v", langs)
	}
	scans := get("/api/v1/ui/scans")
	if scans["total"] != float64(1) {
		t.Errorf("scoped scans total = %v", scans["total"])
	}
	if st := scans["stats"].(map[string]any); st["queued"] != float64(0) || st["running"] != float64(0) {
		t.Errorf("scoped scan stats count B's queue: %v", st)
	}
	if sk := scans["skills"].([]any); len(sk) != 1 || sk[0] != deepDiveSkillName {
		t.Errorf("scoped skills = %v", sk)
	}
	deps := get(repoPath(fx.repoA.ID, "/dependencies"))
	for _, it := range deps["items"].([]any) {
		if row := it.(map[string]any); row[uiKeyName] == "shared-lib" && row["known_repository_id"] != nil {
			t.Errorf("shared-lib known_repository_id = %v, want null", row["known_repository_id"])
		}
	}
	detail := get(fmt.Sprintf("/api/v1/ui/findings/%d", fx.findingA.ID))
	exports := detail["exports"].(map[string]any)
	for _, k := range []string{"disclosure_md", "disclosure_html"} {
		if _, ok := exports[k]; ok {
			t.Errorf("read-only finding exports carry the operator-only %s", k)
		}
	}
	for _, k := range []string{"report_md", "csaf_json", "osv_json", "bundle_tar_gz", "patch_diff"} {
		if _, ok := exports[k]; !ok {
			t.Errorf("read-only finding exports lost %s", k)
		}
	}
}

// TestUIScope_emptyScopeEmptyLists: a present-but-empty scope sees nothing.
func TestUIScope_emptyScopeEmptyLists(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedScopeFixture(t, s.DB)
	empty := ViewScope{RepoIDs: map[uint]struct{}{}, ReadOnly: true}
	for _, path := range []string{"/api/v1/ui/repositories", "/api/v1/ui/findings?facets=status,severity,category", "/api/v1/ui/scans"} {
		body := decodeUIJSON[map[string]any](t, serveUI(t, s, scopedUIReq(http.MethodGet, path, &empty)), http.StatusOK)
		if body["total"] != float64(0) || len(body["items"].([]any)) != 0 {
			t.Errorf("%s under empty scope = %v", path, body)
		}
		if l, ok := body["languages"].([]any); ok && len(l) != 0 {
			t.Errorf("%s languages = %v", path, l)
		}
		if l, ok := body["skills"].([]any); ok && len(l) != 0 {
			t.Errorf("%s skills = %v", path, l)
		}
		if strings.Contains(fmt.Sprint(body), scopeLeakMarker) || strings.Contains(fmt.Sprint(body), "alpha") {
			t.Errorf("%s under empty scope leaked: %v", path, body)
		}
	}
	for _, path := range []string{repoPath(fx.repoA.ID, ""), fmt.Sprintf("/api/v1/ui/findings/%d", fx.findingA.ID),
		fmt.Sprintf("/api/v1/ui/scans/%d/log", fx.scanA.ID)} {
		if w := serveUI(t, s, scopedUIReq(http.MethodGet, path, &empty)); w.Code != http.StatusNotFound {
			t.Errorf("%s under empty scope = %d, want 404", path, w.Code)
		}
	}
}

// TestUIScope_unscopedOperatorUnchanged: the operator (no scope) still sees
// B everywhere, cross references included.
func TestUIScope_unscopedOperatorUnchanged(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedScopeFixture(t, s.DB)
	get := func(path string) (map[string]any, string) {
		w := serveUI(t, s, operatorReq(t, http.MethodGet, path, nil))
		return decodeUIJSON[map[string]any](t, w, http.StatusOK), w.Body.String()
	}
	repos, raw := get("/api/v1/ui/repositories")
	if repos["total"] != float64(2) || !strings.Contains(raw, scopeLeakMarker+"lang") {
		t.Errorf("operator repositories = %s", raw)
	}
	// The operator default order stays recency (A, created last, first).
	if first := repos["items"].([]any)[0].(map[string]any); first["id"] != float64(fx.repoA.ID) {
		t.Errorf("operator default order changed: first = %v", first["id"])
	}
	scans, raw := get("/api/v1/ui/scans")
	if scans["total"] != float64(4) || !strings.Contains(raw, scopeLeakMarker+"-queued") {
		t.Errorf("operator scans = %s", raw)
	}
	if st := scans["stats"].(map[string]any); st["queued"] != float64(1) || st["running"] != float64(1) {
		t.Errorf("operator stats = %v", st)
	}
	if findings, _ := get("/api/v1/ui/findings"); findings["total"] != float64(2) {
		t.Errorf("operator findings = %v", findings)
	}
	deps, _ := get(repoPath(fx.repoA.ID, "/dependencies"))
	found := false
	for _, it := range deps["items"].([]any) {
		if row := it.(map[string]any); row[uiKeyName] == "shared-lib" {
			found = row["known_repository_id"] == float64(fx.repoB.ID)
		}
	}
	if !found {
		t.Errorf("operator dependencies lost known_repository_id: %v", deps)
	}
	if _, raw := get(repoPath(fx.repoA.ID, "/maintainers")); !strings.Contains(raw, scopeLeakMarker+" shared maintainer note") {
		t.Errorf("operator maintainers lost notes: %s", raw)
	}
	if _, raw := get(repoPath(fx.repoB.ID, "")); !strings.Contains(raw, scopeLeakMarker) {
		t.Errorf("operator repo B detail = %s", raw)
	}
	detail, _ := get(fmt.Sprintf("/api/v1/ui/findings/%d", fx.findingA.ID))
	if _, ok := detail["exports"].(map[string]any)["disclosure_md"]; !ok {
		t.Error("operator finding exports lost disclosure_md")
	}
}

// TestUIScope_portalDefaultRepoOrder: under a read-only scope with no sort
// token the list leads with done, then queued, then failed repositories.
func TestUIScope_portalDefaultRepoOrder(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	scope := ViewScope{RepoIDs: map[uint]struct{}{}, ReadOnly: true}
	want := map[db.ScanStatus]uint{}
	// Created failed, queued, done so recency alone would invert the order.
	for _, st := range []db.ScanStatus{db.ScanFailed, db.ScanQueued, db.ScanDone} {
		repo := seedUIRepo(t, s.DB, "order-"+string(st))
		seedUIScan(t, s.DB, repo, st, deepDiveSkillName)
		scope.RepoIDs[repo.ID] = struct{}{}
		want[st] = repo.ID
	}
	body := decodeUIJSON[map[string]any](t, serveUI(t, s, scopedUIReq(http.MethodGet, "/api/v1/ui/repositories", &scope)), http.StatusOK)
	items := body["items"].([]any)
	for i, st := range []db.ScanStatus{db.ScanDone, db.ScanQueued, db.ScanFailed} {
		if got := items[i].(map[string]any)["id"]; got != float64(want[st]) {
			t.Errorf("portal order[%d] = %v, want the %s repo %d", i, got, st, want[st])
		}
	}
	// An explicit sort token wins over the portal default.
	named := decodeUIJSON[map[string]any](t, serveUI(t, s, scopedUIReq(http.MethodGet, "/api/v1/ui/repositories?sort=name", &scope)), http.StatusOK)
	if first := named["items"].([]any)[0].(map[string]any)[uiKeyName]; first != "order-done" {
		t.Errorf("sort=name first = %v", first)
	}
}

// TestUIScope_readOnlyRefusesEveryWrite: every non-GET /api/v1/ui route
// answers 401/403 under a read-only scope, with or without the operator
// token, and never reaches a handler that writes.
func TestUIScope_readOnlyRefusesEveryWrite(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedScopeFixture(t, s.DB)
	scope := ViewScope{RepoIDs: map[uint]struct{}{fx.repoA.ID: {}}, ReadOnly: true}
	param := regexp.MustCompile(`\{[a-z_]+\}`)
	guard := installWriteGuard(t, s.DB)
	guard.arm(true)
	defer guard.arm(false)
	n := 0
	for _, route := range registeredUIRoutes(t) {
		if route.Method == http.MethodGet || route.Method == http.MethodHead {
			continue
		}
		n++
		path := "/api" + param.ReplaceAllString(route.Path, fmt.Sprint(fx.repoA.ID))
		for _, withToken := range []bool{false, true} {
			r := scopedUIReq(route.Method, path, &scope)
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			if withToken {
				asOperator(r)
			}
			w := serveUI(t, s, r)
			if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
				t.Errorf("%s %s (token=%v) under read-only scope = %d, want 401/403", route.Method, path, withToken, w.Code)
			}
		}
	}
	if n < 40 {
		t.Fatalf("only %d non-GET UI routes found; route extraction broken?", n)
	}
	guard.arm(false)
	if len(guard.writes) > 0 {
		t.Errorf("refused writes still wrote:\n%s", strings.Join(guard.writes, "\n"))
	}
}
