package web

import (
	"fmt"
	"net/http"
	"testing"

	"scrutineer/internal/db"
)

// Tests for the RepoDetail tab endpoints (#30-#37, #43).

func repoPath(id uint, suffix string) string {
	return fmt.Sprintf("/api/v1/ui/repositories/%d%s", id, suffix)
}

func getUI(t *testing.T, s *Server, path string) map[string]any {
	t.Helper()
	return decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, path, nil)), http.StatusOK)
}

func TestUIRepoFindingsTab(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "tabs")
	dd := seedUIScan(t, s.DB, repo, db.ScanDone, deepDiveSkillName)
	sg := seedUIScan(t, s.DB, repo, db.ScanDone, "semgrep")
	seedUIFinding(t, s.DB, dd, "dd high", db.FindingNew)
	low := seedUIFinding(t, s.DB, dd, "dd low", db.FindingTriaged)
	s.DB.Model(&low).Update("severity", "Low")
	seedUIFinding(t, s.DB, dd, "dd closed", db.FindingFixed)
	seedUIFinding(t, s.DB, sg, "scanner hit", db.FindingNew)

	body := getUI(t, s, repoPath(repo.ID, "/findings"))
	items := body["items"].([]any)
	if body["total"] != float64(2) || len(items) != 2 || items[0].(map[string]any)["title"] != "dd high" {
		t.Fatalf("findings = %+v", body)
	}
	if c := body["counts"].(map[string]any); c["scanners"] != float64(1) {
		t.Fatalf("counts = %+v", c)
	}
	if commits := body["scan_commit"].(map[string]any); len(commits) != 1 {
		t.Fatalf("scan_commit = %+v", commits)
	}
	scanners := getUI(t, s, repoPath(repo.ID, "/findings?scanners=1"))
	if scanners["total"] != float64(1) {
		t.Fatalf("scanners = %+v", scanners)
	}
	all := getUI(t, s, repoPath(repo.ID, "/findings?status=all&severity=High"))
	if all["total"] != float64(2) {
		t.Fatalf("status=all severity=High = %+v", all)
	}
	for _, q := range []string{"?status=bogus", "?severity=huge", "?category=nope", "?page_size=0"} {
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/findings"+q), nil)), http.StatusBadRequest, uiCodeBadParam)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(9999, "/findings"), nil)), http.StatusNotFound, uiCodeNotFound)
}

func TestUIRepoScansTab(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "scans")
	seedUIScan(t, s.DB, repo, db.ScanFailed, deepDiveSkillName)
	retry := seedUIScan(t, s.DB, repo, db.ScanQueued, deepDiveSkillName)
	seedUIScan(t, s.DB, repo, db.ScanPaused, "recon")

	latest := getUI(t, s, repoPath(repo.ID, "/scans"))
	items := latest["items"].([]any)
	if latest["total"] != float64(2) || len(items) != 2 || items[0].(map[string]any)["id"] != float64(retry.ID+1) {
		t.Fatalf("latest = %+v", latest)
	}
	if c := latest["counts"].(map[string]any); c["active"] != float64(1) || c["paused"] != float64(1) || c["failed"] != float64(0) {
		t.Fatalf("counts = %+v", c)
	}
	if _, blob := items[0].(map[string]any)["log"]; blob {
		t.Fatal("ScanRow carries the log blob")
	}
	history := getUI(t, s, repoPath(repo.ID, "/scans?latest=0&page_size=2&sort=id"))
	if history["total"] != float64(3) || len(history["items"].([]any)) != 2 {
		t.Fatalf("history = %+v", history)
	}
	failed := getUI(t, s, repoPath(repo.ID, "/scans?latest=0&status=failed"))
	if failed["total"] != float64(1) {
		t.Fatalf("history status=failed = %+v", failed)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/scans?latest=2"), nil)), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/scans?latest=0&status=nope"), nil)), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(9999, "/scans"), nil)), http.StatusNotFound, uiCodeNotFound)
}

func TestUIRepoDependenciesTab(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "deps")
	lib := seedUIRepo(t, s.DB, "lib")
	s.DB.Create(&db.Package{RepositoryID: lib.ID, Name: "lib", Ecosystem: "npm", PURL: "pkg:npm/lib"})
	s.DB.Create(&db.Dependency{RepositoryID: repo.ID, Name: "lib", Ecosystem: "npm", PURL: "pkg:npm/lib", DependencyType: "runtime", ManifestPath: "package.json"})
	s.DB.Create(&db.Dependency{RepositoryID: repo.ID, Name: "jest", Ecosystem: "npm", DependencyType: db.DependencyDev, ManifestPath: "package.json"})

	body := getUI(t, s, repoPath(repo.ID, "/dependencies"))
	items := body["items"].([]any)
	if body["total"] != float64(1) || body["hidden"] != float64(1) || len(items) != 1 {
		t.Fatalf("deps = %+v", body)
	}
	if items[0].(map[string]any)["known_repository_id"] != float64(lib.ID) {
		t.Fatalf("known repo = %+v", items[0])
	}
	if all := getUI(t, s, repoPath(repo.ID, "/dependencies?all=1")); all["total"] != float64(2) {
		t.Fatalf("all = %+v", all)
	}
	if q := getUI(t, s, repoPath(repo.ID, "/dependencies?all=1&q=jes")); q["total"] != float64(1) {
		t.Fatalf("q = %+v", q)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(9999, "/dependencies"), nil)), http.StatusNotFound, uiCodeNotFound)
}

func TestUIRepoInventoryTabs(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "inv")
	s.DB.Create(&db.Package{RepositoryID: repo.ID, Name: "p", Ecosystem: "npm"})
	s.DB.Create(&db.Dependent{RepositoryID: repo.ID, Name: "d", Ecosystem: "npm", RepositoryURL: repo.URL})
	adv := db.Advisory{RepositoryID: repo.ID, UUID: "u1", Title: "adv", Severity: "high"}
	s.DB.Create(&adv)
	m := db.Maintainer{Login: "octo"}
	s.DB.Create(&m)
	s.DB.Exec("INSERT INTO repository_maintainers (repository_id, maintainer_id) VALUES (?, ?)", repo.ID, m.ID)
	s.DB.Create(&db.PackageAlternative{RepositoryID: repo.ID, PURL: "pkg:npm/alt", Kind: db.PackageAlternativeFork})
	s.DB.Create(&db.ExpectedFinding{RepositoryID: repo.ID, File: "a.go", CWE: "CWE-79"})
	s.DB.Create(&db.Subproject{RepositoryID: repo.ID, Path: "pkg/x", Name: "x"})
	s.DB.Create(&db.ComplianceControl{RepositoryID: repo.ID, ControlID: "OSPS-AC-01.01", Level: 1, Status: "FAIL"})

	for tab, key := range map[string]string{
		"packages": "name", "dependents": "known_repository_id", "advisories": "audit_status", "maintainers": "login",
		"alternatives": "purl", "expected": statusKey, "subprojects": "scan_count", "compliance": "control_id",
	} {
		body := getUI(t, s, repoPath(repo.ID, "/"+tab))
		items := body["items"].([]any)
		if body["total"] != float64(1) || len(items) != 1 {
			t.Errorf("%s = %+v", tab, body)
			continue
		}
		if _, ok := items[0].(map[string]any)[key]; !ok {
			t.Errorf("%s row missing %s: %+v", tab, key, items[0])
		}
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(9999, "/"+tab), nil)), http.StatusNotFound, uiCodeNotFound)
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/"+tab+"?page=0"), nil)), http.StatusBadRequest, uiCodeBadParam)
	}
	expected := listItems(getUI(t, s, repoPath(repo.ID, "/expected")))
	if expected[0][statusKey] != "missed" || expected[0]["matched_finding_id"] != nil {
		t.Fatalf("expected row = %+v", expected[0])
	}
	dependents := listItems(getUI(t, s, repoPath(repo.ID, "/dependents")))
	if dependents[0]["known_repository_id"] != float64(repo.ID) {
		t.Fatalf("dependent known repo = %+v", dependents[0])
	}
}

func TestUIRepoSingleObjectTabs(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "objects")
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/threat-model"), nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/metadata"), nil)), http.StatusNotFound, uiCodeNotFound)

	tm := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: threatModelSkillName, Commit: "abc123", Report: `{"components":[1]}`}
	s.DB.Create(&tm)
	run1 := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName,
		Report: `{"inventory":[{"id":"S1","location":"a.go:1","class":"sqli"}],"ruled_out":[{"sinks":["S1"],"reason":"safe"}]}`}
	s.DB.Create(&run1)
	run2 := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName,
		Report: `{"inventory":[{"id":"S1","location":"a.go:1","class":"sqli"}],"findings":[{"sinks":["S1"],"title":"SQLi","severity":"High"}]}`}
	s.DB.Create(&run2)
	s.DB.Model(&repo).Updates(map[string]any{"metadata": `{"stars":3}`, "scan_config": "skip:\n  - vendor/**\n"})

	body := getUI(t, s, repoPath(repo.ID, "/threat-model"))
	if body["scan_id"] != float64(tm.ID) || body["commit"] != "abc123" || body["skill_name"] != threatModelSkillName {
		t.Fatalf("threat model = %+v", body)
	}
	wb := getUI(t, s, repoPath(repo.ID, "/workbench"))
	diff := wb["diff"].(map[string]any)
	if wb["has_override"] != false || wb["model"] != `{"components":[1]}` || len(wb["runs"].([]any)) != 2 ||
		len(diff["now_reported"].([]any)) != 1 || len(diff["now_suppressed"].([]any)) != 0 {
		t.Fatalf("workbench = %+v", wb)
	}
	cfg := getUI(t, s, repoPath(repo.ID, "/scan-config"))
	if cfg["set"] != true || len(cfg["ignored_paths"].([]any)) != 1 {
		t.Fatalf("scan config = %+v", cfg)
	}
	if meta := getUI(t, s, repoPath(repo.ID, "/metadata")); meta["stars"] != float64(3) {
		t.Fatalf("metadata = %+v", meta)
	}
	for _, tab := range []string{"/threat-model", "/workbench", "/scan-config", "/metadata"} {
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(9999, tab), nil)), http.StatusNotFound, uiCodeNotFound)
	}
}

func TestUISubprojectDetail(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "mono")
	other := seedUIRepo(t, s.DB, "other")
	sub := db.Subproject{RepositoryID: repo.ID, Path: "pkg/a", Name: "a", DisclosureChannel: "a@acme.test"}
	s.DB.Create(&sub)
	sc := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName, SubPath: "pkg/a"}
	s.DB.Create(&sc)
	s.DB.Create(&db.Finding{ScanID: sc.ID, RepositoryID: repo.ID, Title: "in sub", Severity: "High", Status: db.FindingNew, SubPath: "pkg/a"})
	s.DB.Create(&db.Finding{ScanID: sc.ID, RepositoryID: repo.ID, Title: "root", Severity: "High", Status: db.FindingNew})

	body := getUI(t, s, repoPath(repo.ID, fmt.Sprintf("/subprojects/%d", sub.ID)))
	findings := body["findings"].(map[string]any)
	if findings["total"] != float64(1) || body["subproject"].(map[string]any)["scan_count"] != float64(1) {
		t.Fatalf("subproject = %+v", body)
	}
	if dc := body["disclosure_channel"].(map[string]any); dc["own"] != "a@acme.test" {
		t.Fatalf("channel = %+v", dc)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(other.ID, fmt.Sprintf("/subprojects/%d", sub.ID)), nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/subprojects/x"), nil)), http.StatusBadRequest, uiCodeBadParam)
}

// listItems returns a decoded envelope's items as objects.
func listItems(body map[string]any) []map[string]any {
	raw, _ := body["items"].([]any)
	out := make([]map[string]any, len(raw))
	for i, v := range raw {
		out[i], _ = v.(map[string]any)
	}
	return out
}
