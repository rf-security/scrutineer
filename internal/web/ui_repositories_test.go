package web

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"scrutineer/internal/db"
)

// Tests for GET /ui/repositories (#28), GET /ui/repositories/{id} (#29) and the
// additive 409 body of DELETE /api/v1/repositories/{id}.

// requireRepoEvent asserts a `repository` event with change was published.
func requireRepoEvent(t *testing.T, c *client, id uint, change string) {
	t.Helper()
	select {
	case e := <-c.ch:
		m, ok := e.JSON.(map[string]any)
		if e.Name != uiRepositoryEvent || !ok || m["id"] != id || m[uiEventChangeKey] != change {
			t.Fatalf("event = %s %+v, want repository %d %s", e.Name, e.JSON, id, change)
		}
	case <-time.After(time.Second):
		t.Fatalf("no repository event for %d", id)
	}
}

func TestUIRepoList(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	alpha := seedUIRepo(t, s.DB, "alpha")
	beta := seedUIRepo(t, s.DB, "beta")
	gamma := seedUIRepo(t, s.DB, "gamma")
	s.DB.Model(&alpha).Updates(map[string]any{"languages": "Go, Rust", "health": "active", "disk_bytes": 42, "scan_schedule": "daily"})
	s.DB.Model(&beta).Updates(map[string]any{"languages": "Python"})
	done1 := seedUIScan(t, s.DB, alpha, db.ScanDone, deepDiveSkillName)
	seedUIScan(t, s.DB, alpha, db.ScanRunning, "recon")
	branch := db.Scan{RepositoryID: alpha.ID, Kind: "skill", Status: db.ScanDone, SkillName: "recon", Ref: "dev"}
	s.DB.Create(&branch)
	seedUIFinding(t, s.DB, done1, "open one", db.FindingNew)
	seedUIFinding(t, s.DB, done1, "closed", db.FindingFixed)

	got := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/repositories?sort=name", nil)))
	if got.Total != 3 || len(got.Items) != 3 || got.PageSize != uiDefaultPageSize {
		t.Fatalf("list = %+v", got)
	}
	row := got.Items[0]
	if row["name"] != "alpha" || row["findings_total"] != float64(1) || row["findings_count"] != float64(1) {
		t.Fatalf("alpha row = %+v", row)
	}
	if st := row["status_scan"].(map[string]any); st[statusKey] != string(db.ScanRunning) || st["skill_name"] != "recon" {
		t.Fatalf("status_scan = %+v", st)
	}
	if br := row["branches"].([]any); len(br) != 1 || br[0] != "dev" {
		t.Fatalf("branches = %+v", br)
	}
	if h := row["health"].(map[string]any); h[statusKey] != "active" {
		t.Fatalf("health = %+v", h)
	}
	if sc := row["schedule"].(map[string]any); sc["repo"] != "daily" || sc["effective"] != "daily" {
		t.Fatalf("schedule = %+v", sc)
	}
	if row["disk_bytes"] != float64(42) || got.Items[2]["status_scan"] != nil {
		t.Fatalf("rows = %+v", got.Items)
	}

	body := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/repositories", nil)), http.StatusOK)
	if langs := body["languages"].([]any); len(langs) != 3 {
		t.Fatalf("languages = %+v", langs)
	}

	cases := map[string][]uint{
		"language=Rust":                     {alpha.ID},
		"q=gam":                             {gamma.ID},
		"sort=name.desc&page_size=1&page=2": {beta.ID},
	}
	for query, want := range cases {
		list := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/repositories?"+query, nil)))
		if len(list.Items) != len(want) || list.Items[0]["id"] != float64(want[0]) {
			t.Errorf("%s: items = %+v", query, list.Items)
		}
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/repositories?page=0", nil)), http.StatusBadRequest, uiCodeBadParam)
}

func TestUIRepoDetail(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "detail")
	s.DB.Model(&repo).Updates(map[string]any{"disclosure_channel": "security@acme.test", "threat_model": `{"a":1}`, "baseline_level": 1})
	dd := seedUIScan(t, s.DB, repo, db.ScanDone, deepDiveSkillName)
	f := seedUIFinding(t, s.DB, dd, "sqli", db.FindingNew)
	s.DB.Model(&f).Update("cwe", "CWE-89")
	seedUIScan(t, s.DB, repo, db.ScanQueued, "recon")
	seedUIScan(t, s.DB, repo, db.ScanFailed, "semgrep")
	s.DB.Create(&db.ExpectedFinding{RepositoryID: repo.ID, File: "src/app.go", CWE: "CWE-89"})
	s.DB.Create(&db.ComplianceControl{RepositoryID: repo.ID, ControlID: "OSPS-AC-01.01", Level: 1, Status: "PASS"})
	s.DB.Create(&db.Subproject{RepositoryID: repo.ID, Path: "pkg/a", Name: "a"})

	w := serveUI(t, s, operatorReq(t, http.MethodGet, fmt.Sprintf("/api/v1/ui/repositories/%d", repo.ID), nil))
	body := decodeUIJSON[map[string]any](t, w, http.StatusOK)
	if w.Header().Get("ETag") == "" {
		t.Fatal("missing ETag")
	}
	counts := body["counts"].(map[string]any)
	want := map[string]float64{"active_scans": 1, "failed_scans": 1, "new_findings": 1, "findings": 1, "subprojects": 1,
		"expected": 1, "expected_matched": 1, "compliance": 1}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("counts[%s] = %v, want %v", k, counts[k], v)
		}
	}
	if _, leaked := counts["compliance_passed"]; leaked {
		t.Error("compliance_passed leaked into counts")
	}
	if body["disclosure_channel"] != "security@acme.test" || body["has_threat_model_override"] != true || body["is_local"] != false {
		t.Fatalf("detail scalars = %+v", body)
	}
	if c := body["compliance"].(map[string]any); c["level"] != "L1" || c["passed"] != float64(1) {
		t.Fatalf("compliance = %+v", c)
	}
	latest := body["latest_scan"].(map[string]any)
	findings := latest["findings"].([]any)
	if latest["id"] != float64(dd.ID) || len(findings) != 1 || findings[0].(map[string]any)["expected"] != "matched" {
		t.Fatalf("latest_scan = %+v", latest)
	}
	if _, ok := body["exports"].(map[string]any)["report_md"]; !ok {
		t.Fatal("missing exports.report_md")
	}
	if body["total_cost_usd"] != float64(0) || body["unpriced_scan_count"] != float64(0) {
		t.Fatalf("cost = %v unpriced = %v", body["total_cost_usd"], body["unpriced_scan_count"])
	}
	// A priced scan sums into total_cost_usd like the HTML spend badge; a scan
	// that used tokens on a model with no list price records 0 and is counted
	// as unpriced instead.
	s.DB.Model(&dd).Updates(map[string]any{"cost_usd": 1.5, "input_tokens": 100})
	unpriced := seedUIScan(t, s.DB, repo, db.ScanDone, deepDiveSkillName)
	s.DB.Model(&unpriced).Updates(map[string]any{"cost_usd": 0, "input_tokens": 5000, "output_tokens": 10})
	body = getUI(t, s, fmt.Sprintf("/api/v1/ui/repositories/%d", repo.ID))
	if body["total_cost_usd"] != repoTotalCost(s.DB, repo.ID) || body["total_cost_usd"] != 1.5 || body["unpriced_scan_count"] != float64(1) {
		t.Fatalf("cost = %v unpriced = %v", body["total_cost_usd"], body["unpriced_scan_count"])
	}

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/repositories/9999", nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/repositories/x", nil)), http.StatusBadRequest, uiCodeBadParam)
}

func TestAPIDeleteRepository_inFlightBody(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "busy")
	seedUIScan(t, s.DB, repo, db.ScanQueued, deepDiveSkillName)
	seedUIScan(t, s.DB, repo, db.ScanPaused, deepDiveSkillName)
	w := serveUI(t, s, operatorReq(t, http.MethodDelete, fmt.Sprintf("/api/v1/repositories/%d", repo.ID), nil))
	body := requireUIError(t, w, http.StatusConflict, uiCodeInFlight)
	full := decodeUIJSON[map[string]any](t, w, http.StatusConflict)
	if full["active"] != float64(1) || full["paused"] != float64(1) || body.Error == "" {
		t.Fatalf("409 body = %+v", full)
	}

	idle := seedUIRepo(t, s.DB, "idle")
	c := s.Broker.Subscribe(0, idle.ID, 0, uiRepositoryEvent)
	defer s.Broker.Unsubscribe(c)
	w = serveUI(t, s, operatorReq(t, http.MethodDelete, fmt.Sprintf("/api/v1/repositories/%d", idle.ID), nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete idle = %d %s", w.Code, w.Body)
	}
	requireRepoEvent(t, c, idle.ID, uiChangeDeleted)
}
