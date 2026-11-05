package web

import (
	"net/http"
	"testing"

	"scrutineer/internal/db"
)

// Tests for the repository enqueue actions (#45-#47). newTestServer only:
// the queue is the in-memory sqlite goqite, nothing reaches a model.

// seedUIRepoSkill installs an active skill named name.
func seedUIRepoSkill(t *testing.T, s *Server, name string) db.Skill {
	t.Helper()
	skill := db.Skill{Name: name, Active: true, Source: "ui", Body: name, OutputKind: "freeform", OutputFile: "report.json"}
	if err := s.DB.Where(db.Skill{Name: name}).Assign(db.Skill{Active: true}).FirstOrCreate(&skill).Error; err != nil {
		t.Fatal(err)
	}
	return skill
}

// midModel is what the "mid" tier resolves to, so a test can tell an
// explicit model preference reached the scan.
func midModel(s *Server) string { return resolveModelPreference(s.DB, ModelTierMid, s.DefaultModel()) }

// loadScan loads the queued scan an action returned.
func loadScan(t *testing.T, s *Server, id any) db.Scan {
	t.Helper()
	f, ok := id.(float64)
	if !ok {
		t.Fatalf("scan id = %v", id)
	}
	var sc db.Scan
	if err := s.DB.Omit(uiScanOmit...).First(&sc, uint(f)).Error; err != nil {
		t.Fatal(err)
	}
	return sc
}

func postUI(t *testing.T, s *Server, path string, body any, status int) map[string]any {
	t.Helper()
	return decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, path, body)), status)
}

func TestUIRepoScanAction(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "scan")
	path := repoPath(repo.ID, "/actions/scan")
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{})), http.StatusPreconditionFailed, uiCodePreconditionFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"rescan_mode": "diff"})), http.StatusPreconditionFailed, uiCodePreconditionFailed)
	seedUIRepoSkill(t, s, deepDiveSkillName)

	body := postUI(t, s, path, map[string]any{"model": ModelTierMid, "sub_path": " pkg/a "}, http.StatusAccepted)
	sc := loadScan(t, s, body["scan_id"])
	if sc.SkillName != deepDiveSkillName || sc.Model != midModel(s) || sc.SubPath != "pkg/a" || sc.ScanGroup == "" || sc.Status != db.ScanQueued {
		t.Fatalf("queued scan = %+v", sc)
	}
	assertQueuedJobCount(t, s, 1)

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"rescan_mode": "partial"})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, repoPath(9999, "/actions/scan"), map[string]any{})), http.StatusNotFound, uiCodeNotFound)

	seedUIRepoSkill(t, s, reconSkillName)
	seedUIRepoSkill(t, s, threatModelSkillName)
	diff := postUI(t, s, path, map[string]any{"rescan_mode": "diff"}, http.StatusAccepted)
	ids := diff["scan_ids"].([]any)
	if diff["queued"] != float64(2) || len(ids) != 2 {
		t.Fatalf("diff = %+v", diff)
	}
	a, b := loadScan(t, s, ids[0]), loadScan(t, s, ids[1])
	if a.RescanMode != db.ScanRescanModeDiff || a.ScanGroup == "" || a.ScanGroup != b.ScanGroup || a.SkillName != reconSkillName {
		t.Fatalf("diff scans = %+v / %+v", a, b)
	}
}

func TestUIRepoScanAction_optedOutIsConflict(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "optedout")
	seedUIRepoSkill(t, s, deepDiveSkillName)
	s.DB.Model(&repo).Update("federation_opt_out_at", repo.CreatedAt)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, repoPath(repo.ID, "/actions/scan"), nil)), http.StatusConflict, uiCodeConflict)
	assertQueuedJobCount(t, s, 0)
}

func TestUIRepoScanAllAction(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "mono")
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, repoPath(repo.ID, "/actions/scan-all"), nil)), http.StatusPreconditionFailed, uiCodePreconditionFailed)
	skill := seedUIRepoSkill(t, s, deepDiveSkillName)
	s.DB.Create(&db.Subproject{RepositoryID: repo.ID, Path: "pkg/a", Name: "a"})
	s.DB.Create(&db.Subproject{RepositoryID: repo.ID, Path: "pkg/b", Name: "b"})
	busy := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanRunning, SkillName: deepDiveSkillName, SkillID: &skill.ID, SubPath: "pkg/b"}
	s.DB.Create(&busy)

	body := postUI(t, s, repoPath(repo.ID, "/actions/scan-all"), map[string]any{"model": ModelTierMid}, http.StatusAccepted)
	if body["queued"] != float64(1) || body["skipped"] != float64(1) || body["message"] == "" {
		t.Fatalf("scan-all = %+v", body)
	}
	sc := loadScan(t, s, body["scan_ids"].([]any)[0])
	if sc.SubPath != "pkg/a" || sc.Model != midModel(s) || sc.ScanGroup == "" {
		t.Fatalf("queued = %+v", sc)
	}
}

func TestUIRepoVerifyAllAction(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "verify")
	dd := seedUIScan(t, s.DB, repo, db.ScanDone, deepDiveSkillName)
	f1 := seedUIFinding(t, s.DB, dd, "new one", db.FindingNew)
	seedUIFinding(t, s.DB, dd, "triaged", db.FindingTriaged)
	path := repoPath(repo.ID, "/actions/verify-all")
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, nil)), http.StatusPreconditionFailed, uiCodePreconditionFailed)
	seedUIRepoSkill(t, s, verifySkillName)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path+"?category=bogus", nil)), http.StatusBadRequest, uiCodeBadParam)

	body := postUI(t, s, path, map[string]any{"model": ModelTierMid}, http.StatusAccepted)
	if body["queued"] != float64(1) {
		t.Fatalf("verify-all = %+v", body)
	}
	sc := loadScan(t, s, body["scan_ids"].([]any)[0])
	if sc.FindingID == nil || *sc.FindingID != f1.ID || sc.Model != midModel(s) || sc.SkillName != verifySkillName {
		t.Fatalf("verify scan = %+v", sc)
	}
	again := postUI(t, s, path, nil, http.StatusAccepted)
	if again["queued"] != float64(0) || again["skipped"] != float64(1) {
		t.Fatalf("second verify-all = %+v", again)
	}
}

func TestUIRepoThreatModelRunAction(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "tm")
	path := repoPath(repo.ID, "/actions/threat-model-run")
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"threat_model": "{"})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"threat_model": `{"x":1}`})), http.StatusPreconditionFailed, uiCodePreconditionFailed)
	seedUIRepoSkill(t, s, deepDiveSkillName)
	body := postUI(t, s, path, map[string]any{"threat_model": `{"x":2}`}, http.StatusAccepted)
	sc := loadScan(t, s, body["scan_id"])
	var stored db.Repository
	s.DB.First(&stored, repo.ID)
	if sc.SkillName != deepDiveSkillName || stored.ThreatModel != "{\n  \"x\": 2\n}" {
		t.Fatalf("scan = %+v, threat model = %q", sc, stored.ThreatModel)
	}
	// An absent threat_model keeps the saved override.
	postUI(t, s, path, nil, http.StatusAccepted)
	s.DB.First(&stored, repo.ID)
	if stored.ThreatModel == "" {
		t.Fatal("absent threat_model cleared the override")
	}
}

func TestUIRepoRunSkillAction(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "runskill")
	skill := seedUIRepoSkill(t, s, "custom-audit")
	inactive := db.Skill{Name: "retired", Active: false, Source: "ui", Body: "x", OutputKind: "freeform", OutputFile: "report.json"}
	s.DB.Create(&inactive)
	s.DB.Model(&inactive).Update("active", false)
	path := repoPath(repo.ID, "/actions/run-skill")
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"skill_id": inactive.ID})), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"skill_id": skill.ID, "max_cost_usd": -1})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]any{"skill_id": skill.ID, "egress_policy": "nope"})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	body := postUI(t, s, path, map[string]any{"skill_id": skill.ID, "model": ModelTierMid, "max_cost_usd": 2.5}, http.StatusAccepted)
	sc := loadScan(t, s, body["scan_id"])
	if sc.SkillName != "custom-audit" || sc.Model != midModel(s) || sc.MaxCostUSD != 2.5 {
		t.Fatalf("scan = %+v", sc)
	}
}

func TestUIRepoValidateFixAction(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "fix")
	dd := seedUIRepoSkill(t, s, deepDiveSkillName)
	seedUIRepoSkill(t, s, verifySkillName)
	baseline := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName, SkillID: &dd.ID, SubPath: "pkg/a"}
	s.DB.Create(&baseline)
	f := seedUIFinding(t, s.DB, baseline, "bug", db.FindingNew)
	path := repoPath(repo.ID, "/actions/validate-fix")

	for _, body := range []map[string]any{
		{"finding_ids": []uint{f.ID}},
		{"ref": "bad..ref", "finding_ids": []uint{f.ID}},
		{"ref": "fix-1"},
		{"ref": "fix-1", "finding_ids": []uint{9999}},
	} {
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, body)), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	}
	body := postUI(t, s, path, map[string]any{"ref": "fix-1", "finding_ids": []uint{f.ID}, "model": ModelTierMid}, http.StatusAccepted)
	anchor := loadScan(t, s, body["scan_id"])
	if anchor.BaselineScanID == nil || *anchor.BaselineScanID != baseline.ID || anchor.Ref != "fix-1" || anchor.SubPath != "pkg/a" {
		t.Fatalf("anchor = %+v", anchor)
	}
	verify := body["verify_scan_ids"].([]any)
	if len(verify) != 1 {
		t.Fatalf("verify ids = %+v", body)
	}
	if v := loadScan(t, s, verify[0]); v.FindingID == nil || *v.FindingID != f.ID || v.Ref != "fix-1" {
		t.Fatalf("verify scan = %+v", v)
	}
}
