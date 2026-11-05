package web

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

// Enqueue paths (retry, resume) run only against newTestServer: its queue is
// an in-memory sqlite goqite with no worker consuming it, so nothing runs.

func scanActionPath(id uint, action string) string {
	return fmt.Sprintf("/api/v1/ui/scans/%d/actions/%s", id, action)
}

func TestUIScanActionCancel(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "cancel")
	queued := seedUIScan(t, s.DB, repo, db.ScanQueued, "x")
	finished := seedUIScan(t, s.DB, repo, db.ScanDone, "x")
	paused := seedUIScan(t, s.DB, repo, db.ScanPaused, "x")

	row := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, scanActionPath(queued.ID, "cancel"), nil)), http.StatusOK)
	if row[statusKey] != string(db.ScanCancelled) || row["actions"].(map[string]any)["cancel"] != false {
		t.Errorf("cancelled row = %v", row)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, scanActionPath(finished.ID, "cancel"), nil)), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, scanActionPath(paused.ID, "cancel"), nil)), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, scanActionPath(999, "cancel"), nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, scanActionPath(queued.ID, "explode"), nil)), http.StatusBadRequest, uiCodeBadParam)
	assertQueuedJobCount(t, s, 0)
}

func TestUIScanActionResume(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "resume")
	paused := seedUIScan(t, s.DB, repo, db.ScanPaused, "x")
	running := seedUIScan(t, s.DB, repo, db.ScanRunning, "x")

	row := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, scanActionPath(paused.ID, "resume"), nil)), http.StatusOK)
	if row[statusKey] != string(db.ScanQueued) {
		t.Errorf("resumed row status = %v", row[statusKey])
	}
	assertQueuedJobCount(t, s, 1)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, scanActionPath(running.ID, "resume"), nil)), http.StatusBadRequest, uiCodeBadParam)

	// An opted-out repository refuses the resume (409), as the HTML handler does.
	optedOut := seedUIRepo(t, s.DB, "optout")
	now := time.Now()
	s.DB.Model(&optedOut).Update("federation_opt_out_at", &now)
	blocked := seedUIScan(t, s.DB, optedOut, db.ScanPaused, "x")
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, scanActionPath(blocked.ID, "resume"), nil)), http.StatusConflict, uiCodeConflict)
	assertQueuedJobCount(t, s, 1)
}

func TestUIScanActionRetry(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "retry")
	skill := seedUIScanSkill(t, s)
	failed := seedUIScan(t, s.DB, repo, db.ScanFailed, skill.Name)
	s.DB.Model(&failed).Updates(map[string]any{
		"skill_id": skill.ID, "effort": "high", "sub_path": "crates/a", "ref": "main",
		"import_payload": []byte("payload"),
	})
	noSkill := seedUIScan(t, s.DB, repo, db.ScanFailed, "")

	res := decodeUIJSON[map[string]uint](t, serveUI(t, s, operatorReq(t, http.MethodPost, scanActionPath(failed.ID, "retry"), nil)), http.StatusAccepted)
	var fresh db.Scan
	if err := s.DB.First(&fresh, res[uiEventScanIDKey]).Error; err != nil {
		t.Fatal(err)
	}
	// The queued attempt carries the ScanOpts the HTML retry builds.
	if fresh.ParentScanID == nil || *fresh.ParentScanID != failed.ID || fresh.SkillID == nil || *fresh.SkillID != skill.ID ||
		fresh.Effort != "high" || fresh.SubPath != "crates/a" || fresh.Ref != "main" ||
		string(fresh.ImportPayload) != "payload" || fresh.Status != db.ScanQueued {
		t.Errorf("retry scan = %+v", fresh)
	}
	assertQueuedJobCount(t, s, 1)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, scanActionPath(noSkill.ID, "retry"), nil)), http.StatusBadRequest, uiCodeBadParam)
	assertQueuedJobCount(t, s, 1)
}

func TestUIScansPauseQueued(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "pause")
	seedUIScan(t, s.DB, repo, db.ScanQueued, "x")
	seedUIScan(t, s.DB, repo, db.ScanQueued, "x")
	seedUIScan(t, s.DB, repo, db.ScanRunning, "x")

	res := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/scans/actions/pause-queued", map[string]any{})), http.StatusOK)
	if res["affected"].(float64) != 2 {
		t.Errorf("affected = %v", res)
	}
	var paused int64
	s.DB.Model(&db.Scan{}).Where("status = ?", db.ScanPaused).Count(&paused)
	if paused != 2 {
		t.Errorf("paused = %d", paused)
	}
	// An empty body is accepted; malformed JSON is not.
	if w := serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/scans/actions/pause-queued", nil)); w.Code != http.StatusOK {
		t.Errorf("empty body: %d", w.Code)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/scans/actions/pause-queued", "{")), http.StatusBadRequest, uiCodeBadParam)
}

func TestUIScansResumePaused(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	a := seedUIRepo(t, s.DB, "a")
	b := seedUIRepo(t, s.DB, "b")
	seedUIScan(t, s.DB, a, db.ScanPaused, "x")
	seedUIScan(t, s.DB, b, db.ScanPaused, "x")

	res := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/scans/actions/resume-paused",
		map[string]any{repositoryIDKey: a.ID})), http.StatusOK)
	if res["affected"].(float64) != 1 || res["errored"].(float64) != 0 {
		t.Errorf("result = %v", res)
	}
	assertQueuedJobCount(t, s, 1)
	var stillPaused db.Scan
	if err := s.DB.Where("repository_id = ?", b.ID).First(&stillPaused).Error; err != nil || stillPaused.Status != db.ScanPaused {
		t.Errorf("other repository resumed: %v %v", stillPaused.Status, err)
	}
}

func TestUIScansRetryFailed(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "rf")
	skill := seedUIScanSkill(t, s)
	old := seedUIScan(t, s.DB, repo, db.ScanFailed, skill.Name)
	s.DB.Model(&old).Update("skill_id", skill.ID)

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/scans/actions/retry-failed",
		map[string]any{"completeness": "bogus"})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	assertQueuedJobCount(t, s, 0)

	res := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/scans/actions/retry-failed",
		map[string]any{repositoryIDKey: repo.ID, "skill": skill.Name})), http.StatusOK)
	ids, _ := res["scan_ids"].([]any)
	if res["affected"].(float64) != 1 || res["retried"].(float64) != 1 || res["skipped"].(float64) != 0 || len(ids) != 1 {
		t.Fatalf("result = %v", res)
	}
	var fresh db.Scan
	if err := s.DB.First(&fresh, uint(ids[0].(float64))).Error; err != nil || fresh.ParentScanID == nil || *fresh.ParentScanID != old.ID {
		t.Errorf("retry attempt = %+v err=%v", fresh, err)
	}
	assertQueuedJobCount(t, s, 1)

	// The new attempt supersedes the failure: a second run skips it.
	res = decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/scans/actions/retry-failed", nil)), http.StatusOK)
	if res["affected"].(float64) != 0 || res["skipped"].(float64) != 1 {
		t.Errorf("second run = %v", res)
	}
	assertQueuedJobCount(t, s, 1)
}

func TestUIScansCancelAll(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "ca")
	other := seedUIRepo(t, s.DB, "other")
	seedUIScan(t, s.DB, repo, db.ScanQueued, "x")
	seedUIScan(t, s.DB, repo, db.ScanQueued, "x")
	keep := seedUIScan(t, s.DB, other, db.ScanQueued, "x")

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/scans/actions/cancel-all", map[string]any{})),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)
	res := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/scans/actions/cancel-all",
		map[string]any{repositoryIDKey: repo.ID})), http.StatusOK)
	if res["affected"].(float64) != 2 {
		t.Errorf("result = %v", res)
	}
	s.DB.First(&keep, keep.ID)
	if keep.Status != db.ScanQueued {
		t.Errorf("other repository's scan = %s", keep.Status)
	}
}

func TestUIScansBatch(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "batch")
	q1 := seedUIScan(t, s.DB, repo, db.ScanQueued, "x")
	q2 := seedUIScan(t, s.DB, repo, db.ScanRunning, "x")
	fin := seedUIScan(t, s.DB, repo, db.ScanDone, "x")

	type batchResult struct {
		Results []struct {
			ID     uint   `json:"id"`
			OK     bool   `json:"ok"`
			ScanID uint   `json:"scan_id"`
			Code   string `json:"code"`
			Error  string `json:"error"`
		} `json:"results"`
		Affected int `json:"affected"`
	}
	res := decodeUIJSON[batchResult](t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/scans/batch",
		map[string]any{"ids": []uint{q1.ID, q2.ID, fin.ID, 999, q1.ID}, "action": "cancel"})), http.StatusOK)
	if res.Affected != 2 || len(res.Results) != 4 {
		t.Fatalf("batch = %+v", res)
	}
	byID := map[uint]string{}
	for _, it := range res.Results {
		if it.OK {
			byID[it.ID] = "ok"
		} else {
			byID[it.ID] = it.Code
		}
	}
	if byID[q1.ID] != "ok" || byID[q2.ID] != "ok" || byID[fin.ID] != uiCodeBadParam || byID[999] != uiCodeNotFound {
		t.Errorf("per-item = %v", byID)
	}

	for _, body := range []map[string]any{
		{"ids": []uint{q1.ID}, "action": "explode"},
		{"ids": []uint{}, "action": "cancel"},
		{"ids": make([]uint, uiScanBatchMax+1), "action": "cancel"},
	} {
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/scans/batch", body)), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	}
	assertQueuedJobCount(t, s, 0)
}

func TestUIScansBatchRetry(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "batchretry")
	skill := seedUIScanSkill(t, s)
	failed := seedUIScan(t, s.DB, repo, db.ScanFailed, skill.Name)
	s.DB.Model(&failed).Update("skill_id", skill.ID)

	w := serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/scans/batch", map[string]any{"ids": []uint{failed.ID}, "action": "retry"}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"scan_id":`) {
		t.Fatalf("batch retry: %d %s", w.Code, w.Body.String())
	}
	assertQueuedJobCount(t, s, 1)
}
