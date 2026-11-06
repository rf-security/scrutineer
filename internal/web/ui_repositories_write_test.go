package web

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"scrutineer/internal/db"
)

// Tests for the repository writes (#39-#42, #44).

func patchRepo(t *testing.T, id uint, body any, etag string) *http.Request {
	t.Helper()
	r := operatorReq(t, http.MethodPatch, repoPath(id, ""), body)
	if etag != "" {
		r.Header.Set("If-Match", etag)
	}
	return r
}

func TestUIRepoPatch(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "patch")
	c := s.Broker.Subscribe(0, repo.ID, 0, uiRepositoryEvent)
	defer s.Broker.Unsubscribe(c)

	get := serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, ""), nil))
	etag := get.Header().Get("ETag")
	r := patchRepo(t, repo.ID, map[string]any{
		"disclosure_channel": " security@acme.test ",
		"scan_schedule":      "weekly",
		"upstream_url":       "https://github.com/Upstream/Repo.git",
		"threat_model":       `{"b": 2}`,
		"scan_config":        "skip:\n  - vendor/**\n",
	}, etag)
	w := serveUI(t, s, r)
	body := decodeUIJSON[map[string]any](t, w, http.StatusOK)
	fields := body["fields"].(map[string]any)
	if fields["disclosure_channel"] != "security@acme.test" || fields["scan_schedule"] != "weekly" ||
		fields["upstream_url"] != "https://github.com/upstream/repo" {
		t.Fatalf("fields = %+v", fields)
	}
	if w.Header().Get("ETag") == "" || w.Header().Get("ETag") == etag {
		t.Fatalf("ETag not bumped: %q -> %q", etag, w.Header().Get("ETag"))
	}
	requireRepoEvent(t, c, repo.ID, uiChangeUpdated)
	var stored db.Repository
	s.DB.First(&stored, repo.ID)
	if stored.DisclosureChannel != "security@acme.test" || stored.ScanSchedule != "weekly" || stored.ThreatModel == "" ||
		stored.ScanConfig == "" || stored.NextScheduledScanAt != nil {
		t.Fatalf("stored = %+v", stored)
	}

	// The old ETag is now stale: 409 with the current row.
	r = patchRepo(t, repo.ID, map[string]any{"scan_schedule": "daily"}, etag)
	conflict := requireUIError(t, serveUI(t, s, r), http.StatusConflict, uiCodeConflict)
	if conflict.Current["id"] != float64(repo.ID) {
		t.Fatalf("conflict current = %+v", conflict.Current)
	}

	// Validation names each bad field.
	r = patchRepo(t, repo.ID, map[string]any{"scan_schedule": "every tuesday", "upstream_url": "http://x", "threat_model": "{"}, "")
	bad := requireUIError(t, serveUI(t, s, r), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	for _, f := range []string{"scan_schedule", "upstream_url", "threat_model"} {
		if bad.Fields[f] == "" {
			t.Errorf("missing field error %s: %+v", f, bad.Fields)
		}
	}

	// Prefer: return=representation returns RepoDetail.
	r = patchRepo(t, repo.ID, map[string]any{"threat_model": ""}, "*")
	r.Header.Set("Prefer", "return=representation")
	full := decodeUIJSON[map[string]any](t, serveUI(t, s, r), http.StatusOK)
	if _, ok := full["counts"]; !ok || full["has_threat_model_override"] != false {
		t.Fatalf("representation = %+v", full)
	}

	r = patchRepo(t, 9999, map[string]any{}, "")
	requireUIError(t, serveUI(t, s, r), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPatch, repoPath(repo.ID, ""), "{")), http.StatusBadRequest, uiCodeBadParam)
}

func TestUIRepoPatch_federationOptOutStopsScans(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "optout")
	queued := seedUIScan(t, s.DB, repo, db.ScanQueued, deepDiveSkillName)
	r := patchRepo(t, repo.ID, map[string]any{"federation_opt_out": map[string]any{"enabled": true, "reason": "asked"}}, "")
	decodeUIJSON[map[string]any](t, serveUI(t, s, r), http.StatusOK)
	var sc db.Scan
	s.DB.First(&sc, queued.ID)
	if sc.Status != db.ScanCancelled {
		t.Fatalf("queued scan status = %s, want cancelled", sc.Status)
	}
	detail := getUI(t, s, repoPath(repo.ID, ""))
	if fo, ok := detail["federation_opt_out"].(map[string]any); !ok || fo["reason"] != "asked" || detail["federation_opted_out"] != true {
		t.Fatalf("detail opt-out = %+v", detail["federation_opt_out"])
	}
	r = patchRepo(t, repo.ID, map[string]any{"federation_opt_out": map[string]any{"enabled": false}}, "")
	decodeUIJSON[map[string]any](t, serveUI(t, s, r), http.StatusOK)
	if detail = getUI(t, s, repoPath(repo.ID, "")); detail["federation_opt_out"] != nil {
		t.Fatalf("opt-out not cleared: %+v", detail["federation_opt_out"])
	}
}

func TestUIRepoIgnoredPaths(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "ignored")
	path := repoPath(repo.ID, "/scan-config/ignored-paths")

	add := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"pattern": "vendor/**"})), http.StatusOK)
	if add["changed"] != true || len(add["ignored_paths"].([]any)) != 1 || add["set"] != true {
		t.Fatalf("add = %+v", add)
	}
	again := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"pattern": "vendor/**"})), http.StatusOK)
	if again["changed"] != false {
		t.Fatalf("re-add = %+v", again)
	}
	del := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodDelete, path+"?pattern="+url.QueryEscape("vendor/**"), nil)), http.StatusOK)
	if del["changed"] != true || len(del["ignored_paths"].([]any)) != 0 {
		t.Fatalf("delete = %+v", del)
	}
	absent := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodDelete, path+"?pattern=nope", nil)), http.StatusOK)
	if absent["changed"] != false {
		t.Fatalf("absent delete = %+v", absent)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"pattern": " "})), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, repoPath(9999, "/scan-config/ignored-paths"), map[string]string{"pattern": "x"})), http.StatusNotFound, uiCodeNotFound)
}

func TestUIRepoAlternatives(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "alts")
	other := seedUIRepo(t, s.DB, "other")
	path := repoPath(repo.ID, "/alternatives")
	created := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, path,
		map[string]string{"purl": "pkg:npm/left-pad", "kind": "successor", "note": " n "})), http.StatusCreated)
	if created["kind"] != "successor" || created["note"] != "n" {
		t.Fatalf("created = %+v", created)
	}
	bad := requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"purl": "pkg:npm/x", "kind": "clone"})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if bad.Fields["kind"] == "" {
		t.Fatalf("fields = %+v", bad.Fields)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"purl": ""})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	id := uint(created["id"].(float64))
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodDelete, repoPath(other.ID, fmt.Sprintf("/alternatives/%d", id)), nil)), http.StatusNotFound, uiCodeNotFound)
	if w := serveUI(t, s, operatorReq(t, http.MethodDelete, repoPath(repo.ID, fmt.Sprintf("/alternatives/%d", id)), nil)); w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d %s", w.Code, w.Body)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodDelete, repoPath(repo.ID, fmt.Sprintf("/alternatives/%d", id)), nil)), http.StatusNotFound, uiCodeNotFound)
}

func TestUIRepoExpectedFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "bench")
	path := repoPath(repo.ID, "/expected")
	created := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPost, path,
		map[string]string{"file": "./src/a.go", "cwe": "CWE-79"})), http.StatusCreated)
	if created["file"] != "src/a.go" || created["cwe"] != "CWE-79" || created[statusKey] != "missed" {
		t.Fatalf("created = %+v", created)
	}
	bad := requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"file": "../etc", "cwe": "79"})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if bad.Fields["file"] == "" {
		t.Fatalf("fields = %+v", bad.Fields)
	}
	if bad = requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path, map[string]string{"file": "a.go"})), http.StatusUnprocessableEntity, uiCodeValidationFailed); bad.Fields["cwe"] == "" {
		t.Fatalf("fields = %+v", bad.Fields)
	}
	id := uint(created["id"].(float64))
	if w := serveUI(t, s, operatorReq(t, http.MethodDelete, repoPath(repo.ID, fmt.Sprintf("/expected/%d", id)), nil)); w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d %s", w.Code, w.Body)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodDelete, repoPath(repo.ID, "/expected/x"), nil)), http.StatusBadRequest, uiCodeBadParam)
}

func TestUISubprojectPatch(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "subpatch")
	s.DB.Model(&repo).Update("disclosure_channel", "repo@acme.test")
	sub := db.Subproject{RepositoryID: repo.ID, Path: "pkg/a", Name: "a"}
	s.DB.Create(&sub)
	path := repoPath(repo.ID, fmt.Sprintf("/subprojects/%d", sub.ID))
	body := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPatch, path, map[string]string{"disclosure_channel": " a@acme.test "})), http.StatusOK)
	if dc := body["disclosure_channel"].(map[string]any); dc["own"] != "a@acme.test" || dc["effective"] != "a@acme.test" {
		t.Fatalf("channel = %+v", dc)
	}
	body = decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodPatch, path, map[string]string{"disclosure_channel": ""})), http.StatusOK)
	if dc := body["disclosure_channel"].(map[string]any); dc["own"] != "" || dc["effective"] != "repo@acme.test" {
		t.Fatalf("cleared channel = %+v", dc)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPatch, path, map[string]string{})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPatch, repoPath(repo.ID, "/subprojects/9999"), map[string]string{"disclosure_channel": ""})), http.StatusNotFound, uiCodeNotFound)
}
