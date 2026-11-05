package web

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// seedUISkill creates an active findings-kind skill.
func seedUISkill(t *testing.T, s *Server) db.Skill {
	t.Helper()
	const name = "security-deep-dive"
	sk := db.Skill{Name: name, Active: true, Source: "ui", Body: name, OutputKind: "findings", OutputFile: "report.json"}
	if err := s.DB.Create(&sk).Error; err != nil {
		t.Fatal(err)
	}
	return sk
}

func TestUIScanDetail(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "detail")
	skill := seedUISkill(t, s)
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, skill.Name)
	s.DB.Model(&sc).Updates(map[string]any{
		"skill_id": skill.ID, "findings_count": 1, "commit": "abc123", "input_tokens": 100, "cache_read_tokens": 300,
		"output_tokens": 7, "effort": "high", "profile": "default", "prompt": "do the thing",
		"diff_stats": `{"changed_files":2,"patch_bytes":99,"files":[{"status":"M","path":"a.go"},{"status":"D","path":"b.go"}]}`,
	})
	f := seedUIFinding(t, s.DB, sc, "Overflow", db.FindingNew)

	w := serveUI(t, s, operatorReq(t, http.MethodGet, fmt.Sprintf("/api/v1/ui/scans/%d", sc.ID), nil))
	got := decodeUIJSON[map[string]any](t, w, http.StatusOK)
	if w.Header().Get("ETag") == "" {
		t.Error("missing ETag")
	}
	for _, k := range []string{"log", "report", "prompt", "api_token", "refusal_audit"} {
		if _, ok := got[k]; ok {
			t.Errorf("detail inlines blob %q", k)
		}
	}
	if got["effort"] != "high" || got["profile"] != "default" || got["sub_path"] != "" || got["ref"] != "" {
		t.Errorf("facts: %v %v %q %q", got["effort"], got["profile"], got["sub_path"], got["ref"])
	}
	findings, _ := got[uiKeyFindings].([]any)
	if len(findings) != 1 || findings[0].(map[string]any)["id"].(float64) != float64(f.ID) {
		t.Fatalf("findings = %v", got[uiKeyFindings])
	}
	tokens := got["tokens"].(map[string]any)
	if tokens["input"].(float64) != 100 || tokens["total_input"].(float64) != 400 || tokens["hit_ratio"].(float64) != 0.75 {
		t.Errorf("tokens = %v", tokens)
	}
	sk := got["skill"].(map[string]any)
	if sk["output_kind"] != "findings" || sk[uiKeyName] != skill.Name {
		t.Errorf("skill = %v", sk)
	}
	if got["can_export_report"] != true {
		t.Error("can_export_report = false with a finding")
	}
	rep := got["exports"].(map[string]any)["report_md"].(map[string]any)
	if rep["url"] != fmt.Sprintf("/scans/%d/report.md", sc.ID) || !strings.HasSuffix(rep["filename"].(string), ".md") {
		t.Errorf("report_md = %v", rep)
	}
	diff := got["diff"].(map[string]any)
	files := diff["files"].([]any)
	if diff["changed_files"].(float64) != 2 || len(files) != 2 ||
		files[0].(map[string]any)["status_name"] != "modified" || files[1].(map[string]any)["linkable"] != false {
		t.Errorf("diff = %v", diff)
	}
	if got["investigation"] != nil || got["submitted_report"] != nil || got["disclosure_review_finding_id"] != nil {
		t.Errorf("non-investigate scan carries investigation data: %v", got)
	}
	if got["has_refusal_audit"] != false || got["prompt_bytes"].(float64) != float64(len("do the thing")) {
		t.Errorf("blob flags: refusal=%v prompt_bytes=%v", got["has_refusal_audit"], got["prompt_bytes"])
	}
}

func TestUIScanDetailInvestigation(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "inv")
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, investigateSkillName)
	s.DB.Model(&sc).Updates(map[string]any{
		"report":         `{"notes":"looked","assessments":[{"claim":"c","outcome":"confirmed","evidence":"e"}]}`,
		"import_payload": []byte("the submitted report"),
		"refusal_audit":  `{"refused":[]}`,
	})
	got := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, fmt.Sprintf("/api/v1/ui/scans/%d", sc.ID), nil)), http.StatusOK)
	inv := got["investigation"].(map[string]any)
	if inv["notes"] != "looked" || len(inv["assessments"].([]any)) != 1 {
		t.Errorf("investigation = %v", inv)
	}
	if got["submitted_report"] != "the submitted report" || got["has_refusal_audit"] != true {
		t.Errorf("submitted_report=%v has_refusal_audit=%v", got["submitted_report"], got["has_refusal_audit"])
	}
	if got["skill"] != nil {
		t.Errorf("skill without skill_id = %v", got["skill"])
	}
	if got["can_export_report"] != true {
		t.Error("non-empty report should be exportable")
	}
}

func TestUIScanDetailErrors(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/scans/999", nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/scans/abc", nil)), http.StatusBadRequest, uiCodeBadParam)
}

func TestUIScanLogOffsets(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "log")
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, "x")
	s.DB.Model(&sc).Update("log", "héllo\nworld\n")
	logPath := fmt.Sprintf("/api/v1/ui/scans/%d/log", sc.ID)

	w := serveUI(t, s, operatorReq(t, http.MethodGet, logPath, nil))
	if w.Code != http.StatusOK || w.Body.String() != "héllo\nworld\n" {
		t.Fatalf("full log: %d %q", w.Code, w.Body.String())
	}
	// Byte offsets: "héllo\n" is 7 bytes.
	if w.Header().Get(uiLogLengthHeader) != "13" || w.Header().Get(uiScanStatusHeader) != "done" ||
		!strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("headers = %v", w.Header())
	}
	w = serveUI(t, s, operatorReq(t, http.MethodGet, logPath+"?offset=7", nil))
	if w.Body.String() != "world\n" || w.Header().Get(uiLogLengthHeader) != "13" {
		t.Errorf("offset=7: %q len=%s", w.Body.String(), w.Header().Get(uiLogLengthHeader))
	}
	w = serveUI(t, s, operatorReq(t, http.MethodGet, logPath+"?offset=500", nil))
	if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get(uiLogLengthHeader) != "13" {
		t.Errorf("offset past end: %d %q", w.Code, w.Body.String())
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, logPath+"?offset=-1", nil)), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/scans/999/log", nil)), http.StatusNotFound, uiCodeNotFound)
}

// A running scan's stored log trails the published lines (the worker flushes
// in batches); the endpoint serves the mirror so X-Log-Length lines up with
// the scan-log event offsets, and drops it once the scan stops.
func TestUIScanLogServesLiveMirror(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "live")
	sc := seedUIScan(t, s.DB, repo, db.ScanRunning, "x") // stored log "line one\n"
	logPath := fmt.Sprintf("/api/v1/ui/scans/%d/log", sc.ID)

	_ = s.Handler() // installs the broker hooks, as at startup
	sub := s.Broker.Subscribe(sc.ID, 0, 0, scanLogEvent)
	defer s.Broker.Unsubscribe(sub)
	// The first line was flushed with the stored log; the next two were not.
	s.Broker.Publish(Event{Name: scanLogEvent, ScanID: sc.ID, Data: "line one\n"})
	s.Broker.Publish(Event{Name: scanLogEvent, ScanID: sc.ID, Data: "two\n"})
	s.Broker.Publish(Event{Name: scanLogEvent, ScanID: sc.ID, Data: "three\n"})
	var last int64
	for range 3 {
		last = (<-sub.ch).Offset
	}

	w := serveUI(t, s, operatorReq(t, http.MethodGet, logPath, nil))
	if w.Body.String() != "line one\ntwo\nthree\n" || w.Header().Get(uiLogLengthHeader) != fmt.Sprint(last) {
		t.Fatalf("live log = %q len=%s, last event offset %d", w.Body.String(), w.Header().Get(uiLogLengthHeader), last)
	}
	w = serveUI(t, s, operatorReq(t, http.MethodGet, logPath+"?offset=9", nil))
	if w.Body.String() != "two\nthree\n" {
		t.Errorf("catch-up = %q", w.Body.String())
	}

	// Terminal: the worker wrote the full log; the mirror is retired.
	s.DB.Model(&sc).Updates(map[string]any{"status": db.ScanDone, "log": "line one\ntwo\nthree\nfinal\n"})
	s.Broker.Publish(Event{Name: scanStatusEvent, ScanID: sc.ID, RepoID: repo.ID})
	if _, ok := s.ui.liveLogs.snapshot(sc.ID); ok {
		t.Error("mirror kept after the scan finished")
	}
	w = serveUI(t, s, operatorReq(t, http.MethodGet, logPath, nil))
	if w.Body.String() != "line one\ntwo\nthree\nfinal\n" {
		t.Errorf("terminal log = %q", w.Body.String())
	}
}

func TestUILiveLogsMisalignmentFallsBack(t *testing.T) {
	var l uiLiveLogs
	stored := func(uint) string { return "abc\n" }
	l.observe(1, "def\n", 8, stored)
	if got, ok := l.snapshot(1); !ok || got != "abc\ndef\n" {
		t.Fatalf("seeded = %q %v", got, ok)
	}
	l.observe(1, "ghi\n", 99, stored) // offset gap: retire the mirror
	if _, ok := l.snapshot(1); ok {
		t.Error("misaligned mirror still served")
	}
	l.observe(1, "jkl\n", 103, stored)
	if _, ok := l.snapshot(1); ok {
		t.Error("untracked mirror resumed")
	}
	l.forget(1)
	l.observe(2, "x\n", 50, stored) // seed that cannot line up
	if _, ok := l.snapshot(2); ok {
		t.Error("unaligned seed served")
	}
	l.observe(0, "x\n", 2, stored)
	if _, ok := l.snapshot(0); ok {
		t.Error("scan 0 tracked")
	}
}

func TestUIScanBlobs(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "blobs")
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, "x") // report is JSON
	s.DB.Model(&sc).Updates(map[string]any{"prompt": "the prompt", "refusal_audit": "not json"})
	base := fmt.Sprintf("/api/v1/ui/scans/%d", sc.ID)

	w := serveUI(t, s, operatorReq(t, http.MethodGet, base+"/report", nil))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != uiScanJSONType ||
		w.Header().Get("Content-Length") != fmt.Sprint(len(sc.Report)) || w.Body.String() != sc.Report {
		t.Errorf("report: %d %v %q", w.Code, w.Header(), w.Body.String())
	}
	w = serveUI(t, s, operatorReq(t, http.MethodGet, base+"/prompt", nil))
	if w.Body.String() != "the prompt" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("prompt: %q %v", w.Body.String(), w.Header())
	}
	w = serveUI(t, s, operatorReq(t, http.MethodGet, base+"/refusal-audit", nil))
	if w.Body.String() != "not json" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("non-JSON refusal audit: %q %v", w.Body.String(), w.Header())
	}

	s.DB.Model(&sc).Update("prompt", "")
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, base+"/prompt", nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/scans/999/report", nil)), http.StatusNotFound, uiCodeNotFound)
}

// A report past uiLargeReportBytes is exportable without being parsed; a
// small JSON object of empty values is not.
func TestUIScanDetailExportability(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "export")
	large := seedUIScan(t, s.DB, repo, db.ScanDone, "packages")
	s.DB.Model(&large).Update("report", `{"packages":"`+strings.Repeat("x", uiLargeReportBytes)+`"}`)
	empty := seedUIScan(t, s.DB, repo, db.ScanDone, "packages")
	s.DB.Model(&empty).Update("report", `{"packages":[],"notes":""}`)

	for id, want := range map[uint]bool{large.ID: true, empty.ID: false} {
		got := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, fmt.Sprintf("/api/v1/ui/scans/%d", id), nil)), http.StatusOK)
		if got["can_export_report"] != want {
			t.Errorf("scan %d can_export_report = %v, want %v", id, got["can_export_report"], want)
		}
		if _, ok := got["exports"].(map[string]any)["report_md"]; ok != want {
			t.Errorf("scan %d report_md present = %v", id, ok)
		}
	}
}
