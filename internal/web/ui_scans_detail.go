package web

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"scrutineer/internal/db"
)

// registerUIScanRoutes registers the scan detail, queue actions, audit and chat routes of the /api/v1/ui surface
// (02-api-plan.md sections 3.4 #57-#62, 3.5 #63-#66, plus #38). Owned by WP-API-4. Every route is documented in
// openapi.yaml between the "# --- ui:scans begin/end ---" markers.
func (s *Server) registerUIScanRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui/scans/{id}", s.uiScanDetail)
	mux.HandleFunc("GET /ui/scans/{id}/log", s.uiScanLog)
	mux.HandleFunc("GET /ui/scans/{id}/prompt", s.uiScanPrompt)
	mux.HandleFunc("GET /ui/scans/{id}/report", s.uiScanReport)
	mux.HandleFunc("GET /ui/scans/{id}/refusal-audit", s.uiScanRefusalAudit)

	mux.HandleFunc("POST /ui/scans/{id}/actions/{action}", s.uiScanAction)
	mux.HandleFunc("POST /ui/scans/actions/pause-queued", s.uiScansPauseQueued)
	mux.HandleFunc("POST /ui/scans/actions/resume-paused", s.uiScansResumePaused)
	mux.HandleFunc("POST /ui/scans/actions/retry-failed", s.uiScansRetryFailed)
	mux.HandleFunc("POST /ui/scans/actions/cancel-all", s.uiScansCancelAll)
	mux.HandleFunc("POST /ui/scans/batch", s.uiScansBatch)

	mux.HandleFunc("GET /ui/audit", s.uiAudit)

	mux.HandleFunc("GET /ui/repositories/{id}/conversations", s.uiRepoConversations)
	mux.HandleFunc("POST /ui/repositories/{id}/conversations", s.uiRepoConversationCreate)
	mux.HandleFunc("GET /ui/conversations/{id}", s.uiConversationDetail)
	mux.HandleFunc("DELETE /ui/conversations/{id}", s.uiConversationDelete)
	mux.HandleFunc("POST /ui/conversations/{id}/messages", s.uiConversationMessage)
}

const (
	uiScanWhat = "scan"

	uiScanStatusHeader = "X-Scan-Status"
	uiLogLengthHeader  = "X-Log-Length"
	uiScanContentType  = "Content-Type"
	uiScanTextPlain    = "text/plain; charset=utf-8"
	uiScanJSONType     = "application/json"
)

// uiScanDetailOmit are the blobs the detail never inlines: the log, prompt,
// report and refusal audit have their own routes. The report and the
// submitted payload are loaded on demand (loadUIScanDetail).
var uiScanDetailOmit = []string{"log", "report", "prompt", "refusal_audit", "import_payload", "api_token", "recipe"}

// uiLargeReportBytes is the report size above which the detail treats a
// report as exportable without parsing it: HasExportableReport only says no
// to an empty report or a JSON object of empty values, and no real report
// that large is either. It keeps the 49 MB outlier's detail from parsing the
// whole blob on every refetch.
const uiLargeReportBytes = 1 << 20

// uiScanDetailRow is the detail's scan row and what was loaded alongside.
type uiScanDetailRow struct {
	scan  db.Scan
	skill *db.Skill
	sizes scanBlobSizes
	// largeReport is set when the report was left unloaded because of its
	// size; it counts as exportable.
	largeReport bool
}

// loadUIScanDetail loads the scan row for the detail without its blobs, plus
// the blobs the detail's derived fields need: the report when the result
// projection reads it (investigation, disclosure, exportability without
// findings) and the submitted payload of an investigate scan.
func (s *Server) loadUIScanDetail(id uint) (uiScanDetailRow, error) {
	var row uiScanDetailRow
	err := s.DB.Omit(uiScanDetailOmit...).Preload("Repository").First(&row.scan, id).Error
	if err != nil {
		return row, err
	}
	row.sizes = loadScanBlobSizes(s.DB, []uint{id})[id]
	row.skill = loadScanReportSkill(s.DB, &row.scan)
	scan := &row.scan
	disclose := isDiscloseScanReport(scan, row.skill)
	needsReport := scan.SkillName == investigateSkillName || scan.SkillName == discloseSkillName ||
		(!disclose && scan.FindingsCount == 0)
	if needsReport && scan.SkillName != investigateSkillName && scan.SkillName != discloseSkillName &&
		row.sizes.ReportBytes > uiLargeReportBytes {
		needsReport, row.largeReport = false, true
	}
	if needsReport {
		scan.Report = s.scanBlob(id, "report")
	}
	if scan.SkillName == investigateSkillName {
		scan.ImportPayload = []byte(s.scanBlob(id, "import_payload"))
	}
	return row, nil
}

// scanBlob plucks one blob column of a scan; "" when absent or NULL.
func (s *Server) scanBlob(id uint, column string) string {
	v, _, _ := s.scanBlobFound(id, column)
	return v
}

// scanBlobFound plucks one blob column; found is false when no scan has id.
func (s *Server) scanBlobFound(id uint, column string) (string, bool, error) {
	var vals []sql.NullString
	if err := s.DB.Model(&db.Scan{}).Where("id = ?", id).Pluck(column, &vals).Error; err != nil {
		return "", false, err
	}
	if len(vals) == 0 {
		return "", false, nil
	}
	return vals[0].String, true, nil
}

// uiScanDetail is GET /api/v1/ui/scans/{id} (02 #57): ScanRow plus the facts,
// notices and Result data of the scan page.
func (s *Server) uiScanDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return
	}
	row, err := s.loadUIScanDetail(id)
	if err != nil {
		uiDBError(w, err, uiScanWhat)
		return
	}
	var findings []db.Finding
	if err := s.DB.Where("scan_id = ?", id).Order("id").Find(&findings).Error; err != nil {
		uiInternal(w, err)
		return
	}
	m := uiScanRow(row.scan, row.sizes)
	s.addUIScanDetail(m, row, s.uiFindingRows(findings))
	setETag(w, row.scan.UpdatedAt)
	writeUIJSON(w, http.StatusOK, m)
}

// addUIScanDetail adds the UIScanDetail keys to a ScanRow projection.
func (s *Server) addUIScanDetail(m map[string]any, row uiScanDetailRow, findings []map[string]any) {
	scan, skill := row.scan, row.skill
	m["effort"] = scan.Effort
	m["ref"] = scan.Ref
	m["sub_path"] = scan.SubPath
	m["scope_mode"] = scan.ScopeMode
	m["profile"] = scan.Profile
	m["egress_policy"] = scan.EgressPolicy
	m["rescan_mode"] = scan.RescanMode
	m["diff_base_commit"] = scan.DiffBaseCommit
	m["verification_feedback"] = scan.VerificationFeedback
	m["skills_repo_sha"] = scan.SkillsRepoSHA
	m["tokens"] = map[string]any{
		"input": scan.InputTokens, "output": scan.OutputTokens,
		"cache_read": scan.CacheReadTokens, "cache_write": scan.CacheWriteTokens,
		"total_input": scan.TotalInputTokens(), "hit_ratio": scan.CacheHitRatio(),
	}
	m["skill"] = uiScanSkill(scan, skill)
	m[uiKeyFindings] = findings
	m["investigation"] = uiScanInvestigation(scan)
	m["submitted_report"] = nil
	if scan.SkillName == investigateSkillName && len(scan.ImportPayload) > 0 {
		m["submitted_report"] = string(scan.ImportPayload)
	}
	m["diff"] = uiScanDiff(parseScanDiffView(scan))
	m["disclosure_review_finding_id"] = nil
	if fid := s.disclosureReviewFindingID(scan); fid != 0 {
		m["disclosure_review_finding_id"] = fid
	}
	canExport := row.largeReport || hasExportableScanReport(s.DB, &scan, skill)
	m["can_export_report"] = canExport
	exports := map[string]any{}
	if canExport {
		exports["report_md"] = map[string]string{
			uiKeyURL:   fmt.Sprintf("/scans/%d/report.md", scan.ID),
			"filename": scanReportFilename(&scan),
		}
	}
	m["exports"] = exports
	m["has_refusal_audit"] = s.scanHasBlob(scan.ID, "refusal_audit")
}

// scanHasBlob reports whether a blob column is non-empty without loading it.
func (s *Server) scanHasBlob(id uint, column string) bool {
	var n int64
	s.DB.Model(&db.Scan{}).Where("id = ? AND "+column+" IS NOT NULL AND "+column+" <> ''", id).Count(&n)
	return n > 0
}

// uiScanSkill is the detail's skill reference, nil for a non-skill scan.
func uiScanSkill(scan db.Scan, skill *db.Skill) any {
	if scan.SkillID == nil {
		return nil
	}
	out := map[string]any{"id": *scan.SkillID, uiKeyName: scan.SkillName, "output_kind": ""}
	if skill != nil {
		out["output_kind"] = skill.OutputKind
	}
	return out
}

// uiScanInvestigation is the investigate skill's notes and assessments.
func uiScanInvestigation(scan db.Scan) any {
	rep := scanInvestigationReport(scan)
	if rep == nil {
		return nil
	}
	assessments := rep.Assessments
	if assessments == nil {
		assessments = []investigationAssessment{}
	}
	return map[string]any{"notes": rep.Notes, "assessments": assessments}
}

// uiScanDiffFile is one changed file of a diff rescan.
type uiScanDiffFile struct {
	Status     string `json:"status"`
	StatusName string `json:"status_name"`
	Path       string `json:"path"`
	Old        string `json:"old"`
	Linkable   bool   `json:"linkable"`
}

// uiScanDiff is ScanDiffView: scanDiffView in snake_case.
func uiScanDiff(v *scanDiffView) any {
	if v == nil {
		return nil
	}
	files := make([]uiScanDiffFile, len(v.Files))
	for i, f := range v.Files {
		files[i] = uiScanDiffFile{Status: f.Status, StatusName: f.StatusName(), Path: f.Path, Old: f.Old, Linkable: f.Linkable()}
	}
	return map[string]any{
		"requested_mode": v.RequestedMode, "actual_mode": v.ActualMode, "fallback_reason": v.FallbackReason,
		"completeness": v.Completeness, "completeness_reason": v.CompletenessReason,
		"changed_files": v.ChangedFiles, "patch_bytes": v.PatchBytes, "files": files,
	}
}

// ---------------------------------------------------------------- log

// uiScanLog is GET /api/v1/ui/scans/{id}/log?offset= (02 #58): the log from a
// byte offset, as plain text. X-Log-Length is the total length the body ends
// at, in the same byte space as scan-log event offsets. While the scan runs
// the body comes from the in-memory mirror (ui_scans_log.go) when it is ahead
// of the stored log, which the worker flushes only every couple of seconds.
func (s *Server) uiScanLog(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return
	}
	offset, err := parseUILogOffset(r)
	if err != nil {
		uiBadParam(w, err.Error())
		return
	}
	var scan db.Scan
	if err := s.DB.Select("id", statusKey, "log").First(&scan, id).Error; err != nil {
		uiDBError(w, err, uiScanWhat)
		return
	}
	log := scan.Log
	if scan.Status == db.ScanRunning {
		if live, ok := s.ui.liveLogs.snapshot(id); ok && len(live) > len(log) {
			log = live
		}
	}
	body := ""
	if offset < int64(len(log)) {
		body = log[offset:]
	}
	w.Header().Set(uiScanStatusHeader, string(scan.Status))
	w.Header().Set(uiLogLengthHeader, strconv.Itoa(len(log)))
	w.Header().Set(uiScanContentType, uiScanTextPlain)
	w.Header().Set(cacheControlHeader, noStore)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// parseUILogOffset reads ?offset= (non-negative bytes, default 0).
func parseUILogOffset(r *http.Request) (int64, error) {
	v := r.URL.Query().Get("offset")
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("offset must be a non-negative integer, got %q", v)
	}
	return n, nil
}

// ---------------------------------------------------------------- blobs

// uiScanPrompt is GET /api/v1/ui/scans/{id}/prompt (02 #59).
func (s *Server) uiScanPrompt(w http.ResponseWriter, r *http.Request) {
	s.writeUIScanBlob(w, r, "prompt", "prompt")
}

// uiScanReport is GET /api/v1/ui/scans/{id}/report (02 #59): the raw
// report.json with Content-Length. A report that is not valid JSON (some
// freeform skills) is served as text/plain rather than mislabelled.
func (s *Server) uiScanReport(w http.ResponseWriter, r *http.Request) {
	s.writeUIScanBlob(w, r, "report", "report")
}

// uiScanRefusalAudit is GET /api/v1/ui/scans/{id}/refusal-audit (02 #59).
func (s *Server) uiScanRefusalAudit(w http.ResponseWriter, r *http.Request) {
	s.writeUIScanBlob(w, r, "refusal_audit", "refusal audit")
}

// writeUIScanBlob writes one blob column: 404 when the scan or the blob is
// missing. Prompts are text; reports and refusal audits are JSON when valid.
func (s *Server) writeUIScanBlob(w http.ResponseWriter, r *http.Request, column, what string) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return
	}
	blob, found, err := s.scanBlobFound(id, column)
	switch {
	case err != nil:
		uiInternal(w, err)
		return
	case !found:
		uiNotFound(w, uiScanWhat)
		return
	case blob == "":
		uiNotFound(w, what)
		return
	}
	ct := uiScanTextPlain
	if column != "prompt" && json.Valid([]byte(blob)) {
		ct = uiScanJSONType
	}
	w.Header().Set(uiScanContentType, ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(blob)))
	w.Header().Set(cacheControlHeader, noStore)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(blob))
}
