package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"scrutineer/internal/db"
)

// Finding detail (#10) and the shared row/detail/workflow projections. The
// helpers here are status-agnostic and reused by the writes in this package
// and by WP-API-2's status/actions handlers:
//
//	s.loadUIFinding(w, r)            -> parse {id}, load with Labels, 404/400 in the UI envelope
//	s.uiFindingRowFor(f)             -> FindingRow for one loaded finding
//	s.loadUIFindingRow(id)           -> FindingRow by id
//	s.uiFindingWorkflow(f, scan)     -> FindingDetail.workflow
//	s.uiFindingDetail(f)             -> full FindingDetail
//	s.writeUIFindingResult(w, r, id, extra) -> slim (row + extra) or, with
//	                                    Prefer: return=representation, the detail; sets ETag

const (
	uiExpectedMatched    = "matched"
	uiExpectedUnexpected = "unexpected"
	uiPreferHeader       = "Prefer"
	uiPreferFull         = "return=representation"
	uiKeyUpdatedAt       = "updated_at"
	uiFindingWhat        = "finding"
)

// applyUIExpectedMatches fills the FindingRow `expected` key for findings on
// repositories that carry expected (benchmark) findings: "matched" when the
// finding matches one, "unexpected" otherwise. Repositories without expected
// rows keep null.
func (s *Server) applyUIExpectedMatches(findings []db.Finding, rows []map[string]any) {
	if len(findings) == 0 {
		return
	}
	repoIDs := make([]uint, 0, len(findings))
	for _, f := range findings {
		repoIDs = append(repoIDs, f.RepositoryID)
	}
	var expected []db.ExpectedFinding
	if err := s.DB.Where("repository_id IN ?", repoIDs).Find(&expected).Error; err != nil || len(expected) == 0 {
		return
	}
	byRepo := map[uint][]db.ExpectedFinding{}
	for _, e := range expected {
		byRepo[e.RepositoryID] = append(byRepo[e.RepositoryID], e)
	}
	for i, f := range findings {
		rowsForRepo := byRepo[f.RepositoryID]
		if len(rowsForRepo) == 0 {
			continue
		}
		rows[i]["expected"] = uiExpectedUnexpected
		if expectedStatusForFindings([]db.Finding{f}, rowsForRepo)[f.ID] {
			rows[i]["expected"] = uiExpectedMatched
		}
	}
}

// loadUIFinding parses {id} and loads the finding with its labels, writing
// the UI error envelope (400/404) when it cannot.
func (s *Server) loadUIFinding(w http.ResponseWriter, r *http.Request) (db.Finding, bool) {
	var f db.Finding
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return f, false
	}
	if err := s.DB.WithContext(r.Context()).Preload("Labels").First(&f, id).Error; err != nil {
		uiDBError(w, err, uiFindingWhat)
		return f, false
	}
	return f, true
}

// uiFindingExists parses {id} and checks the finding exists (sub-resource
// reads that only need the id).
func (s *Server) uiFindingExists(w http.ResponseWriter, r *http.Request) (uint, bool) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return 0, false
	}
	var n int64
	if err := s.DB.Model(&db.Finding{}).Where("id = ?", id).Count(&n).Error; err != nil {
		uiInternal(w, err)
		return 0, false
	}
	if n == 0 {
		uiNotFound(w, uiFindingWhat)
		return 0, false
	}
	return id, true
}

// uiFindingRowFor is the FindingRow of one loaded finding.
func (s *Server) uiFindingRowFor(f db.Finding) map[string]any {
	return s.uiFindingRows([]db.Finding{f})[0]
}

// loadUIFindingRow reloads a finding and returns it with its FindingRow.
func (s *Server) loadUIFindingRow(id uint) (db.Finding, map[string]any, error) {
	var f db.Finding
	if err := s.DB.Preload("Labels").First(&f, id).Error; err != nil {
		return f, nil, err
	}
	return f, s.uiFindingRowFor(f), nil
}

// uiScanRef is an in-flight scan id or nil.
func uiScanRef(sc db.Scan, ok bool) any {
	if !ok {
		return nil
	}
	return sc.ID
}

// uiFindingWorkflow is FindingDetail.workflow (the FindingWorkflow object):
// the in-flight scans and the gating flags the finding page's workflow
// buttons read. scan is the finding's scan when the caller already loaded it
// (zero value otherwise); it is only consulted for the repository id when the
// finding row has none.
func (s *Server) uiFindingWorkflow(f db.Finding, scan db.Scan) map[string]any {
	verify, verifyOK := s.openFindingSkillScan(f.ID, verifySkillName)
	critic, criticOK := s.openFindingSkillScan(f.ID, criticSkillName)
	disclose, discloseOK := s.openFindingSkillScan(f.ID, discloseSkillName)
	var attemptID *uint
	if attempt, err := db.LatestRemediationAttempt(s.DB, f.ID); err == nil && attempt != nil {
		attemptID = &attempt.ID
	}
	reattack, reattackOK := s.openFindingSkillScanForAttempt(f.ID, reattackSkillName, attemptID)
	repoID := f.RepositoryID
	if repoID == 0 {
		repoID = scan.RepositoryID
	}
	if repoID == 0 && scan.ID == 0 {
		var sc db.Scan
		if s.DB.Select("id", "repository_id").First(&sc, f.ScanID).Error == nil {
			repoID = sc.RepositoryID
		}
	}
	hasDependents, err := repoHasDependents(s.DB, repoID)
	if err != nil {
		s.Log.Warn("count dependents", "repo", repoID, "err", err)
	}
	var notes []db.FindingNote
	s.DB.Where("finding_id = ?", f.ID).Order("created_at desc").Find(&notes)
	vinceReady, vinceReason := false, "VINCE API key is not configured"
	if s.VINCE.Enabled() {
		if err := vinceEligibility(f, notes); err != nil {
			vinceReason = err.Error()
		} else {
			vinceReady, vinceReason = true, ""
		}
	}
	var akritesSubmissions int64
	s.DB.Model(&db.DisclosureSubmission{}).
		Where("finding_id = ? AND channel = ?", f.ID, db.DisclosureChannelAkrites).Count(&akritesSubmissions)
	return map[string]any{
		"verify_in_flight":     uiScanRef(verify, verifyOK),
		"critic_in_flight":     uiScanRef(critic, criticOK),
		"disclose_in_flight":   uiScanRef(disclose, discloseOK),
		"reattack_in_flight":   uiScanRef(reattack, reattackOK),
		"has_dependents":       hasDependents,
		"has_disclosure_draft": strings.TrimSpace(f.DisclosureDraft) != "",
		"disclosure_blocked":   db.FindingDisclosureBlocked(f),
		"vince":                map[string]any{"ready": vinceReady, "reason": vinceReason},
		"akrites":              map[string]any{"enabled": s.Akrites.Enabled(), "has_submissions": akritesSubmissions > 0},
	}
}

// uiFindingCounts are the sub-resource counts the detail's section headers show.
func (s *Server) uiFindingCounts(f db.Finding) map[string]int64 {
	count := func(model any, where string, args ...any) int64 {
		var n int64
		s.DB.Model(model).Where(where, args...).Count(&n)
		return n
	}
	var observations int64
	if ids, err := db.ContributionFindingIDs(s.DB, f.ID); err == nil && len(ids) > 0 {
		observations = count(&db.FindingObservation{}, "finding_id IN ?", ids)
	}
	return map[string]int64{
		"notes":          count(&db.FindingNote{}, "finding_id = ?", f.ID),
		"communications": count(&db.FindingCommunication{}, "finding_id = ?", f.ID),
		"references":     count(&db.FindingReference{}, "finding_id = ?", f.ID),
		"history":        count(&db.FindingHistory{}, "finding_id = ?", f.ID),
		"observations":   observations,
		"reviews":        count(&db.FindingReview{}, "finding_id = ?", f.ID),
		"verifications":  count(&db.FindingVerification{}, "finding_id = ?", f.ID),
		"attack_paths":   count(&db.FindingAttackPath{}, "finding_id = ?", f.ID),
		"conversations":  count(&db.Conversation{}, "finding_id = ?", f.ID),
		"exposures":      count(&db.FindingDependent{}, "finding_id = ?", f.ID),
	}
}

// uiExportLink is one download: the existing HTML route plus its filename.
func uiExportLink(path, filename string) map[string]string {
	return map[string]string{uiKeyURL: path, "filename": filename}
}

// uiFindingExports lists the download routes (unchanged HTML routes, which
// already send Content-Disposition) with the filenames they use.
func uiFindingExports(f db.Finding, repo db.Repository) map[string]any {
	base := fmt.Sprintf("/findings/%d", f.ID)
	day := todayStamp()
	return map[string]any{
		"report_md":       uiExportLink(base+"/report.md", findingReportFilename(&repo, &f)),
		"disclosure_md":   uiExportLink(base+"/disclosure.md", findingDisclosureMarkdownFilename(&repo, &f)),
		"disclosure_html": uiExportLink(base+"/disclosure.html", fmt.Sprintf("finding-%d-disclosure.html", f.ID)),
		"csaf_json":       uiExportLink(base+"/csaf.json", fmt.Sprintf("scrutineer-finding-%d-%s.json", f.ID, day)),
		"osv_json":        uiExportLink(base+"/osv.json", fmt.Sprintf("scrutineer-finding-%d-osv-%s.json", f.ID, day)),
		"patch_diff":      uiExportLink(base+"/patch.diff", fmt.Sprintf("finding-%d.patch", f.ID)),
		"bundle_tar_gz":   uiExportLink(base+"/bundle.tar.gz", fmt.Sprintf("scrutineer-finding-%d-disclosure-%s.tar.gz", f.ID, day)),
	}
}

// uiCWEInfo is FindingDetail.cwe_info, or nil for an unknown CWE.
func uiCWEInfo(raw string) any {
	id, c, ok := LookupCWE(raw)
	if !ok {
		return nil
	}
	return map[string]any{"id": id, uiKeyName: c.Name, "description": c.Description, uiKeyURL: cweURL(id)}
}

// cweURL is the MITRE definition page for a canonical CWE-<n> id.
func cweURL(id string) string {
	return "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(id, "CWE-") + ".html"
}

// uiPatchView is FindingDetail.patch: the latest done patch scan's report.
func (s *Server) uiPatchView(findingID uint) any {
	patchScan, rep, err := s.latestPatchScan(findingID)
	if err != nil {
		s.Log.Warn("load patch scan", "finding", findingID, "err", err)
	}
	if patchScan == nil || rep == nil {
		return nil
	}
	return map[string]any{
		uiEventScanIDKey: patchScan.ID, "rationale": rep.Rationale, "files": nonNilStrings(rep.FilesChanged),
		"base_commit": rep.BaseCommit, "includes_test": rep.TestsAdded, "notes": rep.Notes, "error": rep.Error,
	}
}

// uiFindingDetail is the FindingDetail projection: every findingExport
// column, overlaid by the FindingRow keys (so FindingRow is a strict subset),
// plus the scan, CWE, workflow, latest sub-records, counts and exports.
func (s *Server) uiFindingDetail(f db.Finding) map[string]any {
	m := findingExport(f)
	for k, v := range s.uiFindingRowFor(f) {
		m[k] = v
	}
	var scan db.Scan
	s.DB.Omit(uiScanOmit...).First(&scan, f.ScanID)
	var repo db.Repository
	s.DB.First(&repo, f.RepositoryID)
	if scanRow, err := s.loadUIScanRow(f.ScanID); err == nil {
		m["scan"] = scanRow
	} else {
		m["scan"] = nil
	}
	m["cwe_info"] = uiCWEInfo(f.CWE)
	m["workflow"] = s.uiFindingWorkflow(f, scan)
	m["verification"], m["attack_path"], m["remediation"] = nil, nil, nil
	if v, err := db.LatestFindingVerification(s.DB, f.ID); err == nil && v != nil {
		m["verification"] = findingVerificationResponse(v)
	}
	if a, err := db.LatestFindingAttackPath(s.DB, f.ID); err == nil && a != nil {
		m["attack_path"] = findingAttackPathResponse(a)
	}
	if attempt, err := db.LatestRemediationAttempt(s.DB, f.ID); err == nil && attempt != nil {
		validation, _ := db.LatestRemediationValidation(s.DB, attempt.ID)
		m["remediation"] = remediationAttemptResponse(attempt, validation)
	}
	m["patch"] = s.uiPatchView(f.ID)
	m["counts"] = s.uiFindingCounts(f)
	m["exports"] = uiFindingExports(f, repo)
	return m
}

func (s *Server) uiFindingDetailHandler(w http.ResponseWriter, r *http.Request) {
	f, ok := s.loadUIFinding(w, r)
	if !ok {
		return
	}
	setETag(w, f.UpdatedAt)
	writeUIJSON(w, http.StatusOK, s.uiFindingDetail(f))
}

// wantsUIRepresentation reports `Prefer: return=representation`.
func wantsUIRepresentation(r *http.Request) bool {
	for _, v := range r.Header.Values(uiPreferHeader) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), uiPreferFull) {
				return true
			}
		}
	}
	return false
}

// writeUIFindingResult reloads finding id after a write and writes the slim
// response (FindingRow plus extra keys) or, on Prefer: return=representation,
// the FindingDetail; both carry the new ETag. Shared with WP-API-2's
// status/actions handlers.
func (s *Server) writeUIFindingResult(w http.ResponseWriter, r *http.Request, id uint, extra map[string]any) {
	f, row, err := s.loadUIFindingRow(id)
	if err != nil {
		uiDBError(w, err, uiFindingWhat)
		return
	}
	setETag(w, f.UpdatedAt)
	if wantsUIRepresentation(r) {
		detail := s.uiFindingDetail(f)
		for k, v := range extra {
			detail[k] = v
		}
		writeUIJSON(w, http.StatusOK, detail)
		return
	}
	for k, v := range extra {
		row[k] = v
	}
	writeUIJSON(w, http.StatusOK, row)
}

// todayStamp is the UTC YYYYMMDD the download filenames embed.
func todayStamp() string { return time.Now().UTC().Format("20060102") }
