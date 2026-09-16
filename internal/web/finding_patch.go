package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

var errNoRemediationAttempt = errors.New("no gated patch is available to re-attack")

// patchReport is the subset of the patch skill's report.json shape the UI
// needs. Mirrors skills/patch/schema.json.
type patchReport struct {
	Patch        string   `json:"patch"`
	Rationale    string   `json:"rationale"`
	FilesChanged []string `json:"files_changed"`
	BaseCommit   string   `json:"base_commit"`
	TestsAdded   bool     `json:"tests_added"`
	Notes        string   `json:"notes"`
	Error        string   `json:"error"`
}

func (s *Server) findingSkillScanOpts(findingID uint, skillName, model string) (ScanOpts, error) {
	opts := ScanOpts{Model: model}
	if skillName != reattackSkillName {
		return opts, nil
	}
	attempt, err := db.LatestRemediationAttempt(s.DB, findingID)
	if err != nil {
		return ScanOpts{}, fmt.Errorf("load remediation attempt: %w", err)
	}
	if attempt == nil {
		return ScanOpts{}, errNoRemediationAttempt
	}
	if strings.TrimSpace(attempt.BaseCommit) == "" {
		return ScanOpts{}, errors.New("gated patch has no base commit and cannot be re-attacked reproducibly")
	}
	opts.RemediationAttemptID = new(attempt.ID)
	opts.Ref = attempt.BaseCommit
	return opts, nil
}

func externalReportingSkill(skillName string) bool {
	return skillName == discloseSkillName || skillName == reportUpstreamSkillName || skillName == publicIssueSkillName
}

func (s *Server) ensureFindingReportable(findingID uint, skillName string) error {
	if !externalReportingSkill(skillName) {
		return nil
	}
	var f db.Finding
	if err := s.DB.Select("id", "production_viability").First(&f, findingID).Error; err != nil {
		return fmt.Errorf("load finding viability: %w", err)
	}
	if db.FindingDisclosureBlocked(f) {
		return db.ErrFindingNonViable
	}
	return nil
}

// latestPatchScan returns the most recent done patch-skill scan for a finding
// along with its parsed report. Returns (nil, nil, nil) when no patch scan
// has completed for this finding — the UI uses that to hide the section.
func (s *Server) latestPatchScan(findingID uint) (*db.Scan, *patchReport, error) {
	attempt, err := db.LatestRemediationAttempt(s.DB, findingID)
	if err != nil {
		return nil, nil, fmt.Errorf("load remediation attempt: %w", err)
	}
	var scan db.Scan
	if attempt != nil {
		err = s.DB.Where("id = ? AND finding_id = ? AND kind = ? AND skill_name = ? AND status = ?",
			attempt.PatchScanID, findingID, worker.JobSkill, patchSkillName, db.ScanDone).First(&scan).Error
	} else {
		// Preserve pre-remediation-history findings after migration. They remain
		// downloadable but must get a fresh gated patch before re-attack.
		err = s.DB.Where("finding_id = ? AND kind = ? AND skill_name = ? AND status = ?",
			findingID, worker.JobSkill, patchSkillName, db.ScanDone).
			Order("finished_at desc").First(&scan).Error
	}
	if err != nil {
		return nil, nil, nil
	}
	if scan.Report == "" {
		return &scan, nil, nil
	}
	var rep patchReport
	if err := json.Unmarshal([]byte(scan.Report), &rep); err != nil {
		return &scan, nil, fmt.Errorf("parse patch report: %w", err)
	}
	return &scan, &rep, nil
}

// findingPatchDownload serves the newest immutable gated remediation attempt.
// The Finding.SuggestedFix projection is deliberately not the source of truth.
func (s *Server) findingPatchDownload(w http.ResponseWriter, r *http.Request) {
	f, ok := loadByID[db.Finding](s, w, r)
	if !ok {
		return
	}
	attempt, err := db.LatestRemediationAttempt(s.DB, f.ID)
	if err != nil {
		http.Error(w, "load gated patch", http.StatusInternalServerError)
		return
	}
	patch := f.SuggestedFix
	if attempt != nil {
		patch = attempt.Patch
	}
	if strings.TrimSpace(patch) == "" {
		http.Error(w, "no gated patch stored for this finding", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/x-diff; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="finding-%d.patch"`, f.ID))
	_, _ = w.Write([]byte(patch))
}
