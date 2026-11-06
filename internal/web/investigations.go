package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

const investigateSkillName = "investigate"

const investigationTitle = "Investigate a report"

const maxInvestigationBytes = 64 << 10

func (s *Server) investigationNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "investigation_new.html", map[string]any{pageTitleKey: investigationTitle})
}

func (s *Server) investigationCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, importMaxBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Could not read report", http.StatusBadRequest)
		return
	}
	data := map[string]any{pageTitleKey: investigationTitle, "URL": r.PostForm.Get("url"), "Ref": r.PostForm.Get("ref"), "Report": r.PostForm.Get("report")}
	fail := func(message string, status int) {
		data["Error"] = message
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		s.render(w, r, "investigation_new.html", data)
	}
	scanID, _, status, err := s.startInvestigation(r.Context(), r.PostForm.Get("url"), r.PostForm.Get("ref"), r.PostForm.Get("report"))
	if err != nil {
		fail(err.Error(), status)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/scans/%d", scanID))
}

// errInvestigationReport is the report-size/encoding rejection message.
var errInvestigationReport = errors.New("Enter a report of up to 64 KB of UTF-8 text.") //nolint:staticcheck // shown verbatim in the form

// startInvestigation validates an investigate request, creates or reuses the
// repository and enqueues the investigate skill with the report as its import
// payload. On failure it returns the HTTP status the form (and the JSON
// endpoint) reports: 422 for bad input, 503 when the skill is unavailable.
func (s *Server) startInvestigation(ctx context.Context, rawURL, rawRef, report string) (scanID, repoID uint, status int, err error) {
	if strings.TrimSpace(report) == "" || len(report) > maxInvestigationBytes || !utf8.ValidString(report) {
		return 0, 0, http.StatusUnprocessableEntity, errInvestigationReport
	}
	input, err := ParseRepoInput(rawURL)
	if err != nil {
		return 0, 0, http.StatusUnprocessableEntity, err
	}
	if ref := strings.TrimSpace(rawRef); ref != "" {
		input.Branch = ref
	}
	if err := worker.ValidateGitRef(input.Branch); err != nil {
		return 0, 0, http.StatusUnprocessableEntity, err
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", investigateSkillName, true).First(&skill).Error; err != nil {
		return 0, 0, http.StatusServiceUnavailable, errors.New("The investigate skill is unavailable. Load the bundled skills and try again.") //nolint:staticcheck // shown verbatim in the form
	}
	repo, err := s.ensureImportRepo(input.CloneURL)
	if err != nil {
		return 0, 0, http.StatusUnprocessableEntity, err
	}
	scanID, err = s.enqueueSkillWith(ctx, repo.ID, skill.ID, ScanOpts{
		Ref: input.Branch, SubPath: input.SubPath, ImportPayload: []byte(report),
	})
	if err != nil {
		return 0, repo.ID, http.StatusUnprocessableEntity, err
	}
	return scanID, repo.ID, http.StatusAccepted, nil
}

type investigationReport struct {
	Notes       string                    `json:"notes"`
	Assessments []investigationAssessment `json:"assessments"`
}

type investigationAssessment struct {
	Claim    string `json:"claim"`
	Outcome  string `json:"outcome"`
	Evidence string `json:"evidence"`
}

func scanInvestigationReport(scan db.Scan) *investigationReport {
	if scan.SkillName != investigateSkillName || scan.Report == "" {
		return nil
	}
	var report investigationReport
	if err := json.Unmarshal([]byte(scan.Report), &report); err != nil {
		return nil
	}
	return &report
}
