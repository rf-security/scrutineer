package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

const investigateSkillName = "investigate"

const maxInvestigationBytes = 64 << 10

func (s *Server) investigationNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "investigation_new.html", nil)
}

func (s *Server) investigationCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, importMaxBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Could not read report", http.StatusBadRequest)
		return
	}
	data := map[string]any{"URL": r.PostForm.Get("url"), "Ref": r.PostForm.Get("ref"), "Report": r.PostForm.Get("report")}
	fail := func(message string, status int) {
		data["Error"] = message
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		s.render(w, r, "investigation_new.html", data)
	}
	report := r.PostForm.Get("report")
	if strings.TrimSpace(report) == "" || len(report) > maxInvestigationBytes || !utf8.ValidString(report) {
		fail("Enter a report of up to 64 KB of UTF-8 text.", http.StatusUnprocessableEntity)
		return
	}
	input, err := ParseRepoInput(r.PostForm.Get("url"))
	if err != nil {
		fail(err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if ref := strings.TrimSpace(r.PostForm.Get("ref")); ref != "" {
		input.Branch = ref
	}
	if err := worker.ValidateGitRef(input.Branch); err != nil {
		fail(err.Error(), http.StatusUnprocessableEntity)
		return
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", investigateSkillName, true).First(&skill).Error; err != nil {
		fail("The investigate skill is unavailable. Load the bundled skills and try again.", http.StatusServiceUnavailable)
		return
	}
	repo, err := s.ensureImportRepo(input.CloneURL)
	if err != nil {
		fail(err.Error(), http.StatusUnprocessableEntity)
		return
	}
	scanID, err := s.enqueueSkillWith(r.Context(), repo.ID, skill.ID, ScanOpts{
		Ref: input.Branch, SubPath: input.SubPath, ImportPayload: []byte(report),
	})
	if err != nil {
		fail(err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/scans/%d", scanID))
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
