package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/skills"
)

const investigationInput = "Decode may accept an incomplete record. Security impact has not been checked."

func investigationServer(t *testing.T) *Server {
	t.Helper()
	s, done := newTestServer(t)
	t.Cleanup(done)
	parsed, err := skills.ParseFile("../../skills/investigate/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Model != "max" {
		t.Fatalf("investigations must request the strongest model tier, got %q", parsed.Model)
	}
	skill, err := parsed.ToModel("local")
	if err != nil {
		t.Fatal(err)
	}
	skill.Active = true
	if err := s.DB.Create(skill).Error; err != nil {
		t.Fatal(err)
	}
	return s
}

func postInvestigation(s *Server, values url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/investigations", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	asOperator(r)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestInvestigationSubmission(t *testing.T) {
	s := investigationServer(t)
	for _, name := range []string{"triage", "metadata", "revalidate", "security-deep-dive"} {
		s.DB.Create(&db.Skill{Name: name, Active: true, Version: 1})
	}
	for _, ref := range []string{"", "candidate-fix"} {
		response := postInvestigation(s, url.Values{
			"url": {"https://github.com/example/parser/tree/research/wire"},
			"ref": {ref}, "report": {investigationInput},
		})
		if response.Code != http.StatusSeeOther {
			t.Fatalf("submission: %d %s", response.Code, response.Body)
		}
	}
	var scans []db.Scan
	s.DB.Order("id").Find(&scans)
	if len(scans) != 2 {
		t.Fatalf("queued %d scans, want only the two investigations", len(scans))
	}
	for i, scan := range scans {
		if scan.SkillName != investigateSkillName || scan.Status != db.ScanQueued || scan.FindingID != nil || string(scan.ImportPayload) != investigationInput || scan.SubPath != "wire" {
			t.Fatalf("wrong investigation scan: %+v", scan)
		}
		wantRef := []string{"research", "candidate-fix"}[i]
		if scan.Ref != wantRef {
			t.Fatalf("ref = %q, want %q", scan.Ref, wantRef)
		}
	}
	var repoCount, findingCount int64
	s.DB.Model(&db.Repository{}).Count(&repoCount)
	s.DB.Model(&db.Finding{}).Count(&findingCount)
	if repoCount != 1 || findingCount != 0 {
		t.Fatalf("repositories=%d findings=%d", repoCount, findingCount)
	}
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, localReq("POST", fmt.Sprintf("/scans/%d/retry", scans[0].ID)))
	if response.Code != http.StatusSeeOther {
		t.Fatalf("retry: %d %s", response.Code, response.Body)
	}
	var retried db.Scan
	s.DB.Order("id desc").First(&retried)
	if string(retried.ImportPayload) != investigationInput || retried.Ref != scans[0].Ref || retried.SubPath != scans[0].SubPath {
		t.Fatalf("retry lost investigation input: %+v", retried)
	}
}

func TestInvestigationRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name, repo, ref, report string
	}{
		{"empty report", "https://github.com/example/parser", "", " \n"},
		{"large report", "https://github.com/example/parser", "", strings.Repeat("x", maxInvestigationBytes+1)},
		{"invalid text", "https://github.com/example/parser", "", string([]byte{0xff})},
		{"invalid repository", "https://", "", investigationInput},
		{"invalid ref", "https://github.com/example/parser", "--help", investigationInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := investigationServer(t)
			response := postInvestigation(s, url.Values{"url": {tc.repo}, "ref": {tc.ref}, "report": {tc.report}})
			if response.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status=%d body=%s", response.Code, response.Body)
			}
			var count int64
			s.DB.Model(&db.Scan{}).Count(&count)
			if count != 0 {
				t.Fatal("invalid input queued work")
			}
			s.DB.Model(&db.Repository{}).Count(&count)
			if count != 0 {
				t.Fatal("invalid input created a repository")
			}
		})
	}
}

func TestInvestigationRequiresOperatorAndActiveSkill(t *testing.T) {
	s := investigationServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/investigations", nil)
	r.Host = testHost
	s.Handler().ServeHTTP(w, r)
	if w.Code < 300 {
		t.Fatalf("unauthenticated submission: %d", w.Code)
	}
	s.DB.Model(&db.Skill{}).Where("name = ?", investigateSkillName).Update("active", false)
	w = postInvestigation(s, url.Values{"url": {"https://github.com/example/parser"}, "report": {investigationInput}})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("inactive skill: %d %s", w.Code, w.Body)
	}
}

func TestInvestigationResultAndFindingsVisible(t *testing.T) {
	s := investigationServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/investigations/new"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `action="/investigations"`) {
		t.Fatalf("form: %d %s", w.Code, w.Body)
	}
	postInvestigation(s, url.Values{"url": {"https://github.com/example/parser"}, "report": {investigationInput + " <script>alert(1)</script>"}})
	var scan db.Scan
	s.DB.First(&scan)
	scan.Status = db.ScanDone
	scan.Report = `{"notes":"Checked the parser through its public API.","assessments":[{"claim":"Incomplete record","outcome":"inconclusive","evidence":"Parsing reproduced; consumer impact remains unestablished."}],"findings":[]}`
	s.DB.Save(&scan)
	for _, suffix := range []string{"", "/report.md"} {
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/scans/%d%s", scan.ID, suffix)))
		for _, want := range []string{"inconclusive", "consumer impact remains unestablished"} {
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) {
				t.Fatalf("result %s missing %q: %d %s", suffix, want, w.Code, w.Body)
			}
		}
		if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
			t.Fatal("submitted text rendered as executable HTML")
		}
	}
	finding := db.Finding{RepositoryID: scan.RepositoryID, ScanID: scan.ID, Title: "Confirmed consumer impact", Status: db.FindingNew, Severity: "Low"}
	s.DB.Create(&finding)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings"))
	if !strings.Contains(w.Body.String(), finding.Title) {
		t.Fatal("investigation finding missing from default findings list")
	}
}
