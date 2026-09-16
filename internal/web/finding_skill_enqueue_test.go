package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"scrutineer/internal/db"
)

func TestFindingSkillConcurrentEnqueue(t *testing.T) {
	for _, name := range []string{verifySkillName, criticSkillName, discloseSkillName, reattackSkillName} {
		t.Run(name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			f, attempt := seedFindingSkillEnqueue(t, s, name)
			const callers = 8
			start := make(chan struct{})
			responses := make(chan *httptest.ResponseRecorder, callers)
			handler := s.Handler()
			for range callers {
				go func() {
					<-start
					r := localReq(http.MethodPost, fmt.Sprintf("/findings/%d/%s", f.ID, name))
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, r)
					responses <- w
				}()
			}
			close(start)
			var location string
			for range callers {
				w := <-responses
				if w.Code != http.StatusSeeOther {
					t.Errorf("enqueue: %d %s", w.Code, w.Body)
				}
				if location != "" && w.Header().Get("Location") != location {
					t.Errorf("redirect = %q, want existing scan %q", w.Header().Get("Location"), location)
				}
				location = w.Header().Get("Location")
			}
			assertQueuedJobCount(t, s, 1)
			var scans []db.Scan
			if err := s.DB.Where("finding_id = ? AND skill_name = ? AND status = ?", f.ID, name, db.ScanQueued).Find(&scans).Error; err != nil {
				t.Fatal(err)
			}
			if len(scans) != 1 {
				t.Fatalf("queued scans = %d, want 1", len(scans))
			}
			if location != fmt.Sprintf("/scans/%d", scans[0].ID) {
				t.Errorf("redirect = %q, want queued scan %d", location, scans[0].ID)
			}
			if name == reattackSkillName && (scans[0].RemediationAttemptID == nil || *scans[0].RemediationAttemptID != attempt.ID) {
				t.Fatal("re-attack did not preserve the selected remediation attempt")
			}
		})
	}
}

func seedFindingSkillEnqueue(t *testing.T, s *Server, name string) (db.Finding, db.RemediationAttempt) {
	t.Helper()
	f := seedVerificationFeedback(t, s)
	if name != verifySkillName {
		skill := db.Skill{Name: name, Active: true, Source: "ui", Body: name, OutputKind: "freeform", OutputFile: "report.json"}
		if err := s.DB.Create(&skill).Error; err != nil {
			t.Fatal(err)
		}
	}
	var attempt db.RemediationAttempt
	if name == reattackSkillName {
		patch := db.Scan{RepositoryID: f.RepositoryID, Kind: "skill", Status: db.ScanDone, SkillName: patchSkillName, FindingID: &f.ID}
		if err := s.DB.Create(&patch).Error; err != nil {
			t.Fatal(err)
		}
		attempt = db.RemediationAttempt{FindingID: f.ID, PatchScanID: patch.ID, Attempt: 1, Patch: "diff", BaseCommit: "deadbeef"}
		if err := s.DB.Create(&attempt).Error; err != nil {
			t.Fatal(err)
		}
	}
	return f, attempt
}
