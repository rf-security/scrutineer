package web

import (
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func TestLoadRemediationAttemptViews_prefersBypassEvidence(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	patchScan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone}
	if err := s.DB.Create(&patchScan).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{ScanID: patchScan.ID, RepositoryID: repo.ID, Title: "t", Severity: "Low"}
	if err := s.DB.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	attempt := db.RemediationAttempt{
		FindingID: finding.ID, PatchScanID: patchScan.ID, Attempt: 1, Patch: "diff", BaseCommit: "abc",
	}
	if err := s.DB.Create(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	validations := []db.RemediationValidation{
		{FindingID: finding.ID, RemediationAttemptID: attempt.ID, ScanID: patchScan.ID + 1,
			RootCauseStatus: db.ReattackBypassedPatch, BypassInput: "bypass", Report: "{}"},
		{FindingID: finding.ID, RemediationAttemptID: attempt.ID, ScanID: patchScan.ID + 2,
			RootCauseStatus: db.ReattackFailedToBypass, ValidVariants: 3, BenignControlPassed: true, Report: "{}"},
	}
	if err := s.DB.Create(&validations).Error; err != nil {
		t.Fatal(err)
	}

	views, err := loadRemediationAttemptViews(s.DB, finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("views = %d, want 1", len(views))
	}
	if views[0].Validation == nil || views[0].Validation.ID != validations[0].ID {
		t.Fatalf("validation = %+v, want bypass validation %d", views[0].Validation, validations[0].ID)
	}
	if views[0].Status != db.ReattackBypassedPatch {
		t.Errorf("status = %q, want %q", views[0].Status, db.ReattackBypassedPatch)
	}
}
