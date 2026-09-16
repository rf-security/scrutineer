package db

import "testing"

func TestLatestRemediationValidation_prefersBypassEvidence(t *testing.T) {
	gdb := newTestDB(t)
	finding := seedFinding(t, gdb)
	attempt := RemediationAttempt{
		FindingID:   finding.ID,
		PatchScanID: finding.ScanID,
		Attempt:     1,
		Patch:       "diff",
		BaseCommit:  "abc",
	}
	if err := gdb.Create(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	rows := []RemediationValidation{
		{FindingID: finding.ID, RemediationAttemptID: attempt.ID, ScanID: finding.ScanID + 1,
			RootCauseStatus: ReattackBypassedPatch, BypassInput: "bypass", Report: "{}"},
		{FindingID: finding.ID, RemediationAttemptID: attempt.ID, ScanID: finding.ScanID + 2,
			RootCauseStatus: ReattackFailedToBypass, ValidVariants: 3, BenignControlPassed: true, Report: "{}"},
	}
	if err := gdb.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}

	got, err := LatestRemediationValidation(gdb, attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != rows[0].ID {
		t.Fatalf("validation = %+v, want bypass validation %d", got, rows[0].ID)
	}
	if status := RemediationPatchStatus(got); status != ReattackBypassedPatch {
		t.Errorf("status = %q, want %q", status, ReattackBypassedPatch)
	}
}
