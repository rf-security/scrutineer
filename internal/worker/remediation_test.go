package worker

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"scrutineer/internal/db"
	"scrutineer/internal/testutil"
)

func generatedVariant(name, input, outcome string) reattackVariant {
	return reattackVariant{
		Name:         name,
		Input:        input,
		Origin:       "generated",
		Valid:        true,
		Outcome:      outcome,
		SameBugClass: true,
		SameSink:     true,
		Sink:         "pkg/foo.go:12",
		Evidence:     "public input reached the patched path",
	}
}

func marshalReattackReport(t *testing.T, report reattackReport) string {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func passingReattackReport() reattackReport {
	return reattackReport{
		Outcome: db.ReattackFailedToBypass,
		Variants: []reattackVariant{
			generatedVariant("length edge", "input-1", "blocked"),
			generatedVariant("encoded edge", "input-2", "blocked"),
			generatedVariant("nested edge", "input-3", "blocked"),
		},
		BenignControl: reattackBenignControl{Input: "benign", ReachedSink: true, Evidence: "expected result"},
	}
}

func TestDecodeReattackReport(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*reattackReport)
		wantErr string
	}{
		{name: "failed to bypass"},
		{name: "fewer than three", mutate: func(r *reattackReport) { r.Variants = r.Variants[:2] }, wantErr: "at least 3"},
		{name: "prior bypass does not replace generated variant", mutate: func(r *reattackReport) {
			r.Variants[2].Origin = "prior_bypass"
		}, wantErr: "at least 3"},
		{name: "duplicate input", mutate: func(r *reattackReport) { r.Variants[2].Input = r.Variants[1].Input }, wantErr: "duplicates"},
		{name: "blank input", mutate: func(r *reattackReport) { r.Variants[0].Input = " \t\n " }, wantErr: "must not be blank"},
		{name: "unrelated blocked input", mutate: func(r *reattackReport) { r.Variants[0].SameBugClass = false }, wantErr: "same bug class"},
		{name: "benign control did not reach sink", mutate: func(r *reattackReport) { r.BenignControl.ReachedSink = false }, wantErr: "benign input"},
		{name: "valid bypass", mutate: func(r *reattackReport) {
			r.Outcome = db.ReattackBypassedPatch
			r.Variants[0].Outcome = "bypassed"
			r.Variants[0].FailureClass = "path traversal"
		}, wantErr: ""},
		{name: "inconclusive", mutate: func(r *reattackReport) {
			r.Outcome = db.ReattackInconclusive
			r.Variants = r.Variants[:1]
			r.BenignControl.ReachedSink = false
		}, wantErr: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := passingReattackReport()
			if tc.mutate != nil {
				tc.mutate(&report)
			}
			_, count, _, err := decodeReattackReport(marshalReattackReport(t, report))
			if tc.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
			if err == nil && report.Outcome == db.ReattackFailedToBypass && count != 3 {
				t.Errorf("valid generated variants = %d, want 3", count)
			}
		})
	}
}

func TestDecodeReattackReport_boundsBypassInput(t *testing.T) {
	report := passingReattackReport()
	report.Outcome = db.ReattackBypassedPatch
	report.Variants[0].Outcome = "bypassed"
	report.Variants[0].FailureClass = "path traversal"
	report.Variants[0].Input = "  " + strings.Repeat("é", maxStagedBypassInputBytes) + "  "

	_, _, bypassInput, err := decodeReattackReport(marshalReattackReport(t, report))
	if err != nil {
		t.Fatal(err)
	}
	if len(bypassInput) > maxStagedBypassInputBytes {
		t.Fatalf("bypass input length = %d, want at most %d", len(bypassInput), maxStagedBypassInputBytes)
	}
	if !utf8.ValidString(bypassInput) {
		t.Fatal("bounded bypass input is not valid UTF-8")
	}
	if strings.TrimSpace(bypassInput) != bypassInput {
		t.Fatal("bounded bypass input was not trimmed")
	}
}

func TestParseReattackOutput_recordsImmutableValidation(t *testing.T) {
	w, finding := newPatchOutputFixture(t)
	patchScan := db.Scan{RepositoryID: finding.RepositoryID, Kind: JobSkill, Status: db.ScanDone, FindingID: &finding.ID}
	if err := w.DB.Create(&patchScan).Error; err != nil {
		t.Fatal(err)
	}
	attempt := db.RemediationAttempt{FindingID: finding.ID, PatchScanID: patchScan.ID, Attempt: 1, Patch: "diff", BaseCommit: "abc"}
	if err := w.DB.Create(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: finding.RepositoryID, Kind: JobSkill, Status: db.ScanRunning,
		FindingID: &finding.ID, RemediationAttemptID: &attempt.ID}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	report := marshalReattackReport(t, passingReattackReport())
	if err := w.parseReattackOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	if err := w.parseReattackOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var rows []db.RemediationValidation
	w.DB.Where("remediation_attempt_id = ?", attempt.ID).Find(&rows)
	if len(rows) != 1 || rows[0].ValidVariants != 3 || !rows[0].BenignControlPassed || rows[0].RootCauseStatus != db.ReattackFailedToBypass {
		t.Fatalf("validations = %+v", rows)
	}
	if got := db.RemediationPatchStatus(&rows[0]); got != db.RemediationVerifiedSecure {
		t.Errorf("derived status = %q", got)
	}
}

func TestParseReattackOutput_persistsBoundedBypassInput(t *testing.T) {
	w, finding := newPatchOutputFixture(t)
	patchScan := db.Scan{RepositoryID: finding.RepositoryID, Kind: JobSkill, Status: db.ScanDone, FindingID: &finding.ID}
	if err := w.DB.Create(&patchScan).Error; err != nil {
		t.Fatal(err)
	}
	attempt := db.RemediationAttempt{FindingID: finding.ID, PatchScanID: patchScan.ID, Attempt: 1, Patch: "diff", BaseCommit: "abc"}
	if err := w.DB.Create(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: finding.RepositoryID, Kind: JobSkill, Status: db.ScanRunning,
		FindingID: &finding.ID, RemediationAttemptID: &attempt.ID}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	report := passingReattackReport()
	report.Outcome = db.ReattackBypassedPatch
	report.Variants[0].Outcome = "bypassed"
	report.Variants[0].FailureClass = "path traversal"
	report.Variants[0].Input = "  " + strings.Repeat("x", maxStagedBypassInputBytes+100) + "  "
	if err := w.parseReattackOutput(&scan, marshalReattackReport(t, report), func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var validation db.RemediationValidation
	if err := w.DB.Where("remediation_attempt_id = ?", attempt.ID).First(&validation).Error; err != nil {
		t.Fatal(err)
	}
	if len(validation.BypassInput) != maxStagedBypassInputBytes {
		t.Errorf("persisted bypass input length = %d, want %d", len(validation.BypassInput), maxStagedBypassInputBytes)
	}
	var note db.FindingNote
	if err := w.DB.Where(map[string]any{"finding_id": finding.ID, "by": reattackSkillName}).First(&note).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(note.Body, validation.BypassInput) {
		t.Fatal("finding note does not contain the bounded persisted bypass input")
	}
}

func TestPrepareRemediationWorkspace_appliesPinnedPatchAndStagesContext(t *testing.T) {
	w, finding := newPatchOutputFixture(t)
	patchScan := db.Scan{RepositoryID: finding.RepositoryID, Kind: JobSkill, Status: db.ScanDone, FindingID: &finding.ID}
	if err := w.DB.Create(&patchScan).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: finding.RepositoryID, Kind: JobSkill, Status: db.ScanRunning, FindingID: &finding.ID}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	workRoot := w.scanWorkRoot(&scan)
	_, diff := gateRepo(t, filepath.Join(workRoot, "src"))
	cmd := exec.Command("git", "-C", filepath.Join(workRoot, "src"), "rev-parse", "HEAD")
	cmd.Env = testutil.GitEnv()
	rawHead, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	head := strings.TrimSpace(string(rawHead))
	attempt := db.RemediationAttempt{FindingID: finding.ID, PatchScanID: patchScan.ID, Attempt: 1, Patch: diff, BaseCommit: head}
	if err := w.DB.Create(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	scan.Ref = head
	scan.RemediationAttemptID = &attempt.ID
	if err := w.prepareRemediationWorkspace(workRoot, &scan, &db.Skill{Name: reattackSkillName}); err != nil {
		t.Fatal(err)
	}
	patched, err := os.ReadFile(filepath.Join(workRoot, "src", "pkg", "foo.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(patched), "patched 12") {
		t.Fatalf("pinned patch was not applied:\n%s", patched)
	}
	for _, name := range []string{remediationPatchFile, remediationContextFile, priorBypassesFile} {
		if _, err := os.Stat(filepath.Join(workRoot, name)); err != nil {
			t.Errorf("%s not staged: %v", name, err)
		}
	}
}
