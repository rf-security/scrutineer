package db

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"gorm.io/gorm"
)

func TestNormaliseLocation(t *testing.T) {
	cases := map[string]string{
		"src/users.rb:42":                 "src/users.rb",
		"src/users.rb:42:7":               "src/users.rb",
		"src/users.rb:12-34":              "src/users.rb",
		"src/users.rb":                    "src/users.rb",
		"./src/users.rb:1":                "src/users.rb",
		"  Src/Users.rb:10  ":             "src/users.rb",
		"C:\\project\\src\\main.go:42":    "c:\\project\\src\\main.go",
		"C:\\project\\src\\main.go:42:7":  "c:\\project\\src\\main.go",
		"C:\\project\\src\\main.go:12-34": "c:\\project\\src\\main.go",
		"C:\\project\\src\\main.go":       "c:\\project\\src\\main.go",
		"":                                "",
	}
	for in, want := range cases {
		if got := normaliseLocation(in); got != want {
			t.Errorf("normaliseLocation(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFingerprintFinding(t *testing.T) {
	base := FingerprintFinding("security-deep-dive", "", "CWE-89", "src/users.rb:42", "SQLi")

	if base != FingerprintFinding("security-deep-dive", "", "CWE-89", "src/users.rb:77", "SQLi rephrased") {
		t.Errorf("line drift / title change must not change fingerprint")
	}
	if FingerprintFinding("security-deep-dive", "", "CWE-89", "src/users.rb:12-34", "SQLi") !=
		FingerprintFinding("security-deep-dive", "", "CWE-89", "src/users.rb:14-36", "SQLi") {
		t.Errorf("range drift must not change fingerprint")
	}
	if base != FingerprintFinding("Security-Deep-Dive", "", "cwe-89", "./SRC/users.rb", "x") {
		t.Errorf("skill/cwe/location case must not change fingerprint")
	}
	if base == FingerprintFinding("security-deep-dive", "", "CWE-89", "src/admin.rb:42", "SQLi") {
		t.Errorf("different file must change fingerprint")
	}
	if base == FingerprintFinding("security-deep-dive", "", "CWE-79", "src/users.rb:42", "SQLi") {
		t.Errorf("different CWE must change fingerprint")
	}
	if base == FingerprintFinding("semgrep", "", "CWE-89", "src/users.rb:42", "SQLi") {
		t.Errorf("different skill must change fingerprint")
	}
	if base == FingerprintFinding("security-deep-dive", "core", "CWE-89", "src/users.rb:42", "SQLi") {
		t.Errorf("different sub-path must change fingerprint")
	}

	// With neither CWE nor location, title is the discriminator.
	a := FingerprintFinding("freeform", "", "", "", "Hardcoded secret")
	b := FingerprintFinding("freeform", "", "", "", "Hardcoded Secret")
	c := FingerprintFinding("freeform", "", "", "", "Weak crypto")
	if a != b {
		t.Errorf("title fallback should be case-insensitive")
	}
	if a == c {
		t.Errorf("different title must change fingerprint when it is the only key")
	}
}

// TestFingerprintCWELessRulesStayDistinct guards the zizmor regression: tools
// that emit findings with a location but no CWE (zizmor, semgrep without a
// CWE mapping) legitimately fire several distinct rules on the same workflow
// file. The rule name (title) must keep them apart, or groupByFingerprint
// collapses them into one row and silently drops the rest.
func TestFingerprintCWELessRulesStayDistinct(t *testing.T) {
	const file = ".github/workflows/foo.yml"

	// Different rules in the same file -> different fingerprints.
	artipacked := FingerprintFinding("zizmor", "", "", file+":18", "artipacked")
	unpinned := FingerprintFinding("zizmor", "", "", file+":18", "unpinned-uses")
	cachePoison := FingerprintFinding("zizmor", "", "", file+":2", "cache-poisoning")
	if artipacked == unpinned || artipacked == cachePoison || unpinned == cachePoison {
		t.Errorf("distinct CWE-less rules in the same file must not collide")
	}

	// Same rule, different lines in the same file -> still one fingerprint
	// (per-rule folding into the locations set is intentional).
	if artipacked != FingerprintFinding("zizmor", "", "", file+":40", "artipacked") {
		t.Errorf("same rule + same file must dedupe regardless of line")
	}

	// Same rule, different file -> different fingerprint.
	if artipacked == FingerprintFinding("zizmor", "", "", ".github/workflows/bar.yml:3", "artipacked") {
		t.Errorf("same rule in a different file must change fingerprint")
	}
}

func TestBackfillFindingFingerprints(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	r := Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&r)
	s := Scan{RepositoryID: r.ID, Kind: "skill", SkillName: "security-deep-dive", Status: ScanDone, Commit: "abc"}
	gdb.Create(&s)
	f := Finding{ScanID: s.ID, RepositoryID: r.ID, Commit: "abc", CWE: "CWE-89", Location: "src/users.rb:42", Title: "SQLi"}
	gdb.Create(&f)

	if err := BackfillFindingFingerprints(gdb); err != nil {
		t.Fatal(err)
	}

	var got Finding
	gdb.First(&got, f.ID)
	want := FingerprintFinding("security-deep-dive", "", "CWE-89", "src/users.rb:42", "SQLi")
	if got.Fingerprint != want {
		t.Errorf("fingerprint = %q, want %q", got.Fingerprint, want)
	}
	if got.LastSeenScanID != s.ID || got.LastSeenCommit != "abc" || got.SeenCount != 1 {
		t.Errorf("last-seen backfill: scan=%d commit=%q seen=%d", got.LastSeenScanID, got.LastSeenCommit, got.SeenCount)
	}

	// Idempotent: a second run does not bump SeenCount.
	if err := BackfillFindingFingerprints(gdb); err != nil {
		t.Fatal(err)
	}
	gdb.First(&got, f.ID)
	if got.SeenCount != 1 {
		t.Errorf("backfill not idempotent: seen=%d", got.SeenCount)
	}
}

func TestBackfillFindingFingerprintsReturnsSelectionError(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.Migrator().DropTable(&Scan{}); err != nil {
		t.Fatal(err)
	}

	err = BackfillFindingFingerprints(gdb)
	if err == nil {
		t.Fatal("expected selection error after dropping scans table")
	}
	if !strings.Contains(err.Error(), "select findings for fingerprint backfill") {
		t.Fatalf("error = %v, want selection context", err)
	}
}

func TestBackfillFindingFingerprintsPreservesCompletedRowsOnUpdateError(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://x/r", Name: "r"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "security-deep-dive", Status: ScanDone, Commit: "abc"}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	findings := []Finding{
		{ScanID: scan.ID, RepositoryID: repo.ID, Commit: "abc", CWE: "CWE-79", Location: "src/a.go:10", Title: "first"},
		{ScanID: scan.ID, RepositoryID: repo.ID, Commit: "abc", CWE: "CWE-89", Location: "src/b.go:20", Title: "second"},
	}
	if err := gdb.Create(&findings).Error; err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("injected fingerprint update failure")
	updates := 0
	const callbackName = "test:fail_second_fingerprint_update"
	if err := gdb.Callback().Update().Before("gorm:update").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Table != "findings" {
			return
		}
		updates++
		if updates == 2 {
			_ = tx.AddError(wantErr)
		}
	}); err != nil {
		t.Fatal(err)
	}

	err = BackfillFindingFingerprints(gdb)
	if removeErr := gdb.Callback().Update().Remove(callbackName); removeErr != nil {
		t.Fatal(removeErr)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want injected update error", err)
	}
	wantContext := fmt.Sprintf("update fingerprint for finding %d", findings[1].ID)
	if !strings.Contains(err.Error(), wantContext) {
		t.Fatalf("error = %v, want context %q", err, wantContext)
	}

	var got []Finding
	if err := gdb.Order("id").Find(&got, []uint{findings[0].ID, findings[1].ID}).Error; err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2", len(got))
	}
	wantFirst := FingerprintFinding(scan.SkillName, findings[0].SubPath, findings[0].CWE, findings[0].Location, findings[0].Title)
	if got[0].Fingerprint != wantFirst || got[0].LastSeenScanID != scan.ID || got[0].LastSeenCommit != scan.Commit || got[0].SeenCount != 1 {
		t.Errorf("first finding was not preserved after second update failed: %+v", got[0])
	}
	if got[1].Fingerprint != "" || got[1].LastSeenScanID != 0 || got[1].LastSeenCommit != "" || got[1].SeenCount != 0 {
		t.Errorf("failed finding was unexpectedly backfilled: %+v", got[1])
	}

	if err := BackfillFindingFingerprints(gdb); err != nil {
		t.Fatalf("retry backfill: %v", err)
	}
	got = nil
	if err := gdb.Order("id").Find(&got, []uint{findings[0].ID, findings[1].ID}).Error; err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("findings after retry = %d, want 2", len(got))
	}
	for _, finding := range got {
		if finding.Fingerprint == "" || finding.LastSeenScanID != scan.ID || finding.LastSeenCommit != scan.Commit || finding.SeenCount != 1 {
			t.Errorf("finding %d not complete after retry: %+v", finding.ID, finding)
		}
	}
}
