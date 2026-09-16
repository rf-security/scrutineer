package web

import (
	"sync"
	"testing"

	"scrutineer/internal/db"
)

// TestAutoEnqueueRevalidate_carriesParentProfile locks #548: the auto-enqueued
// revalidate scan inherits the parent scan's resolved runner profile so it
// skips DetectProfile and runs on the same image the finding came from.
func TestAutoEnqueueRevalidate_carriesParentProfile(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	revalidate := db.Skill{Name: "revalidate", OutputFile: "report.json", OutputKind: "revalidate", Version: 1, Active: true}
	s.DB.Create(&revalidate)
	// Parent scan already has its auto-detected profile persisted
	// (skill.go writes res.Profile back before OnFindingCreated fires).
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillName: "security-deep-dive", Profile: "ruby-ext"}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "t", Severity: "High"}
	s.DB.Create(&f)

	s.autoEnqueueRevalidate(&scan, &f)

	var derived db.Scan
	if err := s.DB.Where("finding_id = ? AND skill_id = ?", f.ID, revalidate.ID).First(&derived).Error; err != nil {
		t.Fatalf("derived revalidate scan not enqueued: %v", err)
	}
	if derived.Profile != "ruby-ext" {
		t.Errorf("derived Profile = %q, want %q (carried from parent)", derived.Profile, "ruby-ext")
	}
}

// TestAutoChainVerify_carriesRevalidateProfile locks #548: the auto-chained
// verify scan inherits the revalidate scan's resolved profile so it reproduces
// on the same image (an ASan crash needs the ruby-ext interpreter, not a
// re-detected guess) and skips a redundant DetectProfile container spawn.
func TestAutoChainVerify_carriesRevalidateProfile(t *testing.T) {
	s, done, verify, newFinding := chainTestSetup(t)
	defer done()
	f := newFinding("High")
	// The revalidate scan whose verdict is being applied; its own profile was
	// resolved (auto-detected or itself carried from the deep-dive parent) and
	// persisted before OnRevalidateVerdict fires.
	parent := db.Scan{RepositoryID: f.RepositoryID, Status: db.ScanDone, SkillName: "revalidate", Profile: "ruby-ext"}
	s.DB.Create(&parent)

	s.autoChainVerifyAfterRevalidate(&parent, f, "true_positive", "High")

	var derived db.Scan
	if err := s.DB.Where("finding_id = ? AND skill_id = ?", f.ID, verify.ID).First(&derived).Error; err != nil {
		t.Fatalf("derived verify scan not enqueued: %v", err)
	}
	if derived.Profile != "ruby-ext" {
		t.Errorf("derived Profile = %q, want %q (carried from revalidate)", derived.Profile, "ruby-ext")
	}
}

// TestAutoChainVerify_nilScanDetectsFresh locks the nil-safe read: a nil scan
// (never happens in production but the callback is a public seam) still chains
// verify with an empty profile — detect fresh — rather than panicking.
func TestAutoChainVerify_nilScanDetectsFresh(t *testing.T) {
	s, done, verify, newFinding := chainTestSetup(t)
	defer done()
	f := newFinding("High")

	s.autoChainVerifyAfterRevalidate(nil, f, "true_positive", "High")

	var derived db.Scan
	if err := s.DB.Where("finding_id = ? AND skill_id = ?", f.ID, verify.ID).First(&derived).Error; err != nil {
		t.Fatalf("derived verify scan not enqueued: %v", err)
	}
	if derived.Profile != "" {
		t.Errorf("derived Profile = %q, want empty (detect fresh)", derived.Profile)
	}
}

func TestAutoChainRevalidate_truePositiveAlwaysQueuesCritic(t *testing.T) {
	s, done, verify, newFinding := chainTestSetup(t)
	defer done()
	critic := db.Skill{Name: criticSkillName, OutputFile: "report.json", OutputKind: "critic", Version: 1, Active: true}
	s.DB.Create(&critic)
	f := newFinding("Medium")
	parent := db.Scan{RepositoryID: f.RepositoryID, Status: db.ScanDone, SkillName: revalidateSkillName, Profile: "go"}
	s.DB.Create(&parent)

	s.autoChainVerifyAfterRevalidate(&parent, f, "true_positive", "Medium")

	var criticScan db.Scan
	if err := s.DB.Where("finding_id = ? AND skill_id = ?", f.ID, critic.ID).First(&criticScan).Error; err != nil {
		t.Fatalf("critic scan not enqueued: %v", err)
	}
	if criticScan.Profile != "go" {
		t.Errorf("critic profile = %q, want inherited go profile", criticScan.Profile)
	}
	var verifyCount int64
	s.DB.Model(&db.Scan{}).Where("finding_id = ? AND skill_id = ?", f.ID, verify.ID).Count(&verifyCount)
	if verifyCount != 0 {
		t.Fatalf("Medium finding queued %d verify scans, want 0", verifyCount)
	}
}

func TestAutoChainRevalidate_nonTruePositiveQueuesNeitherAssessment(t *testing.T) {
	s, done, verify, newFinding := chainTestSetup(t)
	defer done()
	critic := db.Skill{Name: criticSkillName, OutputFile: "report.json", OutputKind: "critic", Version: 1, Active: true}
	s.DB.Create(&critic)
	f := newFinding("High")

	s.autoChainVerifyAfterRevalidate(nil, f, "uncertain", "High")

	var count int64
	s.DB.Model(&db.Scan{}).Where("finding_id = ? AND skill_id IN ?", f.ID, []uint{critic.ID, verify.ID}).Count(&count)
	if count != 0 {
		t.Fatalf("non-true-positive queued %d downstream scans, want 0", count)
	}
}

func TestAutoChainVerify_doesNotDoubleQueueConcurrently(t *testing.T) {
	s, done, verify, newFinding := chainTestSetup(t)
	defer done()
	f := newFinding("High")

	const callers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s.autoChainVerifyAfterRevalidate(nil, f, "true_positive", "High")
		}()
	}
	close(start)
	wg.Wait()

	var queued int64
	s.DB.Model(&db.Scan{}).
		Where("finding_id = ? AND skill_id = ? AND status = ?", f.ID, verify.ID, db.ScanQueued).
		Count(&queued)
	if queued != 1 {
		t.Fatalf("queued verify scans = %d, want 1", queued)
	}
}

func TestAutoEnqueueRevalidate_doesNotDoubleQueueConcurrently(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	revalidate := db.Skill{Name: "revalidate", OutputFile: "report.json", OutputKind: "revalidate", Version: 1, Active: true}
	s.DB.Create(&revalidate)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "t", Severity: "High"}
	s.DB.Create(&f)

	const callers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s.autoEnqueueRevalidate(&scan, &f)
		}()
	}
	close(start)
	wg.Wait()

	var queued int64
	s.DB.Model(&db.Scan{}).
		Where("finding_id = ? AND skill_id = ? AND status = ?", f.ID, revalidate.ID, db.ScanQueued).
		Count(&queued)
	if queued != 1 {
		t.Fatalf("queued revalidate scans = %d, want 1", queued)
	}
}
