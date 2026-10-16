package db

import (
	"path/filepath"
	"testing"
)

func TestOpenAddsSessionCostWithoutChangingExistingScans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scans.db")
	gdb, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.Migrator().DropColumn(&Scan{}, "SessionCostUSD"); err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/legacy-scans"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Exec(`WITH RECURSIVE rows(n) AS (
		SELECT 1 UNION ALL SELECT n + 1 FROM rows WHERE n < 5000
	) INSERT INTO scans (repository_id, kind, status, session_id, cost_usd, input_tokens, report)
	SELECT ?, 'skill', 'failed', 'legacy-session', 0.0110936, 10, '{"summary":"keep"}' FROM rows`, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		upgraded, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var unchanged int64
		if err := upgraded.Model(&Scan{}).Where(
			"session_id = ? AND cost_usd = ? AND session_cost_usd = 0 AND input_tokens = 10 AND report = ?",
			"legacy-session", 0.0110936, `{"summary":"keep"}`,
		).Count(&unchanged).Error; err != nil {
			t.Fatal(err)
		}
		if unchanged != 5000 {
			t.Fatalf("preserved scans = %d, want 5000", unchanged)
		}
		var scan Scan
		if err := upgraded.First(&scan).Error; err != nil {
			t.Fatal(err)
		}
		scan.SessionCostUSD = 0.015707
		if err := upgraded.Save(&scan).Error; err != nil {
			t.Fatal(err)
		}
		var saved Scan
		if err := upgraded.First(&saved, scan.ID).Error; err != nil {
			t.Fatal(err)
		}
		if saved.SessionCostUSD != 0.015707 || saved.CostUSD != 0.0110936 {
			t.Fatalf("upgraded scan cost = %v / %v", saved.CostUSD, saved.SessionCostUSD)
		}
		if err := upgraded.Model(&scan).Update("session_cost_usd", 0).Error; err != nil {
			t.Fatal(err)
		}
		sqlDB, err := upgraded.DB()
		if err != nil {
			t.Fatal(err)
		}
		if err := sqlDB.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
