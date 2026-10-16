package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/queue"
	"scrutineer/internal/skills"
)

func TestInvestigationReportOutcomes(t *testing.T) {
	parsed, err := skills.ParseFile("../../skills/investigate/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []string{"disproved", "already_fixed", "not_security", "inconclusive"} {
		report := strings.ReplaceAll(investigationWorkerReport(t, 0), "inconclusive", outcome)
		if detail := ValidateReportSchema(parsed.SchemaJSON, report); detail != "" {
			t.Errorf("%s rejected: %s", outcome, detail)
		}
	}
	for _, report := range []string{
		`{"notes":"No explanation","assessments":[],"findings":[]}`,
		strings.ReplaceAll(investigationWorkerReport(t, 0), "inconclusive", "confirmed"),
		strings.ReplaceAll(investigationWorkerReport(t, 1), "confirmed", "inconclusive"),
		strings.ReplaceAll(investigationWorkerReport(t, 0), "inconclusive", "clean"),
	} {
		if detail := ValidateReportSchema(parsed.SchemaJSON, report); detail == "" {
			t.Errorf("invalid investigation accepted: %s", report)
		}
	}
}

func TestInvestigationWorker(t *testing.T) {
	for _, count := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			gdb := dbtest.Open(t)
			repo := db.Repository{URL: "https://example.com/parser", Name: "parser"}
			gdb.Create(&repo)
			parsed, err := skills.ParseFile("../../skills/investigate/SKILL.md")
			if err != nil {
				t.Fatal(err)
			}
			skill, err := parsed.ToModel("local")
			if err != nil {
				t.Fatal(err)
			}
			gdb.Create(skill)
			prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: investigateSkillName, Status: db.ScanDone}
			gdb.Create(&prior)
			previousFinding := db.Finding{RepositoryID: repo.ID, ScanID: prior.ID, Title: "Unrelated prior report", Status: db.FindingNew, MissedCount: 2}
			gdb.Create(&previousFinding)
			input := "The parser may accept truncated records. Check public callers for impact."
			scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID, ImportPayload: []byte(input)}
			gdb.Create(&scan)
			report := investigationWorkerReport(t, count)
			if detail := ValidateSkillReport(skill.Name, skill.SchemaJSON, skill.PoCField, report); detail != "" {
				t.Fatal(detail)
			}
			w := &Worker{
				DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DataDir: t.TempDir(),
				SchemaStrict: true, PrepareRepoSrc: stubPrepareRepoSrc,
				Runner: pocTestRunner{run: func(job SkillJob) SkillResult {
					payload, readErr := os.ReadFile(filepath.Join(job.WorkRoot, "import", "report"))
					if readErr != nil || string(payload) != input {
						t.Fatalf("submitted report missing from workspace: %q %v", payload, readErr)
					}
					return SkillResult{Commit: "abc123", Report: report}
				}},
			}
			body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
			if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
				t.Fatal(err)
			}
			gdb.First(&scan, scan.ID)
			if scan.Status != db.ScanDone || scan.Report != report || scan.FindingsCount != count {
				t.Fatalf("wrong persisted result: status=%s count=%d report=%s", scan.Status, scan.FindingsCount, scan.Report)
			}
			var findings []db.Finding
			gdb.Where("scan_id = ?", scan.ID).Find(&findings)
			if len(findings) != count {
				t.Fatalf("persisted %d findings, want %d", len(findings), count)
			}
			gdb.First(&previousFinding, previousFinding.ID)
			if previousFinding.MissedCount != 2 || previousFinding.Status != db.FindingNew {
				t.Fatalf("unrelated finding modified: %+v", previousFinding)
			}
		})
	}
}

func investigationWorkerReport(t *testing.T, count int) string {
	t.Helper()
	findings := make([]map[string]any, 0, count)
	for i := range count {
		findings = append(findings, map[string]any{
			"id": fmt.Sprintf("F%d", i+1), "title": fmt.Sprintf("Parser boundary %d", i+1),
			"severity": "Low", "confidence": "high", "cwe": "CWE-20", "location": fmt.Sprintf("parser%d.go:1", i+1),
			"reachability": "reachable", "quality_tier": "high", "discovered_via": "source",
			"trace": "Public parser accepts attacker input.", "boundary": "Untrusted records enter the public parser.",
			"validation": "Source tracing establishes consumer impact.", "rating": "Requires a non-default consumer configuration.",
		})
	}
	outcome := "inconclusive"
	if count > 0 {
		outcome = "confirmed"
	}
	report, err := json.Marshal(map[string]any{
		"notes": "Checked the submitted report only.", "findings": findings,
		"assessments": []map[string]string{{"claim": "Malformed records may cross a security boundary", "outcome": outcome, "evidence": "Recorded source trace and remaining consumer assumptions."}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(report)
}
