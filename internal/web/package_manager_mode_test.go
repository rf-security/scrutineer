package web

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/skills"
	"scrutineer/internal/worker"
)

func TestPackageManagerModeEnqueueAndStage(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := skills.LoadDirectory(s.DB, log, "../../skills", skills.SourceBundled); err != nil {
		t.Fatal(err)
	}
	repo, parent := seedRunningScan(t, s)
	if err := s.DB.Model(&parent).Update("skill_name", "triage").Error; err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"audit-package-manager", "threat-model"} {
		w := runSkillAPIJSON(t, s, repo, parent, name, `{"ref":"release","sub_path":"packages/client"}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("enqueue %s: %d: %s", name, w.Code, w.Body)
		}
		var skill db.Skill
		if err := s.DB.Where("name = ?", name).First(&skill).Error; err != nil {
			t.Fatal(err)
		}
		var scan db.Scan
		if err := s.DB.Preload("Repository").Where("skill_id = ?", skill.ID).First(&scan).Error; err != nil {
			t.Fatal(err)
		}
		if scan.Status != db.ScanQueued || scan.Ref != "release" || scan.SubPath != "packages/client" {
			t.Fatalf("%s scan: status=%s ref=%s subpath=%s", name, scan.Status, scan.Ref, scan.SubPath)
		}
		work := t.TempDir()
		skillDir := filepath.Join(work, ".claude", "skills", name)
		if err := worker.StageWorkspace(work, skillDir, "http://127.0.0.1/api", "", "", &scan, &skill); err != nil {
			t.Fatal(err)
		}
		if name == "audit-package-manager" {
			assertPackageManagerReferences(t, skillDir)
			if skill.OutputKind != "findings" {
				t.Fatalf("output kind = %q", skill.OutputKind)
			}
			schema, err := os.ReadFile(filepath.Join(work, "schema.json"))
			if err != nil {
				t.Fatal(err)
			}
			report := `{"review_status":"not-applicable","findings":[],"notes":"This application only consumes packages."}`
			if err := worker.ValidateReportSchema(string(schema), report); err != "" {
				t.Fatal(err)
			}
		}
	}

	if err := s.DB.Model(&db.Skill{}).Where("name = ?", "audit-package-manager").Update("active", false).Error; err != nil {
		t.Fatal(err)
	}
	w := runSkillAPIJSON(t, s, repo, parent, "audit-package-manager", `{}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled mode audit: %d: %s", w.Code, w.Body)
	}
}

func assertPackageManagerReferences(t *testing.T, skillDir string) {
	t.Helper()
	for _, name := range []string{"threat-model.md", "weakness-patterns.md", "design-properties.md"} {
		want, err := os.ReadFile(filepath.Join("../../skills/audit-package-manager/references", name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(skillDir, "references", name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("staged %s differs from bundled reference", name)
		}
	}
}

func TestTriageStagesModeRouting(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := skills.LoadDirectory(s.DB, log, "../../skills", skills.SourceBundled); err != nil {
		t.Fatal(err)
	}
	_, parent := seedRunningScan(t, s)
	var triage db.Skill
	if err := s.DB.Where("name = ?", "triage").First(&triage).Error; err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	skillDir := filepath.Join(work, ".claude", "skills", "triage")
	if err := worker.StageWorkspace(work, skillDir, "http://127.0.0.1/api", "", "", &parent, &triage); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../skills/triage/references/modes.md")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(skillDir, "references", "modes.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("staged mode routing differs from bundled reference")
	}
}
