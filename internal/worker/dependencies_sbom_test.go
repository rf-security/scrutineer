package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

func TestDependenciesScanLargeSBOM(t *testing.T) {
	components, report := largeDependencySBOM(t)
	for _, failBatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail_later_batch=%t", failBatch), func(t *testing.T) {
			w, scan, gdb, repo := newDependencyParser(t)
			oldDep := db.Dependency{RepositoryID: repo.ID, Name: "previous-dependency"}
			if err := gdb.Create(&oldDep).Error; err != nil {
				t.Fatal(err)
			}
			oldSBOM := db.SBOMUpload{
				RepositoryID: &repo.ID, Origin: db.SBOMOriginGenerated, Current: true,
				Name: "previous", PackageCount: 1, Packages: []db.SBOMPackage{{Name: "previous-package"}},
			}
			if err := gdb.Create(&oldSBOM).Error; err != nil {
				t.Fatal(err)
			}
			if failBatch {
				failDependencySBOMBatch(t, gdb)
			}
			runDependencySBOMScan(t, w, scan, report)
			if failBatch {
				assertDependencySBOMRollback(t, gdb, scan, oldDep, oldSBOM)
				return
			}
			assertDependencySBOMSaved(t, gdb, scan, components)
		})
	}
}

func largeDependencySBOM(t *testing.T) ([]map[string]string, string) {
	t.Helper()
	const componentCount = 4000
	components := make([]map[string]string, componentCount)
	for i := range components {
		components[i] = map[string]string{
			"type": "library", "name": fmt.Sprintf("example-%d", i),
			"version": "1.0.0", "purl": fmt.Sprintf("pkg:npm/example-%d@1.0.0", i),
		}
	}
	cdx, err := json.Marshal(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components,
	})
	if err != nil {
		t.Fatal(err)
	}
	report := depEnvelope(`[{"name":"new-dependency","ecosystem":"npm","manifest_path":"package.json"}]`, string(cdx))
	return components, report
}

func failDependencySBOMBatch(t *testing.T, gdb *gorm.DB) {
	t.Helper()
	batches := 0
	if err := gdb.Callback().Create().Before("gorm:create").Register("fail_sbom_batch", func(tx *gorm.DB) {
		if tx.Statement.Table == "sbom_packages" {
			batches++
			if batches == 2 {
				_ = tx.AddError(errors.New("SBOM batch write failed"))
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func runDependencySBOMScan(t *testing.T, w *Worker, scan *db.Scan, report string) {
	t.Helper()
	gdb := w.DB
	skill := db.Skill{
		Name: "dependencies", Description: "Inventory", Body: "Inventory",
		OutputFile: "report.json", OutputKind: "dependencies", Version: 1, Active: true, Source: "ui",
	}
	if err := gdb.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	scan.Kind, scan.Status, scan.SkillID, scan.Model = JobSkill, db.ScanQueued, &skill.ID, "fake"
	if err := gdb.Save(scan).Error; err != nil {
		t.Fatal(err)
	}
	w.Runner = fakeRunner{skillRes: SkillResult{Commit: "abc", Report: report}}
	w.PrepareRepoSrc = stubPrepareRepoSrc
	body, err := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	if err := gdb.First(scan, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
}

func dependencySBOMState(t *testing.T, gdb *gorm.DB, repoID uint) ([]db.Dependency, []db.SBOMUpload) {
	t.Helper()
	var deps []db.Dependency
	if err := gdb.Where("repository_id = ?", repoID).Find(&deps).Error; err != nil {
		t.Fatal(err)
	}
	var snapshots []db.SBOMUpload
	if err := gdb.Where("repository_id = ?", repoID).Order("id").Preload("Packages").Find(&snapshots).Error; err != nil {
		t.Fatal(err)
	}
	return deps, snapshots
}

func assertDependencySBOMRollback(t *testing.T, gdb *gorm.DB, scan *db.Scan, oldDep db.Dependency, oldSBOM db.SBOMUpload) {
	t.Helper()
	deps, snapshots := dependencySBOMState(t, gdb, scan.RepositoryID)
	if scan.Status != db.ScanFailed || !strings.Contains(scan.Error, "SBOM batch write failed") {
		t.Fatalf("status=%s error=%s", scan.Status, scan.Error)
	}
	if len(deps) != 1 || deps[0].ID != oldDep.ID {
		t.Fatalf("previous dependency lost: %+v", deps)
	}
	if len(snapshots) != 1 || snapshots[0].ID != oldSBOM.ID || !snapshots[0].Current || len(snapshots[0].Packages) != 1 {
		t.Fatalf("previous snapshot changed: %d snapshots", len(snapshots))
	}
	var packageCount int64
	if err := gdb.Model(&db.SBOMPackage{}).Count(&packageCount).Error; err != nil {
		t.Fatal(err)
	}
	if packageCount != 1 {
		t.Fatalf("partial package rows retained: %d packages", packageCount)
	}
}

func assertDependencySBOMSaved(t *testing.T, gdb *gorm.DB, scan *db.Scan, components []map[string]string) {
	t.Helper()
	deps, snapshots := dependencySBOMState(t, gdb, scan.RepositoryID)
	componentCount := len(components)
	if scan.Status != db.ScanDone {
		t.Fatalf("status=%s error=%s", scan.Status, scan.Error)
	}
	if len(deps) != 1 || deps[0].Name != "new-dependency" {
		t.Fatalf("inventory not replaced: %+v", deps)
	}
	if len(snapshots) != 2 || snapshots[0].Current || !snapshots[1].Current {
		t.Fatalf("current snapshot not advanced: %d snapshots", len(snapshots))
	}
	latest := snapshots[1]
	if latest.PackageCount != componentCount || len(latest.Packages) != componentCount {
		t.Fatalf("package count=%d rows=%d, want %d", latest.PackageCount, len(latest.Packages), componentCount)
	}
	seen := make(map[string]bool, componentCount)
	for _, pkg := range latest.Packages {
		seen[pkg.PURL] = true
	}
	for _, component := range components {
		if !seen[component["purl"]] {
			t.Fatalf("missing component %s", component["purl"])
		}
	}
}
