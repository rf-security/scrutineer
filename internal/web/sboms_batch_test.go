package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

func TestSBOMUploadLargeDocument(t *testing.T) {
	components, content := largeUploadSBOM(t)
	for _, failBatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail_later_batch=%t", failBatch), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			if failBatch {
				failUploadSBOMBatch(t, s.DB)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, multipartReq(t, "/sboms", "file", "large.cdx.json", content))
			if failBatch {
				assertSBOMUploadRollback(t, s.DB, w)
				return
			}
			if w.Code != http.StatusSeeOther {
				t.Fatalf("HTTP %d: %s", w.Code, w.Body)
			}
			assertLargeSBOMUpload(t, s.DB, components)
		})
	}
}

func largeUploadSBOM(t *testing.T) ([]map[string]string, string) {
	t.Helper()
	const componentCount = 4000
	components := make([]map[string]string, componentCount)
	for i := range components {
		components[i] = map[string]string{
			"type": "library", "name": fmt.Sprintf("example-%d", i),
			"version": "1.0.0", "purl": fmt.Sprintf("pkg:npm/example-%d@1.0.0", i),
		}
	}
	content, err := json.Marshal(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components,
	})
	if err != nil {
		t.Fatal(err)
	}
	return components, string(content)
}

func failUploadSBOMBatch(t *testing.T, gdb *gorm.DB) {
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

func assertSBOMUploadRollback(t *testing.T, gdb *gorm.DB, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "SBOM batch write failed") {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body)
	}
	var uploads, packages int64
	if err := gdb.Model(&db.SBOMUpload{}).Count(&uploads).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Model(&db.SBOMPackage{}).Count(&packages).Error; err != nil {
		t.Fatal(err)
	}
	if uploads != 0 || packages != 0 {
		t.Fatalf("partial upload retained: uploads=%d packages=%d", uploads, packages)
	}
}

func assertLargeSBOMUpload(t *testing.T, gdb *gorm.DB, components []map[string]string) {
	t.Helper()
	componentCount := len(components)
	var upload db.SBOMUpload
	if err := gdb.Preload("Packages").First(&upload).Error; err != nil {
		t.Fatal(err)
	}
	if upload.PackageCount != componentCount || len(upload.Packages) != componentCount {
		t.Fatalf("package count=%d rows=%d, want %d", upload.PackageCount, len(upload.Packages), componentCount)
	}
	if !upload.ImportPending {
		t.Fatal("upload resolved before confirmation")
	}
	seen := make(map[string]bool, componentCount)
	for _, pkg := range upload.Packages {
		seen[pkg.PURL] = true
	}
	for _, component := range components {
		if !seen[component["purl"]] {
			t.Fatalf("missing component %s", component["purl"])
		}
	}
}
