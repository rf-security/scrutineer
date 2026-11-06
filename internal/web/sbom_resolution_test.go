package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

type sbomReportRunner struct{}

func (sbomReportRunner) SkillDir(root, name string) string {
	return filepath.Join(root, "skills", name)
}
func (sbomReportRunner) RunSkill(context.Context, worker.SkillJob, func(worker.Event)) (worker.SkillResult, error) {
	return worker.SkillResult{Commit: "abc", Report: `{"schema_version":1,"analyses":{"inventory":{"status":"ok","result":[{"name":"library","ecosystem":"npm","manifest_path":"package.json"}]},"sbom":{"status":"ok","result":{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"library","version":"1.0.0","purl":"pkg:npm/library@1.0.0"}]}}}}`}, nil
}

func TestGeneratedSBOMResolvesAfterQueuedScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.resolveSync = true
	s.resolvePURLs = func(_ context.Context, purls []string) (map[string]string, error) {
		return map[string]string{"pkg:npm/library@1.0.0": "https://github.com/example/library"}, nil
	}
	w := s.Worker
	w.Log, w.DataDir, w.Runner = s.Log, t.TempDir(), sbomReportRunner{}
	w.PrepareRepoSrc = func(_ context.Context, _, _, root string, _ func(worker.Event)) (string, error) {
		return "abc", os.MkdirAll(filepath.Join(root, "src"), 0o755)
	}
	w.Register(s.Queue)
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() { s.Queue.Start(ctx); close(stopped) }()
	defer func() { cancel(); <-stopped }()
	repo := db.Repository{URL: "https://github.com/example/app", Name: "app"}
	skill := db.Skill{Name: "inventory-test", OutputKind: "dependencies", Body: "Inventory dependencies", OutputFile: "report.json", Active: true}
	for _, row := range []any{&repo, &skill, &db.Skill{Name: defaultSkillName, Body: "Triage", Active: true}} {
		if err := s.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	form := url.Values{"skill_id": {fmt.Sprint(skill.ID)}}
	req := localReq("POST", fmt.Sprintf("/repositories/%d/skill-scan", repo.ID))
	req.Body = io.NopCloser(strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("HTTP %d: %s", response.Code, response.Body)
	}
	waitForSBOMLink(t, s)
	var scans int64
	if err := s.DB.Model(&db.Scan{}).Count(&scans).Error; err != nil {
		t.Fatal(err)
	}
	if scans != 1 {
		t.Fatalf("generated snapshot queued extra scans: %d", scans)
	}
}

func waitForSBOMLink(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		var count int64
		if err := s.DB.Model(&db.SBOMPackage{}).Where("source_repository_id IS NOT NULL").Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			return
		}
		select {
		case <-deadline.C:
			var scans []db.Scan
			s.DB.Select("id", "status", "error").Find(&scans)
			t.Fatalf("generated SBOM not linked: %+v", scans)
		case <-tick.C:
		}
	}
}

func TestSBOMBulkFailureCanBeRetried(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.resolveSync = true
	up := db.SBOMUpload{Name: "generated", Origin: db.SBOMOriginGenerated, Packages: []db.SBOMPackage{{Name: "library", PURL: "pkg:npm/library@1.0.0"}}}
	if err := s.DB.Create(&up).Error; err != nil {
		t.Fatal(err)
	}
	s.resolvePURLs = func(context.Context, []string) (map[string]string, error) {
		return nil, errors.New("upstream unavailable")
	}
	resolveSBOMRequest(t, s, up.ID)
	var pkg db.SBOMPackage
	if err := s.DB.Where("sbom_upload_id = ?", up.ID).First(&pkg).Error; err != nil {
		t.Fatal(err)
	}
	if pkg.SourceRepositoryID != nil || !strings.Contains(pkg.ResolveError, "lookup failed") {
		t.Fatalf("failure not preserved: %+v", pkg)
	}
	s.resolvePURLs = func(context.Context, []string) (map[string]string, error) {
		return map[string]string{pkg.PURL: "https://github.com/example/library"}, nil
	}
	resolveSBOMRequest(t, s, up.ID)
	if err := s.DB.First(&pkg, pkg.ID).Error; err != nil {
		t.Fatal(err)
	}
	if pkg.SourceRepositoryID == nil || pkg.ResolveError != "" {
		t.Fatalf("retry did not link package: %+v", pkg)
	}
	s.resolvePURLs = func(context.Context, []string) (map[string]string, error) {
		t.Error("resolved package looked up again")
		return nil, nil
	}
	resolveSBOMRequest(t, s, up.ID)
}

func resolveSBOMRequest(t *testing.T, s *Server, id uint) {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("POST", fmt.Sprintf("/sboms/%d/resolve", id)))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body)
	}
}
