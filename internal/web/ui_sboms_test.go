package web

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/sbom"

	"scrutineer/internal/db"
)

// uiMultipartReq builds an operator multipart POST /api/v1/ui/sboms.
func uiMultipartReq(t *testing.T, field, filename, content string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	_ = mw.Close()
	r := httptest.NewRequest("POST", "/api/v1/ui/sboms", &buf)
	asOperator(r)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

func TestUIInventorySBOMUploadAndList(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.SBOMUpload{Name: "generated", Origin: db.SBOMOriginGenerated})

	got := decodeUIJSON[map[string]any](t, serveUI(t, s, uiMultipartReq(t, "file", "demo.cdx.json", cdxFixture)), http.StatusCreated)
	if got["name"] != "demo" || got["format"] != "cyclonedx" || got["package_count"] != float64(2) ||
		got["import_pending"] != true || got["resolving"] != false || got["filename"] != "demo.cdx.json" {
		t.Fatalf("upload = %v", got)
	}
	var scans int64
	s.DB.Model(&db.Scan{}).Count(&scans)
	if scans != 0 {
		t.Fatalf("upload enqueued %d scans", scans)
	}

	body := requireUIError(t, serveUI(t, s, uiMultipartReq(t, "file", "x.json", `{"hello":"world"}`)),
		http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if body.Fields["file"] == "" {
		t.Errorf("422 fields = %v", body.Fields)
	}
	requireUIError(t, serveUI(t, s, uiMultipartReq(t, "other", "x.json", cdxFixture)), http.StatusBadRequest, uiCodeBadParam)

	serveUI(t, s, uiMultipartReq(t, "file", "second.json", strings.Replace(cdxFixture, `"demo"`, `"zzz"`, 1)))
	list := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/sboms", nil)))
	if list.Total != 2 || list.Items[0]["name"] != "zzz" {
		t.Fatalf("list (uploads only, newest first) = %+v", list)
	}
	byName := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/sboms?sort=name&page_size=1", nil)))
	if byName.Total != 2 || len(byName.Items) != 1 || byName.Items[0]["name"] != "demo" {
		t.Errorf("sort=name = %+v", byName)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/sboms?page_size=0", nil)), http.StatusBadRequest, uiCodeBadParam)
}

// sbomFixture is a confirmed upload with one linked direct package (to a
// repository carrying an open finding and an advisory), one errored
// transitive package and one still resolving.
func seedSBOMFixture(t *testing.T, s *Server) (db.SBOMUpload, db.Repository, db.Finding) {
	t.Helper()
	repo := seedUIRepo(t, s.DB, "lodash")
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, deepDiveSkillName)
	f := seedUIFinding(t, s.DB, sc, "proto pollution", db.FindingNew)
	seedUIFinding(t, s.DB, sc, "closed", db.FindingRejected)
	s.DB.Create(&db.Advisory{RepositoryID: repo.ID, UUID: "GHSA-x", Title: "adv", CVSSScore: 5})
	withdrawn := time.Now()
	s.DB.Create(&db.Advisory{RepositoryID: repo.ID, UUID: "GHSA-y", Title: "gone", WithdrawnAt: &withdrawn})
	up := db.SBOMUpload{Name: "app", Origin: db.SBOMOriginUploaded, PackageCount: 3, Packages: []db.SBOMPackage{
		{Name: "lodash", PURL: "pkg:npm/lodash@4", Scope: sbom.ScopeDirect, SourceRepositoryID: &repo.ID, License: "MIT"},
		{Name: "ghost", PURL: "pkg:npm/ghost@1", Scope: sbom.ScopeTransitive, ResolveError: "no repository_url for purl"},
		{Name: "pending", PURL: "pkg:npm/pending@1", Scope: sbom.ScopeTransitive},
	}}
	if err := s.DB.Create(&up).Error; err != nil {
		t.Fatal(err)
	}
	return up, repo, f
}

func TestUIInventorySBOMShowAndTabs(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	up, repo, f := seedSBOMFixture(t, s)
	base := fmt.Sprintf("/api/v1/ui/sboms/%d", up.ID)

	type detail struct {
		ID        uint           `json:"id"`
		Resolving bool           `json:"resolving"`
		HasScope  bool           `json:"has_scope"`
		Counts    map[string]int `json:"counts"`
	}
	d := decodeUIJSON[detail](t, serveUI(t, s, operatorReq(t, "GET", base, nil)), http.StatusOK)
	want := map[string]int{"packages": 3, "resolved": 2, "linked": 1, "direct": 1, "transitive": 2, "findings": 1, "advisories": 1}
	for k, v := range want {
		if d.Counts[k] != v {
			t.Errorf("counts[%s] = %d, want %d (all %v)", k, d.Counts[k], v, d.Counts)
		}
	}
	if !d.Resolving || !d.HasScope {
		t.Errorf("resolving=%v has_scope=%v, want both true", d.Resolving, d.HasScope)
	}

	pkgs := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", base+"/packages", nil)))
	if pkgs.Total != 3 {
		t.Fatalf("packages = %+v", pkgs)
	}
	states := []string{}
	for _, p := range pkgs.Items {
		states = append(states, p["resolution"].(map[string]any)["state"].(string))
	}
	if strings.Join(states, ",") != "linked,error,resolving" {
		t.Errorf("states = %v", states)
	}
	linked := pkgs.Items[0]["resolution"].(map[string]any)
	if linked["repository"].(map[string]any)["id"] != float64(repo.ID) || pkgs.Items[0]["license"] != "MIT" {
		t.Errorf("linked row = %v", pkgs.Items[0])
	}
	if pkgs.Items[1]["resolution"].(map[string]any)["error"] != "no repository_url for purl" {
		t.Errorf("error row = %v", pkgs.Items[1])
	}
	direct := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", base+"/packages?scope=direct", nil)))
	if direct.Total != 1 || direct.Items[0]["name"] != "lodash" {
		t.Errorf("scope=direct = %+v", direct)
	}
	q := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", base+"/packages?q=GHO", nil)))
	if q.Total != 1 || q.Items[0]["name"] != "ghost" {
		t.Errorf("q=GHO = %+v", q)
	}

	findings := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", base+"/findings?sort=severity", nil)))
	if findings.Total != 1 || findings.Items[0]["id"] != float64(f.ID) {
		t.Errorf("findings = %+v", findings)
	}
	none := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", base+"/findings?severity=Low", nil)))
	if none.Total != 0 || none.Items == nil {
		t.Errorf("severity=Low = %+v", none)
	}
	transitive := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", base+"/findings?scope=transitive", nil)))
	if transitive.Total != 0 {
		t.Errorf("scope=transitive findings = %+v", transitive)
	}
	advs := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", base+"/advisories", nil)))
	if advs.Total != 1 || advs.Items[0]["title"] != "adv" {
		t.Errorf("advisories (withdrawn hidden) = %+v", advs)
	}

	requireUIError(t, serveUI(t, s, operatorReq(t, "GET", base+"/packages?scope=sideways", nil)), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, "GET", base+"/findings?severity=huge", nil)), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, "GET", base+"/findings?category=Nope", nil)), http.StatusBadRequest, uiCodeBadParam)
	for _, sub := range []string{"", "/packages", "/findings", "/advisories"} {
		requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/sboms/9999"+sub, nil)), http.StatusNotFound, uiCodeNotFound)
	}
}

func TestUIInventorySBOMPendingStates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	up := db.SBOMUpload{Name: "pending", ImportPending: true, PackageCount: 1, Packages: []db.SBOMPackage{{Name: "a", PURL: "pkg:npm/a@1"}}}
	s.DB.Create(&up)
	base := fmt.Sprintf("/api/v1/ui/sboms/%d", up.ID)
	d := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", base, nil)), http.StatusOK)
	if d["import_pending"] != true || d["resolving"] != false || d["has_scope"] != false {
		t.Errorf("pending detail = %v", d)
	}
	pkgs := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", base+"/packages", nil)))
	if pkgs.Items[0]["resolution"].(map[string]any)["state"] != sbomResolutionAwaitingImport {
		t.Errorf("pending package = %v", pkgs.Items[0])
	}
	// Resolving before confirmation is refused, and nothing is created.
	requireUIError(t, serveUI(t, s, operatorReq(t, "POST", base+"/actions/resolve", nil)), http.StatusConflict, uiCodeConflict)
	var repos int64
	s.DB.Model(&db.Repository{}).Count(&repos)
	if repos != 0 {
		t.Errorf("unconfirmed resolve created %d repos", repos)
	}
}

// drainSBOMEvents collects the sbom events already published on c.
func drainSBOMEvents(c *client) []map[string]any {
	var out []map[string]any
	for {
		select {
		case e := <-c.ch:
			if m, ok := e.JSON.(map[string]any); ok && e.Name == uiSBOMEvent {
				out = append(out, m)
			}
		default:
			return out
		}
	}
}

func TestUIInventorySBOMConfirmAndResolve(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	// Stub ecosyste.ms: the direct dependency resolves, the transitive one
	// resolves without triage, the third has no repository.
	s.resolvePURL = func(_ context.Context, purl string) string {
		switch {
		case strings.Contains(purl, "direct"):
			return "https://github.com/acme/direct"
		case strings.Contains(purl, "transitive"):
			return "https://github.com/acme/transitive"
		default:
			return ""
		}
	}
	s.DB.Create(&db.Skill{Name: defaultSkillName, Body: "b", Active: true})
	up := db.SBOMUpload{Name: "pending", Origin: db.SBOMOriginUploaded, ImportPending: true, PackageCount: 3, Packages: []db.SBOMPackage{
		{Name: "direct", PURL: "pkg:npm/direct@1", Scope: sbom.ScopeDirect},
		{Name: "transitive", PURL: "pkg:npm/transitive@1", Scope: sbom.ScopeTransitive},
		{Name: "ghost", PURL: "pkg:npm/ghost@1", Scope: sbom.ScopeTransitive},
	}}
	s.DB.Create(&up)
	base := fmt.Sprintf("/api/v1/ui/sboms/%d", up.ID)
	sub := s.Broker.Subscribe(0, 0, 0, uiSBOMEvent)
	defer s.Broker.Unsubscribe(sub)

	got := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, "POST", base+"/actions/confirm", nil)), http.StatusAccepted)
	if got["importing"] != float64(3) {
		t.Fatalf("confirm = %v", got)
	}
	// The direct dependency got exactly one queued triage scan; the
	// transitive one was linked without a scan.
	var scans []db.Scan
	s.DB.Preload("Repository").Find(&scans)
	if len(scans) != 1 || scans[0].Repository.URL != "https://github.com/acme/direct" ||
		scans[0].SkillName != defaultSkillName || scans[0].Status != db.ScanQueued {
		t.Fatalf("scans after confirm = %+v", scans)
	}
	events := drainSBOMEvents(sub)
	if len(events) != 2 || events[0]["state"] != sbomStateResolving || events[1]["state"] != sbomStateResolved ||
		events[1]["resolved"] != 3 || events[1]["total"] != 3 || events[1]["id"] != up.ID {
		t.Fatalf("sbom events = %v", events)
	}

	// A second confirmation is a conflict and enqueues nothing.
	requireUIError(t, serveUI(t, s, operatorReq(t, "POST", base+"/actions/confirm", nil)), http.StatusConflict, uiCodeConflict)

	// Re-resolve retries only the unlinked package; nothing new is queued.
	s.resolvePURL = func(context.Context, string) string { return "" }
	row := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, "POST", base+"/actions/resolve", nil)), http.StatusAccepted)
	if row["id"] != float64(up.ID) || row["resolving"] != false {
		t.Errorf("resolve = %v", row)
	}
	var count int64
	s.DB.Model(&db.Scan{}).Count(&count)
	if count != 1 {
		t.Errorf("scans after re-resolve = %d, want 1", count)
	}
	if events := drainSBOMEvents(sub); len(events) != 2 || events[1]["state"] != sbomStateResolved {
		t.Errorf("re-resolve events = %v", events)
	}

	requireUIError(t, serveUI(t, s, operatorReq(t, "POST", "/api/v1/ui/sboms/9999/actions/confirm", nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, "POST", "/api/v1/ui/sboms/9999/actions/resolve", nil)), http.StatusNotFound, uiCodeNotFound)
}

func TestUIInventorySBOMResolveErrorEvent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	up := db.SBOMUpload{Name: "x", Packages: []db.SBOMPackage{{Name: "a", PURL: "pkg:npm/a@1"}}}
	s.DB.Create(&up)
	// A run that leaves packages unresolved reports state error.
	s.DB.Model(&db.SBOMUpload{}).Where("id = ?", up.ID).Update("import_pending", false)
	sub := s.Broker.Subscribe(0, 0, 0, uiSBOMEvent)
	defer s.Broker.Unsubscribe(sub)
	s.publishSBOMProgress(up.ID, true)
	if events := drainSBOMEvents(sub); len(events) != 1 || events[0]["state"] != sbomStateError || events[0]["resolved"] != 0 {
		t.Errorf("events = %v", events)
	}
}

func TestUIInventorySBOMDelete(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	up, _, _ := seedSBOMFixture(t, s)
	path := fmt.Sprintf("/api/v1/ui/sboms/%d", up.ID)

	w := serveUI(t, s, operatorReq(t, "DELETE", path, nil))
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("delete = %d %q", w.Code, w.Body.String())
	}
	var ups, pkgs int64
	s.DB.Model(&db.SBOMUpload{}).Count(&ups)
	s.DB.Model(&db.SBOMPackage{}).Count(&pkgs)
	if ups != 0 || pkgs != 0 {
		t.Errorf("after delete uploads=%d packages=%d", ups, pkgs)
	}
	var repos int64
	s.DB.Model(&db.Repository{}).Count(&repos)
	if repos != 1 {
		t.Errorf("resolved repository must survive, repos=%d", repos)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, "DELETE", path, nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, "DELETE", "/api/v1/ui/sboms/x", nil)), http.StatusBadRequest, uiCodeBadParam)
}
