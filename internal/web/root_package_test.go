package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestRootPackageLegacyFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedFindings(t, s)
	// Adding the nullable sub_path column left existing root findings as NULL.
	if err := s.DB.Model(&db.Finding{}).Where("title IN ?", []string{"F1", "G1"}).Update("sub_path", nil).Error; err != nil {
		t.Fatal(err)
	}
	root := db.Subproject{RepositoryID: repo.ID, Path: ".", Name: "root-package"}
	sibling := db.Subproject{RepositoryID: repo.ID, Path: "packages/client", Name: "client"}
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SubPath: sibling.Path}
	for _, row := range []any{&root, &sibling, &scan} {
		if err := s.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, SubPath: sibling.Path, Title: "F3", Status: db.FindingNew}
	if err := s.DB.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	export := fmt.Sprintf("/api/v1/repositories/%d/findings", repo.ID)
	for _, tt := range []struct {
		name, path string
		want       []string
	}{
		{"root page", subURL(repo.ID, root.ID, ""), []string{"F1", "F2"}},
		{"root export", export + "?sub_path=.", []string{"F1", "F2"}},
		{"root bundle", export + "?sub_path=.&format=bundle", []string{"F1", "F2"}},
		{"filtered root export", export + "?sub_path=.&severity=High", []string{"F1"}},
		{"sibling page", subURL(repo.ID, sibling.ID, ""), []string{"F3"}},
		{"sibling export", export + "?sub_path=packages/client", []string{"F3"}},
		{"all scopes", export, []string{"F1", "F2", "F3"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, localReq("GET", tt.path))
			if response.Code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", response.Code, response.Body)
			}
			for _, title := range []string{"F1", "F2", "F3", "G1"} {
				if got, want := strings.Contains(response.Body.String(), title), slices.Contains(tt.want, title); got != want {
					t.Errorf("finding %s present=%t, want %t", title, got, want)
				}
			}
		})
	}
}

func TestRootPackageLegacyScanCount(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/root-count", Name: "root-count"}
	other := db.Repository{URL: "https://example.com/other", Name: "other"}
	for _, row := range []*db.Repository{&repo, &other} {
		if err := s.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	root := db.Subproject{RepositoryID: repo.ID, Path: ".", Name: "root-package"}
	sibling := db.Subproject{RepositoryID: repo.ID, Path: "packages/client", Name: "client"}
	for _, row := range []*db.Subproject{&root, &sibling} {
		if err := s.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []map[string]any{
		{"repository_id": repo.ID, "sub_path": nil},
		{"repository_id": repo.ID, "sub_path": nil},
		{"repository_id": repo.ID, "sub_path": ""},
		{"repository_id": repo.ID, "sub_path": sibling.Path},
		{"repository_id": other.ID, "sub_path": nil},
		{"repository_id": other.ID, "sub_path": ""},
	} {
		row["kind"] = "skill"
		row["status"] = db.ScanDone
		if err := s.DB.Model(&db.Scan{}).Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, localReq("GET", fmt.Sprintf("/repositories/%d", repo.ID)))
	if response.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", response.Code, response.Body)
	}
	for _, tt := range []struct {
		project db.Subproject
		count   int
	}{{root, 3}, {sibling, 1}} {
		link := `href="` + subURL(repo.ID, tt.project.ID, "") + `"`
		var row string
		for _, candidate := range strings.Split(response.Body.String(), "</tr>") {
			if strings.Contains(candidate, link) {
				row = candidate
				break
			}
		}
		want := fmt.Sprintf(`<td class="text-right text-sm text-muted-foreground">%d</td>`, tt.count)
		if !strings.Contains(row, want) {
			t.Errorf("project %q: want scan count %d in row %s", tt.project.Path, tt.count, row)
		}
	}
}

func TestRootPackageScanAll(t *testing.T) {
	for _, existing := range []string{"none", "root scan", "root focus"} {
		t.Run(existing, func(t *testing.T) {
			testRootPackageScanAll(t, existing)
		})
	}
}

func testRootPackageScanAll(t *testing.T, existing string) {
	t.Helper()
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/neos-ui", Name: "neos-ui"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: deepDiveSkillName, Body: "audit", OutputKind: "freeform", Active: true, Source: "ui"}
	s.DB.Create(&skill)
	for _, project := range []db.Subproject{
		{RepositoryID: repo.ID, Path: ".", Name: "neos/neos-ui", Kind: "composer-package"},
		{RepositoryID: repo.ID, Path: "packages/utils-redux", Name: "utils-redux", Kind: "npm-package"},
	} {
		if err := s.DB.Create(&project).Error; err != nil {
			t.Fatal(err)
		}
	}
	if existing != "none" {
		scan := db.Scan{RepositoryID: repo.ID, SkillID: &skill.ID, SkillName: skill.Name, Status: db.ScanRunning}
		if existing == "root focus" {
			scan.FocusArea = `{"name":"JS actions","paths":["packages/utils-redux/**"],"surface":"actions"}`
		}
		if err := s.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		request := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/scan-all", repo.ID), nil)
		asOperator(request)
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusSeeOther {
			t.Fatalf("status %d: %s", response.Code, response.Body)
		}
	}
	var scans []db.Scan
	if err := s.DB.Where("repository_id = ? AND status = ?", repo.ID, db.ScanQueued).Order("sub_path").Find(&scans).Error; err != nil {
		t.Fatal(err)
	}
	want := 2
	if existing == "root scan" {
		want = 1
	}
	if len(scans) != want {
		t.Fatalf("queued=%d, want %d: %+v", len(scans), want, scans)
	}
	if want == 2 && (scans[0].SubPath != "" || scans[0].ScanGroup == "" || scans[0].ScanGroup != scans[1].ScanGroup) {
		t.Fatalf("root scope or group: %+v", scans)
	}
	if scans[len(scans)-1].SubPath != "packages/utils-redux" {
		t.Fatalf("workspace missing: %+v", scans)
	}
}

func TestRootPackagePagesAndFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/neos-ui", Name: "neos-ui", DisclosureChannel: "repo@example.com"}
	s.DB.Create(&repo)
	root := db.Subproject{RepositoryID: repo.ID, Path: ".", Name: "neos/neos-ui", Kind: "composer-package", DisclosureChannel: "php@example.com"}
	s.DB.Create(&root)
	skill := db.Skill{Name: deepDiveSkillName, Body: "audit", OutputKind: "freeform", Active: true, Source: "ui"}
	s.DB.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillID: &skill.ID}
	s.DB.Create(&scan)
	for _, finding := range []db.Finding{
		{ScanID: scan.ID, RepositoryID: repo.ID, SubPath: "", FindingID: "PHP1", Title: "PHP root finding", Status: db.FindingNew},
		{ScanID: scan.ID, RepositoryID: repo.ID, SubPath: "packages/utils-redux", FindingID: "JS1", Title: "JS sibling finding", Status: db.FindingNew},
	} {
		if err := s.DB.Create(&finding).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{fmt.Sprintf("/repositories/%d", repo.ID), subURL(repo.ID, root.ID, "")} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", path, nil)
		asOperator(request)
		s.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d", path, response.Code)
		}
		for _, want := range []string{"neos/neos-ui", "composer-package", `name="sub_path" value=""`, ">root</code>"} {
			if !strings.Contains(response.Body.String(), want) {
				t.Errorf("%s missing %q", path, want)
			}
		}
		if path == subURL(repo.ID, root.ID, "") && (!strings.Contains(response.Body.String(), "PHP root finding") || strings.Contains(response.Body.String(), "JS sibling finding")) {
			t.Fatal("root project findings included the wrong scope")
		}
	}
	if got := s.loadRepoSubprojectView(repo.ID).ScanCount[""]; got != 1 {
		t.Fatalf("root scan count=%d, want 1", got)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/repositories/%d/findings?sub_path=.", repo.ID), nil)
	asOperator(request)
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "PHP root finding") || strings.Contains(response.Body.String(), "JS sibling finding") {
		t.Fatalf("root export: HTTP %d %s", response.Code, response.Body)
	}
	if got := db.EffectiveDisclosureChannel(s.DB, repo.ID, ""); got != "php@example.com" {
		t.Fatalf("root disclosure channel=%q", got)
	}
	form := url.Values{"sub_path": {root.ScanSubPath()}}
	request = httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/scan", repo.ID), strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	asOperator(request)
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("root scan: HTTP %d %s", response.Code, response.Body)
	}
	var queued db.Scan
	if err := s.DB.Where("repository_id = ? AND status = ?", repo.ID, db.ScanQueued).First(&queued).Error; err != nil {
		t.Fatal(err)
	}
	if queued.SubPath != "" {
		t.Fatalf("root scan subpath=%q", queued.SubPath)
	}
}
