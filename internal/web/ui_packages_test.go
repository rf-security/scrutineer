package web

import (
	"fmt"
	"net/http"
	"testing"

	"scrutineer/internal/db"
)

func TestUIInventoryPackages(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "hashbrown")
	big := db.Package{RepositoryID: repo.ID, Name: "hashbrown", Ecosystem: "cargo", PURL: "pkg:cargo/hashbrown",
		Downloads: 900, DependentRepos: 5, RegistryURL: "https://crates.io/crates/hashbrown", LatestVersion: "0.15.0",
		RiskFlags: "single_maintainer,stale_release", Metadata: `{"name":"hashbrown","keywords":["hash"]}`}
	small := db.Package{RepositoryID: repo.ID, Name: "ahash", Ecosystem: "cargo", Downloads: 10, Metadata: "not json"}
	other := db.Package{RepositoryID: repo.ID, Name: "left-pad", Ecosystem: "npm", Downloads: 50}
	for _, p := range []*db.Package{&big, &small, &other} {
		if err := s.DB.Create(p).Error; err != nil {
			t.Fatal(err)
		}
	}

	type pkgList struct {
		uiList[map[string]any]
		Ecosystems []string `json:"ecosystems"`
	}
	list := decodeUIJSON[pkgList](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/packages", nil)), http.StatusOK)
	if list.Total != 3 || list.Items[0]["name"] != "ahash" {
		t.Fatalf("list = %+v", list)
	}
	if len(list.Ecosystems) != 2 || list.Ecosystems[0] != "cargo" || list.Ecosystems[1] != "npm" {
		t.Errorf("ecosystems = %v", list.Ecosystems)
	}
	byDownloads := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/packages?sort=downloads&ecosystem=cargo", nil)))
	if byDownloads.Total != 2 {
		t.Fatalf("cargo total = %d", byDownloads.Total)
	}
	row := byDownloads.Items[0]
	if row["name"] != "hashbrown" || row["registry"] != "crates.io" || row["dependents"] != float64(5) {
		t.Errorf("hashbrown row = %v", row)
	}
	if ref, _ := row["repository"].(map[string]any); ref["name"] != "hashbrown" {
		t.Errorf("repository ref = %v", row["repository"])
	}
	if flags, _ := row["risk_flags"].([]any); len(flags) != 2 {
		t.Errorf("risk_flags = %v", row["risk_flags"])
	}
	q := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/packages?q=LEFT", nil)))
	if q.Total != 1 || q.Items[0]["name"] != "left-pad" {
		t.Errorf("q=LEFT = %+v", q)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/packages?page=x", nil)), http.StatusBadRequest, uiCodeBadParam)

	type detail struct {
		Package    map[string]any      `json:"package"`
		Repository map[string]any      `json:"repository"`
		RiskFlags  []map[string]string `json:"risk_flags"`
		Metadata   map[string]any      `json:"metadata"`
	}
	d := decodeUIJSON[detail](t, serveUI(t, s, operatorReq(t, "GET", fmt.Sprintf("/api/v1/ui/packages/%d", big.ID), nil)), http.StatusOK)
	if d.Package["latest_version"] != "0.15.0" || d.Repository["id"] != float64(repo.ID) {
		t.Errorf("detail = %+v", d)
	}
	if len(d.RiskFlags) != 2 || d.RiskFlags[0]["id"] != "single_maintainer" || d.RiskFlags[0]["label"] != "single maintainer" {
		t.Errorf("risk_flags = %v", d.RiskFlags)
	}
	if d.Metadata["name"] != "hashbrown" {
		t.Errorf("metadata = %v", d.Metadata)
	}
	bad := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", fmt.Sprintf("/api/v1/ui/packages/%d", small.ID), nil)), http.StatusOK)
	if bad["metadata"] != nil {
		t.Errorf("invalid metadata should be null, got %v", bad["metadata"])
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/packages/9999", nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/packages/0", nil)), http.StatusBadRequest, uiCodeBadParam)
}
