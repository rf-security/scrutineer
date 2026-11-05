package web

import (
	"net/http"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// inventoryFixture is a small org graph: owner acme (two repos, one curated
// open finding, one closed, one scanner finding, an advisory, a maintainer)
// and owner zeta (one repo, no findings).
type inventoryFixture struct {
	repoA, repoB, repoZ db.Repository
	open, closed        db.Finding
	advisory            db.Advisory
	maintainer          db.Maintainer
}

func seedInventory(t *testing.T, s *Server) inventoryFixture {
	t.Helper()
	var fx inventoryFixture
	fx.repoA = seedUIRepo(t, s.DB, "alpha")
	fx.repoB = seedUIRepo(t, s.DB, "beta")
	fx.repoZ = db.Repository{URL: "https://github.com/zeta/z", Name: "z", FullName: "zeta/z", Owner: "zeta"}
	if err := s.DB.Create(&fx.repoZ).Error; err != nil {
		t.Fatal(err)
	}
	audit := seedUIScan(t, s.DB, fx.repoA, db.ScanDone, deepDiveSkillName)
	fx.open = seedUIFinding(t, s.DB, audit, "open bug", db.FindingNew)
	fx.closed = seedUIFinding(t, s.DB, audit, "closed bug", db.FindingFixed)
	scanner := seedUIScan(t, s.DB, fx.repoB, db.ScanDone, "zizmor")
	seedUIFinding(t, s.DB, scanner, "lint noise", db.FindingNew)

	fx.advisory = db.Advisory{RepositoryID: fx.repoA.ID, UUID: "GHSA-aaaa-bbbb-cccc", Title: "adv", Severity: "high", CVSSScore: 7.5}
	if err := s.DB.Create(&fx.advisory).Error; err != nil {
		t.Fatal(err)
	}
	fx.maintainer = db.Maintainer{Login: "alice", Name: "Alice", Status: db.MaintainerActive}
	if err := s.DB.Create(&fx.maintainer).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&fx.maintainer).Association("Repositories").Append(&fx.repoA, &fx.repoB); err != nil {
		t.Fatal(err)
	}
	return fx
}

func TestUIInventoryOrgList(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedInventory(t, s)

	list := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs", nil)))
	if list.Total != 2 || len(list.Items) != 2 {
		t.Fatalf("total=%d items=%d, want 2", list.Total, len(list.Items))
	}
	acme := list.Items[0]
	if acme["owner"] != "acme" || acme["repos"] != float64(2) {
		t.Fatalf("first row = %v, want acme with 2 repos (name sort)", acme)
	}
	// Parity: findings_total counts the closed finding; open_findings does not.
	if acme["findings_total"] != float64(2) || acme["open_findings"] != float64(1) {
		t.Errorf("findings_total=%v open_findings=%v, want 2 and 1", acme["findings_total"], acme["open_findings"])
	}
	if acme["last_activity"] == nil {
		t.Error("last_activity missing")
	}

	page := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs?sort=name.desc&page=2&page_size=1", nil)))
	if page.Total != 2 || len(page.Items) != 1 || page.Items[0]["owner"] != "acme" {
		t.Errorf("page 2 desc = %+v, want acme alone", page)
	}
	open := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs?sort=open_findings.asc", nil)))
	if open.Items[0]["owner"] != "zeta" {
		t.Errorf("open_findings asc first = %v, want zeta", open.Items[0]["owner"])
	}
	q := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs?q=ZET", nil)))
	if q.Total != 1 || q.Items[0]["owner"] != "zeta" {
		t.Errorf("q=ZET = %+v", q)
	}
	past := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs?page=9", nil)))
	if past.Total != 2 || len(past.Items) != 0 {
		t.Errorf("past last page = %+v, want empty items", past)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs?page=0", nil)), http.StatusBadRequest, uiCodeBadParam)
}

func TestUIInventoryOrgShow(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedInventory(t, s)

	type orgDetail struct {
		Owner     string         `json:"owner"`
		RepoCount int            `json:"repo_count"`
		Counts    map[string]int `json:"counts"`
		Exports   map[string]struct {
			URL      string `json:"url"`
			Filename string `json:"filename"`
		} `json:"exports"`
	}
	got := decodeUIJSON[orgDetail](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs/acme", nil)), http.StatusOK)
	if got.Owner != "acme" || got.RepoCount != 2 {
		t.Fatalf("detail = %+v", got)
	}
	if got.Counts["findings"] != 1 || got.Counts["advisories"] != 1 || got.Counts["maintainers"] != 1 {
		t.Errorf("counts = %v, want findings 1 advisories 1 maintainers 1", got.Counts)
	}
	if e := got.Exports["summary_md"]; e.URL != "/orgs/acme/summary.md" || !strings.HasPrefix(e.Filename, "scrutineer-acme-summary-") {
		t.Errorf("summary export = %+v", e)
	}
	if e := got.Exports["findings_md"]; e.URL != "/orgs/acme/findings.md" || !strings.HasSuffix(e.Filename, ".md") {
		t.Errorf("findings export = %+v", e)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs/nobody", nil)), http.StatusNotFound, uiCodeNotFound)
}

func TestUIInventoryOrgTabs(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	fx := seedInventory(t, s)
	s.DB.Create(&db.AdvisoryAudit{RepositoryID: fx.repoA.ID, AdvisoryUUID: fx.advisory.UUID, Status: advisoryAuditFixed})

	repos := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs/acme/repositories?page_size=1", nil)))
	if repos.Total != 2 || len(repos.Items) != 1 || repos.Items[0]["name"] != "alpha" {
		t.Fatalf("repositories = %+v", repos)
	}
	if repos.Items[0]["findings_count"] != float64(1) || repos.Items[0]["federation_opted_out"] != false {
		t.Errorf("RepoRow = %v", repos.Items[0])
	}

	findings := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs/acme/findings", nil)))
	if findings.Total != 1 || findings.Items[0]["id"] != float64(fx.open.ID) {
		t.Fatalf("findings = %+v, want only the open curated finding", findings)
	}
	if repo, _ := findings.Items[0]["repository"].(map[string]any); repo["name"] != "alpha" {
		t.Errorf("FindingRow repository = %v", findings.Items[0]["repository"])
	}
	none := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs/acme/findings?category=Uncategorized", nil)))
	if none.Total != 1 {
		t.Errorf("Uncategorized total = %d, want 1 (finding has no cwe)", none.Total)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs/acme/findings?category=Nope", nil)), http.StatusBadRequest, uiCodeBadParam)

	advs := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs/acme/advisories", nil)))
	if advs.Total != 1 || advs.Items[0]["audit_status"] != advisoryAuditFixed {
		t.Fatalf("advisories = %+v", advs)
	}

	ms := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs/acme/maintainers", nil)))
	if ms.Total != 1 || ms.Items[0]["login"] != "alice" || ms.Items[0]["repository_count"] != float64(2) {
		t.Fatalf("maintainers = %+v", ms)
	}
	empty := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs/zeta/maintainers", nil)))
	if empty.Total != 0 || empty.Items == nil {
		t.Errorf("zeta maintainers = %+v, want empty array", empty)
	}

	for _, sub := range []string{"repositories", "findings", "advisories", "maintainers"} {
		requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs/nobody/"+sub, nil)), http.StatusNotFound, uiCodeNotFound)
		requireUIError(t, serveUI(t, s, operatorReq(t, "GET", "/api/v1/ui/orgs/acme/"+sub+"?page_size=999", nil)), http.StatusBadRequest, uiCodeBadParam)
	}
}

// The HTML org pages keep their behaviour after the helper extraction.
func TestUIInventoryOrgHTMLUnchanged(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedInventory(t, s)
	w := serveUI(t, s, localReq("GET", "/orgs?sort=findings"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="org-acme"`) {
		t.Fatalf("orgs page = %d", w.Code)
	}
	w = serveUI(t, s, localReq("GET", "/orgs/acme"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "open bug") || strings.Contains(w.Body.String(), "closed bug") {
		t.Fatalf("org page = %d", w.Code)
	}
}
