package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"scrutineer/internal/db"
)

// Tests for the JSON add paths (#48-#53). The network seams (listBranches,
// fetchOrgRepos, resolvePURL) are stubbed; enqueues land in the test queue.

func TestUIRepoCreate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	triage := seedUISkill(t, s, defaultSkillName)
	c := s.Broker.Subscribe(0, 0, 0, uiRepositoryEvent)
	defer s.Broker.Unsubscribe(c)

	body := postUI(t, s, "/api/v1/ui/repositories", map[string]any{"url": "https://github.com/Acme/Widget.git"}, http.StatusCreated)
	repo := body["repository"].(map[string]any)
	ids := body["scan_ids"].([]any)
	if body["created"] != true || len(ids) != 1 || body["scan_id"] != ids[0] || repo["url"] != "https://github.com/acme/widget" {
		t.Fatalf("create = %+v", body)
	}
	sc := loadScan(t, s, body["scan_id"])
	if sc.SkillID == nil || *sc.SkillID != triage.ID {
		t.Fatalf("triage scan = %+v", sc)
	}
	requireRepoEvent(t, c, uint(repo["id"].(float64)), uiChangeCreated)

	// A bare re-add is created:false and enqueues nothing.
	again := postUI(t, s, "/api/v1/ui/repositories", map[string]any{"url": "https://github.com/acme/widget"}, http.StatusCreated)
	if again["created"] != false || len(again["scan_ids"].([]any)) != 0 || again["scan_id"] != nil {
		t.Fatalf("re-add = %+v", again)
	}
	assertQueuedJobCount(t, s, 1)

	// ...but a re-add naming a branch does enqueue.
	branch := postUI(t, s, "/api/v1/ui/repositories", map[string]any{"url": "https://github.com/acme/widget", "ref": "dev"}, http.StatusCreated)
	if branch["created"] != false || len(branch["scan_ids"].([]any)) != 1 || loadScan(t, s, branch["scan_id"]).Ref != "dev" {
		t.Fatalf("branch re-add = %+v", branch)
	}

	// triage:false adds without scanning.
	quiet := postUI(t, s, "/api/v1/ui/repositories", map[string]any{"url": "https://github.com/acme/quiet", "triage": false}, http.StatusCreated)
	if quiet["created"] != true || len(quiet["scan_ids"].([]any)) != 0 {
		t.Fatalf("triage:false = %+v", quiet)
	}
	assertQueuedJobCount(t, s, 2)

	bad := requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/repositories", map[string]any{"url": "ftp://x"})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if bad.Fields["url"] == "" {
		t.Fatalf("fields = %+v", bad.Fields)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/repositories", map[string]any{"url": "https://github.com/acme/widget", "ref": "bad..ref"})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
}

func TestUIRepoBranches(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	var asked string
	s.listBranches = func(_ context.Context, cloneURL string) ([]string, error) {
		asked = cloneURL
		return []string{"main", "dev"}, nil
	}
	body := getUI(t, s, "/api/v1/ui/repositories/branches?url="+url.QueryEscape("https://github.com/acme/widget"))
	if len(body["branches"].([]any)) != 2 || asked != "https://github.com/acme/widget" {
		t.Fatalf("branches = %+v (asked %q)", body, asked)
	}
	s.listBranches = func(context.Context, string) ([]string, error) { return nil, errors.New("timeout") }
	if body = getUI(t, s, "/api/v1/ui/repositories/branches?url="+url.QueryEscape("https://github.com/acme/widget")); len(body["branches"].([]any)) != 0 {
		t.Fatalf("unreachable = %+v", body)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/repositories/branches", nil)), http.StatusBadRequest, uiCodeBadParam)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/repositories/branches?url=ftp://x", nil)), http.StatusUnprocessableEntity, uiCodeValidationFailed)
}

func TestUIRepoBulkCreate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedUISkill(t, s, defaultSkillName)
	seedUIRepo(t, s.DB, "present")
	body := postUI(t, s, "/api/v1/ui/repositories/bulk", map[string]any{
		"urls": []string{"https://github.com/acme/one"},
		"text": "https://github.com/acme/present\n\nnot a url\nhttps://github.com/acme/present/tree/dev\n",
	}, http.StatusOK)
	invalid := body["invalid"].([]any)
	if body["added"] != float64(1) || body["present"] != float64(1) || body["queued"] != float64(1) || len(invalid) != 1 {
		t.Fatalf("bulk = %+v", body)
	}
	if line := invalid[0].(map[string]any); line["line"] != float64(4) || line["url"] != "not a url" {
		t.Fatalf("invalid = %+v", line)
	}
	if repos := body["repositories"].([]any); len(repos) != 2 {
		t.Fatalf("repositories = %+v", repos)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/repositories/bulk", map[string]any{"text": "\n"})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
}

func TestUIOrgImport(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedUISkill(t, s, defaultSkillName)
	seedUIRepo(t, s.DB, "existing")
	calls := 0
	s.fetchOrgRepos = func(_ context.Context, org string) ([]OrgRepo, error) {
		calls++
		if org == "down" {
			return nil, errors.New("GitHub API returned 500")
		}
		return []OrgRepo{
			{FullName: "acme/new", CloneURL: "https://github.com/acme/new.git", Stars: 7},
			{FullName: "acme/existing", CloneURL: "https://github.com/acme/existing.git"},
			{FullName: "acme/forked", CloneURL: "https://github.com/acme/forked.git", Fork: true},
			{FullName: "acme/mirror", CloneURL: "https://github.com/acme/mirror.git", MirrorURL: "https://x"},
		}, nil
	}
	preview := postUI(t, s, "/api/v1/ui/repositories/org/preview", map[string]any{"org": "@acme"}, http.StatusOK)
	repos := preview["repos"].([]any)
	if preview["org"] != "acme" || preview["total"] != float64(2) || preview["filtered"] != float64(2) || len(repos) != 2 {
		t.Fatalf("preview = %+v", preview)
	}
	if first := repos[0].(map[string]any); first["name"] != "new" || first["stars"] != float64(7) {
		t.Fatalf("preview row = %+v", first)
	}
	assertQueuedJobCount(t, s, 0)

	imported := postUI(t, s, "/api/v1/ui/repositories/org", map[string]any{"org": "acme", "include_forks": true}, http.StatusOK)
	if imported["created"] != float64(2) || imported["skipped"] != float64(1) || imported["filtered"] != float64(1) ||
		len(imported["repositories"].([]any)) != 3 {
		t.Fatalf("import = %+v", imported)
	}
	assertQueuedJobCount(t, s, 2)

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/repositories/org/preview", map[string]any{"org": " "})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/repositories/org", map[string]any{"org": "down"})), http.StatusBadGateway, uiCodeNetwork)
}

func TestUIInvestigationCreate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	body := map[string]any{"url": "https://github.com/acme/inv", "report": "the parser overflows"}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/investigations", body)), http.StatusServiceUnavailable, uiCodeUnavailable)
	seedUISkill(t, s, investigateSkillName)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/investigations", map[string]any{"url": "https://github.com/acme/inv", "report": " "})), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/investigations", map[string]any{"url": "nope", "report": "x"})), http.StatusUnprocessableEntity, uiCodeValidationFailed)

	got := postUI(t, s, "/api/v1/ui/investigations", map[string]any{"url": "https://github.com/acme/inv", "ref": "v1", "report": "the parser overflows"}, http.StatusAccepted)
	var sc db.Scan
	if err := s.DB.First(&sc, uint(got["scan_id"].(float64))).Error; err != nil {
		t.Fatal(err)
	}
	if sc.SkillName != investigateSkillName || sc.Ref != "v1" || string(sc.ImportPayload) != "the parser overflows" || sc.RepositoryID != uint(got["repository_id"].(float64)) {
		t.Fatalf("investigation scan = %+v", sc)
	}
}

func TestUIDependencyImport(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedUISkill(t, s, defaultSkillName)
	repo := seedUIRepo(t, s.DB, "app")
	dep := db.Dependency{RepositoryID: repo.ID, Name: "lib", Ecosystem: "npm", PURL: "pkg:npm/lib"}
	s.DB.Create(&dep)
	unresolvable := db.Dependency{RepositoryID: repo.ID, Name: "nopurl", Ecosystem: "npm"}
	s.DB.Create(&unresolvable)
	path := func(id uint) string { return "/api/v1/ui/dependencies/" + uintStr(id) + "/import" }

	s.ecosystemsEnrichment = false
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path(dep.ID), nil)), http.StatusServiceUnavailable, uiCodeUnavailable)
	s.ecosystemsEnrichment = true
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path(unresolvable.ID), nil)), http.StatusUnprocessableEntity, uiCodeValidationFailed)
	s.resolvePURL = func(context.Context, string) string { return "https://github.com/acme/lib" }
	got := postUI(t, s, path(dep.ID), nil, http.StatusAccepted)
	if got["created"] != true || got["scan_id"] == nil {
		t.Fatalf("import = %+v", got)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, path(9999), nil)), http.StatusNotFound, uiCodeNotFound)

	dependent := db.Dependent{RepositoryID: repo.ID, Name: "user", Ecosystem: "npm", RepositoryURL: "https://github.com/acme/lib"}
	s.DB.Create(&dependent)
	again := postUI(t, s, "/api/v1/ui/dependents/"+uintStr(dependent.ID)+"/import", nil, http.StatusAccepted)
	if again["created"] != false || again["scan_id"] != nil || again["repository_id"] != got["repository_id"] {
		t.Fatalf("dependent import = %+v", again)
	}
	empty := db.Dependent{RepositoryID: repo.ID, Name: "nourl", Ecosystem: "npm"}
	s.DB.Create(&empty)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodPost, "/api/v1/ui/dependents/"+uintStr(empty.ID)+"/import", nil)), http.StatusUnprocessableEntity, uiCodeValidationFailed)
}

func uintStr(id uint) string { return strconv.FormatUint(uint64(id), 10) }
