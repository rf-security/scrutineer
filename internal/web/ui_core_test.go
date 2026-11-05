package web

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

func TestUISessionGet(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	s.Version = "1.2.3"

	anon := httptest.NewRequest(http.MethodGet, "/api/v1/ui/session", nil)
	anon.Host = testHost
	requireUIError(t, serveUI(t, s, anon), http.StatusUnauthorized, uiCodeUnauthorized)

	r := operatorReq(t, http.MethodGet, "/api/v1/ui/session", nil)
	r.AddCookie(&http.Cookie{Name: "color_scheme", Value: "dark"})
	body := decodeUIJSON[map[string]any](t, serveUI(t, s, r), http.StatusOK)
	if body["authenticated"] != true || body["ui_base"] != uiBasePath {
		t.Fatalf("session = %v", body)
	}
	if v := body["version"].(map[string]any); v["version"] != "1.2.3" {
		t.Fatalf("version = %v", v)
	}
	if p := body["prefs"].(map[string]any); p["color_scheme"] != "dark" || p["theme"] != "" {
		t.Fatalf("prefs = %v", p)
	}

	bearerReq := httptest.NewRequest(http.MethodGet, "/api/v1/ui/session", nil)
	bearerReq.Host = testHost
	bearerReq.Header.Set("Authorization", "Bearer "+testOperatorToken)
	if w := serveUI(t, s, bearerReq); w.Code != http.StatusOK {
		t.Fatalf("bearer session = %d", w.Code)
	}
}

func TestUISessionCreateAndDelete(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/ui/session", strings.NewReader(body))
		r.Host = testHost
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		return serveUI(t, s, r)
	}
	requireUIError(t, post(`{"token":"wrong"}`), http.StatusUnauthorized, uiCodeUnauthorized)
	requireUIError(t, post(`not json`), http.StatusBadRequest, uiCodeBadParam)

	w := post(`{"token":"` + testOperatorToken + `"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("login = %d %s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()
	if len(cookie) != 1 || cookie[0].Name != testOperatorCookie || !cookie[0].HttpOnly || cookie[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie = %+v", cookie)
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/v1/ui/session", nil)
	del.Host = testHost
	w = serveUI(t, s, del)
	if w.Code != http.StatusNoContent || w.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatalf("logout = %d %+v", w.Code, w.Result().Cookies())
	}

	// A cross-site browser cannot sign the operator in or out.
	cross := httptest.NewRequest(http.MethodDelete, "/api/v1/ui/session", nil)
	cross.Host = testHost
	cross.Header.Set("Sec-Fetch-Site", "cross-site")
	if w := serveUI(t, s, cross); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site DELETE = %d", w.Code)
	}
}

func TestLoginNext(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	cases := map[string]string{
		"":                  "/",
		"/ui/findings/12":   "/ui/findings/12",
		"//evil.example":    "/",
		"/\\evil.example":   "/",
		"https://evil.test": "/",
		"ui/relative":       "/",
	}
	for next, want := range cases {
		r := httptest.NewRequest(http.MethodGet, "/login?token="+testOperatorToken+"&next="+urlQueryEscape(next), nil)
		r.Host = testHost
		w := serveUI(t, s, r)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
			t.Errorf("next=%q: %d Location=%q, want %q", next, w.Code, w.Header().Get("Location"), want)
		}
	}
}

func urlQueryEscape(s string) string {
	return strings.NewReplacer("%", "%25", "&", "%26", "/", "%2F", "\\", "%5C", ":", "%3A").Replace(s)
}

func TestUIRoutesRequireOperatorWithJSON401(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/ui/meta", nil)
	r.Host = testHost
	requireUIError(t, serveUI(t, s, r), http.StatusUnauthorized, uiCodeUnauthorized)

	// The export surface keeps its plain-text 401.
	r = httptest.NewRequest(http.MethodGet, "/api/v1/repositories", nil)
	r.Host = testHost
	w := serveUI(t, s, r)
	if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Body.String(), "unauthorized") {
		t.Fatalf("export 401 = %d %q", w.Code, w.Body.String())
	}
}

func TestSecurityHeadersRejectCrossSiteUnsafeMethods(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
		r := operatorReq(t, method, "/api/v1/findings/1", nil)
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		if w := serveUI(t, s, r); w.Code != http.StatusForbidden {
			t.Errorf("%s cross-site = %d, want 403", method, w.Code)
		}
	}
	r := operatorReq(t, http.MethodGet, "/api/v1/ui/meta", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if w := serveUI(t, s, r); w.Code != http.StatusOK {
		t.Errorf("GET cross-site = %d, want 200", w.Code)
	}
}

func TestUIRequestIDIsLoggedAndEchoed(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	w := serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/scans?page=0", nil))
	body := requireUIError(t, w, http.StatusBadRequest, uiCodeBadParam)
	if got := w.Header().Get(requestIDHeader); got == "" || got != body.RequestID {
		t.Fatalf("X-Request-Id = %q, envelope = %q", got, body.RequestID)
	}
}

func TestUIMeta(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	w := serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/meta", nil))
	body := decodeUIJSON[map[string]any](t, w, http.StatusOK)
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=3600") {
		t.Fatalf("Cache-Control = %q", cc)
	}
	for _, key := range []string{"finding_statuses", "severities", "scan_statuses", "cwe_categories", "themes", "resolutions",
		"campaign_statuses", "review_verdicts", "communication_channels", "efforts", "model_tiers", "repo_tabs"} {
		if _, ok := body[key]; !ok {
			t.Errorf("meta missing %s", key)
		}
	}
	tabs := body["repo_tabs"].(map[string]any)
	if legacy := tabs["legacy"].(map[string]any); legacy["rt3"] != "scans" || legacy["rt15"] != "alternatives" || len(legacy) != 16 {
		t.Fatalf("legacy tabs = %v", legacy)
	}
	if list := tabs["tabs"].([]any); len(list) != 17 {
		t.Fatalf("tabs = %d, want 17 canonical tabs", len(list))
	}
	sev := body["severities"].([]any)[0].(map[string]any)
	if sev["value"] != "Critical" {
		t.Fatalf("severities should start at Critical: %v", sev)
	}
}

func TestUIMetaDynamic(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	s.DB.Create(&db.FindingLabel{Name: "needs-info", Color: "#00ff00"})
	s.DB.Create(&db.Skill{Name: "active-skill", Active: true, OutputKind: "findings"})
	s.DB.Create(&db.Skill{Name: "inactive-skill", OutputKind: "findings"})
	s.DB.Model(&db.Skill{}).Where("name = ?", "inactive-skill").Update("active", false)
	w := serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/meta/dynamic", nil))
	body := decodeUIJSON[map[string]any](t, w, http.StatusOK)
	if w.Header().Get("Cache-Control") != noStore {
		t.Fatalf("Cache-Control = %q", w.Header().Get("Cache-Control"))
	}
	labels := body["labels"].([]any)
	found := false
	for _, l := range labels {
		if l.(map[string]any)["name"] == "needs-info" {
			found = true
		}
	}
	if !found {
		t.Fatalf("labels = %v", labels)
	}
	for _, sk := range body["skills_active"].([]any) {
		if sk.(map[string]any)["name"] == "inactive-skill" {
			t.Fatal("inactive skill listed as active")
		}
	}
	if f := body["features"].(map[string]any); f["vince"] != false {
		t.Fatalf("features = %v", f)
	}
}

func TestUIMetaCWE(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	rows := decodeUIJSON[[]map[string]string](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/meta/cwe?q=79", nil)), http.StatusOK)
	if len(rows) == 0 || rows[0]["id"] != "CWE-79" {
		t.Fatalf("cwe 79 = %v", rows)
	}
	rows = decodeUIJSON[[]map[string]string](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/meta/cwe?q=injection&limit=3", nil)), http.StatusOK)
	if len(rows) == 0 || len(rows) > 3 {
		t.Fatalf("injection = %v", rows)
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/meta/cwe?limit=0", nil)), http.StatusBadRequest, uiCodeBadParam)
}

func TestUISearch(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	repo := seedUIRepo(t, s.DB, "widget")
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, "security-deep-dive")
	f := seedUIFinding(t, s.DB, sc, "Widget overflow", db.FindingNew)
	s.DB.Create(&db.Maintainer{Login: "widgetmaker", Name: "W"})

	type groups struct {
		Groups map[string]struct {
			Items []searchRef `json:"items"`
			Total int64       `json:"total"`
		} `json:"groups"`
	}
	body := decodeUIJSON[groups](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/search?q=WIDGET", nil)), http.StatusOK)
	if len(body.Groups) != 9 {
		t.Fatalf("groups = %d, want 9", len(body.Groups))
	}
	for _, g := range []string{"repositories", "findings", "maintainers"} {
		if body.Groups[g].Total != 1 || len(body.Groups[g].Items) != 1 {
			t.Errorf("%s = %+v", g, body.Groups[g])
		}
	}
	if body.Groups["orgs"].Total != 0 {
		t.Errorf("orgs should not match widget: %+v", body.Groups["orgs"])
	}

	body = decodeUIJSON[groups](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/search?q=%23"+itoa(f.ID), nil)), http.StatusOK)
	if items := body.Groups["findings"].Items; len(items) != 1 || items[0].ID != float64(f.ID) {
		t.Fatalf("#id search = %+v", body.Groups["findings"])
	}
	body = decodeUIJSON[groups](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/search?q=s"+itoa(sc.ID), nil)), http.StatusOK)
	if items := body.Groups["scans"].Items; len(items) != 1 || items[0].ID != float64(sc.ID) {
		t.Fatalf("s<id> search = %+v", body.Groups["scans"])
	}
	// A literal % does not match everything.
	body = decodeUIJSON[groups](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/search?q=%25", nil)), http.StatusOK)
	if body.Groups["repositories"].Total != 0 {
		t.Fatalf("%% matched %+v", body.Groups["repositories"])
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/search?q=a&limit=99", nil)), http.StatusBadRequest, uiCodeBadParam)
}

func itoa(n uint) string { return strconv.FormatUint(uint64(n), 10) }

func TestUIActivity(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	repo := seedUIRepo(t, s.DB, "act")
	seedUIScan(t, s.DB, repo, db.ScanRunning, "a")
	seedUIScan(t, s.DB, repo, db.ScanQueued, "b")
	seedUIScan(t, s.DB, repo, db.ScanQueued, "c")
	failed := seedUIScan(t, s.DB, repo, db.ScanFailed, "d")
	now := time.Now()
	s.DB.Model(&failed).Update("finished_at", now)
	done := seedUIScan(t, s.DB, repo, db.ScanDone, "e")
	seedUIFinding(t, s.DB, done, "open", db.FindingNew)
	seedUIFinding(t, s.DB, done, "closed", db.FindingFixed)

	body := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/activity", nil)), http.StatusOK)
	scans := body["scans"].(map[string]any)
	if scans["running"] != float64(1) || scans["queued"] != float64(2) || scans["paused"] != float64(0) || scans["failed_24h"] != float64(1) {
		t.Fatalf("scans = %v", scans)
	}
	if f := body["findings"].(map[string]any); f["open"] != float64(1) || f["new"] != float64(1) {
		t.Fatalf("findings = %v", f)
	}
	if body["account_paused"] != false {
		t.Fatalf("account_paused = %v", body["account_paused"])
	}
}

func TestUIScanList(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	alpha := seedUIRepo(t, s.DB, "alpha")
	beta := seedUIRepo(t, s.DB, "beta")
	running := seedUIScan(t, s.DB, beta, db.ScanRunning, "triage")
	done := seedUIScan(t, s.DB, alpha, db.ScanDone, "security-deep-dive")
	seedUIScan(t, s.DB, alpha, db.ScanQueued, "triage")
	seedUIFinding(t, s.DB, done, "x", db.FindingNew)
	s.DB.Model(&done).Update("findings_count", 1)

	type list struct {
		uiList[map[string]any]
		Stats  map[string]any  `json:"stats"`
		Skills []string        `json:"skills"`
		Any    map[string]bool `json:"any"`
	}
	get := func(q string) list {
		t.Helper()
		return decodeUIJSON[list](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/scans"+q, nil)), http.StatusOK)
	}

	all := get("")
	if all.Total != 3 || len(all.Items) != 3 || all.Page != 1 || all.PageSize != uiDefaultPageSize {
		t.Fatalf("list = %+v", all.uiList)
	}
	// Default order: running first (status_priority).
	if all.Items[0]["id"] != float64(running.ID) {
		t.Fatalf("first row = %v", all.Items[0]["id"])
	}
	row := all.Items[0]
	for _, key := range []string{"repository", "actions", "log_bytes", "report_bytes", "prompt_bytes", "focus", "duration_seconds", "resumable", "has_exportable_report"} {
		if _, ok := row[key]; !ok {
			t.Errorf("ScanRow missing %s", key)
		}
	}
	for _, blob := range []string{"log", "report", "prompt", "api_token"} {
		if _, ok := row[blob]; ok {
			t.Errorf("ScanRow leaked %s", blob)
		}
	}
	if row["log_bytes"] != float64(len("line one\n")) {
		t.Errorf("log_bytes = %v", row["log_bytes"])
	}
	if a := row["actions"].(map[string]any); a["cancel"] != true {
		t.Errorf("actions = %v", a)
	}
	if all.Stats["running"] != float64(1) || all.Stats["queued"] != float64(1) {
		t.Errorf("stats = %v", all.Stats)
	}
	if len(all.Skills) != 2 {
		t.Errorf("skills = %v", all.Skills)
	}

	if got := get("?skill=triage"); got.Total != 2 {
		t.Errorf("skill filter total = %d", got.Total)
	}
	if got := get("?status=done"); got.Total != 1 || got.Items[0]["id"] != float64(done.ID) {
		t.Errorf("status filter = %+v", got.uiList)
	}
	if got := get("?repository_id=" + itoa(alpha.ID)); got.Total != 2 {
		t.Errorf("repository filter total = %d", got.Total)
	}
	if got := get("?sort=repository"); got.Items[0]["repository"].(map[string]any)["name"] != "alpha" {
		t.Errorf("repository sort first = %v", got.Items[0]["repository"])
	}
	if got := get("?sort=findings"); got.Items[0]["id"] != float64(done.ID) {
		t.Errorf("findings sort first = %v", got.Items[0]["id"])
	}
	if got := get("?sort=id.asc&page=2&page_size=2"); len(got.Items) != 1 || got.Total != 3 || got.Page != 2 {
		t.Errorf("paging = %+v", got.uiList)
	}
	for _, bad := range []string{"?status=bogus", "?page_size=500", "?completeness=nope", "?repository_id=x"} {
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/scans"+bad, nil)), http.StatusBadRequest, uiCodeBadParam)
	}
}
