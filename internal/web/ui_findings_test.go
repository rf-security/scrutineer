package web

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"scrutineer/internal/db"
)

// Tests for the WP-API-1 findings surface (list, detail, sub-resources).

// captureUIEvents subscribes to the broker and returns a drain function that
// yields every event published since the last drain (fan-out is synchronous).
func captureUIEvents(t *testing.T, s *Server, names ...string) func() []Event {
	t.Helper()
	c := s.Broker.Subscribe(0, 0, 0, names...)
	t.Cleanup(func() { s.Broker.Unsubscribe(c) })
	return func() []Event {
		var out []Event
		for {
			select {
			case e := <-c.ch:
				out = append(out, e)
			default:
				return out
			}
		}
	}
}

// eventFields returns the `fields` of a finding event payload.
func eventFields(t *testing.T, e Event) []string {
	t.Helper()
	m, ok := e.JSON.(map[string]any)
	if !ok {
		t.Fatalf("event JSON = %#v", e.JSON)
	}
	fields, _ := m[uiEventFieldsKey].([]string)
	return fields
}

func findingPath(id uint, suffix string) string {
	return "/api/v1/ui/findings/" + strconv.FormatUint(uint64(id), 10) + suffix
}

// uiFindingFixture seeds two repos: three deep-dive findings and one scanner
// finding on repo a, one deep-dive finding on repo b.
type uiFindingFixture struct {
	repoA, repoB            db.Repository
	high, low, fixed, other db.Finding
	scanner                 db.Finding
	deepDiveScan, toolScan  db.Scan
	deepDiveScanB           db.Scan
}

func seedUIFindingFixture(t *testing.T, s *Server) uiFindingFixture {
	t.Helper()
	var fx uiFindingFixture
	fx.repoA = seedUIRepo(t, s.DB, "alpha")
	fx.repoB = seedUIRepo(t, s.DB, "beta")
	fx.deepDiveScan = seedUIScan(t, s.DB, fx.repoA, db.ScanDone, deepDiveSkillName)
	fx.toolScan = seedUIScan(t, s.DB, fx.repoA, db.ScanDone, "semgrep")
	fx.deepDiveScanB = seedUIScan(t, s.DB, fx.repoB, db.ScanDone, deepDiveSkillName)
	fx.high = seedUIFinding(t, s.DB, fx.deepDiveScan, "SQL injection", db.FindingNew)
	fx.low = seedUIFinding(t, s.DB, fx.deepDiveScan, "Weak hash", db.FindingTriaged)
	fx.fixed = seedUIFinding(t, s.DB, fx.deepDiveScan, "Old bug", db.FindingFixed)
	fx.other = seedUIFinding(t, s.DB, fx.deepDiveScanB, "XSS", db.FindingNew)
	fx.scanner = seedUIFinding(t, s.DB, fx.toolScan, "Lint", db.FindingNew)
	s.DB.Model(&fx.low).Updates(map[string]any{"severity": "Low", "cwe": "CWE-328", "sub_path": "pkg/core"})
	s.DB.Model(&fx.high).Updates(map[string]any{"cwe": "CWE-89", "missed_count": 2})
	s.DB.Model(&fx.other).Update("cwe", "CWE-79")
	return fx
}

type uiFindingListBody struct {
	Items  []map[string]any            `json:"items"`
	Total  int64                       `json:"total"`
	Counts map[string]int64            `json:"counts"`
	Facets map[string]map[string]int64 `json:"facets"`
}

func getUIFindingList(t *testing.T, s *Server, query string) uiFindingListBody {
	t.Helper()
	return decodeUIJSON[uiFindingListBody](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/findings?"+query, nil)), http.StatusOK)
}

func listIDs(body uiFindingListBody) []uint {
	out := make([]uint, len(body.Items))
	for i, it := range body.Items {
		out[i] = uint(it["id"].(float64))
	}
	return out
}

func TestUIFindingListFiltersAndRowShape(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)

	// Default: open, deep-dive only, newest first.
	body := getUIFindingList(t, s, "")
	if got := listIDs(body); body.Total != 3 || len(got) != 3 || got[0] != fx.other.ID {
		t.Fatalf("default list = %v total %d", got, body.Total)
	}
	if body.Counts["missed"] != 1 || body.Counts["scanners"] != 1 {
		t.Fatalf("counts = %v", body.Counts)
	}
	row := body.Items[0]
	for _, key := range []string{"title_summary", "repository", "labels", "model", "created_at", "updated_at",
		"location_ref", "locations", "extra_location_count", "commit", "last_seen_scan_id", "skill_name", "expected", "cwe_info"} {
		if _, ok := row[key]; !ok {
			t.Errorf("FindingRow missing %q", key)
		}
	}
	if _, ok := row["disclosure_draft"]; ok {
		t.Error("FindingRow must stay slim (no disclosure_draft)")
	}
	if info, ok := row["cwe_info"].(map[string]any); !ok || info["id"] != "CWE-79" || info["name"] == "" || info["category"] == "" {
		t.Fatalf("FindingRow cwe_info = %v", row["cwe_info"])
	}
	if repo := row["repository"].(map[string]any); repo["name"] != "beta" {
		t.Fatalf("repository = %v", repo)
	}
	if body.Facets != nil {
		t.Fatal("facets must be opt-in")
	}

	cases := []struct {
		query string
		want  []uint
	}{
		{"status=all", []uint{fx.other.ID, fx.fixed.ID, fx.low.ID, fx.high.ID}},
		{"status=fixed", []uint{fx.fixed.ID}},
		{"severity=Low", []uint{fx.low.ID}},
		{fmt.Sprintf("repository_id=%d", fx.repoA.ID), []uint{fx.low.ID, fx.high.ID}},
		{"sub_path=pkg/core", []uint{fx.low.ID}},
		{"missed=1", []uint{fx.high.ID}},
		{"scanners=1&q=lint", []uint{fx.scanner.ID}},
		{"category=Injection", []uint{fx.other.ID, fx.high.ID}},
		{"owner=acme&sort=title.asc", []uint{fx.high.ID, fx.low.ID, fx.other.ID}},
		{"sort=repository", []uint{fx.low.ID, fx.high.ID, fx.other.ID}},
		{"page=2&page_size=2", []uint{fx.high.ID}},
		{"sort=bogus", []uint{fx.other.ID, fx.low.ID, fx.high.ID}},
	}
	for _, tc := range cases {
		got := listIDs(getUIFindingList(t, s, tc.query))
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: ids = %v, want %v", tc.query, got, tc.want)
		}
	}
}

func TestUIFindingListFacets(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)

	body := getUIFindingList(t, s, fmt.Sprintf("facets=status,severity,category&severity=High&repository_id=%d", fx.repoA.ID))
	if body.Total != 1 {
		t.Fatalf("total = %d", body.Total)
	}
	st := body.Facets["status"]
	// status facet ignores the status filter: high(new) + fixed on repo a at High.
	if st["open"] != 1 || st["all"] != 2 || st["fixed"] != 1 || st["new"] != 1 || st["triaged"] != 0 {
		t.Fatalf("status facet = %v", st)
	}
	// severity facet ignores the severity filter: high + low open on repo a.
	if sev := body.Facets["severity"]; sev["High"] != 1 || sev["Low"] != 1 || sev["Critical"] != 0 {
		t.Fatalf("severity facet = %v", sev)
	}
	if cat := body.Facets["category"]; cat["Injection"] != 1 {
		t.Fatalf("category facet = %v", cat)
	}
}

func TestUIFindingListBadParams(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	for _, q := range []string{"severity=huge", "status=open-ish", "facets=colour", "category=Nope",
		"viability=maybe", "missed=yes", "repository_id=x", "page_size=999"} {
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/findings?"+q, nil)), http.StatusBadRequest, uiCodeBadParam)
	}
}

func TestUIFindingListExpectedMatch(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	if err := s.DB.Create(&db.ExpectedFinding{RepositoryID: fx.repoA.ID, File: "src/app.go", CWE: "CWE-89"}).Error; err != nil {
		t.Fatal(err)
	}
	byID := map[uint]any{}
	for _, it := range getUIFindingList(t, s, "").Items {
		byID[uint(it["id"].(float64))] = it["expected"]
	}
	if byID[fx.high.ID] != uiExpectedMatched || byID[fx.low.ID] != uiExpectedUnexpected || byID[fx.other.ID] != nil {
		t.Fatalf("expected = %v", byID)
	}
}

func TestUIFindingDetail(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	s.DB.Model(&fx.high).Updates(map[string]any{"trace": "first para\n\nsecond", "disclosure_draft": "draft"})
	if err := db.SetFindingLabels(s.DB, fx.high.ID, []string{"needs-info"}, db.SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddFindingNote(s.DB, fx.high.ID, "hello", ""); err != nil {
		t.Fatal(err)
	}

	w := serveUI(t, s, operatorReq(t, http.MethodGet, findingPath(fx.high.ID, ""), nil))
	d := decodeUIJSON[map[string]any](t, w, http.StatusOK)
	if w.Header().Get("ETag") == "" {
		t.Fatal("detail must carry an ETag")
	}
	if d["title_summary"] != "first para" || d["trace"] != "first para\n\nsecond" || d["disclosure_draft"] != "draft" {
		t.Fatalf("detail prose = %v / %v", d["title_summary"], d["trace"])
	}
	if _, ok := d["locations"].([]any); !ok {
		t.Fatalf("locations must be the FindingRow array, got %T", d["locations"])
	}
	if info := d["cwe_info"].(map[string]any); d["cwe"] != "CWE-89" || info["id"] != "CWE-89" || info["category"] == "" || info["url"] == "" {
		t.Fatalf("cwe = %v / %v", d["cwe"], d["cwe_info"])
	}
	wf := d["workflow"].(map[string]any)
	if wf["has_disclosure_draft"] != true || wf["verify_in_flight"] != nil {
		t.Fatalf("workflow = %v", wf)
	}
	counts := d["counts"].(map[string]any)
	if counts["notes"].(float64) != 1 {
		t.Fatalf("counts = %v", counts)
	}
	if exp := d["exports"].(map[string]any)["report_md"].(map[string]any); exp["url"] != fmt.Sprintf("/findings/%d/report.md", fx.high.ID) {
		t.Fatalf("exports = %v", exp)
	}
	if scan := d["scan"].(map[string]any); uint(scan["id"].(float64)) != fx.deepDiveScan.ID {
		t.Fatalf("scan = %v", scan)
	}
	if labels := d["labels"].([]any); len(labels) != 1 {
		t.Fatalf("labels = %v", labels)
	}

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, findingPath(9999, ""), nil)), http.StatusNotFound, uiCodeNotFound)
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/findings/abc", nil)), http.StatusBadRequest, uiCodeBadParam)
}

func TestUIFindingSubResourceReads(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	id := fx.high.ID
	if _, err := db.AddFindingCommunication(s.DB, id, "email", "outbound", "maint", "hi", "pr", time.Time{}, db.SourceAnalyst); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddFindingReference(s.DB, id, "https://example.com/a", "issue", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddFindingReview(s.DB, id, "true_positive", "", "true_positive", "me"); err != nil {
		t.Fatal(err)
	}
	s.DB.Create(&db.DisclosureSubmission{FindingID: id, Channel: db.DisclosureChannelPVR, Status: "submitted", Request: "secret"})
	s.DB.Create(&db.FindingVerification{FindingID: id, ScanID: fx.deepDiveScan.ID, Status: "confirmed", Report: "{}"})
	s.DB.Create(&db.FindingAttackPath{FindingID: id, ScanID: fx.deepDiveScan.ID, ProductionViability: "VIABLE",
		Report: `{"production_viability":"VIABLE","reason":"r"}`})
	s.DB.Create(&db.FindingObservation{FindingID: id, ScanID: fx.deepDiveScan.ID, RepositoryID: fx.repoA.ID,
		Severity: "High", Evidence: `{"trace":"t"}`})
	s.DB.Create(&db.FindingObservation{FindingID: id, ScanID: fx.toolScan.ID, RepositoryID: fx.repoA.ID, Severity: "Low"})

	arr := func(suffix string) []map[string]any {
		return decodeUIJSON[[]map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, findingPath(id, suffix), nil)), http.StatusOK)
	}
	if c := arr("/communications"); len(c) != 1 || c[0]["offered_help"] != "pr" || c[0]["channel"] != "email" {
		t.Fatalf("communications = %v", c)
	}
	if r := arr("/references"); len(r) != 1 || r[0]["url"] != "https://example.com/a" {
		t.Fatalf("references = %v", r)
	}
	if r := arr("/reviews"); len(r) != 1 || r[0]["agreed"] != true {
		t.Fatalf("reviews = %v", r)
	}
	if sub := arr("/submissions"); len(sub) != 1 || sub[0]["status"] != "submitted" || sub[0]["request"] != nil {
		t.Fatalf("submissions = %v", sub)
	}
	if v := arr("/verifications"); len(v) != 1 || v[0]["status"] != "confirmed" || v[0]["score_label"] != "ungraded" {
		t.Fatalf("verifications = %v", v)
	}
	if a := arr("/attack-paths"); len(a) != 1 || a[0]["parsed"] != true {
		t.Fatalf("attack paths = %v", a)
	}
	if n := arr("/notes"); len(n) != 0 {
		t.Fatalf("notes = %v", n)
	}
	if l := arr("/labels"); len(l) != 0 {
		t.Fatalf("labels = %v", l)
	}

	obs := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, findingPath(id, "/observations?page_size=1"), nil)), http.StatusOK)
	if obs["total"].(float64) != 2 || len(obs["items"].([]any)) != 1 || obs["disagreement"] != true {
		t.Fatalf("observations = %v", obs)
	}

	rem := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, findingPath(id, "/remediation"), nil)), http.StatusOK)
	if len(rem["attempts"].([]any)) != 0 || rem["current"] != nil {
		t.Fatalf("remediation = %v", rem)
	}
	exp := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, findingPath(id, "/exposures"), nil)), http.StatusOK)
	if exp["show"] != false || len(exp["rows"].([]any)) != 0 {
		t.Fatalf("exposures = %v", exp)
	}
	guide := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, findingPath(id, "/migration-guide"), nil)), http.StatusOK)
	if guide["available"] != false {
		t.Fatalf("guide = %v", guide)
	}

}

func TestUIFindingHistoryAndNotFound(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	id := fx.high.ID
	if err := db.WriteFindingField(s.DB, id, "assignee", "w", db.SourceAnalyst, "w"); err != nil {
		t.Fatal(err)
	}
	hist := decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, findingPath(id, "/history"), nil)))
	if hist.PageSize != uiHistoryDefaultPageSize || hist.Total != 1 || hist.Items[0]["field"] != "assignee" {
		t.Fatalf("history page size = %d", hist.PageSize)
	}

	for _, suffix := range []string{"/history", "/notes", "/communications", "/references", "/reviews", "/submissions",
		"/labels", "/verifications", "/observations", "/attack-paths", "/remediation", "/exposures", "/migration-guide"} {
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, findingPath(9999, suffix), nil)), http.StatusNotFound, uiCodeNotFound)
	}
}

func TestUIFindingMigrationGuideAvailable(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fx := seedUIFindingFixture(t, s)
	s.DB.Model(&fx.repoA).Update("health", db.RepositoryHealthAbandoned)
	dep := db.Dependent{RepositoryID: fx.repoA.ID, Name: "user", DependentRepos: 3}
	s.DB.Create(&dep)
	s.DB.Create(&db.FindingDependent{FindingID: fx.high.ID, DependentID: dep.ID, Status: db.ExposureKnownAffected})

	guide := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, findingPath(fx.high.ID, "/migration-guide"), nil)), http.StatusOK)
	if guide["available"] != true || guide["health"] != string(db.RepositoryHealthAbandoned) {
		t.Fatalf("guide = %v", guide)
	}
	if rows := guide["priority_dependents"].([]any); len(rows) != 1 {
		t.Fatalf("priority dependents = %v", rows)
	}
	exp := decodeUIJSON[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, findingPath(fx.high.ID, "/exposures"), nil)), http.StatusOK)
	if exp["show"] != true || len(exp["rows"].([]any)) != 1 {
		t.Fatalf("exposures = %v", exp)
	}
}
