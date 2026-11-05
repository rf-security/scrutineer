package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// Shared helpers for the /api/v1/ui tests. Wave-1 packages use these.

// operatorReq builds a loopback request carrying the operator cookie. body is
// JSON-encoded unless it is nil, a string or a []byte.
func operatorReq(t testing.TB, method, path string, body any) *http.Request {
	t.Helper()
	var buf *bytes.Reader
	switch b := body.(type) {
	case nil:
		buf = bytes.NewReader(nil)
	case string:
		buf = bytes.NewReader([]byte(b))
	case []byte:
		buf = bytes.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		buf = bytes.NewReader(data)
	}
	r := httptest.NewRequest(method, path, buf)
	asOperator(r)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

// serveUI runs r through the full handler stack.
func serveUI(t testing.TB, s *Server, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// uiList is a decoded list envelope.
type uiList[T any] struct {
	Items    []T   `json:"items"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
}

// decodeList decodes a list envelope, failing on a non-200.
func decodeList[T any](t testing.TB, w *httptest.ResponseRecorder) uiList[T] {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var out uiList[T]
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list: %v; body = %s", err, w.Body.String())
	}
	return out
}

// decodeUIJSON decodes a JSON body into T, failing when status differs.
//
//nolint:ireturn // T is a concrete type at every call site
func decodeUIJSON[T any](t testing.TB, w *httptest.ResponseRecorder, status int) T {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d, want %d; body = %s", w.Code, status, w.Body.String())
	}
	var out T
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v; body = %s", err, w.Body.String())
	}
	return out
}

// uiErrorBody is the decoded error envelope.
type uiErrorBody struct {
	Error     string            `json:"error"`
	Code      string            `json:"code"`
	Fields    map[string]string `json:"fields"`
	RequestID string            `json:"request_id"`
	Current   map[string]any    `json:"current"`
	ScanID    uint              `json:"scan_id"`
}

// requireUIError asserts an error envelope with status and code.
func requireUIError(t testing.TB, w *httptest.ResponseRecorder, status int, code string) uiErrorBody {
	t.Helper()
	body := decodeUIJSON[uiErrorBody](t, w, status)
	if body.Code != code {
		t.Fatalf("code = %q, want %q; body = %s", body.Code, code, w.Body.String())
	}
	if body.RequestID == "" || body.Error == "" {
		t.Fatalf("envelope missing error/request_id: %s", w.Body.String())
	}
	return body
}

// seedUIRepo creates a repository.
func seedUIRepo(t testing.TB, gdb *gorm.DB, name string) db.Repository {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/acme/" + name, Name: name, FullName: "acme/" + name, Owner: "acme"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	return repo
}

// seedUIScan creates a scan on repo with the given status and skill.
func seedUIScan(t testing.TB, gdb *gorm.DB, repo db.Repository, status db.ScanStatus, skill string) db.Scan {
	t.Helper()
	sc := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: status, StatusPriority: db.StatusPriorityFor(status), SkillName: skill, Log: "line one\n", Report: `{"ok":true,"padding":"xxxxxxxxxxxx"}`}
	if err := gdb.Create(&sc).Error; err != nil {
		t.Fatal(err)
	}
	return sc
}

// seedUIFinding creates a finding on scan.
func seedUIFinding(t testing.TB, gdb *gorm.DB, sc db.Scan, title string, status db.FindingLifecycle) db.Finding {
	t.Helper()
	f := db.Finding{ScanID: sc.ID, RepositoryID: sc.RepositoryID, Title: title, Severity: "High", Status: status,
		Location: "src/app.go:12-14", Commit: "abc123"}
	if err := gdb.Create(&f).Error; err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParseListPage(t *testing.T) {
	cases := []struct {
		query    string
		page     int
		pageSize int
		wantErr  bool
	}{
		{"", 1, uiDefaultPageSize, false},
		{"page=3&page_size=50", 3, 50, false},
		{"page_size=all", 1, uiMaxPageSize, false},
		{"page=0", 0, 0, true},
		{"page=x", 0, 0, true},
		{"page_size=201", 0, 0, true},
		{"page_size=0", 0, 0, true},
	}
	for _, tc := range cases {
		p, err := parseListPage(httptest.NewRequest(http.MethodGet, "/?"+tc.query, nil))
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: want error", tc.query)
			}
			continue
		}
		if err != nil || p.Page != tc.page || p.PageSize != tc.pageSize {
			t.Errorf("%q: got %+v, %v", tc.query, p, err)
		}
	}
}

func TestWriteListEnvelope(t *testing.T) {
	w := httptest.NewRecorder()
	writeListWith(w, []int{1, 2}, 7, listPage{Page: 2, PageSize: 2}, map[string]any{"stats": 1, "total": "ignored"})
	got := decodeList[int](t, w)
	if got.Total != 7 || got.Page != 2 || got.PageSize != 2 || len(got.Items) != 2 {
		t.Fatalf("envelope = %+v", got)
	}
	if cc := w.Header().Get("Cache-Control"); cc != noStore {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

func TestWriteUIErrorEnvelope(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set(requestIDHeader, "req-1")
	writeUIError(w, http.StatusUnprocessableEntity, "", "bad ghsa", map[string]string{"ghsa_id": "invalid"})
	body := requireUIError(t, w, http.StatusUnprocessableEntity, uiCodeValidationFailed)
	if body.RequestID != "req-1" || body.Fields["ghsa_id"] != "invalid" {
		t.Fatalf("body = %+v", body)
	}
}

func TestIfMatch(t *testing.T) {
	stored := time.Date(2026, 10, 28, 17, 12, 48, 511790123, time.UTC)
	cases := []struct {
		header string
		ok     bool
	}{
		{"", true},
		{"*", true},
		{etagFor(stored), true},
		// Postgres keeps microseconds: a nanosecond-trimmed echo still matches.
		{etagFor(stored.Truncate(time.Microsecond)), true},
		{etagFor(stored.Add(time.Second)), false},
		{`"not a time"`, false},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodPatch, "/", nil)
		if tc.header != "" {
			r.Header.Set("If-Match", tc.header)
		}
		w := httptest.NewRecorder()
		if got := checkIfMatch(w, r, stored, map[string]any{"id": 1}); got != tc.ok {
			t.Errorf("If-Match %q: ok = %v, want %v", tc.header, got, tc.ok)
		}
		if !tc.ok {
			body := requireUIError(t, w, http.StatusConflict, uiCodeConflict)
			if body.Current["id"] != float64(1) {
				t.Errorf("conflict current = %v", body.Current)
			}
		}
	}
}

func TestMapEnqueueErr(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{errDeepDiveMissing, http.StatusPreconditionFailed, uiCodePreconditionFailed},
		{db.ErrFindingNonViable, http.StatusPreconditionFailed, uiCodePreconditionFailed},
		{ErrFederationClaimPending, http.StatusConflict, uiCodeFederationClaimed},
		{errRepositoryDeleteInFlight, http.StatusConflict, uiCodeInFlight},
		{ErrRepoFederationOptOut, http.StatusConflict, uiCodeConflict},
		{ErrUnknownEgressPolicy, http.StatusUnprocessableEntity, uiCodeValidationFailed},
		{ErrInvalidMaxCost, http.StatusUnprocessableEntity, uiCodeValidationFailed},
		{ErrInvalidRef, http.StatusUnprocessableEntity, uiCodeValidationFailed},
		{gorm.ErrRecordNotFound, http.StatusNotFound, uiCodeNotFound},
		{errors.New("boom"), http.StatusInternalServerError, uiCodeInternal},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		mapEnqueueErr(w, tc.err)
		requireUIError(t, w, tc.status, tc.code)
	}
}

func TestUILocationRef(t *testing.T) {
	ref := uiLocationRef("./src/a.go:12-14", "c0ffee")
	if ref["path"] != "src/a.go" || ref["line_start"] != 12 || ref["line_end"] != 14 || ref["commit"] != "c0ffee" {
		t.Fatalf("ref = %v", ref)
	}
	if ref := uiLocationRef("src/a.go:7", ""); ref["line_start"] != 7 || ref["line_end"] != nil {
		t.Fatalf("single line ref = %v", ref)
	}
	if uiLocationRef("  ", "") != nil {
		t.Fatal("empty location should be nil")
	}
	if ref := uiLocationRef("web/app.js:42:7", ""); ref["path"] != "web/app.js" || ref["line_start"] != 42 {
		t.Fatalf("SARIF column ref = %v", ref)
	}
	if ref := uiLocationRef("the request router", ""); ref["path"] != "the request router" || ref["line_start"] != 0 {
		t.Fatalf("prose without a file reference = %v", ref)
	}
}

// A model-written prose location (finding 145 in the dev dataset) links each
// file reference it names instead of one bogus path.
func TestUILocationRefsProse(t *testing.T) {
	const loc = "src/lib.rs:214-296 (get_or_try / insert); manifests in src/lib.rs:444-475 (RawIter::next_mut), see ./src/raw.rs:9 and src/lib.rs:214-296"
	refs := uiFindingLocations(loc, nil, "c0ffee")
	want := []struct {
		path       string
		start, end any
	}{{"src/lib.rs", 214, 296}, {"src/lib.rs", 444, 475}, {"src/raw.rs", 9, nil}}
	if len(refs) != len(want) {
		t.Fatalf("refs = %v", refs)
	}
	for i, w := range want {
		if refs[i]["path"] != w.path || refs[i]["line_start"] != w.start || refs[i]["line_end"] != w.end || refs[i]["commit"] != "c0ffee" {
			t.Fatalf("refs[%d] = %v, want %+v", i, refs[i], w)
		}
	}
	if first := uiLocationRef(loc, "c0ffee"); first["path"] != "src/lib.rs" || first["line_start"] != 214 {
		t.Fatalf("location_ref = %v", first)
	}
	// Grouped positions stay one entry each, in order, as the HTML page lists them.
	grouped := uiFindingLocations("a.go:1", []string{"a.go:1", "b.go:2-3"}, "")
	if len(grouped) != 2 || grouped[1]["path"] != "b.go" || grouped[1]["line_end"] != 3 {
		t.Fatalf("grouped = %v", grouped)
	}
	if one := uiFindingLocations("lib/x.rb:5", nil, ""); len(one) != 1 || one[0]["line_start"] != 5 {
		t.Fatalf("single = %v", one)
	}
	if none := uiFindingLocations("", nil, ""); len(none) != 0 {
		t.Fatalf("empty = %v", none)
	}
}

func TestUIFindingRowsProjection(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	repo := seedUIRepo(t, s.DB, "rows")
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, "security-deep-dive")
	f := seedUIFinding(t, s.DB, sc, "SQL injection", db.FindingNew)
	label := db.FindingLabel{Name: "regression", Color: "#ff0000"}
	if err := s.DB.Create(&label).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&f).Association("Labels").Append(&label); err != nil {
		t.Fatal(err)
	}
	var loaded []db.Finding
	s.DB.Find(&loaded)
	rows := s.uiFindingRows(loaded)
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	row := rows[0]
	if row["skill_name"] != "security-deep-dive" || row["title_summary"] != "SQL injection" {
		t.Fatalf("row = %v", row)
	}
	if r := row["repository"].(map[string]any); r["full_name"] != "acme/rows" {
		t.Fatalf("repository = %v", r)
	}
	if labels := row["labels"].([]map[string]any); len(labels) != 1 || labels[0]["name"] != "regression" {
		t.Fatalf("labels = %v", row["labels"])
	}
	if ref := row["location_ref"].(map[string]any); ref["path"] != "src/app.go" {
		t.Fatalf("location_ref = %v", ref)
	}
}

func TestScanRowActions(t *testing.T) {
	skill := uint(1)
	cases := []struct {
		scan db.Scan
		want map[string]bool
	}{
		{db.Scan{Status: db.ScanRunning}, map[string]bool{"cancel": true, "resume": false, "retry": false}},
		{db.Scan{Status: db.ScanPaused}, map[string]bool{"cancel": false, "resume": true, "retry": false}},
		{db.Scan{Status: db.ScanFailed, SkillID: &skill}, map[string]bool{"cancel": false, "resume": false, "retry": true}},
		{db.Scan{Status: db.ScanFailed}, map[string]bool{"cancel": false, "resume": false, "retry": false}},
		{db.Scan{Status: db.ScanDone, SkillID: &skill, MaxTurnsHit: true}, map[string]bool{"cancel": false, "resume": false, "retry": true}},
	}
	for _, tc := range cases {
		got := scanRowActions(tc.scan)
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("%s: %s = %v, want %v", tc.scan.Status, k, got[k], v)
			}
		}
	}
}

// The helpers below are what wave-1 handlers are built from; exercise each so
// their contract is pinned before the first caller lands.
func TestUIWriteHelpers(t *testing.T) {
	w := httptest.NewRecorder()
	writeList(w, []string{}, 0, listPage{Page: 1, PageSize: uiDefaultPageSize})
	if got := decodeList[string](t, w); got.Items == nil || got.Total != 0 {
		t.Fatalf("empty list = %+v", got)
	}

	w = httptest.NewRecorder()
	enqueueResult(w, 42)
	if got := decodeUIJSON[map[string]uint](t, w, http.StatusAccepted); got["scan_id"] != 42 {
		t.Fatalf("enqueueResult = %v", got)
	}
	w = httptest.NewRecorder()
	enqueueBatchResult(w, enqueueBatch{Queued: 0, Message: "nothing to do"})
	if got := decodeUIJSON[map[string]any](t, w, http.StatusAccepted); got["scan_ids"] == nil || got["message"] != "nothing to do" {
		t.Fatalf("enqueueBatchResult = %v", got)
	}

	w = httptest.NewRecorder()
	writeUIFields(w, fmt.Errorf("wrapped: %w", uiFieldErrors{"severity": "must be one of Low Medium High Critical"}))
	if body := requireUIError(t, w, http.StatusUnprocessableEntity, uiCodeValidationFailed); body.Fields["severity"] == "" {
		t.Fatalf("fields = %v", body.Fields)
	}
	if apiFieldsError(errors.New("plain")) != nil {
		t.Fatal("plain error has no fields")
	}

	w = httptest.NewRecorder()
	uiDBError(w, gorm.ErrRecordNotFound, "finding")
	requireUIError(t, w, http.StatusNotFound, uiCodeNotFound)
	w = httptest.NewRecorder()
	uiDBError(w, errors.New("db down"), "finding")
	requireUIError(t, w, http.StatusInternalServerError, uiCodeInternal)

	ts := time.Date(2026, 1, 2, 3, 4, 5, 600, time.UTC)
	w = httptest.NewRecorder()
	setETag(w, ts)
	r := httptest.NewRequest(http.MethodPatch, "/", nil)
	r.Header.Set("If-Match", w.Header().Get("ETag"))
	if got, ok := ifMatch(r); !ok || !got.Equal(ts) {
		t.Fatalf("ETag round trip = %v %v", got, ok)
	}

	var ob orderBy = func(token string) (string, string) { return "id desc", token }
	if expr, eff := ob("newest"); expr != "id desc" || eff != "newest" {
		t.Fatal("orderBy signature")
	}
}

func TestUIPathID(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /x/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, ok := uiPathID(w, r, "id")
		if ok {
			writeUIJSON(w, http.StatusOK, map[string]uint{"id": id})
		}
	})
	_ = s
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x/7", nil))
	if got := decodeUIJSON[map[string]uint](t, w, http.StatusOK); got["id"] != 7 {
		t.Fatalf("id = %v", got)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x/abc", nil))
	requireUIError(t, w, http.StatusBadRequest, uiCodeBadParam)
}

func TestUIRepoRow(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	repo := seedUIRepo(t, s.DB, "rr")
	s.DB.Model(&repo).Updates(map[string]any{"archived": true, "default_branch": "main"})
	s.DB.First(&repo, repo.ID)
	row := uiRepoRow(repositoryExportRow{ID: repo.ID, URL: repo.URL, Name: repo.Name, FullName: repo.FullName}, repo)
	if row["archived"] != true || row["default_branch"] != "main" || row["last_scan"] != nil || row["federation_opted_out"] != false {
		t.Fatalf("row = %v", row)
	}
}
