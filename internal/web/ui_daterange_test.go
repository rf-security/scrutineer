package web

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

func TestParseUIDateRange(t *testing.T) {
	day := func(s string) time.Time {
		v, err := time.Parse(uiDateOnly, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cases := []struct {
		query   string
		from    time.Time
		to      time.Time
		toExcl  bool
		wantErr bool
	}{
		{query: ""},
		{query: "date_from=2026-10-01", from: day("2026-10-01")},
		// A date-only date_to includes that whole day.
		{query: "date_to=2026-10-05", to: day("2026-10-06"), toExcl: true},
		{query: "date_from=2026-10-05&date_to=2026-10-05", from: day("2026-10-05"), to: day("2026-10-06"), toExcl: true},
		{query: "date_from=2026-10-01T08:00:00%2B02:00", from: time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)},
		{query: "date_to=2026-10-01T08:00:00.5Z", to: time.Date(2026, 10, 1, 8, 0, 0, 5e8, time.UTC)},
		{query: "date_from=yesterday", wantErr: true},
		{query: "date_to=2026-13-01", wantErr: true},
		{query: "date_from=2026-10-01T08:00", wantErr: true},
		{query: "date_from=2026-10-06&date_to=2026-10-05", wantErr: true},
		{query: "date_from=2026-10-05T12:00:00Z&date_to=2026-10-05T11:00:00Z", wantErr: true},
	}
	for _, c := range cases {
		q, err := url.ParseQuery(c.query)
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseUIDateRange(q)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: want error, got %+v", c.query, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.query, err)
			continue
		}
		if !got.from.Equal(c.from) || !got.to.Equal(c.to) || got.toExclusive != c.toExcl {
			t.Errorf("%q = %+v, want from %v to %v excl %v", c.query, got, c.from, c.to, c.toExcl)
		}
	}
}

// dateFixtureTimes are the created_at values the date tests seed, in the
// server's local zone (the zone GORM writes time.Now() in). The last two tie,
// so the id tiebreak decides their order.
func dateFixtureTimes() []time.Time {
	utc := func(d, h, m int) time.Time { return time.Date(2026, 10, d, h, m, 0, 0, time.UTC).Local() }
	return []time.Time{
		utc(1, 10, 0),  // 0: before the window
		utc(5, 23, 30), // 1: last half hour of Oct 5 (inclusive date_to)
		utc(6, 0, 0),   // 2: first instant of Oct 6
		utc(10, 12, 0), // 3: tie …
		utc(10, 12, 0), // 4: … tie
	}
}

func setCreatedAt(t *testing.T, gdb *gorm.DB, model any, id uint, at time.Time) {
	t.Helper()
	if err := gdb.Model(model).Where("id = ?", id).UpdateColumn("created_at", at).Error; err != nil {
		t.Fatal(err)
	}
}

func rowIDs(items []map[string]any) []uint {
	out := make([]uint, len(items))
	for i, it := range items {
		out[i] = uint(it["id"].(float64))
	}
	return out
}

func requireIDs(t *testing.T, what string, got, want []uint) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s ids = %v, want %v", what, got, want)
	}
}

// seedDatedScans seeds one scan per fixture time and returns their ids.
func seedDatedScans(t *testing.T, s *Server, repo db.Repository) []uint {
	t.Helper()
	ids := []uint{}
	for _, at := range dateFixtureTimes() {
		sc := seedUIScan(t, s.DB, repo, db.ScanDone, "security-deep-dive")
		setCreatedAt(t, s.DB, &db.Scan{}, sc.ID, at)
		ids = append(ids, sc.ID)
	}
	return ids
}

// seedDatedFindings seeds one finding per fixture time (alternating
// severity, so facet counts have two buckets) and returns their ids.
func seedDatedFindings(t *testing.T, s *Server, repo db.Repository) []uint {
	t.Helper()
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, "security-deep-dive")
	ids := []uint{}
	for i, at := range dateFixtureTimes() {
		f := seedUIFinding(t, s.DB, sc, "f"+itoa(uint(i)), db.FindingNew)
		if i%2 == 1 {
			s.DB.Model(&f).UpdateColumn("severity", "Low")
		}
		setCreatedAt(t, s.DB, &db.Finding{}, f.ID, at)
		ids = append(ids, f.ID)
	}
	return ids
}

func TestUIScanListDateFilterAndSort(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	repo := seedUIRepo(t, s.DB, "dated")
	id := seedDatedScans(t, s, repo)
	get := func(q string) uiList[map[string]any] {
		t.Helper()
		return decodeList[map[string]any](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/scans"+q, nil)))
	}

	// Sort: desc by default and on .desc, id breaks the created_at tie.
	requireIDs(t, "date", rowIDs(get("?sort=date").Items), []uint{id[4], id[3], id[2], id[1], id[0]})
	requireIDs(t, "date.desc", rowIDs(get("?sort=date.desc").Items), []uint{id[4], id[3], id[2], id[1], id[0]})
	requireIDs(t, "date.asc", rowIDs(get("?sort=date.asc").Items), []uint{id[0], id[1], id[2], id[3], id[4]})

	// Filter: date-only date_to includes the whole day; date_from starts at midnight.
	if got := get("?date_to=2026-10-05&sort=date.asc"); got.Total != 2 {
		t.Errorf("date_to total = %d", got.Total)
	} else {
		requireIDs(t, "date_to", rowIDs(got.Items), []uint{id[0], id[1]})
	}
	if got := get("?date_from=2026-10-06&sort=date.asc"); got.Total != 3 {
		t.Errorf("date_from total = %d", got.Total)
	} else {
		requireIDs(t, "date_from", rowIDs(got.Items), []uint{id[2], id[3], id[4]})
	}
	if got := get("?date_from=2026-10-05&date_to=2026-10-06"); got.Total != 2 {
		t.Errorf("window total = %d", got.Total)
	}
	if got := get("?date_from=2026-10-05T23:45:00Z&date_to=2026-10-10T12:00:00Z"); got.Total != 3 {
		t.Errorf("RFC3339 window total = %d (to is inclusive)", got.Total)
	}

	for _, bad := range []string{"?date_from=yesterday", "?date_to=2026-02-30", "?date_from=2026-10-07&date_to=2026-10-06"} {
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/scans"+bad, nil)), http.StatusBadRequest, uiCodeBadParam)
	}
}

func TestUIFindingListDateFilterAndSort(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	repo := seedUIRepo(t, s.DB, "dated")
	id := seedDatedFindings(t, s, repo)
	type list struct {
		uiList[map[string]any]
		Facets map[string]map[string]int64 `json:"facets"`
	}
	get := func(q string) list {
		t.Helper()
		return decodeUIJSON[list](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/findings"+q, nil)), http.StatusOK)
	}

	requireIDs(t, "date", rowIDs(get("?sort=date").Items), []uint{id[4], id[3], id[2], id[1], id[0]})
	requireIDs(t, "date.asc", rowIDs(get("?sort=date.asc").Items), []uint{id[0], id[1], id[2], id[3], id[4]})

	got := get("?date_to=2026-10-05&sort=date.asc&facets=severity,status")
	if got.Total != 2 {
		t.Fatalf("date_to total = %d", got.Total)
	}
	requireIDs(t, "date_to", rowIDs(got.Items), []uint{id[0], id[1]})
	// Facets count inside the date window: one High (id0) and one Low (id1).
	if got.Facets["severity"]["High"] != 1 || got.Facets["severity"]["Low"] != 1 || got.Facets["status"]["all"] != 2 {
		t.Errorf("facets = %v", got.Facets)
	}
	if got := get("?date_from=2026-10-06&facets=severity"); got.Total != 3 || got.Facets["severity"]["High"] != 2 || got.Facets["severity"]["Low"] != 1 {
		t.Errorf("date_from total = %d facets = %v", got.Total, got.Facets)
	}

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/findings?date_to=soon", nil)), http.StatusBadRequest, uiCodeBadParam)
}

func TestUIRepoTabsDateFilterAndSort(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	repo := seedUIRepo(t, s.DB, "dated")
	fid := seedDatedFindings(t, s, repo)
	ids := func(m map[string]any) []uint {
		items := m["items"].([]any)
		out := make([]uint, len(items))
		for i, it := range items {
			out[i] = uint(it.(map[string]any)["id"].(float64))
		}
		return out
	}

	// Findings tab: sort + filter.
	requireIDs(t, "tab date", ids(getUI(t, s, repoPath(repo.ID, "/findings?sort=date"))), []uint{fid[4], fid[3], fid[2], fid[1], fid[0]})
	requireIDs(t, "tab date.asc", ids(getUI(t, s, repoPath(repo.ID, "/findings?sort=date.asc"))), []uint{fid[0], fid[1], fid[2], fid[3], fid[4]})
	inDay := getUI(t, s, repoPath(repo.ID, "/findings?date_from=2026-10-05&date_to=2026-10-05"))
	if inDay["total"] != float64(1) {
		t.Errorf("findings tab one-day total = %v", inDay["total"])
	}
	requireIDs(t, "tab one day", ids(inDay), []uint{fid[1]})
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/findings?date_from=nope"), nil)), http.StatusBadRequest, uiCodeBadParam)

	// Scans tab, full history: filter + sort through the /ui/scans params.
	// seedDatedFindings made one scan first (created now); the dated scans follow.
	sid := seedDatedScans(t, s, repo)
	requireIDs(t, "history date.asc", ids(getUI(t, s, repoPath(repo.ID, "/scans?latest=0&sort=date.asc&date_to=2026-10-10"))), sid)
	hist := getUI(t, s, repoPath(repo.ID, "/scans?latest=0&date_from=2026-10-06"))
	if hist["total"] != float64(4) { // three dated scans + the findings' scan (created now)
		t.Errorf("history date_from total = %v", hist["total"])
	}
	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, repoPath(repo.ID, "/scans?latest=0&date_to=x"), nil)), http.StatusBadRequest, uiCodeBadParam)

	// Latest set: one attempt per skill (the newest id), so sort only reorders
	// that set and never picks a different attempt.
	other := seedUIScan(t, s.DB, repo, db.ScanDone, "triage")
	setCreatedAt(t, s.DB, &db.Scan{}, other.ID, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).Local())
	latest := getUI(t, s, repoPath(repo.ID, "/scans?sort=date.asc"))
	requireIDs(t, "latest date.asc", ids(latest), []uint{other.ID, sid[4]})
	requireIDs(t, "latest date.desc", ids(getUI(t, s, repoPath(repo.ID, "/scans?sort=date.desc"))), []uint{sid[4], other.ID})
	requireIDs(t, "latest default", ids(getUI(t, s, repoPath(repo.ID, "/scans"))), []uint{other.ID, sid[4]})
}
