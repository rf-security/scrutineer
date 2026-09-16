package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"scrutineer/internal/db"
)

func TestExportScans_filters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/export-filters"}
	other := db.Repository{URL: "https://example.com/other-export"}
	for _, row := range []*db.Repository{&repo, &other} {
		if err := s.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	cutoff := time.Date(2026, time.September, 1, 12, 0, 0, 123456789, time.UTC)
	scans := []db.Scan{
		{RepositoryID: repo.ID, Kind: "skill", SkillName: "audit", Status: db.ScanDone, CreatedAt: cutoff},
		{RepositoryID: repo.ID, Kind: "skill", SkillName: "audit", Status: db.ScanDone, CreatedAt: cutoff.Add(-time.Nanosecond), UpdatedAt: cutoff.Add(time.Hour)},
		{RepositoryID: repo.ID, Kind: "import", SkillName: "audit", Status: db.ScanDone, CreatedAt: cutoff},
		{RepositoryID: other.ID, Kind: "skill", SkillName: "audit", Status: db.ScanDone, CreatedAt: cutoff},
		{RepositoryID: repo.ID, Kind: "skill", SkillName: "audit", Status: db.ScanQueued, CreatedAt: cutoff},
		{RepositoryID: repo.ID, Kind: "skill", SkillName: "recon", Status: db.ScanDone, CreatedAt: cutoff},
		{RepositoryID: repo.ID, Kind: "exposure", Status: db.ScanDone, CreatedAt: cutoff},
	}
	if err := s.DB.Create(&scans).Error; err != nil {
		t.Fatal(err)
	}
	repoID := strconv.FormatUint(uint64(repo.ID), 10)
	for _, tt := range []struct {
		name  string
		query url.Values
		want  []int
	}{
		{"unfiltered", nil, []int{6, 5, 4, 3, 2, 1, 0}},
		{"repository", url.Values{"repository_id": {repoID}}, []int{6, 5, 4, 2, 1, 0}},
		{"missing repository", url.Values{"repository_id": {"9223372036854775807"}}, nil},
		{"import kind", url.Values{"kind": {"import"}}, []int{2}},
		{"exposure kind", url.Values{"kind": {"exposure"}}, []int{6}},
		{"unknown kind", url.Values{"kind": {"future-kind"}}, nil},
		{"case sensitive kind", url.Values{"kind": {"SKILL"}}, nil},
		{"empty kind", url.Values{"kind": {""}}, []int{6, 5, 4, 3, 2, 1, 0}},
		{"since", url.Values{"since": {cutoff.Format(time.RFC3339Nano)}}, []int{6, 5, 4, 3, 2, 0}},
		{"future since", url.Values{"since": {cutoff.Add(time.Hour).Format(time.RFC3339Nano)}}, nil},
		{"combined", url.Values{
			"repository_id": {repoID}, "kind": {"skill"}, "status": {"done"}, "skill": {"audit"},
			"since": {cutoff.Format(time.RFC3339Nano)},
		}, []int{0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := exportScanIDs(t, s, tt.query)
			var want []uint
			for _, index := range tt.want {
				want = append(want, scans[index].ID)
			}
			if !slices.Equal(got, want) {
				t.Errorf("scan IDs = %v, want %v", got, want)
			}
		})
	}
}

func TestExportScans_sinceOffsetsAndPrecision(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/export-time"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	for _, instant := range []string{"2026-09-01T12:00:00Z", "2026-09-01T12:00:00.123456789Z", "2026-09-01T12:00:00.999999999Z"} {
		t.Run(instant, func(t *testing.T) {
			cutoff, err := time.Parse(time.RFC3339Nano, instant)
			if err != nil {
				t.Fatal(err)
			}
			for _, offset := range []string{"+00:00", "-07:00", "+05:30"} {
				t.Run(offset, func(t *testing.T) {
					checkExportScanCutoff(t, s, repo.ID, cutoff, offset)
				})
			}
		})
	}
}

func checkExportScanCutoff(t *testing.T, s *Server, repoID uint, cutoff time.Time, offset string) {
	t.Helper()
	zone, err := time.Parse("-07:00", offset)
	if err != nil {
		t.Fatal(err)
	}
	var scans []db.Scan
	for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		scans = append(scans, db.Scan{RepositoryID: repoID, Kind: "skill", Status: db.ScanDone,
			CreatedAt: cutoff.Add(delta).In(zone.Location())})
	}
	if err := s.DB.Create(&scans).Error; err != nil {
		t.Fatal(err)
	}
	for _, since := range []time.Time{cutoff, cutoff.In(zone.Location())} {
		params := url.Values{"since": {since.Format(time.RFC3339Nano)}}
		got := exportScanIDs(t, s, params)
		if want := []uint{scans[2].ID, scans[1].ID}; !slices.Equal(got, want) {
			t.Errorf("since %s: scan IDs = %v, want %v", since, got, want)
		}
	}
	if err := s.DB.Delete(&scans).Error; err != nil {
		t.Fatal(err)
	}
}

func exportScanIDs(t *testing.T, s *Server, params url.Values) []uint {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/api/v1/scans?"+params.Encode()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var ids []uint
	for _, row := range readJSONL(t, w.Body.String()) {
		ids = append(ids, uint(row["id"].(float64)))
	}
	return ids
}

func TestExportScans_rejectsInvalidFiltersBeforeStreaming(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedFindings(t, s)
	for _, query := range []string{
		"repository_id=", "repository_id=0", "repository_id=-1", "repository_id=abc",
		"repository_id=1.5", "repository_id=9223372036854775808",
		"since=", "since=yesterday", "since=2026-09-01", "since=2026-09-01T12:00:00",
		"since=2026-02-30T12:00:00Z",
	} {
		t.Run(query, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/api/v1/scans?"+query))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if got := w.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
				t.Errorf("Content-Type = %q, want JSON error before JSONL streaming", got)
			}
		})
	}
}
