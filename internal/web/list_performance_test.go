package web

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"

	"gorm.io/gorm"
)

func TestListPagesQueryCountsStayBounded(t *testing.T) {
	cases := []struct {
		name string
		path string
		max  int64
	}{
		{name: "repositories", path: "/", max: 8},
		{name: "findings", path: "/findings", max: 8},
		{name: "scans", path: "/scans", max: 6},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oneRow := listPageQueryCount(t, tc.path, 1)
			manyRows := listPageQueryCount(t, tc.path, 60)

			if manyRows > oneRow+1 {
				t.Fatalf("%s query count grew with rows: 1 row=%d, 60 rows=%d", tc.path, oneRow, manyRows)
			}
			if manyRows > tc.max {
				t.Fatalf("%s ran %d queries, want <= %d", tc.path, manyRows, tc.max)
			}
		})
	}
}

func TestScanListStatsAggregatesCounts(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/stats", Name: "stats"}
	s.DB.Create(&repo)
	for _, status := range []db.ScanStatus{db.ScanQueued, db.ScanQueued, db.ScanPaused, db.ScanRunning} {
		s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: status})
	}
	// A scan paused because the account hit an account-level Claude problem
	// (auto-paused by the worker), plus an unrelated failure that must not
	// be counted.
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID,
		Kind:         "skill",
		Status:       db.ScanPaused,
		Error:        worker.AccountPausePrefix + " Queued scan paused automatically; resume once the account recovers.",
	})
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID,
		Kind:         "skill",
		Status:       db.ScanFailed,
		Error:        "different failure",
	})

	// PausedCount counts both the bare paused scan and the account-paused one;
	// AccountPausedCount counts only the latter.
	stats := s.scanListStats()
	if stats.QueuedCount != 2 || stats.PausedCount != 2 || stats.AccountPausedCount != 1 {
		t.Fatalf("scanListStats = %+v, want queued=2 paused=2 account-paused=1", stats)
	}
}

func BenchmarkListPagesLargeDataset(b *testing.B) {
	s, done := newTestServer(b)
	defer done()
	seedListPagePerfFixtures(b, s, 500)
	handler := s.Handler()

	for _, path := range []string{"/", "/findings", "/scans"} {
		b.Run(path, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, localReq("GET", path))
				if w.Code != 200 {
					b.Fatalf("%s status %d: %s", path, w.Code, w.Body)
				}
			}
		})
	}
}

// The repo list renders the disk-usage badge from Repository.DiskBytes, not
// by walking each repo's clone cache per row (#126). Seeding the column with
// no cache directory on disk and seeing the size render proves the column is
// the source: the old per-row filepath.Walk would have found nothing and
// shown "-".
func TestRepoList_diskBadgeReadsCachedColumn(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/sized", Name: "sized", DiskBytes: 2048}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	row := requireRepoListRow(t, w.Body.String(), repo.ID)
	if !strings.Contains(row, "2.0 KB") {
		t.Errorf("repo row did not render cached disk size from the column: %s", row)
	}
}

func TestRepoList_projectsRenderedRepositoryColumns(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{
		URL:        "https://example.com/rendered-fields",
		Name:       "rendered-fields",
		Languages:  "Go, Ruby",
		Health:     db.RepositoryHealthActive,
		CloneError: "clone unavailable",
		DiskBytes:  2048,
	}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	listSQL := captureRepoListSQL(t, s)
	handler := s.Handler()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, localReq("GET", "/"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	row := requireRepoListRow(t, w.Body.String(), repo.ID)
	for _, want := range []string{
		"example.com/rendered-fields", "Go, Ruby", string(db.RepositoryHealthActive),
		"clone unavailable", "2.0 KB",
	} {
		if !strings.Contains(row, want) {
			t.Errorf("repo row missing rendered field %q: %s", want, row)
		}
	}

	if *listSQL == "" {
		t.Fatal("did not capture repository list query")
	}
	projection := func(sql string) string {
		selectClause, _, _ := strings.Cut(strings.ToLower(sql), " from ")
		selectClause = strings.TrimPrefix(selectClause, "select ")
		selectClause = strings.ReplaceAll(selectClause, "`", "")
		selectClause = strings.ReplaceAll(selectClause, "repositories.", "")
		return strings.ReplaceAll(selectClause, " ", "")
	}
	const wantProjection = "id,url,languages,health,clone_error,disk_bytes"
	if got := projection(*listSQL); got != wantProjection {
		t.Errorf("repository list query projection = %s, want %s", got, wantProjection)
	}
	lowerSQL := strings.ToLower(*listSQL)
	if strings.Contains(lowerSQL, "select *") {
		t.Errorf("repository list query hydrates every column: %s", *listSQL)
	}
	for _, blobColumn := range []string{
		"metadata", "threat_model", "scan_config",
		"ecosystems_repo_data", "ecosystems_packages_data", "ecosystems_advisories_data",
		"ecosystems_commits_data", "ecosystems_issues_data", "ecosystems_dependents_data",
	} {
		if strings.Contains(lowerSQL, blobColumn) {
			t.Errorf("repository list query hydrates %s: %s", blobColumn, *listSQL)
		}
	}

	// Every sort branch shares the one Find, so clearing between requests
	// catches a branch that stops issuing it rather than rechecking the
	// statement the previous request left behind.
	for _, sort := range []string{"name", "stars", "language", "size", "findings", "scanned", statusKey} {
		*listSQL = ""
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, localReq("GET", "/?sort="+sort))
		if w.Code != 200 {
			t.Fatalf("sort %s status %d: %s", sort, w.Code, w.Body)
		}
		if got := projection(*listSQL); got != wantProjection {
			t.Errorf("sort %s repository projection = %s, want %s", sort, got, wantProjection)
		}
	}
}

// The default newest-first order runs on every / and /repositories render.
// Without an index on updated_at SQLite scans the whole table and builds a
// temporary sort, dragging each row's large cache columns through it: the
// projection alone leaves that scan in place, so both halves of the fix have
// to hold for the page to stay fast.
func TestRepoList_defaultSortUsesUpdatedAtIndex(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/indexed-order", Name: "indexed-order"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	listSQL := captureRepoListSQL(t, s)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if *listSQL == "" {
		t.Fatal("did not capture repository list query")
	}

	var plan []struct{ Detail string }
	if err := s.DB.Raw("EXPLAIN QUERY PLAN " + *listSQL).Scan(&plan).Error; err != nil {
		t.Fatal(err)
	}
	joinedPlan := fmt.Sprint(plan)
	if !strings.Contains(joinedPlan, "USING INDEX idx_repositories_updated_at") {
		t.Errorf("repository list query plan does not use updated_at index: %s", joinedPlan)
	}
	if strings.Contains(joinedPlan, "USE TEMP B-TREE FOR ORDER BY") {
		t.Errorf("repository list query plan still builds a temporary sort: %s", joinedPlan)
	}
}

// captureRepoListSQL returns a handle on the SELECT the repository list last
// issued, so a test can assert against the statement the handler really ran
// rather than one it rebuilt itself. The callback outlives the test by design:
// it is scoped to the per-test database newTestServer closes on cleanup, and
// GORM logs a warning on every callback removal.
func captureRepoListSQL(t *testing.T, s *Server) *string {
	t.Helper()
	var listSQL string
	name := fmt.Sprintf("scrutineer:test-repo-list-sql:%d", time.Now().UnixNano())
	if err := s.DB.Callback().Query().After("gorm:query").Register(name, func(tx *gorm.DB) {
		if _, ok := tx.Statement.Dest.(*[]repoListFields); ok && tx.Statement.Table == "repositories" {
			listSQL = tx.Statement.SQL.String()
		}
	}); err != nil {
		t.Fatal(err)
	}
	return &listSQL
}

func BenchmarkRepoListLargeCachedRows(b *testing.B) {
	s, done := newTestServer(b)
	defer done()

	const (
		repositories = 75
		blobBytes    = 256 << 10
	)
	blob := strings.Repeat("x", blobBytes)
	repoIDs := make([]uint, 0, repositories)
	for i := 0; i < repositories; i++ {
		repo := db.Repository{
			URL:                      fmt.Sprintf("https://example.com/large-%03d", i),
			Name:                     fmt.Sprintf("large-%03d", i),
			Languages:                "Go",
			Metadata:                 blob,
			EcosystemsRepoData:       blob,
			EcosystemsPackagesData:   blob,
			EcosystemsAdvisoriesData: blob,
			EcosystemsCommitsData:    blob,
			EcosystemsIssuesData:     blob,
			EcosystemsDependentsData: blob,
		}
		if err := s.DB.Create(&repo).Error; err != nil {
			b.Fatal(err)
		}
		repoIDs = append(repoIDs, repo.ID)
	}

	// Build the mux once, as main does. Re-registering ~200 routes per
	// iteration costs ~200us and ~2200 allocations, which would otherwise
	// swamp the allocation figure this benchmark exists to watch.
	handler := s.Handler()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, localReq("GET", "/"))
	if w.Code != 200 {
		b.Fatalf("fixture status %d: %s", w.Code, w.Body)
	}
	lastRepoID := repoIDs[len(repoIDs)-1]
	if !strings.Contains(w.Body.String(), fmt.Sprintf(`<tr id="repo-%d">`, lastRepoID)) {
		b.Fatalf("fixture repository %d did not render", lastRepoID)
	}
	run := func(b *testing.B) {
		b.Helper()
		b.ReportAllocs()
		b.ReportMetric(float64(repositories*7*blobBytes)/(1<<20), "cache-MiB")
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, localReq("GET", "/"))
			if w.Code != 200 {
				b.Fatalf("status %d: %s", w.Code, w.Body)
			}
		}
	}

	b.Run("idle", run)
	b.Run("with-enrichment-writes", func(b *testing.B) {
		stop := make(chan struct{})
		done := make(chan struct{})
		// RefreshEcosystems writes each source as a single-row UPDATE of that
		// source's cached payload column. Keep one such writer active to
		// exercise WAL read/write concurrency without involving the network
		// or a live database.
		go func() {
			defer close(done)
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				_ = s.DB.Model(&db.Repository{}).
					Where("id = ?", repoIDs[i%len(repoIDs)]).
					Update("ecosystems_issues_data", blob).Error
			}
		}()
		b.Cleanup(func() {
			close(stop)
			<-done
		})
		run(b)
	})
}

func listPageQueryCount(t *testing.T, path string, rows int) int64 {
	t.Helper()
	s, done := newTestServer(t)
	defer done()
	seedListPagePerfFixtures(t, s, rows)
	getCount := countDBQueries(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))
	if w.Code != 200 {
		t.Fatalf("%s status %d: %s", path, w.Code, w.Body)
	}
	return getCount()
}

func countDBQueries(t testing.TB, s *Server) func() int64 {
	t.Helper()
	var count atomic.Int64
	name := fmt.Sprintf("scrutineer:test-query-count:%d", time.Now().UnixNano())
	callback := func(*gorm.DB) {
		count.Add(1)
	}
	if err := s.DB.Callback().Query().Before("gorm:query").Register(name+":query", callback); err != nil {
		t.Fatal(err)
	}
	// GORM routes statements through three processors: Find/First/Pluck use
	// Query, Scan (including Raw(...).Scan) uses Row, and Exec uses Raw.
	// Register on all three so the bound counts every statement a handler
	// issues rather than whichever processor it happens to reach for.
	if err := s.DB.Callback().Row().Before("gorm:row").Register(name+":row", callback); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Callback().Raw().Before("gorm:raw").Register(name+":raw", callback); err != nil {
		t.Fatal(err)
	}
	return count.Load
}

func seedListPagePerfFixtures(t testing.TB, s *Server, rows int) {
	t.Helper()
	for i := 0; i < rows; i++ {
		repo := db.Repository{
			URL:         fmt.Sprintf("https://example.com/repo-%03d", i),
			Name:        fmt.Sprintf("repo-%03d", i),
			FullName:    fmt.Sprintf("org/repo-%03d", i),
			Owner:       "org",
			Description: "fixture repository",
			Languages:   "Go, Java",
		}
		if err := s.DB.Create(&repo).Error; err != nil {
			t.Fatal(err)
		}
		scan := db.Scan{
			RepositoryID:   repo.ID,
			Kind:           "skill",
			Status:         db.ScanDone,
			StatusPriority: db.StatusPriorityFor(db.ScanDone),
			SkillName:      deepDiveSkillName,
			FindingsCount:  2,
			Ref:            "main",
		}
		if err := s.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.DB.Create(&db.Scan{
			RepositoryID:   repo.ID,
			Kind:           "skill",
			Status:         db.ScanQueued,
			StatusPriority: db.StatusPriorityFor(db.ScanQueued),
			SkillName:      "metadata",
		}).Error; err != nil {
			t.Fatal(err)
		}
		for j, severity := range []string{"High", "Medium"} {
			if err := s.DB.Create(&db.Finding{
				ScanID:       scan.ID,
				RepositoryID: repo.ID,
				FindingID:    fmt.Sprintf("F%d-%d", i, j),
				Title:        fmt.Sprintf("finding %d-%d", i, j),
				Severity:     severity,
				Status:       db.FindingNew,
			}).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
}
