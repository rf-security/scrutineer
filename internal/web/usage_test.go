package web

import (
	"fmt"
	"math"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func almostEq(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestPercentile(t *testing.T) {
	cases := []struct {
		xs   []float64
		p    float64
		want float64
	}{
		{[]float64{5}, 0.5, 5},
		{[]float64{1, 2, 3, 4}, 0.5, 2.5},
		{[]float64{1, 2, 3, 4, 5}, 0.5, 3},
		{[]float64{0, 10}, 0.9, 9},
		{[]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.9, 9.1},
		{[]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 1.0, 10},
		{[]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.0, 1},
	}
	for _, tc := range cases {
		if got := percentile(tc.xs, tc.p); !almostEq(got, tc.want) {
			t.Errorf("percentile(%v, %v) = %v, want %v", tc.xs, tc.p, got, tc.want)
		}
	}
}

func TestSummarise(t *testing.T) {
	got := summarise([]float64{4, 1, 3, 2})
	if !almostEq(got.Min, 1) || !almostEq(got.Max, 4) || !almostEq(got.Sum, 10) || !almostEq(got.Median, 2.5) {
		t.Errorf("summarise = %+v", got)
	}
	if z := summarise(nil); z != (Stats{}) {
		t.Errorf("empty summarise = %+v", z)
	}
}

func TestUsageDriverReportParsing(t *testing.T) {
	t.Run("repo overview SLOC", func(t *testing.T) {
		got, ok := repoOverviewSLOC(`{"lines":{"total_lines":1234}}`)
		if !ok || got != 1234 {
			t.Fatalf("repoOverviewSLOC = %v, %v, want 1234, true", got, ok)
		}
		if _, ok := repoOverviewSLOC(`{"lines":{"total_files":12}}`); ok {
			t.Fatal("repoOverviewSLOC accepted report without total_lines")
		}
	})

	t.Run("deep dive sinks", func(t *testing.T) {
		got, ok := deepDiveSinkCount(`{"inventory":[{"id":"S1"},{"id":"S2"}]}`)
		if !ok || got != 2 {
			t.Fatalf("deepDiveSinkCount = %v, %v, want 2, true", got, ok)
		}
		if _, ok := deepDiveSinkCount(`{"findings":[]}`); ok {
			t.Fatal("deepDiveSinkCount accepted report without inventory")
		}
	})
}

func TestPearsonCorrelation(t *testing.T) {
	positive := []usageDriverPair{{Driver: 1, Cost: 2}, {Driver: 2, Cost: 4}, {Driver: 3, Cost: 6}}
	if got, ok := pearsonCorrelation(positive); !ok || !almostEq(got, 1) {
		t.Fatalf("positive correlation = %v, %v, want 1, true", got, ok)
	}
	negative := []usageDriverPair{{Driver: 1, Cost: 6}, {Driver: 2, Cost: 4}, {Driver: 3, Cost: 2}}
	if got, ok := pearsonCorrelation(negative); !ok || !almostEq(got, -1) {
		t.Fatalf("negative correlation = %v, %v, want -1, true", got, ok)
	}
	if _, ok := pearsonCorrelation(positive[:2]); ok {
		t.Fatal("two samples produced a correlation")
	}
	constant := []usageDriverPair{{Driver: 1, Cost: 2}, {Driver: 1, Cost: 3}, {Driver: 1, Cost: 4}}
	if _, ok := pearsonCorrelation(constant); ok {
		t.Fatal("constant driver produced a correlation")
	}
}

func TestUsageDriverValuesByScan_appliesRootMeasurements(t *testing.T) {
	scans := []db.Scan{
		{ID: 10, RepositoryID: 1, SkillName: "repo-overview"},
		{ID: 11, RepositoryID: 1, SkillName: "dependencies"},
		{ID: 12, RepositoryID: 1, SkillName: "security-deep-dive"},
		{ID: 20, RepositoryID: 1},
		{ID: 21, RepositoryID: 1, SubPath: "cmd/tool"},
		{ID: 22, RepositoryID: 1, FocusArea: `{"name":"parser"}`},
	}
	got := usageDriverValuesByScan(scans, map[uint]int{1: 100}, map[uint]int{1: 1}, map[uint]int{12: 2})
	if got[20].SLOC == nil || *got[20].SLOC != 100 || got[20].Manifests == nil || *got[20].Manifests != 1 {
		t.Fatalf("root values = %+v, want SLOC 100 and manifests 1", got[20])
	}
	for _, id := range []uint{21, 22} {
		if got[id].SLOC != nil || got[id].Manifests != nil {
			t.Errorf("scan %d inherited root-only values: %+v", id, got[id])
		}
	}
	if got[10].SLOC != nil {
		t.Errorf("repo-overview correlated against its own output: %+v", got[10])
	}
	if got[11].Manifests != nil {
		t.Errorf("dependencies correlated against its own output: %+v", got[11])
	}
	if got[12].Sinks == nil || *got[12].Sinks != 2 {
		t.Fatalf("deep-dive sink count = %+v, want 2", got[12])
	}
}

func TestUsageDriverLoaders(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://x/loaders", Name: "loaders"}
	s.DB.Create(&repo)
	for _, path := range []string{"go.mod", "go.mod", " cmd/go.mod ", ""} {
		s.DB.Create(&db.Dependency{RepositoryID: repo.ID, Name: path, ManifestPath: path})
	}
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillName: "repo-overview", Status: db.ScanDone, Report: `{"lines":{"total_lines":100}}`})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillName: "repo-overview", Status: db.ScanDone, Report: `{"lines":{"total_lines":200}}`})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillName: "repo-overview", Status: db.ScanFailed, Report: `{"lines":{"total_lines":300}}`})
	oldDeepDive := db.Scan{RepositoryID: repo.ID, SkillName: "security-deep-dive", Status: db.ScanDone, CostUSD: 1, Report: `{"inventory":[{}]}`}
	s.DB.Create(&oldDeepDive)
	deepDive := db.Scan{RepositoryID: repo.ID, SkillName: "security-deep-dive", Status: db.ScanDone, CostUSD: 1, Report: `{"inventory":[{},{}]}`}
	s.DB.Create(&deepDive)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillName: "security-deep-dive", Status: db.ScanDone, Report: `{"inventory":[{},{},{}]}`})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillName: "security-deep-dive", Status: db.ScanFailed, CostUSD: 2, Report: `{"inventory":[{},{},{},{}]}`})

	if got := s.loadUsageSLOC()[repo.ID]; got != 200 {
		t.Fatalf("latest SLOC = %d, want 200", got)
	}
	if got := s.loadUsageManifestCounts()[repo.ID]; got != 2 {
		t.Fatalf("manifest count = %d, want 2", got)
	}
	sinks := s.loadUsageDeepDiveSinks()
	if got := sinks[deepDive.ID]; got != 2 {
		t.Fatalf("deep-dive sink count = %d, want 2", got)
	}
	if len(sinks) != 1 {
		t.Fatalf("sink measurements = %v, want only latest positive-cost completed scan per repository", sinks)
	}
}

func TestFormatUSD(t *testing.T) {
	cases := []struct {
		v    float64
		want string
	}{
		{0, "$0.00"},
		{0.0042, "$0.0042"},
		{0.09, "$0.0900"},
		{0.10, "$0.10"},
		{12.345, "$12.35"},
	}
	for _, tc := range cases {
		if got := formatUSD(tc.v); got != tc.want {
			t.Errorf("formatUSD(%v) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

func TestUsage_perSkillStatsAndOrdering(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://x/u", Name: "u"}
	s.DB.Create(&repo)

	mk := func(skill string, status db.ScanStatus, cost float64, turns int) {
		s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: skill,
			Status: status, CostUSD: cost, Turns: turns})
	}
	// deep-dive: three done runs spread across the cost range.
	mk("security-deep-dive", db.ScanDone, 1.00, 10)
	mk("security-deep-dive", db.ScanDone, 3.00, 30)
	mk("security-deep-dive", db.ScanDone, 8.00, 80)
	// metadata: two cheap runs, one failed (still counted).
	mk("metadata", db.ScanDone, 0.0012, 1)
	mk("metadata", db.ScanFailed, 0.0034, 2)
	// queued/running excluded.
	mk("metadata", db.ScanQueued, 0, 0)
	mk("security-deep-dive", db.ScanRunning, 0, 0)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/usage"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()

	// Grand total = 12.0046, rendered at 2dp.
	if !strings.Contains(body, "$12.00") {
		t.Errorf("missing grand total in body")
	}
	// 5 counted runs (queued/running excluded).
	if !strings.Contains(body, "5 runs") {
		t.Errorf("missing run count")
	}
	// deep-dive median is $3.00, max $8.00.
	for _, want := range []string{"security-deep-dive", "$3.00", "$8.00"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	// metadata costs are sub-dollar so render at 4dp.
	if !strings.Contains(body, "$0.0012") {
		t.Errorf("missing 4dp metadata min cost")
	}
	// Ordered by total cost desc: deep-dive ($12) before metadata ($0.0046).
	if strings.Index(body, "security-deep-dive") > strings.Index(body, ">metadata<") {
		t.Errorf("expected deep-dive row before metadata row")
	}
}

func TestBuildRateLimitPanel(t *testing.T) {
	reset := time.Date(2026, 7, 1, 12, 30, 0, 0, time.UTC)
	// Unsorted input across both windows; the panel sorts by window label.
	statuses := []worker.RateLimitInfo{
		{Type: "seven_day", Status: "allowed", ResetsAt: reset.Add(48 * time.Hour).Unix()},
		{Type: "five_hour", Status: "rejected", ResetsAt: reset.Unix()},
	}
	p := buildRateLimitPanel(statuses)
	if len(p.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(p.Rows))
	}
	if p.Rows[0].Window != "5-hour" || p.Rows[1].Window != "7-day" {
		t.Fatalf("window order = %q,%q, want 5-hour,7-day", p.Rows[0].Window, p.Rows[1].Window)
	}
	if p.Rows[0].Status != "rejected" {
		t.Errorf("status = %q, want rejected", p.Rows[0].Status)
	}
	if p.Rows[0].ResetAt != "2026-07-01 12:30 UTC" {
		t.Errorf("reset = %q, want formatted UTC", p.Rows[0].ResetAt)
	}
	if got := buildRateLimitPanel(nil); len(got.Rows) != 0 {
		t.Errorf("nil statuses yielded %d rows, want 0", len(got.Rows))
	}
}

func TestUsage_hidesRateLimitPanelWhenNoStatus(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	// No rate_limit_event captured -> panel is absent.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/usage"))
	if strings.Contains(w.Body.String(), "Claude subscription limits") {
		t.Error("rate-limit panel rendered with no captured status")
	}
}

func TestUsage_perDay(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://x/day", Name: "day"}
	s.DB.Create(&repo)

	day1 := time.Date(2025, 1, 10, 12, 0, 0, 0, time.UTC)
	day2 := time.Date(2025, 1, 11, 12, 0, 0, 0, time.UTC)
	mk := func(skill string, status db.ScanStatus, cost float64, finished *time.Time) {
		s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: skill,
			Status: status, CostUSD: cost, FinishedAt: finished})
	}
	mk("audit", db.ScanDone, 1.00, &day1)
	mk("audit", db.ScanDone, 2.00, &day1)
	mk("metadata", db.ScanFailed, 0.50, &day2)
	// queued/running excluded.
	mk("audit", db.ScanQueued, 0, nil)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/usage?view=day"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()

	// Both dates present; newest (day2) should appear before day1.
	if !strings.Contains(body, "2025-01-10") {
		t.Errorf("missing 2025-01-10 row")
	}
	if !strings.Contains(body, "2025-01-11") {
		t.Errorf("missing 2025-01-11 row")
	}
	if strings.Index(body, "2025-01-11") > strings.Index(body, "2025-01-10") {
		t.Errorf("expected newer date before older date")
	}
	// Day1 total = $3.00; day2 total = $0.50.
	if !strings.Contains(body, "$3.00") {
		t.Errorf("missing day1 total $3.00")
	}
	if !strings.Contains(body, "$0.50") {
		t.Errorf("missing day2 total $0.50")
	}
	// Header totals still cover all days.
	if !strings.Contains(body, "$3.50") {
		t.Errorf("missing grand total $3.50")
	}
	if !strings.Contains(body, "3 runs") {
		t.Errorf("missing 3 runs count")
	}
}

func TestUsage_costDriversAndOutliers(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	sloc := []int{100, 200, 300}
	costs := []float64{1, 2, 30}
	var outlier db.Scan
	for i := range sloc {
		repo := db.Repository{
			URL:      fmt.Sprintf("https://x/drivers-%d", i+1),
			Name:     fmt.Sprintf("drivers-%d", i+1),
			FullName: fmt.Sprintf("owner/drivers-%d", i+1),
		}
		s.DB.Create(&repo)
		s.DB.Create(&db.Scan{
			RepositoryID: repo.ID,
			Kind:         "skill",
			SkillName:    "repo-overview",
			Status:       db.ScanDone,
			Report:       `{"lines":{"total_lines":` + fmt.Sprint(sloc[i]) + `}}`,
		})
		scan := db.Scan{
			RepositoryID: repo.ID,
			Kind:         "skill",
			SkillName:    "audit",
			Status:       db.ScanDone,
			Model:        "test-model",
			Profile:      "go",
			CostUSD:      costs[i],
			Turns:        5 + i,
		}
		s.DB.Create(&scan)
		if i == 2 {
			outlier = scan
		}
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/usage?view=drivers"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		"Cost correlations",
		"audit",
		"SLOC",
		"3",
		"0.88",
		"strong positive",
		"Cost outliers",
		fmt.Sprintf("/scans/%d", outlier.ID),
		"owner/drivers-3",
		"test-model / go",
		"15.0×",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("usage drivers page missing %q", want)
		}
	}
}

func TestUsage_costOutlierRendersProfileWithoutMissingModelMarker(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://x/profile-only", Name: "profile-only"}
	s.DB.Create(&repo)
	for _, cost := range []float64{1, 1, 30} {
		s.DB.Create(&db.Scan{
			RepositoryID: repo.ID,
			Kind:         "skill",
			SkillName:    "profile-only",
			Status:       db.ScanDone,
			Profile:      "go",
			CostUSD:      cost,
		})
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/usage?view=drivers"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, ">go</td>") {
		t.Error("profile-only outlier did not render its profile")
	}
	if strings.Contains(body, "— / go") {
		t.Error("profile-only outlier rendered a missing-model marker")
	}
}

func TestRepoShow_totalCostBadge(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://x/spend", Name: "spend", FetchedAt: new(time.Now())}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "a", Status: db.ScanDone, CostUSD: 1.50})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "b", Status: db.ScanDone, CostUSD: 0.25})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/repositories/1"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "$1.75") {
		t.Errorf("repo summary missing total cost $1.75")
	}
}
