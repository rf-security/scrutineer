package web

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

// waitMetaEvent returns the `changed` list of the next meta event on c, or
// fails after a short wait.
func waitMetaEvent(t *testing.T, c *client) []string {
	t.Helper()
	select {
	case ev := <-c.ch:
		if ev.Name != uiMetaEvent {
			t.Fatalf("event %q, want %q", ev.Name, uiMetaEvent)
		}
		m, ok := ev.JSON.(map[string]any)
		if !ok {
			t.Fatalf("meta payload %T", ev.JSON)
		}
		changed, _ := m[uiEventChangedKey].([]string)
		return changed
	case <-time.After(2 * time.Second):
		t.Fatal("no meta event published")
		return nil
	}
}

func requireNoEvent(t *testing.T, c *client) {
	t.Helper()
	select {
	case ev := <-c.ch:
		t.Fatalf("unexpected event %q", ev.Name)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestUIBenchmark(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	scored := seedUIRepo(t, s.DB, "scored")
	unscored := seedUIRepo(t, s.DB, "unscored")
	seedUIRepo(t, s.DB, "no-expectations")
	for _, ef := range []db.ExpectedFinding{
		{RepositoryID: scored.ID, File: "a.go", CWE: "CWE-79"},
		{RepositoryID: unscored.ID, File: "b.go", CWE: "CWE-89"},
	} {
		if err := s.DB.Create(&ef).Error; err != nil {
			t.Fatal(err)
		}
	}
	sc := seedUIScan(t, s.DB, scored, db.ScanDone, deepDiveSkillName)

	type row struct {
		Repository struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"repository"`
		Scan *struct {
			ID        uint   `json:"id"`
			SkillName string `json:"skill_name"`
		} `json:"scan"`
		Expected int    `json:"expected"`
		Skill    string `json:"skill"`
	}
	type view struct {
		Totals struct {
			Expected int     `json:"expected"`
			Recall   float64 `json:"recall"`
		} `json:"totals"`
		Rows []row `json:"rows"`
	}
	got := decodeUIJSON[view](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/benchmark", nil)), http.StatusOK)
	if len(got.Rows) != 2 || got.Totals.Expected != 2 {
		t.Fatalf("rows = %+v totals = %+v, want 2 rows / 2 expected", got.Rows, got.Totals)
	}
	if r := got.Rows[0]; r.Repository.ID != scored.ID || r.Scan == nil || r.Scan.ID != sc.ID || r.Skill != deepDiveSkillName {
		t.Errorf("scored row = %+v, want scan %d", r, sc.ID)
	}
	if r := got.Rows[1]; r.Repository.ID != unscored.ID || r.Scan != nil || r.Expected != 1 {
		t.Errorf("unscored row = %+v, want scan null", r)
	}

	// A skill filter with no matching scans leaves every row unscored.
	got = decodeUIJSON[view](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/benchmark?skill=nope", nil)), http.StatusOK)
	for _, r := range got.Rows {
		if r.Scan != nil {
			t.Errorf("skill=nope row %+v has a scan", r)
		}
	}
}

func TestUIUsage(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "usage")
	for _, cost := range []float64{1, 3} {
		sc := seedUIScan(t, s.DB, repo, db.ScanDone, "semgrep")
		if err := s.DB.Model(&sc).Updates(map[string]any{"cost_usd": cost, "turns": 4, "output_tokens": 10}).Error; err != nil {
			t.Fatal(err)
		}
	}
	type view struct {
		View         string  `json:"view"`
		TotalRuns    int     `json:"total_runs"`
		TotalCostUSD float64 `json:"total_cost_usd"`
		RateLimit    struct {
			Windows []any `json:"windows"`
		} `json:"rate_limit"`
		BySkill []struct {
			Skill string `json:"skill"`
			Runs  int    `json:"runs"`
			Cost  Stats  `json:"cost"`
		} `json:"by_skill"`
		ByDay []struct {
			Date      string  `json:"date"`
			TotalCost float64 `json:"total_cost"`
		} `json:"by_day"`
		Drivers *struct {
			Correlations []any `json:"correlations"`
			Outliers     []any `json:"outliers"`
		} `json:"drivers"`
	}
	got := decodeUIJSON[view](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/usage", nil)), http.StatusOK)
	if got.View != usageViewSkill || got.TotalRuns != 2 || got.TotalCostUSD != 4 {
		t.Fatalf("header = %+v, want skill view, 2 runs, $4", got)
	}
	if len(got.BySkill) != 1 || got.BySkill[0].Skill != "semgrep" || got.BySkill[0].Cost.Median != 2 {
		t.Errorf("by_skill = %+v", got.BySkill)
	}
	if len(got.ByDay) != 1 || got.ByDay[0].TotalCost != 4 {
		t.Errorf("by_day = %+v", got.ByDay)
	}
	if got.RateLimit.Windows == nil || got.Drivers != nil {
		t.Errorf("windows = %v (want []), drivers = %v (want null)", got.RateLimit.Windows, got.Drivers)
	}

	got = decodeUIJSON[view](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/usage?view=drivers", nil)), http.StatusOK)
	if got.Drivers == nil || got.Drivers.Correlations == nil || got.Drivers.Outliers == nil {
		t.Errorf("drivers view: drivers = %+v, want both lists", got.Drivers)
	}

	requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/usage?view=week", nil)),
		http.StatusBadRequest, uiCodeBadParam)
}

func TestUIReporting(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedUIRepo(t, s.DB, "rep")
	sc := seedUIScan(t, s.DB, repo, db.ScanDone, deepDiveSkillName)
	seedUIFinding(t, s.DB, sc, "f", db.FindingNew)

	type view struct {
		Period struct {
			Key string `json:"key"`
		} `json:"period"`
		Filters struct {
			MinimumSeverity *string `json:"minimum_severity"`
		} `json:"filters"`
		Activity struct {
			ScansStarted int `json:"scans_started"`
		} `json:"activity_in_period"`
		ByDay     []any `json:"activity_by_day"`
		Intervals []struct {
			Key string `json:"key"`
		} `json:"intervals"`
		Severities []string `json:"severities"`
		Rates      struct {
			CompletionRate float64 `json:"completion_rate"`
		} `json:"rates"`
		Exports struct {
			CSV  string `json:"csv"`
			JSON string `json:"json"`
		} `json:"exports"`
	}
	got := decodeUIJSON[view](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/reporting", nil)), http.StatusOK)
	if got.Period.Key != "all" || got.Filters.MinimumSeverity != nil || len(got.Intervals) != len(reportIntervals) ||
		len(got.Severities) != len(db.SeverityLevels) || got.ByDay == nil {
		t.Fatalf("default view = %+v", got)
	}
	if got.Exports.CSV != "/reporting/report.csv?interval=all" || got.Exports.JSON != "/reporting/report.json?interval=all" {
		t.Errorf("exports = %+v", got.Exports)
	}

	got = decodeUIJSON[view](t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/reporting?interval=week&severity=high", nil)), http.StatusOK)
	if got.Period.Key != "week" || got.Filters.MinimumSeverity == nil || *got.Filters.MinimumSeverity != "High" {
		t.Errorf("week/high view = %+v", got)
	}
	if !strings.Contains(got.Exports.CSV, "interval=week") || !strings.Contains(got.Exports.CSV, "severity=High") {
		t.Errorf("exports = %+v, want the selection", got.Exports)
	}

	for _, q := range []string{"interval=year", "severity=urgent"} {
		requireUIError(t, serveUI(t, s, operatorReq(t, http.MethodGet, "/api/v1/ui/reporting?"+q, nil)),
			http.StatusBadRequest, uiCodeBadParam)
	}
}
