package web

import (
	"net/http"
)

// GET /api/v1/ui/usage (02 #83, F-USE-01..05). by_skill and by_day are both
// always present (they come from the same pass over the scans); drivers is
// only computed for view=drivers, since it reads every repo-overview and
// deep-dive report, and is null otherwise.

func (s *Server) uiUsage(w http.ResponseWriter, r *http.Request) {
	view := r.URL.Query().Get("view")
	switch view {
	case "":
		view = usageViewSkill
	case usageViewSkill, usageViewDay, usageViewDrivers:
	default:
		uiBadParam(w, `view must be one of skill, day, drivers; got "`+view+`"`)
		return
	}
	data := s.loadUsage(view)
	rl := data.RateLimit
	if rl.Rows == nil {
		rl.Rows = []rateLimitRow{}
	}
	body := map[string]any{
		"view":           view,
		"total_runs":     data.TotalRuns,
		"total_cost_usd": data.TotalCost,
		"rate_limit":     rl,
		"by_skill":       data.Rows,
		"by_day":         data.DayRows,
		"drivers":        nil,
	}
	if view == usageViewDrivers {
		d := data.Drivers
		if d.Correlations == nil {
			d.Correlations = []usageDriverCorrelation{}
		}
		if d.Outliers == nil {
			d.Outliers = []usageCostOutlier{}
		}
		body["drivers"] = d
	}
	writeUIJSON(w, http.StatusOK, body)
}
