package web

import (
	"net/http"
	"net/url"
	"strings"

	"scrutineer/internal/reporting"
)

// GET /api/v1/ui/reporting (02 #84, F-REP-01..03): the same reporting.Export
// document /reporting/report.json downloads, plus the pickers' vocabularies,
// the two derived rates the page shows, and the export links for the current
// selection. Unlike the HTML page, an unknown interval or severity is a 400
// rather than a silent fall-back to "all".

type uiReportInterval struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Meaning string `json:"meaning"`
}

type uiReportRates struct {
	// ScansPerRepo and CompletionRate are reportTotals' display-only ratios
	// (see their doc comments; CompletionRate may exceed 1 in a window).
	ScansPerRepo   float64 `json:"scans_per_repo"`
	CompletionRate float64 `json:"completion_rate"`
}

type uiReportExports struct {
	CSV  string `json:"csv"`
	JSON string `json:"json"`
}

type uiReportingView struct {
	reporting.Export
	Intervals  []uiReportInterval `json:"intervals"`
	Severities []string           `json:"severities"`
	Rates      uiReportRates      `json:"rates"`
	Exports    uiReportExports    `json:"exports"`
}

// parseReportParams validates ?interval and ?severity, returning the
// canonical values ("" severity = unfiltered).
func parseReportParams(r *http.Request) (reportInterval, string, error) {
	q := r.URL.Query()
	key := q.Get("interval")
	iv := resolveReportInterval(key)
	if key != "" && iv.Key != key {
		return iv, "", uiFieldErrors{"interval": "unknown interval " + strings.TrimSpace(key)}
	}
	raw := q.Get("severity")
	sev := resolveMinSeverity(raw)
	if raw != "" && sev == "" {
		return iv, "", uiFieldErrors{"severity": "unknown severity " + strings.TrimSpace(raw)}
	}
	return iv, sev, nil
}

// reportExportLinks are the download URLs for a selection (root-absolute,
// cookie-authenticated HTML routes; 02 section 5.3).
func reportExportLinks(intervalKey, minSeverity string) uiReportExports {
	v := url.Values{"interval": {intervalKey}}
	if minSeverity != "" {
		v.Set("severity", minSeverity)
	}
	qs := "?" + v.Encode()
	return uiReportExports{CSV: "/reporting/report.csv" + qs, JSON: "/reporting/report.json" + qs}
}

func (s *Server) uiReporting(w http.ResponseWriter, r *http.Request) {
	iv, sev, err := parseReportParams(r)
	if err != nil {
		writeUIError(w, http.StatusBadRequest, uiCodeBadParam, err.Error(), apiFieldsError(err))
		return
	}
	data, err := s.buildReport(iv, sev)
	if err != nil {
		s.Log.Error("build report", "err", err)
		uiInternal(w, err)
		return
	}
	intervals := make([]uiReportInterval, len(reportIntervals))
	for i, it := range reportIntervals {
		intervals[i] = uiReportInterval{Key: it.Key, Label: it.Label, Meaning: it.Meaning}
	}
	writeUIJSON(w, http.StatusOK, uiReportingView{
		Export:     reportExport(data),
		Intervals:  intervals,
		Severities: reportSeverities,
		Rates: uiReportRates{
			ScansPerRepo:   data.Totals.ScansPerRepo(),
			CompletionRate: data.Totals.CompletionRate(),
		},
		Exports: reportExportLinks(data.Interval.Key, data.MinSeverity),
	})
}
