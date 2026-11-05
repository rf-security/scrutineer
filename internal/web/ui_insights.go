package web

import "net/http"

// registerUIInsightRoutes registers the benchmark, usage, reporting, skills and settings routes of the /api/v1/ui surface
// (02-api-plan.md section 3.7 #82-#91). Owned by WP-API-6. Handlers live in
// ui_benchmark.go, ui_usage.go, ui_reporting.go, ui_skills.go and
// ui_settings.go; each route is documented in openapi.yaml between the
// "# --- ui:insights begin/end ---" markers.
func (s *Server) registerUIInsightRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui/benchmark", s.uiBenchmark)
	mux.HandleFunc("GET /ui/usage", s.uiUsage)
	mux.HandleFunc("GET /ui/reporting", s.uiReporting)
}
