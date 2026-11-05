package web

import "net/http"

// registerUIInsightRoutes registers the benchmark, usage, reporting, skills and settings routes of the /api/v1/ui surface
// (02-api-plan.md section 3.7 #82-#91). Owned by WP-API-6: add handlers in this file (or
// siblings you own) with string-literal, method-qualified patterns relative to
// /api/v1, e.g. mux.HandleFunc("GET /ui/...", s.handler), and document each in
// openapi.yaml between the "# --- ui:insights begin/end ---" markers.
// TestOpenAPICoversRegisteredAPIRoutes fails on any undocumented route.
func (s *Server) registerUIInsightRoutes(mux *http.ServeMux) {
	_ = mux
}
