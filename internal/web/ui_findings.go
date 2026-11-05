package web

import "net/http"

// registerUIFindingRoutes registers the findings read/write routes of the /api/v1/ui surface
// (02-api-plan.md section 3.2 #9-#18, #22, #22a). Owned by WP-API-1: add handlers in this file (or
// siblings you own) with string-literal, method-qualified patterns relative to
// /api/v1, e.g. mux.HandleFunc("GET /ui/...", s.handler), and document each in
// openapi.yaml between the "# --- ui:findings begin/end ---" markers.
// TestOpenAPICoversRegisteredAPIRoutes fails on any undocumented route.
func (s *Server) registerUIFindingRoutes(mux *http.ServeMux) {
	_ = mux
}
