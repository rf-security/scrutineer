package web

import "net/http"

// registerUIFindingActionRoutes registers the finding status, action and disclosure routes of the /api/v1/ui surface
// (02-api-plan.md section 3.2 #12, #19-#21, #23-#27). Owned by WP-API-2: add handlers in this file (or
// siblings you own) with string-literal, method-qualified patterns relative to
// /api/v1, e.g. mux.HandleFunc("GET /ui/...", s.handler), and document each in
// openapi.yaml between the "# --- ui:finding-actions begin/end ---" markers.
// TestOpenAPICoversRegisteredAPIRoutes fails on any undocumented route.
func (s *Server) registerUIFindingActionRoutes(mux *http.ServeMux) {
	_ = mux
}
