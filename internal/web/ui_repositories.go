package web

import "net/http"

// registerUIRepositoryRoutes registers the repository and code routes of the /api/v1/ui surface
// (02-api-plan.md section 3.3 #28-#55). Owned by WP-API-3: add handlers in this file (or
// siblings you own) with string-literal, method-qualified patterns relative to
// /api/v1, e.g. mux.HandleFunc("GET /ui/...", s.handler), and document each in
// openapi.yaml between the "# --- ui:repositories begin/end ---" markers.
// TestOpenAPICoversRegisteredAPIRoutes fails on any undocumented route.
func (s *Server) registerUIRepositoryRoutes(mux *http.ServeMux) {
	_ = mux
}
