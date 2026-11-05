package web

import "net/http"

// registerUIInventoryRoutes registers the orgs, maintainers, packages, advisories and SBOM routes of the /api/v1/ui surface
// (02-api-plan.md section 3.6 #67-#81). Owned by WP-API-5: add handlers in this file (or
// siblings you own) with string-literal, method-qualified patterns relative to
// /api/v1, e.g. mux.HandleFunc("GET /ui/...", s.handler), and document each in
// openapi.yaml between the "# --- ui:inventory begin/end ---" markers.
// TestOpenAPICoversRegisteredAPIRoutes fails on any undocumented route.
func (s *Server) registerUIInventoryRoutes(mux *http.ServeMux) {
	_ = mux
}
