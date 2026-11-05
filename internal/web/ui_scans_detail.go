package web

import "net/http"

// registerUIScanRoutes registers the scan detail, queue actions, audit and chat routes of the /api/v1/ui surface
// (02-api-plan.md sections 3.4 #57-#62, 3.5 #63-#66, plus #38). Owned by WP-API-4: add handlers in this file (or
// siblings you own) with string-literal, method-qualified patterns relative to
// /api/v1, e.g. mux.HandleFunc("GET /ui/...", s.handler), and document each in
// openapi.yaml between the "# --- ui:scans begin/end ---" markers.
// TestOpenAPICoversRegisteredAPIRoutes fails on any undocumented route.
func (s *Server) registerUIScanRoutes(mux *http.ServeMux) {
	_ = mux
}
