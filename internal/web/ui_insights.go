package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// registerUIInsightRoutes registers the benchmark, usage, reporting, skills and settings routes of the /api/v1/ui surface
// (02-api-plan.md section 3.7 #82-#91). Owned by WP-API-6. Handlers live in
// ui_benchmark.go, ui_usage.go, ui_reporting.go, ui_skills.go and
// ui_settings.go; each route is documented in openapi.yaml between the
// "# --- ui:insights begin/end ---" markers.
func (s *Server) registerUIInsightRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui/benchmark", s.uiBenchmark)
	mux.HandleFunc("GET /ui/usage", s.uiUsage)
	mux.HandleFunc("GET /ui/reporting", s.uiReporting)
	mux.HandleFunc("GET /ui/skills", s.uiSkillsList)
	mux.HandleFunc("POST /ui/skills", s.uiSkillCreate)
	mux.HandleFunc("GET /ui/skills/{id}", s.uiSkillShow)
	mux.HandleFunc("PATCH /ui/skills/{id}", s.uiSkillPatch)
}

// insightBodyMax caps skill and settings bodies. A SKILL.md body is the
// largest thing written here and stays well under it.
const insightBodyMax = 1 << 20

// decodeInsightBody decodes a JSON body into dst, rejecting unknown keys so
// a misspelled autosave field is a 400 rather than a silent no-op. It writes
// the 400 itself and reports false on failure.
func decodeInsightBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, insightBodyMax)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			uiBadParam(w, "request body required")
			return false
		}
		uiBadParam(w, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}
