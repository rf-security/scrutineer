package web

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Session routes for the SPA (02-api-plan.md section 3.1 #1-#3). They are
// registered on the root mux outside requireOperator: GET answers 401 itself
// when signed out, and POST is how a signed-out browser signs in.

const sessionBodyMax = 4 << 10

// registerUISessionRoutes registers the session routes on the root mux. The
// patterns carry the full /api/v1 prefix because they bypass exportHandler.
func (s *Server) registerUISessionRoutes(root *http.ServeMux) {
	root.Handle("GET /api/v1/ui/session", securityHeaders(s.AllowRemote, http.HandlerFunc(s.uiSessionGet)))
	root.Handle("POST /api/v1/ui/session", securityHeaders(s.AllowRemote, http.HandlerFunc(s.uiSessionCreate)))
	root.Handle("DELETE /api/v1/ui/session", securityHeaders(s.AllowRemote, http.HandlerFunc(s.uiSessionDelete)))
}

// operatorRequestToken is the operator token the request presents, as a
// bearer or as the operator cookie.
func (s *Server) operatorRequestToken(r *http.Request) string {
	token := bearer(r.Header.Get("Authorization"))
	if c, err := r.Cookie(operatorCookieName(s.OperatorToken)); token == "" && err == nil {
		token = c.Value
	}
	return token
}

func (s *Server) uiSessionGet(w http.ResponseWriter, r *http.Request) {
	if !s.validOperatorToken(s.operatorRequestToken(r)) {
		writeUIError(w, http.StatusUnauthorized, uiCodeUnauthorized, "operator token required", nil)
		return
	}
	writeUIJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"version":       map[string]string{"version": s.Version, "commit": s.Commit, "commit_date": s.CommitDate},
		"token_file":    s.operatorTokenPath(),
		"ui_base":       uiBasePath,
		"prefs":         map[string]string{"theme": themeCookie(r), "color_scheme": resolveColorScheme(r)},
	})
}

// themeCookie is the raw legacy theme cookie when it names a valid theme, so
// the SPA can tell "never chosen" (empty) from the default.
func themeCookie(r *http.Request) string {
	if c, err := r.Cookie("theme"); err == nil && c.Value != "" && resolveTheme(r) == c.Value {
		return c.Value
	}
	return ""
}

func (s *Server) uiSessionCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, sessionBodyMax)
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		uiBadParam(w, "invalid JSON request body")
		return
	}
	token := strings.TrimSpace(body.Token)
	if !s.validOperatorToken(token) {
		writeUIError(w, http.StatusUnauthorized, uiCodeUnauthorized, "invalid operator token", nil)
		return
	}
	s.setOperatorCookie(w, token)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) uiSessionDelete(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     operatorCookieName(s.OperatorToken),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}
