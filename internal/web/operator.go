package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
)

const (
	// Browsers cap a cookie's lifetime at 400 days; the token itself does
	// not expire, so the cookie only needs to outlive a browser restart.
	operatorCookieMaxAge = 400 * 24 * 60 * 60
)

// validOperatorToken fails closed when no token is configured, so a Server
// built without one serves nothing behind requireOperator.
func (s *Server) validOperatorToken(got string) bool {
	return s.OperatorToken != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.OperatorToken)) == 1
}

// operatorCookieName is derived from the token because browsers scope
// cookies by host but not port: two instances on 127.0.0.1 sharing one name
// would sign each other out.
func operatorCookieName(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "operator-" + hex.EncodeToString(sum[:4])
}

// requireOperator gates the browser UI and /api/v1 on the operator token,
// sent as a bearer by scripts or as the cookie /login sets for a browser.
func (s *Server) requireOperator(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.DisableOperatorToken {
			h.ServeHTTP(w, r)
			return
		}
		// The sharing portal authenticates and authorizes its GET allow-list
		// before attaching this server-side scope. Its visitors are not operators.
		if r.Method == http.MethodGet && isReadOnly(r) {
			h.ServeHTTP(w, r)
			return
		}
		token := bearer(r.Header.Get("Authorization"))
		if c, err := r.Cookie(operatorCookieName(s.OperatorToken)); token == "" && err == nil {
			token = c.Value
		}
		if !s.validOperatorToken(token) {
			// The SPA's API routes answer with the JSON envelope so a 401
			// can route to its login screen; everything else keeps the text.
			if strings.HasPrefix(r.URL.Path, "/api/v1/ui/") || strings.Contains(r.Header.Get("Accept"), "application/json") {
				writeUIError(w, http.StatusUnauthorized, uiCodeUnauthorized, "operator token required", nil)
				return
			}
			http.Error(w, "unauthorized: operator token required, sign in with /login?token= followed by the contents of "+s.operatorTokenPath(), http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// login trades the token in the printed link for the operator cookie and
// redirects so the token leaves the address bar. `next` picks the landing
// page; only a local absolute path is honoured, so the link cannot bounce the
// browser to another origin.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if !s.validOperatorToken(token) {
		http.Error(w, "unauthorized: invalid operator token", http.StatusUnauthorized)
		return
	}
	s.setOperatorCookie(w, token)
	http.Redirect(w, r, loginNext(r.URL.Query().Get("next")), http.StatusSeeOther)
}

// loginNext validates the post-login redirect: a path starting with a single
// "/" (not "//" or "/\", which browsers treat as another host), default "/".
func loginNext(next string) string {
	if next == "" || next[0] != '/' || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") ||
		strings.ContainsAny(next, "\r\n") {
		return "/"
	}
	return next
}

// setOperatorCookie sets the HttpOnly operator cookie GET /login and POST
// /api/v1/ui/session both hand out.
func (s *Server) setOperatorCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     operatorCookieName(s.OperatorToken),
		Value:    token,
		Path:     "/",
		MaxAge:   operatorCookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) operatorTokenPath() string {
	if s.OperatorTokenFile == "" {
		return "<data>/operator-token"
	}
	return s.OperatorTokenFile
}
