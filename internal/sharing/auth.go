package sharing

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"scrutineer/internal/web"
)

// user is the authenticated identity attached to a request context.
type user struct {
	GitHubUserID int64
	Login        string
	RepoIDs      map[uint]struct{}
	// Scope is the view scope requireAuth attached, kept here because
	// internal/web does not export a getter for it.
	Scope web.ViewScope
}

type userKey struct{}

func userFrom(ctx context.Context) (*user, bool) {
	u, ok := ctx.Value(userKey{}).(*user)
	return u, ok
}

// oauthConfig builds the GitHub OAuth2 config.
func (c *Config) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint:     github.Endpoint,
		RedirectURL:  c.BaseURL + "/auth/callback",
		Scopes:       []string{"read:org"},
	}
}

// maxNextLen bounds the post-login path carried through the state cookie.
const maxNextLen = 2048

// validNext reports whether next is a same-origin path safe to redirect to
// after sign-in: a single leading "/" (not "//" or "/\", which browsers treat
// as scheme-relative), no backslash or control character anywhere, and no
// scheme or host once parsed.
func validNext(next string) bool {
	if next == "" || len(next) > maxNextLen || next[0] != '/' {
		return false
	}
	if strings.HasPrefix(next, "//") || strings.ContainsRune(next, '\\') {
		return false
	}
	for _, c := range next {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	u, err := url.Parse(next)
	return err == nil && u.Scheme == "" && u.Host == "" && u.User == nil
}

// sanitizeNext returns next when valid, otherwise "/".
func sanitizeNext(next string) string {
	if validNext(next) {
		return next
	}
	return "/"
}

// login starts the OAuth handshake: it sets a random state cookie, carrying the
// validated ?next= the callback lands on, and redirects to GitHub's authorize
// page. With the dev identity it signs in directly.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	next := sanitizeNext(r.URL.Query().Get("next"))
	if s.cfg.dev != nil {
		s.devLogin(w, r, next)
		return
	}
	state, err := randToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, stateCookie, state+"."+base64.RawURLEncoding.EncodeToString([]byte(next)), stateTTL)
	http.Redirect(w, r, s.cfg.oauthConfig().AuthCodeURL(state), http.StatusFound)
}

// parseStateCookie splits the state cookie into the OAuth state and the
// post-login path. The path is validated again: the cookie is ours, but it is
// cheaper to re-check than to reason about who else could have set it.
func parseStateCookie(v string) (state, next string) {
	state, enc, _ := strings.Cut(v, ".")
	next = "/"
	if raw, err := base64.RawURLEncoding.DecodeString(enc); err == nil {
		next = sanitizeNext(string(raw))
	}
	return state, next
}

// callback completes the handshake: it validates the state cookie, exchanges
// the code for a token, fetches the visitor's GitHub identity, and seals a
// session cookie containing the token used for the periodic repo checks.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	st, err := r.Cookie(stateCookie)
	if err != nil || st.Value == "" {
		http.Error(w, "invalid OAuth state", http.StatusBadRequest)
		return
	}
	state, next := parseStateCookie(st.Value)
	if state == "" || state != r.URL.Query().Get("state") {
		http.Error(w, "invalid OAuth state", http.StatusBadRequest)
		return
	}
	s.clearCookie(w, stateCookie)

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}
	tok, err := s.cfg.oauthConfig().Exchange(r.Context(), code)
	if err != nil {
		s.log.Warn("oauth exchange failed", "err", err)
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}

	identity, err := fetchUser(r.Context(), tok.AccessToken)
	if err != nil {
		s.log.Warn("fetch github user failed", "err", err)
		http.Error(w, "could not read GitHub identity", http.StatusBadGateway)
		return
	}

	if !s.startSession(w, session{
		GitHubUserID: identity.ID,
		Login:        identity.Login,
		Token:        tok.AccessToken,
		ExpiresAt:    time.Now().Add(sessionTTL).Unix(),
	}) {
		return
	}
	s.log.Info("sharing login", "login", identity.Login, "github_user_id", identity.ID)
	http.Redirect(w, r, next, http.StatusFound)
}

// startSession seals sess into the session cookie and starts the repository
// lookup so it is usually done, or at least in flight, by the time the
// redirected request needs it.
func (s *Server) startSession(w http.ResponseWriter, sess session) bool {
	sealed, err := s.cfg.seal(sess)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	s.setCookie(w, sessionCookie, sealed, sessionTTL)
	s.access.prefetch(sess.GitHubUserID, sess.Token)
	return true
}

// logout de-authorizes the visitor and clears the session cookie. Clearing the
// cookie alone does not log them out: the OAuth app stays authorized on GitHub,
// so /auth/login silently re-issues a token and signs them right back in. So we
// first revoke the app's grant on GitHub (best effort — a failure there must not
// block the local logout), then always clear the cookie. The SPA asks with
// Accept: application/json and gets 204; forms and htmx keep the redirect.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := s.openSession(r); ok && sess.Token != "" {
		s.access.invalidate(sess.GitHubUserID, sess.Token)
		switch {
		case s.cfg.dev != nil:
			s.log.Info("sharing dev logout", "login", sess.Login)
		default:
			if err := revokeGrant(r.Context(), s.cfg.clientID, s.cfg.clientSecret, sess.Token); err != nil {
				s.log.Warn("sharing logout: github grant revocation failed", "login", sess.Login, "err", err)
			} else {
				s.log.Info("sharing logout", "login", sess.Login)
			}
		}
	}
	s.clearCookie(w, sessionCookie)
	if acceptsJSON(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	redirectTo(w, r, "/auth/login")
}

func acceptsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

// openSession reads and validates the session cookie.
func (s *Server) openSession(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	sess, err := s.cfg.open(c.Value)
	if err != nil {
		return session{}, false
	}
	return sess, true
}

func hasCookie(r *http.Request, name string) bool {
	_, err := r.Cookie(name)
	return err == nil
}

// sessionInfo is GET /auth/session.
type sessionInfo struct {
	Authenticated bool          `json:"authenticated"`
	Login         string        `json:"login"`
	GitHubUserID  int64         `json:"github_user_id"`
	ExpiresAt     time.Time     `json:"expires_at"`
	Access        sessionAccess `json:"access"`
	Version       versionInfo   `json:"version"`
}

type sessionAccess struct {
	State   accessState `json:"state"`
	Found   int         `json:"found"`
	Partial bool        `json:"partial"`
}

type versionInfo struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	CommitDate string `json:"commit_date"`
}

// sessionHandler answers GET /auth/session. It never blocks and never starts
// a repository lookup: it only reads the cached lookup state, so the SPA can
// call it on every boot.
func (s *Server) sessionHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.openSession(r)
	if !ok {
		if hasCookie(r, sessionCookie) {
			s.clearCookie(w, sessionCookie)
		}
		writeAPIError(w, http.StatusUnauthorized, codeUnauthorized, "sign in required")
		return
	}
	st := s.access.status(sess.GitHubUserID, sess.Token)
	if st.State == accessUnauthorized {
		s.clearCookie(w, sessionCookie)
		writeAPIError(w, http.StatusUnauthorized, codeUnauthorized, "GitHub sign-in expired")
		return
	}
	writeJSON(w, http.StatusOK, sessionInfo{
		Authenticated: true,
		Login:         sess.Login,
		GitHubUserID:  sess.GitHubUserID,
		ExpiresAt:     time.Unix(sess.ExpiresAt, 0).UTC(),
		Access:        sessionAccess{State: st.State, Found: st.Found, Partial: st.Partial},
		Version:       versionInfo{Version: s.cfg.Version, Commit: s.cfg.Commit, CommitDate: s.cfg.CommitDate},
	})
}

// accessInfo is GET /auth/access.
type accessInfo struct {
	AuthorizedRepoCount int                    `json:"authorized_repo_count"`
	ScannedRepoCount    int                    `json:"scanned_repo_count"`
	RepositoryIDs       []uint                 `json:"repository_ids"`
	Unscanned           []externalRepoJSON     `json:"unscanned"`
	Insufficient        []insufficientRepoJSON `json:"insufficient"`
	Incomplete          bool                   `json:"incomplete"`
}

type externalRepoJSON struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type insufficientRepoJSON struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Access string `json:"access"`
}

// accessHandler answers GET /auth/access (behind requireAuth): the visitor's
// resolved scope, for the SPA's repository-access card and to notice when it
// changes.
func (s *Server) accessHandler(w http.ResponseWriter, r *http.Request) {
	u, ok := userFrom(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, codeUnauthorized, "sign in required")
		return
	}
	scope := u.Scope
	out := accessInfo{
		AuthorizedRepoCount: scope.AuthorizedRepoCount,
		ScannedRepoCount:    len(scope.RepoIDs),
		RepositoryIDs:       make([]uint, 0, len(scope.RepoIDs)),
		Unscanned:           make([]externalRepoJSON, 0, len(scope.UnscannedRepositories)),
		Insufficient:        make([]insufficientRepoJSON, 0, len(scope.InsufficientRepositories)),
		Incomplete:          scope.Incomplete,
	}
	for id := range scope.RepoIDs {
		out.RepositoryIDs = append(out.RepositoryIDs, id)
	}
	sort.Slice(out.RepositoryIDs, func(i, j int) bool { return out.RepositoryIDs[i] < out.RepositoryIDs[j] })
	for _, r := range scope.UnscannedRepositories {
		out.Unscanned = append(out.Unscanned, externalRepoJSON{Name: r.Name, URL: r.URL})
	}
	for _, r := range scope.InsufficientRepositories {
		out.Insufficient = append(out.Insufficient, insufficientRepoJSON{Name: r.Name, URL: r.URL, Access: r.Access})
	}
	writeJSON(w, http.StatusOK, out)
}

// stateTokenBytes is the size of the random OAuth state token (256 bits).
const stateTokenBytes = 32

func randToken() (string, error) {
	b := make([]byte, stateTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.cfg.insecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.cfg.insecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
