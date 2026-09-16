package sharing

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// user is the authenticated identity attached to a request context.
type user struct {
	Login   string
	RepoIDs map[uint]struct{}
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

// login starts the OAuth handshake: it sets a random state cookie and redirects
// to GitHub's authorize page.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	state, err := randToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(stateTTL.Seconds()),
	})
	http.Redirect(w, r, s.cfg.oauthConfig().AuthCodeURL(state), http.StatusFound)
}

// callback completes the handshake: it validates the state cookie, exchanges
// the code for a token, fetches the visitor's GitHub identity, and seals a
// session cookie containing the token for real-time repo checks on each request.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	st, err := r.Cookie(stateCookie)
	if err != nil || st.Value == "" || st.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid OAuth state", http.StatusBadRequest)
		return
	}
	clearCookie(w, stateCookie)

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

	login, err := fetchUser(r.Context(), tok.AccessToken)
	if err != nil {
		s.log.Warn("fetch github user failed", "err", err)
		http.Error(w, "could not read GitHub identity", http.StatusBadGateway)
		return
	}

	sealed, err := s.cfg.seal(session{
		Login:     login,
		Token:     tok.AccessToken,
		ExpiresAt: time.Now().Add(sessionTTL).Unix(),
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sealed,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	s.log.Info("sharing login", "login", login)
	http.Redirect(w, r, "/", http.StatusFound)
}

// logout de-authorizes the visitor and clears the session cookie. Clearing the
// cookie alone does not log them out: the OAuth app stays authorized on GitHub,
// so /auth/login silently re-issues a token and signs them right back in. So we
// first revoke the app's grant on GitHub (best effort — a failure there must not
// block the local logout), then always clear the cookie.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if sess, err := s.cfg.open(c.Value); err == nil && sess.Token != "" {
			if err := revokeGrant(r.Context(), s.cfg.clientID, s.cfg.clientSecret, sess.Token); err != nil {
				s.log.Warn("sharing logout: github grant revocation failed", "login", sess.Login, "err", err)
			} else {
				s.log.Info("sharing logout", "login", sess.Login)
			}
		}
	}
	clearCookie(w, sessionCookie)
	redirectTo(w, r, "/auth/login")
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

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
