package sharing

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/web"
)

// localHost is the host the reused inner handler is rewritten to so its
// localhost-only DNS-rebinding guard passes; the portal has already validated
// the real public host in secure() by then.
const localHost = "127.0.0.1"

// Server is the maintainer portal: a thin authenticating, authorizing proxy in
// front of the reused scrutineer web handler.
type Server struct {
	cfg    *Config
	db     *gorm.DB
	log    *slog.Logger
	inner  http.Handler // the reused web.Server handler
	grants GrantSource
	access *accessCache
}

// New builds a portal Server. inner is the handler returned by
// (*web.Server).Handler(); the portal forwards its whitelisted routes to it.
func New(cfg *Config, gdb *gorm.DB, log *slog.Logger, inner http.Handler, grants GrantSource) *Server {
	if grants == nil {
		grants = EmptyGrantSource()
	}
	return &Server{cfg: cfg, db: gdb, log: log, inner: inner, grants: grants, access: newAccessCache(log)}
}

// Handler wires the portal: auth routes, the whitelisted authenticated surface,
// and static assets, all behind the outer host/CSRF guard.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /auth/logout", s.logout)
	mux.HandleFunc("GET /auth/status", s.accessStatus)
	mux.HandleFunc("GET /auth/loading.js", s.loadingScript)
	mux.HandleFunc("GET /auth/access-watch.js", s.accessWatchScript)

	// Static assets are embedded, read-only, and needed before login; forward
	// them straight through without a session.
	mux.Handle("GET /static/", s.forward())

	for _, rt := range append(append([]route{}, legacyPageRoutes...), downloadRoutes...) {
		mux.Handle(rt.pattern, s.requireAuth(s.authorize(rt.kind, s.forward())))
	}

	return s.secure(mux)
}

// secure enforces the outer boundary: the request must target the portal's
// configured public host, and every state-changing POST must be same-origin
// (a stricter CSRF stance than the local app, which tolerates a missing
// Sec-Fetch-Site header).
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if !strings.EqualFold(strings.Trim(host, "[]"), s.cfg.host) {
			http.Error(w, "forbidden: invalid host", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && r.Header.Get("Sec-Fetch-Site") != "same-origin" {
			http.Error(w, "forbidden: cross-site POST", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuth admits only requests with a valid session. The visitor's
// repositories come from GitHub via s.access, which re-checks them in the
// background once they are older than accessFreshTTL, so access changes take
// effect within minutes without a GitHub round trip on every request. When
// nothing is cached yet (first visit after login), a page navigation gets the
// progress page and other requests wait — both for at most accessLoadingMax.
// After that the request is served on the repositories found so far, marked
// Incomplete so the page says so and reloads once the lookup finishes. An
// invalid GitHub token clears the session and redirects to login;
// transient upstream failures leave the session intact and return 503 so a
// temporary GitHub outage cannot turn into a login loop.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			s.redirectToLogin(w, r)
			return
		}
		sess, err := s.cfg.open(c.Value)
		if err != nil {
			clearCookie(w, sessionCookie)
			s.redirectToLogin(w, r)
			return
		}
		repos, flight := s.access.lookup(sess.GitHubUserID, sess.Token)
		complete := true
		if flight != nil {
			if wantsDocument(r) && !s.access.pastLoadingWindow(flight) {
				s.renderLoading(w)
				return
			}
			repos, complete, err = s.access.waitBounded(r.Context(), flight)
		}
		if err != nil {
			s.log.Warn("fetch repository access failed", "login", sess.Login, "err", err)
			if isGitHubUnauthorized(err) {
				clearCookie(w, sessionCookie)
				s.redirectToLogin(w, r)
				return
			}
			http.Error(w, "GitHub is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		grantedRepoIDs, err := s.grants.RepositoryIDs(r.Context(), sess.GitHubUserID)
		if err != nil {
			s.log.Error("resolve configured grants failed", "login", sess.Login, "github_user_id", sess.GitHubUserID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		scope, err := resolveScope(r.Context(), s.db, repos, grantedRepoIDs)
		if err != nil {
			s.log.Error("resolve scope failed", "login", sess.Login, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		ctx := context.WithValue(r.Context(), userKey{}, &user{
			GitHubUserID: sess.GitHubUserID,
			Login:        sess.Login,
			RepoIDs:      scope.RepoIDs,
		})
		scope.Incomplete = !complete
		ctx = web.WithViewScope(ctx, scope)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authorize enforces per-resource ownership: it resolves the route's {id} to a
// repository and 404s when that repository is not in the visitor's scope. List
// routes carry no {id} and are already constrained by the scoped query.
func (s *Server) authorize(kind resourceKind, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if kind == kindList || kind == kindStatic {
			next.ServeHTTP(w, r)
			return
		}
		u, ok := userFrom(r.Context())
		if !ok {
			http.NotFound(w, r)
			return
		}
		id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		repoID, err := s.repoIDFor(r.Context(), kind, uint(id))
		if err != nil || repoID == 0 {
			http.NotFound(w, r)
			return
		}
		if _, allowed := u.RepoIDs[repoID]; !allowed {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// repoIDFor resolves the repository a route's target belongs to.
func (s *Server) repoIDFor(ctx context.Context, kind resourceKind, id uint) (uint, error) {
	switch kind {
	case kindRepo:
		var repo db.Repository
		if err := s.db.WithContext(ctx).Select("id").First(&repo, id).Error; err != nil {
			return 0, err
		}
		return repo.ID, nil
	case kindFinding:
		var f db.Finding
		if err := s.db.WithContext(ctx).Select("repository_id").First(&f, id).Error; err != nil {
			return 0, err
		}
		return f.RepositoryID, nil
	case kindScan:
		var scan db.Scan
		if err := s.db.WithContext(ctx).Select("repository_id").First(&scan, id).Error; err != nil {
			return 0, err
		}
		return scan.RepositoryID, nil
	default:
		return 0, nil
	}
}

// forward hands the request to the reused scrutineer handler, rewriting Host to
// localhost so that handler's localhost-only guard passes (secure() already
// vetted the real host).
func (s *Server) forward() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = localHost
		s.inner.ServeHTTP(w, r)
	})
}

func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	redirectTo(w, r, "/auth/login")
}

// isHX reports whether the request originated from htmx.
func isHX(r *http.Request) bool { return r.Header.Get("HX-Request") != "" }

// redirectTo issues a redirect that navigates the browser whether or not the
// request is driven by htmx. htmx swallows ordinary 3xx responses — it follows
// them over XHR and swaps the body rather than navigating — so an htmx request
// needs an explicit HX-Redirect header instead. This matters especially for the
// portal, whose auth redirects chain through /auth/login on to GitHub: that hop
// is cross-origin, so htmx's XHR cannot follow it and a bare 3xx leaves the page
// sitting still (the "sign out does nothing" symptom). Mirrors internal/web's
// redirect helper so the portal behaves like the rest of the app.
func redirectTo(w http.ResponseWriter, r *http.Request, path string) {
	if isHX(r) {
		w.Header().Set("HX-Redirect", path)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}
