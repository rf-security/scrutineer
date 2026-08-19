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
	cfg   *Config
	db    *gorm.DB
	log   *slog.Logger
	inner http.Handler // the reused web.Server handler
}

// New builds a portal Server. inner is the handler returned by
// (*web.Server).Handler(); the portal forwards its whitelisted routes to it.
func New(cfg *Config, gdb *gorm.DB, log *slog.Logger, inner http.Handler) *Server {
	return &Server{cfg: cfg, db: gdb, log: log, inner: inner}
}

// resourceKind classifies a whitelisted route so the authorization middleware
// knows how to resolve the {id} in its path to a repository ID.
type resourceKind int

const (
	kindList    resourceKind = iota // list pages; scoped by the query filter, no {id}
	kindRepo                        // {id} is a repository ID
	kindFinding                     // {id} is a finding ID
)

// route is a whitelisted path forwarded to the reused handler.
type route struct {
	pattern string
	kind    resourceKind
}

// sharedRoutes is the entire surface the portal exposes. It is read-only: every
// route is a GET. Anything not listed here 404s at the portal and never reaches
// the inner handler — in particular /api, /api/v1, /events, /settings, /scans,
// add-repo, delete, the source blob view, and the finding status/notes writes
// are all withheld. (The ReadOnly view scope also refuses those writes at the
// handler as defense in depth, but the portal never forwards them in the first
// place.)
var sharedRoutes = []route{
	{"GET /{$}", kindList},
	{"GET /findings", kindList},
	{"GET /repositories/{id}", kindRepo},
	{"GET /repositories/{id}/report.md", kindRepo},
	{"GET /findings/{id}", kindFinding},
	{"GET /findings/{id}/report.md", kindFinding},
	{"GET /findings/{id}/csaf.json", kindFinding},
	{"GET /findings/{id}/osv.json", kindFinding},
	{"GET /findings/{id}/bundle.tar.gz", kindFinding},
}

// Handler wires the portal: auth routes, the whitelisted authenticated surface,
// and static assets, all behind the outer host/CSRF guard.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /auth/logout", s.logout)

	// Static assets are embedded, read-only, and needed before login; forward
	// them straight through without a session.
	mux.Handle("GET /static/", s.forward())

	for _, rt := range sharedRoutes {
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

// requireAuth admits only requests with a valid session. On every request it
// re-fetches the visitor's maintained repositories from GitHub so that changes
// in repo access are reflected immediately without waiting for the session to
// expire. An invalid GitHub token clears the session and redirects to login;
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
		repos, err := fetchMaintainedRepos(r.Context(), sess.Token)
		if err != nil {
			s.log.Warn("fetch maintained repos failed", "login", sess.Login, "err", err)
			if isGitHubUnauthorized(err) {
				clearCookie(w, sessionCookie)
				s.redirectToLogin(w, r)
				return
			}
			http.Error(w, "GitHub is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		scope, err := resolveScope(r.Context(), s.db, repos)
		if err != nil {
			s.log.Error("resolve scope failed", "login", sess.Login, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		ctx := context.WithValue(r.Context(), userKey{}, &user{Login: sess.Login, RepoIDs: scope.RepoIDs})
		ctx = web.WithViewScope(ctx, web.ViewScope{RepoIDs: scope.RepoIDs, ReadOnly: true})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authorize enforces per-resource ownership: it resolves the route's {id} to a
// repository and 404s when that repository is not in the visitor's scope. List
// routes carry no {id} and are already constrained by the scoped query.
func (s *Server) authorize(kind resourceKind, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if kind == kindList {
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
