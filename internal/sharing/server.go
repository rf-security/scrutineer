package sharing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
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
// front of the reused scrutineer web handler, plus (in SPA mode) the embedded
// portal UI.
type Server struct {
	cfg    *Config
	db     *gorm.DB
	log    *slog.Logger
	inner  http.Handler // the reused web.Server handler
	grants GrantSource
	access *accessCache
}

// New builds a portal Server. inner is the handler returned by
// (*web.Server).Handler(); the portal forwards its allow-listed routes to it.
func New(cfg *Config, gdb *gorm.DB, log *slog.Logger, inner http.Handler, grants GrantSource) *Server {
	if grants == nil {
		grants = EmptyGrantSource()
	}
	s := &Server{cfg: cfg, db: gdb, log: log, inner: inner, grants: grants, access: newAccessCache(log)}
	if cfg.dev != nil {
		s.access.fetch = devFetch(cfg.dev)
		s.grants = devGrants{inner: grants, userID: cfg.dev.UserID, ids: cfg.dev.RepoIDs}
	}
	return s
}

// Handler wires the portal: auth routes, the allow-listed authenticated
// surface (routes.go), the SPA or legacy pages, and a default-deny fallback,
// all behind the outer host/CSRF guard.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /auth/login", noStore(http.HandlerFunc(s.login)))
	mux.Handle("GET /auth/callback", noStore(http.HandlerFunc(s.callback)))
	mux.Handle("POST /auth/logout", noStore(http.HandlerFunc(s.logout)))
	mux.Handle("GET /auth/status", noStore(http.HandlerFunc(s.accessStatus)))
	mux.Handle("GET /auth/session", noStore(http.HandlerFunc(s.sessionHandler)))
	mux.Handle("GET /auth/access", noStore(s.requireAuth(http.HandlerFunc(s.accessHandler))))

	for _, rt := range apiRoutes {
		mux.Handle(rt.pattern, noStore(s.requireAuth(s.authorize(rt.kind, s.forward()))))
	}
	for _, rt := range downloadRoutes {
		mux.Handle(rt.pattern, noStore(s.requireAuth(s.authorize(rt.kind, s.forward()))))
	}

	if s.cfg.legacy() {
		mux.HandleFunc("GET /auth/loading.js", s.loadingScript)
		mux.HandleFunc("GET /auth/access-watch.js", s.accessWatchScript)
		// Static assets are embedded, read-only, and needed before login;
		// forward them straight through without a session.
		mux.Handle("GET /static/", s.forward())
		for _, rt := range legacyPageRoutes {
			mux.Handle(rt.pattern, s.requireAuth(s.authorize(rt.kind, s.forward())))
		}
	}

	// Everything else: refused, or in SPA mode the document for client routes.
	mux.HandleFunc("/", s.fallback)

	return s.secure(mux)
}

// fallback answers every request no allow-listed pattern matched. Non-GET
// methods, unknown /api/ and /auth/ paths, and anything shaped like a download
// are 404 (never forwarded). In SPA mode other GETs serve the SPA's files or
// its document, which carries no data and so needs no session.
func (s *Server) fallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.notFound(w, r)
		return
	}
	p := r.URL.Path
	if s.cfg.legacy() || isAPIPath(p) || strings.HasPrefix(p, "/auth/") || strings.HasPrefix(p, "/static/") {
		s.notFound(w, r)
		return
	}
	s.serveSPA(w, r)
}

// isAPIPath reports paths whose failures answer with the JSON envelope rather
// than a redirect or text: the API and the portal's JSON auth endpoints.
func isAPIPath(p string) bool {
	return strings.HasPrefix(p, "/api/") || p == "/api"
}

func wantsJSONErrors(r *http.Request) bool {
	return isAPIPath(r.URL.Path) || strings.HasPrefix(r.URL.Path, "/auth/")
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	if isAPIPath(r.URL.Path) {
		writeAPIError(w, http.StatusNotFound, codeNotFound, "not found")
		return
	}
	http.NotFound(w, r)
}

// secure enforces the outer boundary: the request must target the portal's
// configured public host (any loopback name with the dev identity), and every
// state-changing method must be same-origin. A missing Sec-Fetch-Site is
// refused too: a stricter CSRF stance than the local app's.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if !strings.EqualFold(host, s.cfg.host) && (s.cfg.dev == nil || !isLoopbackHost(host)) {
			http.Error(w, "forbidden: invalid host", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("Sec-Fetch-Site") != "same-origin" {
			http.Error(w, "forbidden: cross-site "+r.Method, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// portalScopeHeader tells the SPA whether the answer was built on the
// visitor's complete repository list or on the part found so far.
const portalScopeHeader = "X-Portal-Scope"

// requireAuth admits only requests with a valid session. The visitor's
// repositories come from GitHub via s.access, which re-checks them in the
// background once they are older than accessFreshTTL, so access changes take
// effect within minutes without a GitHub round trip on every request. When
// nothing is cached yet (first visit after login) a request waits at most
// accessLoadingMax (in legacy mode a page navigation gets the progress page
// instead) and is then served on the repositories found so far, marked
// Incomplete and X-Portal-Scope: partial.
//
// Failures: API and /auth/ requests get the JSON envelope (401 unauthorized,
// never a redirect; 503 unavailable). Other requests are redirected to
// /auth/login (with ?next= in SPA mode). An invalid GitHub token clears the
// session; transient upstream failures keep it, so a temporary GitHub outage
// cannot turn into a login loop.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asJSON := wantsJSONErrors(r)
		sess, ok := s.openSession(r)
		if !ok {
			if hasCookie(r, sessionCookie) {
				s.clearCookie(w, sessionCookie)
			}
			s.unauthenticated(w, r, asJSON)
			return
		}
		repos, flight := s.access.lookup(sess.GitHubUserID, sess.Token)
		complete := true
		var err error
		if flight != nil {
			if s.cfg.legacy() && !asJSON && wantsDocument(r) && !s.access.pastLoadingWindow(flight) {
				s.renderLoading(w)
				return
			}
			repos, complete, err = s.access.waitBounded(r.Context(), flight)
		}
		if err != nil {
			s.log.Warn("fetch repository access failed", "login", sess.Login, "err", err)
			if isGitHubUnauthorized(err) {
				s.clearCookie(w, sessionCookie)
				s.unauthenticated(w, r, asJSON)
				return
			}
			s.failure(w, asJSON, http.StatusServiceUnavailable, codeUnavailable, "GitHub is temporarily unavailable")
			return
		}
		grantedRepoIDs, err := s.grants.RepositoryIDs(r.Context(), sess.GitHubUserID)
		if err != nil {
			s.log.Error("resolve configured grants failed", "login", sess.Login, "github_user_id", sess.GitHubUserID, "err", err)
			s.failure(w, asJSON, http.StatusInternalServerError, codeInternal, "internal error")
			return
		}
		scope, err := resolveScope(r.Context(), s.db, repos, grantedRepoIDs)
		if err != nil {
			s.log.Error("resolve scope failed", "login", sess.Login, "err", err)
			s.failure(w, asJSON, http.StatusInternalServerError, codeInternal, "internal error")
			return
		}
		scope.Incomplete = !complete
		if complete {
			w.Header().Set(portalScopeHeader, "complete")
		} else {
			w.Header().Set(portalScopeHeader, "partial")
		}
		ctx := context.WithValue(r.Context(), userKey{}, &user{
			GitHubUserID: sess.GitHubUserID,
			Login:        sess.Login,
			RepoIDs:      scope.RepoIDs,
			Scope:        scope,
		})
		ctx = web.WithViewScope(ctx, scope)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) unauthenticated(w http.ResponseWriter, r *http.Request, asJSON bool) {
	switch {
	case asJSON:
		writeAPIError(w, http.StatusUnauthorized, codeUnauthorized, "sign in required")
	case s.cfg.legacy():
		redirectTo(w, r, "/auth/login")
	default:
		redirectTo(w, r, "/auth/login?next="+escapeNext(r.URL.RequestURI()))
	}
}

func escapeNext(uri string) string {
	if !validNext(uri) {
		return "%2F"
	}
	return url.QueryEscape(uri)
}

func (s *Server) failure(w http.ResponseWriter, asJSON bool, status int, code, msg string) {
	if asJSON {
		writeAPIError(w, status, code, msg)
		return
	}
	http.Error(w, msg, status)
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
			s.notFound(w, r)
			return
		}
		id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
		if err != nil {
			s.notFound(w, r)
			return
		}
		repoID, err := s.repoIDFor(r.Context(), kind, uint(id))
		if err != nil || repoID == 0 {
			s.notFound(w, r)
			return
		}
		if _, allowed := u.RepoIDs[repoID]; !allowed {
			s.notFound(w, r)
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

// noStore marks a response private to this visitor: Cache-Control: no-store
// and Vary: Cookie, forced at WriteHeader so a forwarded handler's own caching
// header (e.g. the meta vocabularies' max-age) cannot make a scoped answer
// cacheable.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&noStoreWriter{ResponseWriter: w}, r)
	})
}

type noStoreWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *noStoreWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		addVary(h, "Cookie")
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *noStoreWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *noStoreWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func addVary(h http.Header, v string) {
	for _, existing := range h.Values("Vary") {
		for _, part := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(part), v) {
				return
			}
		}
	}
	h.Add("Vary", v)
}

// The error envelope, byte-compatible with internal/web's writeUIError so the
// SPA's ApiError parsing treats portal and forwarded errors alike:
// {"code":..., "error":..., "request_id":...} with X-Request-Id echoing the id
// (TestErrorEnvelopeMatchesWeb pins this).
const (
	codeUnauthorized = "unauthorized"
	codeNotFound     = "not_found"
	codeUnavailable  = "unavailable"
	codeInternal     = "internal"

	requestIDHeader = "X-Request-Id"
	requestIDBytes  = 8
)

func writeAPIError(w http.ResponseWriter, status int, code, msg string) {
	id := w.Header().Get(requestIDHeader)
	if id == "" {
		b := make([]byte, requestIDBytes)
		_, _ = rand.Read(b)
		id = hex.EncodeToString(b)
		w.Header().Set(requestIDHeader, id)
	}
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	writeJSON(w, status, map[string]any{"error": msg, "code": code, "request_id": id})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
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
