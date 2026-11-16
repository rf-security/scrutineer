package web

import (
	"bytes"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// UI v2 at the root. With Server.UIRoot set, Handler() serves the SPA (built
// with UI_BASE=/) at "/" and moves the template UI under /legacy/. Download
// routes (report.md, csaf.json, bundle.tar.gz, ...) keep answering at the root
// as well, because the SPA's exports links are root-absolute (02-api-plan.md
// section 5.3). /api/, /static/ and /claim-check are unchanged.
//
// The template UI's handlers and templates are untouched: /legacy/ strips its
// prefix before the operator mux sees the request, and legacyRewriter puts it
// back on the root-absolute URLs the pages, redirects and SSE fragments carry.

const (
	legacyPrefix = "/legacy"
	uiRootBase   = "/"
)

// uiDownloadRE matches the export and download paths the SPA links to, which
// the operator mux serves at the root next to the SPA.
var uiDownloadRE = regexp.MustCompile(`\.(md|html|json|diff|patch|tar\.gz|csv|sarif|jsonl)$`)

// uiBase is where the SPA is mounted: "/ui/" by default, "/" with UIRoot.
func (s *Server) uiBase() string {
	if s.UIRoot {
		return uiRootBase
	}
	return uiBasePath
}

// registerUIMount mounts the SPA and the template UI on root. Without UIRoot
// that is the transition layout: SPA under /ui/, template UI at "/".
func (s *Server) registerUIMount(root *http.ServeMux, mux http.Handler) {
	spa := securityHeaders(s.AllowRemote, s.uiHandler())
	operator := securityHeaders(s.AllowRemote, s.requireOperator(mux))
	if !s.UIRoot {
		root.Handle("GET "+uiBasePath, spa)
		root.Handle("GET /login", securityHeaders(s.AllowRemote, http.HandlerFunc(s.login)))
		root.Handle("/", operator)
		return
	}

	// Old /ui/ bookmarks land on the same SPA route at the root.
	root.HandleFunc("GET "+uiBasePath, func(w http.ResponseWriter, r *http.Request) {
		target := "/" + strings.TrimPrefix(r.URL.Path, uiBasePath)
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusFound)
	})
	// GET /login?token= is the printed sign-in link; without a token the path
	// is the SPA's own login route.
	root.Handle("GET /login", securityHeaders(s.AllowRemote, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("token") {
			s.login(w, r)
			return
		}
		s.uiHandler().ServeHTTP(w, r)
	})))

	legacy := http.NewServeMux()
	legacy.Handle("GET /static/", http.FileServerFS(staticFS))
	legacy.HandleFunc("GET /login", s.login)
	legacy.Handle("/", s.requireOperator(mux))
	root.Handle(legacyPrefix+"/", securityHeaders(s.AllowRemote, http.StripPrefix(legacyPrefix, legacyRewrite(legacy))))

	root.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && !uiDownloadRE.MatchString(r.URL.Path) {
			spa.ServeHTTP(w, r)
			return
		}
		operator.ServeHTTP(w, r)
	}))
}

// legacyURLAttrRE matches the URL-valued attributes the templates emit; group
// 1 is everything up to the opening quote, group 2 the value.
var legacyURLAttrRE = regexp.MustCompile(`(?i)(\s(?:href|src|action|formaction|hx-get|hx-post|hx-put|hx-patch|hx-delete|hx-push-url|hx-replace-url|sse-connect)\s*=\s*["'])(/[^"']*)`)

// legacyRedirectHeaders carry URLs the browser follows.
var legacyRedirectHeaders = []string{"Location", "HX-Redirect", "HX-Location", "HX-Push-Url", "HX-Replace-Url"}

// legacyPath prefixes a root-absolute path with /legacy. Protocol-relative
// URLs, other schemes and already-prefixed paths are returned unchanged.
func legacyPath(v string) string {
	if !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") || strings.HasPrefix(v, `/\`) {
		return v
	}
	if v == legacyPrefix || strings.HasPrefix(v, legacyPrefix+"/") || strings.HasPrefix(v, legacyPrefix+"?") {
		return v
	}
	return legacyPrefix + v
}

func rewriteLegacyHTML(b []byte) []byte {
	return legacyURLAttrRE.ReplaceAllFunc(b, func(m []byte) []byte {
		sub := legacyURLAttrRE.FindSubmatch(m)
		out := make([]byte, 0, len(m)+len(legacyPrefix))
		out = append(out, sub[1]...)
		return append(out, legacyPath(string(sub[2]))...)
	})
}

func legacyRewrite(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lw := &legacyRewriter{ResponseWriter: w}
		h.ServeHTTP(lw, r)
		lw.finish()
	})
}

type legacyMode int

const (
	legacyUndecided legacyMode = iota
	legacyPass                 // non-HTML: bytes go straight through
	legacyBuffer               // HTML: buffered, rewritten, then sent
	legacyStream               // SSE: each write rewritten as it goes
)

// legacyRewriter rewrites the template UI's responses for the /legacy/ mount.
type legacyRewriter struct {
	http.ResponseWriter
	mode   legacyMode
	status int
	buf    bytes.Buffer
}

func (lw *legacyRewriter) Unwrap() http.ResponseWriter { return lw.ResponseWriter }

func (lw *legacyRewriter) WriteHeader(code int) {
	if lw.mode != legacyUndecided {
		return
	}
	h := lw.Header()
	for _, k := range legacyRedirectHeaders {
		if v := h.Get(k); v != "" {
			h.Set(k, legacyPath(v))
		}
	}
	ct := h.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "text/html"):
		lw.mode = legacyBuffer
		lw.status = code
		h.Del("Content-Length")
		return
	case strings.HasPrefix(ct, "text/event-stream"):
		lw.mode = legacyStream
	default:
		lw.mode = legacyPass
	}
	lw.ResponseWriter.WriteHeader(code)
}

func (lw *legacyRewriter) Write(b []byte) (int, error) {
	if lw.mode == legacyUndecided {
		if lw.Header().Get("Content-Type") == "" {
			lw.Header().Set("Content-Type", http.DetectContentType(b))
		}
		lw.WriteHeader(http.StatusOK)
	}
	switch lw.mode {
	case legacyBuffer:
		return lw.buf.Write(b)
	case legacyStream:
		if _, err := lw.ResponseWriter.Write(rewriteLegacyHTML(b)); err != nil {
			return 0, err
		}
		return len(b), nil
	default:
		return lw.ResponseWriter.Write(b)
	}
}

func (lw *legacyRewriter) Flush() {
	if lw.mode == legacyBuffer {
		return
	}
	if f, ok := lw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// finish sends a buffered HTML response once the handler returns.
func (lw *legacyRewriter) finish() {
	if lw.mode != legacyBuffer {
		return
	}
	body := rewriteLegacyHTML(lw.buf.Bytes())
	lw.Header().Set("Content-Length", strconv.Itoa(len(body)))
	lw.ResponseWriter.WriteHeader(lw.status)
	_, _ = lw.ResponseWriter.Write(body)
}
