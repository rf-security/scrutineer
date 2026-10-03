// model_proxy.go implements the opt-in host-side Anthropic API proxy
// (-model-proxy). Each scan gets a short-lived token that authenticates only
// to this proxy; the proxy swaps the token for the real ANTHROPIC_API_KEY and
// forwards the request, so the key itself never enters a scan container. See
// docs/model-proxy.md.
package worker

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

// ModelProxyPathPrefix is the path the web server routes to a ModelProxy when
// one is configured (Server.ModelProxy in internal/web). Containers reach
// it through the egress proxy at ModelProxyURL, never directly.
const ModelProxyPathPrefix = "/model-proxy/anthropic"

// defaultAnthropicBaseURL is the upstream ModelProxy forwards to when the
// operator has not set a custom model base URL.
const defaultAnthropicBaseURL = "https://api.anthropic.com"

// modelProxyMaxBody caps a forwarded request body at 32 MiB, generous for a
// single Messages API turn, so a hostile scan cannot use the proxy to buffer
// unbounded data on the host.
const modelProxyMaxBody = 32 << 20

// modelProxyTokenPrefix names a proxy-issued scan token so it reads clearly in
// logs and error messages; the token itself is never logged.
const modelProxyTokenPrefix = "scrutineer-scan-"

// modelProxyTokenEntropy is the number of crypto/rand bytes backing each
// issued token.
const modelProxyTokenEntropy = 32

// ModelProxy keeps the real Anthropic API key on the host and hands out
// short-lived, scan-scoped tokens that a container presents instead of it.
// ServeHTTP swaps a valid token for the key on an allowlisted route and
// forwards the request upstream, so a hostile scan that reads its own
// environment or process list never sees the key.
type ModelProxy struct {
	upstream *url.URL
	apiKey   string
	log      *slog.Logger
	proxy    *httputil.ReverseProxy

	mu     sync.RWMutex
	grants map[[sha256.Size]byte]time.Time // sha256(token) -> expiry; zero means no expiry
}

// errUpstreamRedirect marks an upstream 3xx response, which ServeHTTP refuses
// to follow or relay: forwarding a Location the allowlist never approved
// would turn the proxy into an open redirector.
var errUpstreamRedirect = errors.New("model proxy: upstream redirect refused")

// NewModelProxy builds a ModelProxy that forwards allowlisted Anthropic API
// routes to upstreamBaseURL (defaultAnthropicBaseURL when empty), attaching
// apiKey to every forwarded request. log receives denial and upstream-error
// lines, never headers, keys or tokens; a nil log discards them.
func NewModelProxy(upstreamBaseURL, apiKey string, log *slog.Logger) (*ModelProxy, error) {
	if apiKey == "" {
		return nil, errors.New("model proxy requires ANTHROPIC_API_KEY")
	}
	if upstreamBaseURL == "" {
		upstreamBaseURL = defaultAnthropicBaseURL
	}
	u, err := url.Parse(upstreamBaseURL)
	if err != nil {
		return nil, fmt.Errorf("model proxy: parse upstream base url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("model proxy: upstream base url must be an absolute http or https url, got %q", upstreamBaseURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("model proxy: upstream base url must not carry userinfo: %s", redactURLUserinfo(upstreamBaseURL))
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("model proxy: upstream base url must not carry a query or fragment")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	p := &ModelProxy{upstream: u, apiKey: apiKey, log: log, grants: make(map[[sha256.Size]byte]time.Time)}
	p.proxy = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		FlushInterval:  -1, // stream SSE turns to the CLI as they arrive
		Transport:      http.DefaultTransport,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
	}
	return p, nil
}

// Issue mints a scan-scoped token valid until expires (the zero Time means no
// expiry) and returns it along with an idempotent revoke function. Only the
// token's sha256 is stored; the token itself is never logged.
func (p *ModelProxy) Issue(expires time.Time) (token string, revoke func()) {
	var raw [modelProxyTokenEntropy]byte
	_, _ = rand.Read(raw[:])
	token = modelProxyTokenPrefix + hex.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))
	p.mu.Lock()
	p.grants[sum] = expires
	p.mu.Unlock()
	var once sync.Once
	return token, func() {
		once.Do(func() {
			p.mu.Lock()
			delete(p.grants, sum)
			p.mu.Unlock()
		})
	}
}

// ServeHTTP authenticates a scan token, allowlists the requested Anthropic
// route, then forwards the request upstream with the real API key attached.
func (p *ModelProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, ModelProxyPathPrefix+"/") {
		http.NotFound(w, r)
		return
	}
	sub := strings.TrimPrefix(r.URL.Path, ModelProxyPathPrefix)

	if !p.authorized(r) {
		p.log.Warn("model proxy denied", "method", r.Method, "path", r.URL.Path, "reason", "missing or unknown token")
		writeAnthropicError(w, http.StatusUnauthorized, "authentication_error", "invalid or expired scan token")
		return
	}
	if r.URL.RawPath != "" || path.Clean(sub) != sub || !modelProxyRouteAllowed(r.Method, sub) {
		p.log.Warn("model proxy denied", "method", r.Method, "path", r.URL.Path, "reason", "route not permitted")
		writeAnthropicError(w, http.StatusForbidden, "permission_error", "route not permitted")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, modelProxyMaxBody)
	r.URL.Path = sub
	p.proxy.ServeHTTP(w, r)
}

// authorized reports whether r carries a token (the x-api-key header, or a
// Bearer Authorization header) matching a live grant. The raw token is hashed
// before lookup and never logged.
func (p *ModelProxy) authorized(r *http.Request) bool {
	token := r.Header.Get("X-Api-Key")
	if token == "" {
		if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
			token = strings.TrimPrefix(v, "Bearer ")
		}
	}
	if token == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	p.mu.RLock()
	expires, ok := p.grants[sum]
	p.mu.RUnlock()
	return ok && (expires.IsZero() || time.Now().Before(expires))
}

// modelProxyRouteAllowed is the fixed allowlist of Anthropic API routes a scan
// container may reach: a Messages call plus its token count plus read-only
// model catalog lookups. Anything else, including a nested segment under
// /v1/models, is refused.
func modelProxyRouteAllowed(method, sub string) bool {
	switch {
	case method == http.MethodPost && (sub == "/v1/messages" || sub == "/v1/messages/count_tokens"):
		return true
	case method == http.MethodGet && sub == "/v1/models":
		return true
	case method == http.MethodGet && strings.HasPrefix(sub, "/v1/models/"):
		id := strings.TrimPrefix(sub, "/v1/models/")
		return id != "" && !strings.Contains(id, "/")
	default:
		return false
	}
}

// rewrite retargets the outgoing request at the upstream Anthropic API and
// replaces the caller's credentials with the real API key. pr.In.URL.Path is
// already the route with ModelProxyPathPrefix stripped: ServeHTTP sets it on
// the request before invoking the reverse proxy. Out starts as a clone of
// In, so both carry that trimmed path here.
func (p *ModelProxy) rewrite(pr *httputil.ProxyRequest) {
	pr.Out.URL.Scheme = p.upstream.Scheme
	pr.Out.URL.Host = p.upstream.Host
	pr.Out.URL.Path = p.upstream.Path + pr.In.URL.Path
	pr.Out.URL.RawPath = ""
	pr.Out.URL.RawQuery = pr.In.URL.RawQuery
	pr.Out.Host = p.upstream.Host
	for _, h := range []string{"Authorization", "X-Api-Key", "Proxy-Authorization", "Cookie", "X-Real-Ip"} {
		pr.Out.Header.Del(h)
	}
	pr.Out.Header.Set("X-Api-Key", p.apiKey)
}

// modifyResponse strips any upstream Set-Cookie and refuses to relay a
// redirect (see errUpstreamRedirect).
func (p *ModelProxy) modifyResponse(resp *http.Response) error {
	resp.Header.Del("Set-Cookie")
	if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
		return errUpstreamRedirect
	}
	return nil
}

// errorHandler turns a forwarding failure into the Anthropic error shape the
// CLI already knows how to surface, logging only the method, route and error,
// never headers, the key or the token.
func (p *ModelProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeAnthropicError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the model proxy limit")
		return
	}
	p.log.Warn("model proxy upstream error", "method", r.Method, "route", r.URL.Path, "err", err)
	if errors.Is(err, errUpstreamRedirect) {
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "upstream redirect refused")
		return
	}
	writeAnthropicError(w, http.StatusBadGateway, "api_error", "model proxy could not reach the upstream API")
}

// modelProxyErrorBody is the Anthropic error JSON shape so the CLI surfaces a
// proxy-side denial exactly like an API-side one.
type modelProxyErrorBody struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeAnthropicError(w http.ResponseWriter, status int, errType, message string) {
	body := modelProxyErrorBody{Type: "error"}
	body.Error.Type = errType
	body.Error.Message = message
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ModelProxyOf looks through a HostSplitRunner (as containerRunnerOf does) to
// find a configured ModelProxy, or nil when the runner is not container-backed
// or -model-proxy was not enabled.
func ModelProxyOf(r SkillRunner) *ModelProxy {
	if d, ok := containerRunnerOf(r); ok {
		return d.ModelProxy
	}
	return nil
}
