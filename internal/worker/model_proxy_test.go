package worker

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewModelProxy_Validation(t *testing.T) {
	for _, tc := range []struct {
		name, upstream, apiKey, wantErrContains string
	}{
		{"empty key", "https://api.anthropic.com", "", "ANTHROPIC_API_KEY"},
		{"userinfo", "https://user:pass@api.anthropic.com", "key", "userinfo"},
		{"query", "https://api.anthropic.com?x=1", "key", "query"},
		{"fragment", "https://api.anthropic.com#frag", "key", "query"},
		{"non-http scheme", "ftp://api.anthropic.com", "key", "http or https"},
		{"no host", "https://", "key", "http or https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewModelProxy(tc.upstream, tc.apiKey, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErrContains)
			}
		})
	}
}

func TestNewModelProxy_DefaultUpstream(t *testing.T) {
	mp, err := NewModelProxy("", "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := mp.upstream.String(); got != defaultAnthropicBaseURL {
		t.Errorf("upstream = %q, want %q", got, defaultAnthropicBaseURL)
	}
}

func TestModelProxy_ForwardsWithRealKeyAndPreservesPathPrefixAndQuery(t *testing.T) {
	var gotPath, gotQuery, gotAPIKey, gotAuth, gotCookie, headerDump string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		gotAPIKey, gotAuth, gotCookie = r.Header.Get("X-Api-Key"), r.Header.Get("Authorization"), r.Header.Get("Cookie")
		headerDump = r.Header.Get("Authorization") + " " + r.Header.Get("X-Api-Key") + " " + r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	mp, err := NewModelProxy(upstream.URL+"/gw", "real-secret-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := mp.Issue(time.Time{})

	req := httptest.NewRequest(http.MethodPost, ModelProxyPathPrefix+"/v1/messages?beta=true", strings.NewReader("{}"))
	req.Header.Set("X-Api-Key", token)
	req.Header.Set("Authorization", "Bearer caller-token")
	req.Header.Set("Cookie", "session=abc")
	w := httptest.NewRecorder()
	mp.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	if gotPath != "/gw/v1/messages" {
		t.Errorf("upstream path = %q, want /gw/v1/messages", gotPath)
	}
	if gotQuery != "beta=true" {
		t.Errorf("upstream query = %q, want beta=true", gotQuery)
	}
	if gotAPIKey != "real-secret-key" {
		t.Errorf("upstream X-Api-Key = %q, want the real key", gotAPIKey)
	}
	if gotAuth != "" {
		t.Errorf("caller Authorization leaked to upstream: %q", gotAuth)
	}
	if gotCookie != "" {
		t.Errorf("caller Cookie leaked to upstream: %q", gotCookie)
	}
	if strings.Contains(headerDump, token) {
		t.Errorf("scan token reached upstream headers: %q", headerDump)
	}
}

func TestModelProxy_BearerTokenAccepted(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	mp, err := NewModelProxy(upstream.URL, "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := mp.Issue(time.Time{})

	req := httptest.NewRequest(http.MethodGet, ModelProxyPathPrefix+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mp.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body)
	}
}

func TestModelProxy_TokenDenials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	mp, err := NewModelProxy(upstream.URL, "key", nil)
	if err != nil {
		t.Fatal(err)
	}

	live, _ := mp.Issue(time.Time{})
	expired, _ := mp.Issue(time.Now().Add(-time.Minute))
	revoked, revoke := mp.Issue(time.Time{})
	revoke()
	revoke() // idempotent; must not panic or double-free

	for _, tc := range []struct{ name, token string }{
		{"missing", ""},
		{"unknown", "scrutineer-scan-" + strings.Repeat("0", 64)},
		{"expired", expired},
		{"revoked", revoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, ModelProxyPathPrefix+"/v1/models", nil)
			if tc.token != "" {
				req.Header.Set("X-Api-Key", tc.token)
			}
			w := httptest.NewRecorder()
			mp.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401, body = %s", w.Code, w.Body)
			}
		})
	}

	req := httptest.NewRequest(http.MethodGet, ModelProxyPathPrefix+"/v1/models", nil)
	req.Header.Set("X-Api-Key", live)
	w := httptest.NewRecorder()
	mp.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("live token status = %d, want 200, body = %s", w.Code, w.Body)
	}
}

func TestModelProxy_RouteDenials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	mp, err := NewModelProxy(upstream.URL, "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := mp.Issue(time.Time{})

	for _, tc := range []struct {
		name, method, path string
	}{
		{"disallowed route", http.MethodGet, "/v1/files"},
		{"nested models id", http.MethodGet, "/v1/models/a/b"},
		{"wrong method", http.MethodGet, "/v1/messages"},
		{"dot-dot traversal", http.MethodPost, "/v1/messages/../complete"},
		{"encoded slash", http.MethodPost, "/v1/messages%2Fcount_tokens"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, ModelProxyPathPrefix+tc.path, nil)
			req.Header.Set("X-Api-Key", token)
			w := httptest.NewRecorder()
			mp.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403, body = %s", w.Code, w.Body)
			}
		})
	}
}

func TestModelProxy_404OutsidePrefix(t *testing.T) {
	mp, err := NewModelProxy("", "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/some/other/path", nil)
	w := httptest.NewRecorder()
	mp.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestModelProxy_UpstreamRedirectRefused(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://evil.example/steal")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()
	mp, err := NewModelProxy(upstream.URL, "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := mp.Issue(time.Time{})

	req := httptest.NewRequest(http.MethodGet, ModelProxyPathPrefix+"/v1/models", nil)
	req.Header.Set("X-Api-Key", token)
	w := httptest.NewRecorder()
	mp.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502, body = %s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location header leaked: %q", loc)
	}
}

func TestModelProxy_UpstreamDown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstream.Close() // closed before use, so every dial fails

	mp, err := NewModelProxy(upstream.URL, "real-secret-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := mp.Issue(time.Time{})

	req := httptest.NewRequest(http.MethodGet, ModelProxyPathPrefix+"/v1/models", nil)
	req.Header.Set("X-Api-Key", token)
	w := httptest.NewRecorder()
	mp.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502, body = %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if strings.Contains(body, "real-secret-key") || strings.Contains(body, token) {
		t.Errorf("error body leaked a secret: %s", body)
	}
}

// limitBustingReader streams n zero bytes without allocating a real buffer,
// so the oversized-body test does not need to hold 32+ MiB in memory.
type limitBustingReader struct{ remaining int64 }

func (r *limitBustingReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	r.remaining -= int64(n)
	return n, nil
}

func TestModelProxy_OversizedBodyRejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	mp, err := NewModelProxy(upstream.URL, "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := mp.Issue(time.Time{})

	const oversize = modelProxyMaxBody + 1
	req := httptest.NewRequest(http.MethodPost, ModelProxyPathPrefix+"/v1/messages", &limitBustingReader{remaining: oversize})
	req.ContentLength = oversize
	req.Header.Set("X-Api-Key", token)
	w := httptest.NewRecorder()
	mp.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413, body = %s", w.Code, w.Body)
	}
}

func TestModelProxy_SSEStreaming(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream ResponseWriter does not support Flush")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event: first\ndata: 1\n\n")
		flusher.Flush()
		<-release
		_, _ = io.WriteString(w, "event: second\ndata: 2\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	mp, err := NewModelProxy(upstream.URL, "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(mp)
	defer server.Close()
	token, _ := mp.Issue(time.Time{})

	req, err := http.NewRequest(http.MethodPost, server.URL+ModelProxyPathPrefix+"/v1/messages", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Api-Key", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	first := make(chan string, 1)
	go func() {
		buf := make([]byte, 256)
		n, _ := resp.Body.Read(buf)
		first <- string(buf[:n])
	}()
	select {
	case got := <-first:
		if !strings.Contains(got, "first") {
			t.Fatalf("first chunk = %q, want it to contain \"first\"", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first SSE chunk; streaming may be buffered instead of flushed")
	}

	close(release)

	second := make(chan string, 1)
	go func() {
		buf := make([]byte, 256)
		n, _ := resp.Body.Read(buf)
		second <- string(buf[:n])
	}()
	select {
	case got := <-second:
		if !strings.Contains(got, "second") {
			t.Fatalf("second chunk = %q, want it to contain \"second\"", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the second SSE chunk")
	}
}

func TestModelProxy_ConcurrentTokens(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	mp, err := NewModelProxy(upstream.URL, "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	tokenA, revokeA := mp.Issue(time.Time{})
	tokenB, revokeB := mp.Issue(time.Time{})
	defer revokeB()

	var wg sync.WaitGroup
	statuses := make(chan int, 10)
	for _, tok := range []string{tokenA, tokenB} {
		for range 5 {
			wg.Add(1)
			go func(tok string) {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, ModelProxyPathPrefix+"/v1/models", nil)
				req.Header.Set("X-Api-Key", tok)
				w := httptest.NewRecorder()
				mp.ServeHTTP(w, req)
				statuses <- w.Code
			}(tok)
		}
	}
	wg.Wait()
	close(statuses)
	for code := range statuses {
		if code != http.StatusOK {
			t.Errorf("concurrent request status = %d, want 200", code)
		}
	}

	revokeA()
	req := httptest.NewRequest(http.MethodGet, ModelProxyPathPrefix+"/v1/models", nil)
	req.Header.Set("X-Api-Key", tokenA)
	w := httptest.NewRecorder()
	mp.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("revoked token status = %d, want 401", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, ModelProxyPathPrefix+"/v1/models", nil)
	req.Header.Set("X-Api-Key", tokenB)
	w = httptest.NewRecorder()
	mp.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("other token status = %d, want 200", w.Code)
	}
}

func TestModelProxyOf(t *testing.T) {
	if ModelProxyOf(LocalClaude{}) != nil {
		t.Error("a non-container runner must report no model proxy")
	}
	if ModelProxyOf(ContainerRunner{}) != nil {
		t.Error("a container runner without -model-proxy must report no model proxy")
	}
	mp, err := NewModelProxy("", "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	d := ContainerRunner{ModelProxy: mp}
	if ModelProxyOf(d) != mp {
		t.Error("ModelProxyOf did not return the configured proxy")
	}
	split := HostSplitRunner{Container: d}
	if ModelProxyOf(split) != mp {
		t.Error("ModelProxyOf did not look through HostSplitRunner")
	}
}
