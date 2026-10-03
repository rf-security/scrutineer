package web

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/worker"
)

func TestHandler_modelProxyRoute(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	t.Run("absent without -model-proxy", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, worker.ModelProxyPathPrefix+"/v1/models", nil)
		r.Host = "host.docker.internal:8080"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code == http.StatusUnauthorized {
			t.Fatal("model proxy route answered although no proxy is configured")
		}
	})

	mp, err := worker.NewModelProxy("", "real-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.ModelProxy = mp
	var logBuf bytes.Buffer
	s.Log = slog.New(slog.NewTextHandler(&logBuf, nil))

	// A scan container's request carries the runtime host alias, which the
	// browser-facing securityHeaders host check rejects. The route must still
	// reach the proxy, whose own token check answers 401 here.
	r := httptest.NewRequest(http.MethodGet, worker.ModelProxyPathPrefix+"/v1/models", nil)
	r.Host = "host.docker.internal:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 from the model proxy token check; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "authentication_error") {
		t.Errorf("body = %s, want the proxy's Anthropic-shaped error", w.Body.String())
	}
	if !strings.Contains(logBuf.String(), "path="+worker.ModelProxyPathPrefix+"/v1/models") {
		t.Errorf("model proxy request left no http log line; log=%s", logBuf.String())
	}
}
