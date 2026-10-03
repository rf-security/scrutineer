package worker

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
)

// modelProxyIntegrationScript runs inside the real container: it dumps the
// container's own environment, then exercises the model proxy through
// $ANTHROPIC_BASE_URL exactly as the claude CLI would, so the assertions in
// TestIntegration_ModelProxyRealContainer can tell an allowed route from a
// denied one purely from the recorded HTTP status codes. --path-as-is stops
// curl normalising the ".." locally, so the traversal attempt reaches the
// proxy exactly as written.
const modelProxyIntegrationScript = `
env > /work/env.txt
status_ok=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "x-api-key: $ANTHROPIC_API_KEY" -H 'content-type: application/json' --data '{}' "$ANTHROPIC_BASE_URL/v1/messages")
echo "$status_ok" > /work/status_ok.txt
status_disallowed=$(curl -s -o /dev/null -w '%{http_code}' -H "x-api-key: $ANTHROPIC_API_KEY" "$ANTHROPIC_BASE_URL/v1/files")
echo "$status_disallowed" > /work/status_disallowed.txt
status_traversal=$(curl -s -o /dev/null -w '%{http_code}' --path-as-is -H "x-api-key: $ANTHROPIC_API_KEY" "$ANTHROPIC_BASE_URL/v1/messages/../complete")
echo "$status_traversal" > /work/status_traversal.txt
echo "$ANTHROPIC_API_KEY" > /work/key.txt
`

// modelProxyIntegrationHarness stands in for the claude harness: same Env()
// shape (so ANTHROPIC_API_KEY and ANTHROPIC_BASE_URL are wired the way
// container.go expects), but sh -c the probe script above instead of
// exec'ing a real claude CLI. curlimages/curl's entrypoint execs "$@" when
// the first argument does not start with "-", so "sh -c <script>" runs
// unmodified.
type modelProxyIntegrationHarness struct{ stubHarness }

func (modelProxyIntegrationHarness) Binary() string { return "sh" }
func (modelProxyIntegrationHarness) Args(harness.Job) []string {
	return []string{"-c", modelProxyIntegrationScript}
}
func (modelProxyIntegrationHarness) Env(string) []string { return ClaudeHarness{}.Env("") }

// TestIntegration_ModelProxyRealContainer proves the -model-proxy flow end to
// end against a real docker container: the container never sees the real
// ANTHROPIC_API_KEY, an allowlisted route reaches the fake upstream with the
// real key attached, a disallowed route and a path-traversal attempt are both
// refused. The scan token stops working once RunSkill returns.
func TestIntegration_ModelProxyRealContainer(t *testing.T) {
	image := os.Getenv("SCRUTINEER_TEST_MODEL_PROXY_IMAGE")
	if image == "" {
		t.Skip("set SCRUTINEER_TEST_MODEL_PROXY_IMAGE (e.g. curlimages/curl:8.11.1) to run the model proxy container integration test")
	}
	rt, ok := container.DetectRuntime("docker")
	if !ok {
		t.Skip("docker is unavailable")
	}
	if !imageExistsLocally(t.Context(), rt, image) {
		t.Skipf("image %q is unavailable locally", image)
	}

	const realSecret = "sk-ant-REAL-INTEGRATION-SECRET"
	t.Setenv("ANTHROPIC_API_KEY", realSecret)

	var upstreamSawKey string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSawKey = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	mp, err := NewModelProxy(upstream.URL, realSecret, nil)
	if err != nil {
		t.Fatal(err)
	}

	// The "web listener" the container reaches through the egress proxy,
	// standing in for the web server's root mux that serves the proxy route.
	mux := http.NewServeMux()
	mux.Handle(ModelProxyPathPrefix+"/", mp)
	webListener := httptest.NewServer(mux)
	defer webListener.Close()
	_, webPort, err := net.SplitHostPort(webListener.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	token := NewProxyToken()
	egressPort, err := StartEgressProxy(&EgressProxy{
		Allow:    []string{HostGatewayAlias},
		Token:    token,
		APIPort:  webPort,
		APIHosts: []string{HostGatewayAlias},
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := ProxyURLForHost(token, HostGatewayAlias, egressPort)

	d := ContainerRunner{
		Image:         image,
		Runtime:       rt,
		Harness:       modelProxyIntegrationHarness{},
		ProxyURL:      proxyURL,
		ModelProxy:    mp,
		ModelProxyURL: "http://" + HostGatewayAlias + ":" + webPort + ModelProxyPathPrefix,
	}

	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	var logLines []string
	_, err = d.RunSkill(t.Context(), SkillJob{WorkRoot: work, SrcReady: true, Name: "model-proxy-integration"}, func(e Event) {
		logLines = append(logLines, e.Text)
	})
	if err != nil {
		t.Fatalf("RunSkill: %v\nlog:\n%s", err, strings.Join(logLines, "\n"))
	}

	readWork := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(work, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return strings.TrimSpace(string(data))
	}

	if got := readWork("status_ok.txt"); got != "200" {
		t.Errorf("allowed route status = %q, want 200", got)
	}
	if upstreamSawKey != realSecret {
		t.Errorf("upstream saw X-Api-Key = %q, want the real key", upstreamSawKey)
	}
	if got := readWork("status_disallowed.txt"); got != "403" && got != "404" {
		t.Errorf("disallowed route status = %q, want 403 or 404", got)
	}
	// Go's http.ServeMux redirects an unclean subtree path (307) to the
	// cleaned path before mp.ServeHTTP ever sees it; curl here does not
	// follow that redirect, so 307 lands instead of 403. Either way nothing
	// reaches the upstream: a client that does follow the redirect hits
	// mp.ServeHTTP with the now-clean path, which modelProxyRouteAllowed
	// still refuses (TestModelProxy_RouteDenials/dot-dot_traversal covers
	// that refusal directly, without the redirect hop).
	if got := readWork("status_traversal.txt"); got != "403" && got != "404" && got != "307" {
		t.Errorf("traversal route status = %q, want 403, 404, or 307", got)
	}

	env := readWork("env.txt")
	if strings.Contains(env, realSecret) {
		t.Error("real ANTHROPIC_API_KEY reached the container environment")
	}
	if !strings.Contains(env, "ANTHROPIC_BASE_URL="+d.ModelProxyURL) {
		t.Errorf("container env missing the model proxy base url:\n%s", env)
	}

	scanToken := readWork("key.txt")
	if scanToken == realSecret || !strings.HasPrefix(scanToken, "scrutineer-scan-") {
		t.Fatalf("container ANTHROPIC_API_KEY = %q, want a scan token", scanToken)
	}

	req := httptest.NewRequest(http.MethodGet, ModelProxyPathPrefix+"/v1/models", nil)
	req.Header.Set("X-Api-Key", scanToken)
	w := httptest.NewRecorder()
	mp.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("scan token still valid after RunSkill returned: status = %d", w.Code)
	}
}
