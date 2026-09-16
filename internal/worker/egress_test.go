package worker

import (
	"bufio"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStartScopedEgressProxyClosesListener(t *testing.T) {
	port, cleanup, err := StartScopedEgressProxy(&EgressProxy{
		Allow: []string{"example.com"},
		Token: "scan-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		cleanup()
		t.Fatalf("dial scoped proxy: %v", err)
	}
	_ = conn.Close()
	cleanup()
	if conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("scoped proxy listener remains open after cleanup")
	}
}

func TestEgressProxyRejectsAPIPortCONNECT(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	upstreamHost, apiPort, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	type starter func(*EgressProxy) (string, func(), error)
	starters := map[string]starter{
		"process-wide": func(p *EgressProxy) (string, func(), error) {
			port, err := StartEgressProxy(p)
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), func() {}, err
		},
		"scoped": func(p *EgressProxy) (string, func(), error) {
			port, cleanup, err := StartScopedEgressProxy(p)
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), cleanup, err
		},
		"sidecar": func(p *EgressProxy) (string, func(), error) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return "", func() {}, err
			}
			addr := ln.Addr().String()
			if err := ln.Close(); err != nil {
				return "", func() {}, err
			}
			go func() { _ = ServeEgressProxy(p, addr) }()
			return addr, func() {}, nil
		},
	}
	forms := []struct {
		name          string
		requestTarget string
		host          string
	}{
		{name: "authority-form", requestTarget: net.JoinHostPort(HostGatewayAlias, apiPort), host: net.JoinHostPort(HostGatewayAlias, apiPort)},
		{name: "path-form", requestTarget: "/x", host: net.JoinHostPort(HostGatewayAlias, apiPort)},
	}

	for starterName, start := range starters {
		t.Run(starterName, func(t *testing.T) {
			const token = "scan-token"
			proxyAddr, cleanup, err := start(&EgressProxy{
				Allow:           []string{HostGatewayAlias},
				Token:           token,
				APIPort:         apiPort,
				GatewayDialHost: upstreamHost,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()

			for _, form := range forms {
				t.Run(form.name, func(t *testing.T) {
					resp, conn := connectThroughProxy(t, proxyAddr, token, form.requestTarget, form.host)
					defer func() { _ = conn.Close() }()
					defer func() { _ = resp.Body.Close() }()
					if resp.StatusCode != http.StatusForbidden {
						t.Fatalf("authenticated CONNECT to host API: got %d, want 403", resp.StatusCode)
					}
				})
			}
		})
	}
}

func TestAPIConnectGuardMatchesConfiguredHostCaseInsensitively(t *testing.T) {
	const token = "scan-token"
	p := &EgressProxy{Token: token, APIPort: "8080", APIHosts: []string{"192.168.64.1"}}
	for _, host := range []string{"192.168.64.1:8080", "HOST.DOCKER.INTERNAL:8080"} {
		if strings.HasPrefix(host, "HOST.") {
			p.APIHosts = nil
		}
		r := httptest.NewRequest(http.MethodConnect, host, nil)
		r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("harness:"+token)))
		w := httptest.NewRecorder()
		apiConnectGuard(p).ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("CONNECT %s: got %d, want 403", host, w.Code)
		}
	}
}

func TestAPIConnectGuardPreservesProxyAuthentication(t *testing.T) {
	p := &EgressProxy{Token: "scan-token", APIPort: "8080", Allow: []string{HostGatewayAlias}}
	for _, auth := range []string{"", "Basic " + base64.StdEncoding.EncodeToString([]byte("harness:wrong"))} {
		r := httptest.NewRequest(http.MethodConnect, HostGatewayAlias+":8080", nil)
		r.Header.Set("Proxy-Authorization", auth)
		w := httptest.NewRecorder()
		apiConnectGuard(p).ServeHTTP(w, r)
		if w.Code != http.StatusProxyAuthRequired {
			t.Errorf("authorization %q: got %d, want 407", auth, w.Code)
		}
		if got, want := w.Header().Get("Proxy-Authenticate"), `Basic realm="harness"`; got != want {
			t.Errorf("authorization %q: Proxy-Authenticate = %q, want %q", auth, got, want)
		}
	}
}

func TestEgressProxyPreservesInspectedAPIRequest(t *testing.T) {
	const scanToken = "bearer-token"
	var gotHost, spoofedHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/ping":
			gotHost = r.Host
		case "/api/v1/findings":
			spoofedHost = r.Host
			if strings.HasPrefix(r.Host, "localhost:") {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Error(w, "forbidden: invalid host", http.StatusForbidden)
			return
		default:
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+scanToken {
			http.Error(w, "bad API request", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	upstreamHost, apiPort, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	const proxyToken = "scan-proxy-token"
	proxyPort, cleanup, err := StartScopedEgressProxy(&EgressProxy{
		Allow:           []string{HostGatewayAlias},
		Token:           proxyToken,
		APIPort:         apiPort,
		GatewayDialHost: upstreamHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	proxyURL, err := url.Parse(ProxyURLForHost(proxyToken, "127.0.0.1", proxyPort))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: time.Second}
	target := "http://" + net.JoinHostPort(HostGatewayAlias, apiPort) + "/api/ping"
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+scanToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("forward request to host API: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("forward request to host API: got %d, want 204", resp.StatusCode)
	}
	if want := net.JoinHostPort(HostGatewayAlias, apiPort); gotHost != want {
		t.Fatalf("forward request Host = %q, want %q", gotHost, want)
	}

	// A contradictory Host header on an absolute-form proxy request does not
	// recreate the CONNECT bypass: net/http derives the proxy request's Host
	// from the absolute target before the inspected forward path sees it.
	conn, err := net.DialTimeout("tcp", proxyURL.Host, time.Second)
	if err != nil {
		t.Fatalf("dial proxy for conflicting Host request: %v", err)
	}
	defer func() { _ = conn.Close() }()
	auth := base64.StdEncoding.EncodeToString([]byte("harness:" + proxyToken))
	if _, err := conn.Write([]byte("GET http://" + net.JoinHostPort(HostGatewayAlias, apiPort) +
		"/api/v1/findings HTTP/1.1\r\nHost: " + net.JoinHostPort("localhost", apiPort) +
		"\r\nProxy-Authorization: Basic " + auth + "\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write conflicting Host request: %v", err)
	}
	spoofResp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read conflicting Host response: %v", err)
	}
	defer func() { _ = spoofResp.Body.Close() }()
	if spoofResp.StatusCode != http.StatusForbidden {
		t.Fatalf("forward request with conflicting Host: got %d, want 403", spoofResp.StatusCode)
	}
	if want := net.JoinHostPort(HostGatewayAlias, apiPort); spoofedHost != want {
		t.Fatalf("forward request with conflicting Host reached upstream as %q, want %q", spoofedHost, want)
	}
}

func TestEgressProxyPreservesConfiguredHostPortCONNECT(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	upstreamHost, modelPort, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	const token = "scan-token"
	proxyPort, cleanup, err := StartScopedEgressProxy(&EgressProxy{
		Allow:           []string{HostGatewayAlias},
		Token:           token,
		APIPort:         "1",
		HostPorts:       []string{modelPort},
		GatewayDialHost: upstreamHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
	resp, conn := connectThroughProxy(t, proxyAddr, token, net.JoinHostPort(HostGatewayAlias, modelPort), net.JoinHostPort(HostGatewayAlias, modelPort))
	defer func() { _ = conn.Close() }()
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated CONNECT to configured host port: got %d, want 200", resp.StatusCode)
	}
}

func connectThroughProxy(t *testing.T, proxyAddr, token, requestTarget, host string) (*http.Response, net.Conn) {
	t.Helper()
	var conn net.Conn
	var err error
	deadline := time.Now().Add(time.Second)
	for {
		conn, err = net.DialTimeout("tcp", proxyAddr, 50*time.Millisecond)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial proxy: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	auth := base64.StdEncoding.EncodeToString([]byte("harness:" + token))
	if _, err := conn.Write([]byte("CONNECT " + requestTarget + " HTTP/1.1\r\nHost: " + host +
		"\r\nProxy-Authorization: Basic " + auth + "\r\n\r\n")); err != nil {
		_ = conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	return resp, conn
}
