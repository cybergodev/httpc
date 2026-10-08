package httpc

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// forwardProxy creates an HTTP forward proxy that forwards requests to their
// target and tags each with an identifying header so tests can detect which
// proxy was actually used.
func forwardProxy(id string) *httptest.Server {
	// Dedicated transport for forwarding — no proxy, no compression surprises.
	fwd := &http.Transport{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For HTTP proxy requests, r.URL is the full target URL.
		outReq := &http.Request{
			Method: r.Method,
			URL:    r.URL,
			Header: r.Header.Clone(),
		}
		outReq.Header.Set("X-Proxy-ID", id)

		resp, err := fwd.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body) // best-effort test proxying
	}))
}

// TestProxyPool_EndToEndRotation verifies that round-robin actually routes
// sequential requests through different proxies — proving the full pipeline
// (httpc engine → transport.Proxy → pool.Select → proxy dial) rotates IPs.
// TestProxyPool_Rotation consolidates the former EndToEndRotation and
// RotatePerRequest_NoRetries tests (identical echo-target + 3-forwardProxy
// scaffold; only the ProxyRotatePerRequest flag and request count varied).
func TestProxyPool_Rotation(t *testing.T) {
	tests := []struct {
		name             string
		rotatePerRequest bool
		maxRetries       int
		requests         int
	}{
		// Round-robin spreads sequential requests across the pool.
		{"round robin across sequential requests", false, 1, 6},
		// ProxyRotatePerRequest guarantees per-request rotation even on the
		// MaxRetries=0 fast path, which previously had no rotation wiring.
		{"per-request rotation on the no-retry fast path", true, 0, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(r.Header.Get("X-Proxy-ID"))) // best-effort test response
			}))
			defer target.Close()

			ids := []string{"proxy-A", "proxy-B", "proxy-C"}
			proxyURLs := make([]string, len(ids))
			for i, id := range ids {
				p := forwardProxy(id)
				defer p.Close()
				proxyURLs[i] = p.URL
			}

			cfg := DefaultConfig()
			cfg.Connection.ProxyPool = proxyURLs
			cfg.Connection.ProxyRotatePerRequest = tt.rotatePerRequest
			cfg.Retry.MaxRetries = tt.maxRetries
			cfg.Security.AllowPrivateIPs = true // test servers are on localhost
			cfg.Timeouts.Request = 5 * time.Second

			client, err := New(cfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			defer func() { _ = client.Close() }()

			seen := make(map[string]int)
			for i := 0; i < tt.requests; i++ {
				result, err := client.Get(target.URL)
				if err != nil {
					t.Fatalf("Request %d failed: %v", i, err)
				}
				body := strings.TrimSpace(result.Body())
				seen[body]++
				t.Logf("Request %d: proxy=%s, status=%d", i, body, result.StatusCode())
			}

			if len(seen) != 3 {
				t.Errorf("expected 3 distinct proxies visited, got %d: %v", len(seen), seen)
			}
		})
	}
}

// TestProxyPool_RotatePerRequest_SkipsBadProxy was removed: the dead-proxy
// skip scenario is asserted with a stronger contract (dead proxy + Meta
// verification) by TestProxyPool_MetaProxyURL_AfterRetry below.

// TestProxyPool_RotateOn403 verifies that a 403 response triggers a retry
// through a different proxy (status-based rotation via ProxyRotateOnStatus),
// both for a direct target and for a redirect-then-403 target. The redirect
// variant (formerly TestProxyPool_RotateOn403_RedirectSafe) pins that
// redirect-following within a single attempt does NOT consume the rotation
// budget: without deterministic SelectIndex, http.Client's extra Proxy() call
// per redirect would advance the round-robin counter and could land the retry
// on the same proxy.
func TestProxyPool_RotateOn403(t *testing.T) {
	tests := []struct {
		name        string
		redirecting bool
	}{
		{"direct 403 target", false},
		{"redirect-then-403 target stays rotation-safe", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var attempted []string

			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxyID := r.Header.Get("X-Proxy-ID")
				mu.Lock()
				attempted = append(attempted, proxyID)
				mu.Unlock()

				// Redirecting variant: first hop redirects (extra Proxy()
				// call within the same attempt), final hop returns 403.
				if tt.redirecting && r.URL.Path != "/challenge" {
					http.Redirect(w, r, "/challenge", http.StatusFound)
					return
				}
				w.WriteHeader(http.StatusForbidden)
			}))
			defer target.Close()

			ids := []string{"proxy-A", "proxy-B", "proxy-C"}
			proxyURLs := make([]string, len(ids))
			for i, id := range ids {
				p := forwardProxy(id)
				defer p.Close()
				proxyURLs[i] = p.URL
			}

			cfg := DefaultConfig()
			cfg.Connection.ProxyPool = proxyURLs
			cfg.Connection.ProxyRotateOnStatus = []int{403}
			cfg.Security.AllowPrivateIPs = true
			cfg.Retry.MaxRetries = 2
			cfg.Retry.Delay = 50 * time.Millisecond
			cfg.Timeouts.Request = 10 * time.Second

			client, err := New(cfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			defer func() { _ = client.Close() }()

			result, err := client.Get(target.URL)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			if result.StatusCode() != http.StatusForbidden {
				t.Errorf("expected final status 403, got %d", result.StatusCode())
			}

			// Should have attempted at least 2 different proxies
			// (1 original + 1 retry), despite any extra Proxy() calls.
			mu.Lock()
			defer mu.Unlock()
			distinct := make(map[string]bool)
			for _, id := range attempted {
				distinct[id] = true
			}
			if len(distinct) < 2 {
				t.Errorf("expected rotation across >=2 proxies on 403, but only used %d distinct: %v (all attempts: %v)",
					len(distinct), distinct, attempted)
			}
			t.Logf("403 rotation: %d attempts across %d distinct proxies: %v",
				len(attempted), len(distinct), attempted)
		})
	}
}

// newCONNECTProxies spins up n CONNECT-tunnel proxies that each relay to
// targetAddr and count their tunnels. Shared by the HTTPS rotation tests.
func newCONNECTProxies(t *testing.T, n int, targetAddr string) (proxyURLs []string, counts func() []int64) {
	t.Helper()
	raw := make([]int64, n)
	servers := make([]*httptest.Server, n)
	proxyURLs = make([]string, n)

	for i := range proxyURLs {
		idx := i
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "only CONNECT supported", http.StatusBadRequest)
				return
			}
			atomic.AddInt64(&raw[idx], 1)

			dst, err := net.Dial("tcp", targetAddr)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				_ = dst.Close()
				http.Error(w, "hijack not supported", http.StatusInternalServerError)
				return
			}
			clientConn, bufrw, err := hj.Hijack()
			if err != nil {
				_ = dst.Close()
				return
			}
			defer func() { _ = clientConn.Close() }()
			defer func() { _ = dst.Close() }()

			_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n") // best-effort handshake
			_ = bufrw.Flush()                                                       // best-effort handshake completion

			go func() {
				_, _ = io.Copy(dst, bufrw) // tunnel relay
				_ = dst.Close()
			}()
			_, _ = io.Copy(clientConn, dst) // tunnel relay
		}))
		servers[i] = proxy
		t.Cleanup(proxy.Close)
		proxyURLs[i] = proxy.URL
	}

	return proxyURLs, func() []int64 {
		out := make([]int64, len(raw))
		for i := range raw {
			out[i] = atomic.LoadInt64(&raw[i])
		}
		return out
	}
}

// TestProxyPool_HTTPSRotation consolidates the former EndToEndRotation_HTTPS
// and RotatePerRequest_HTTPS tests (identical CONNECT-tunnel scaffold; the
// only differences were the ProxyRotatePerRequest flag and the exactness of
// the distinct-proxy count). Each row proves the full pipeline — engine →
// transport.Proxy → pool.Select → CONNECT tunnel — through real TLS tunnels.
func TestProxyPool_HTTPSRotation(t *testing.T) {
	tests := []struct {
		name              string
		rotatePerRequest  bool
		requests          int
		wantUsedProxies   int    // distinct proxies that opened >=1 tunnel
		wantCountOperator string // "==" or ">="
	}{
		// Baseline: without per-request rotation the pool still spreads
		// sequential requests across all proxies.
		{"sequential requests spread across proxies", false, 6, 3, ">="},
		// ProxyRotatePerRequest: exactly one fresh tunnel per request, no
		// connection reuse through the previous request's tunnel.
		{"per-request rotation uses each proxy exactly once", true, 3, 3, "=="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(r.RemoteAddr)) // best-effort test response
			}))
			defer target.Close()
			targetAddr := strings.TrimPrefix(target.URL, "https://")

			proxyURLs, tunnelCounts := newCONNECTProxies(t, 3, targetAddr)

			cfg := DefaultConfig()
			cfg.Connection.ProxyPool = proxyURLs
			cfg.Connection.ProxyRotatePerRequest = tt.rotatePerRequest
			cfg.Security.AllowPrivateIPs = true
			cfg.Security.InsecureSkipVerify = true // test TLS cert is self-signed
			cfg.Timeouts.Request = 5 * time.Second

			client, err := New(cfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			defer func() { _ = client.Close() }()

			for i := 0; i < tt.requests; i++ {
				result, err := client.Get(target.URL)
				if err != nil {
					t.Fatalf("Request %d failed: %v", i, err)
				}
				t.Logf("Request %d: RemoteAddr=%s, status=%d", i,
					strings.TrimSpace(result.Body()), result.StatusCode())
			}

			counts := tunnelCounts()
			used := 0
			for _, c := range counts {
				if c > 0 {
					used++
				}
			}
			switch tt.wantCountOperator {
			case "==":
				if used != tt.wantUsedProxies {
					t.Errorf("distinct CONNECT proxies used = %d, want exactly %d (tunnel counts: %v)",
						used, tt.wantUsedProxies, counts)
				}
			default:
				if used < tt.wantUsedProxies {
					t.Errorf("distinct CONNECT proxies used = %d, want at least %d (tunnel counts: %v)",
						used, tt.wantUsedProxies, counts)
				}
			}
		})
	}
}

// TestProxyPool_RotateOn403_OneProxySucceeds simulates the real-world CF/WAF
// scenario: proxy-A always gets 403 (blocked), proxy-B returns 200 (passes).
// The client should rotate from A to B on 403 and return 200.
func TestProxyPool_RotateOn403_OneProxySucceeds(t *testing.T) {
	var mu sync.Mutex
	var attempted []string

	// Target returns 403 if request came from proxy-A, 200 if from proxy-B.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyID := r.Header.Get("X-Proxy-ID")
		mu.Lock()
		attempted = append(attempted, proxyID)
		mu.Unlock()

		if proxyID == "proxy-A" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("CF blocked")) // best-effort test response
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK from " + proxyID)) // best-effort test response
	}))
	defer target.Close()

	// Two forward proxies: A (blocked by CF) and B (passes CF).
	proxyA := forwardProxy("proxy-A")
	defer proxyA.Close()
	proxyB := forwardProxy("proxy-B")
	defer proxyB.Close()

	cfg := DefaultConfig()
	cfg.Connection.ProxyPool = []string{proxyA.URL, proxyB.URL}
	cfg.Connection.ProxyRotateOnStatus = []int{403}
	cfg.Security.AllowPrivateIPs = true
	cfg.Retry.MaxRetries = 3
	cfg.Retry.Delay = 50 * time.Millisecond
	cfg.Timeouts.Request = 10 * time.Second

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	t.Logf("Final status: %d, body: %s, attempts: %d",
		result.StatusCode(), strings.TrimSpace(result.Body()), result.Meta.Attempts)
	t.Logf("Attempted proxies: %v", attempted)

	if result.StatusCode() != http.StatusOK {
		t.Errorf("expected final status 200 (from proxy-B), got %d", result.StatusCode())
	}
	if len(attempted) < 2 {
		t.Errorf("expected at least 2 attempts (A then B), got %d: %v", len(attempted), attempted)
	}
}

// TestProxyPool_MetaProxyURL verifies Result.Meta.ProxyURL reports the pool
// entry that actually served each request. The target echoes the forwarding
// proxy's ID, so the metadata is cross-checked against ground truth rather
// than against itself.
func TestProxyPool_MetaProxyURL(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("X-Proxy-ID"))) // best-effort test response
	}))
	defer target.Close()

	ids := []string{"proxy-A", "proxy-B", "proxy-C"}
	proxyURLs := make([]string, len(ids))
	idByURL := make(map[string]string, len(ids))
	for i, id := range ids {
		p := forwardProxy(id)
		defer p.Close()
		proxyURLs[i] = p.URL
		idByURL[p.URL] = id
	}

	cfg := DefaultConfig()
	cfg.Connection.ProxyPool = proxyURLs
	cfg.Connection.ProxyRotatePerRequest = true
	cfg.Retry.MaxRetries = 0 // exercise the no-retry fast path
	cfg.Security.AllowPrivateIPs = true
	cfg.Timeouts.Request = 5 * time.Second

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	seen := make(map[string]int)
	for i := 0; i < 3; i++ {
		result, err := client.Get(target.URL)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		if result.Meta.ProxyURL == "" {
			t.Fatalf("Request %d: Meta.ProxyURL is empty, want the serving proxy", i)
		}
		id, ok := idByURL[result.Meta.ProxyURL]
		if !ok {
			t.Fatalf("Request %d: Meta.ProxyURL %q is not a configured pool entry", i, result.Meta.ProxyURL)
		}
		if echoed := strings.TrimSpace(result.Body()); echoed != id {
			t.Errorf("Request %d: Meta.ProxyURL says %s but the request was forwarded by %s",
				i, id, echoed)
		}
		seen[result.Meta.ProxyURL]++
	}
	if len(seen) != 3 {
		t.Errorf("expected Meta.ProxyURL to report 3 distinct proxies, got %d: %v", len(seen), seen)
	}
}

// TestProxyPool_MetaProxyURL_SingleProxy verifies Meta.ProxyURL for a single
// static Connection.ProxyURL (the highest-priority proxy mode).
func TestProxyPool_MetaProxyURL_SingleProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("X-Proxy-ID"))) // best-effort test response
	}))
	defer target.Close()

	staticProxy := forwardProxy("static-proxy")
	defer staticProxy.Close()

	cfg := DefaultConfig()
	cfg.Connection.ProxyURL = staticProxy.URL
	cfg.Security.AllowPrivateIPs = true
	cfg.Timeouts.Request = 5 * time.Second

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if result.Meta.ProxyURL != staticProxy.URL {
		t.Errorf("Meta.ProxyURL = %q, want %q", result.Meta.ProxyURL, staticProxy.URL)
	}
}

// TestMetaProxyURL_DirectConnection verifies Meta.ProxyURL stays empty when
// no proxy is configured.
func TestMetaProxyURL_DirectConnection(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok")) // best-effort test response
	}))
	defer target.Close()

	cfg := DefaultConfig()
	cfg.Security.AllowPrivateIPs = true // test server is on localhost
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if result.Meta.ProxyURL != "" {
		t.Errorf("Meta.ProxyURL = %q, want empty for direct connection", result.Meta.ProxyURL)
	}
}

// TestProxyPool_MetaProxyURL_AfterRetry verifies Meta.ProxyURL reports the
// proxy that served the FINAL attempt when earlier attempts failed on a dead
// proxy and rotated away — the scenario dev_test/main_6.go debugs.
func TestProxyPool_MetaProxyURL_AfterRetry(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("X-Proxy-ID"))) // best-effort test response
	}))
	defer target.Close()

	deadProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "should not be reached", http.StatusInternalServerError)
	}))
	deadProxy.Close() // closed immediately so connections are refused

	healthyProxy := forwardProxy("proxy-A")
	defer healthyProxy.Close()

	cfg := DefaultConfig()
	// Dead proxy first: the initial attempt (base index 0) hits it, the
	// retry (base index 1) must rotate to the healthy proxy.
	cfg.Connection.ProxyPool = []string{deadProxy.URL, healthyProxy.URL}
	cfg.Connection.ProxyRotatePerRequest = true
	cfg.Retry.MaxRetries = 1
	cfg.Retry.Delay = 10 * time.Millisecond
	cfg.Security.AllowPrivateIPs = true
	cfg.Timeouts.Request = 10 * time.Second

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("Request failed (should have rotated past dead proxy): %v", err)
	}
	if result.Meta.Attempts < 2 {
		t.Fatalf("expected a retry past the dead proxy, attempts = %d", result.Meta.Attempts)
	}
	if result.Meta.ProxyURL != healthyProxy.URL {
		t.Errorf("Meta.ProxyURL = %q, want %q (the final attempt's proxy)",
			result.Meta.ProxyURL, healthyProxy.URL)
	}
	if echoed := strings.TrimSpace(result.Body()); echoed != "proxy-A" {
		t.Errorf("forwarded by %q, want proxy-A", echoed)
	}
}
