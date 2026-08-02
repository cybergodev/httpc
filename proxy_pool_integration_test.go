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
		defer resp.Body.Close()

		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
}

// TestProxyPool_EndToEndRotation verifies that round-robin actually routes
// sequential requests through different proxies — proving the full pipeline
// (httpc engine → transport.Proxy → pool.Select → proxy dial) rotates IPs.
func TestProxyPool_EndToEndRotation(t *testing.T) {
	// Target echoes which proxy forwarded the request.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.Header.Get("X-Proxy-ID")))
	}))
	defer target.Close()

	// Create 3 forward proxies.
	ids := []string{"proxy-A", "proxy-B", "proxy-C"}
	proxyURLs := make([]string, len(ids))
	for i, id := range ids {
		p := forwardProxy(id)
		defer p.Close()
		proxyURLs[i] = p.URL
	}

	cfg := DefaultConfig()
	cfg.Connection.ProxyPool = proxyURLs
	cfg.Security.AllowPrivateIPs = true // test servers are on localhost
	cfg.Timeouts.Request = 5 * time.Second

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	seen := make(map[string]int)
	for i := 0; i < 6; i++ {
		result, err := client.Get(target.URL)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		body := strings.TrimSpace(string(result.Body()))
		seen[body]++
		t.Logf("Request %d: proxy=%s, status=%d", i, body, result.StatusCode())
	}

	if len(seen) != 3 {
		t.Errorf("expected 3 distinct proxies visited, got %d: %v", len(seen), seen)
	}
}

// TestProxyPool_RotateOn403 verifies that a 403 response triggers a retry
// through a different proxy (status-based rotation via ProxyRotateOnStatus).
func TestProxyPool_RotateOn403(t *testing.T) {
	var mu sync.Mutex
	var attempted []string

	// Target always returns 403 and records which proxy forwarded each attempt.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempted = append(attempted, r.Header.Get("X-Proxy-ID"))
		mu.Unlock()
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
	defer client.Close()

	result, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if result.StatusCode() != http.StatusForbidden {
		t.Errorf("expected final status 403, got %d", result.StatusCode())
	}

	// Should have attempted at least 2 different proxies (1 original + 1 retry).
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
	t.Logf("403 rotation: %d attempts across %d distinct proxies: %v", len(attempted), len(distinct), attempted)
}

// TestProxyPool_EndToEndRotation_HTTPS verifies proxy rotation for HTTPS
// requests (CONNECT tunneling) — the path used by real-world proxy pools
// against targets like api.ip.sb. Each proxy opens a separate CONNECT tunnel;
// we count tunnels per proxy to prove rotation.
func TestProxyPool_EndToEndRotation_HTTPS(t *testing.T) {
	// TLS target — the body echoes the TCP RemoteAddr so we can distinguish
	// which proxy's tunnel the request arrived through.
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.RemoteAddr))
	}))
	defer target.Close()

	targetAddr := strings.TrimPrefix(target.URL, "https://")

	// Create 3 CONNECT-proxy servers; each counts its tunnels.
	var connectCounts [3]int64
	proxyURLs := make([]string, 3)
	for i := range proxyURLs {
		idx := i
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "only CONNECT supported", http.StatusBadRequest)
				return
			}
			atomic.AddInt64(&connectCounts[idx], 1)

			dst, err := net.Dial("tcp", targetAddr)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				dst.Close()
				http.Error(w, "hijack not supported", http.StatusInternalServerError)
				return
			}
			clientConn, bufrw, err := hj.Hijack()
			if err != nil {
				dst.Close()
				return
			}
			defer clientConn.Close()
			defer dst.Close()

			bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			bufrw.Flush()

			// Bidirectional tunnel: client ↔ target
			go func() {
				io.Copy(dst, bufrw)
				dst.Close()
			}()
			io.Copy(clientConn, dst)
		}))
		defer proxy.Close()
		proxyURLs[i] = proxy.URL
	}

	cfg := DefaultConfig()
	cfg.Connection.ProxyPool = proxyURLs
	cfg.Security.AllowPrivateIPs = true
	cfg.Security.InsecureSkipVerify = true // test TLS cert is self-signed
	cfg.Timeouts.Request = 5 * time.Second

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	seen := make(map[string]int)
	for i := 0; i < 6; i++ {
		result, err := client.Get(target.URL)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		body := strings.TrimSpace(string(result.Body()))
		seen[body]++
		t.Logf("Request %d: RemoteAddr=%s, status=%d", i, body, result.StatusCode())
	}

	// Verify all 3 proxies were used (each opened at least 1 CONNECT tunnel).
	usedCount := 0
	for i := range connectCounts {
		if atomic.LoadInt64(&connectCounts[i]) > 0 {
			usedCount++
		}
	}
	if usedCount < 3 {
		t.Errorf("expected all 3 CONNECT proxies used, but only %d were (tunnel counts: %v)",
			usedCount, connectCounts)
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
			w.Write([]byte("CF blocked"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK from " + proxyID))
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
	defer client.Close()

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

// TestProxyPool_RotateOn403_RedirectSafe verifies that redirect-following
// within a single attempt does NOT consume the proxy rotation budget.
// The target always returns 403 but first issues a 302 redirect, causing
// http.Client to call transport.Proxy twice per attempt. Without deterministic
// SelectIndex, the round-robin counter would be consumed by the redirect,
// and the retry might land on the same proxy instead of advancing.
func TestProxyPool_RotateOn403_RedirectSafe(t *testing.T) {
	var mu sync.Mutex
	var attempted []string

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyID := r.Header.Get("X-Proxy-ID")
		mu.Lock()
		attempted = append(attempted, proxyID)
		mu.Unlock()

		// On the initial path, redirect to /challenge to simulate CF's
		// redirect-then-block pattern. This causes an extra Proxy() call.
		if r.URL.Path != "/challenge" {
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
	defer client.Close()

	result, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if result.StatusCode() != http.StatusForbidden {
		t.Errorf("expected final status 403, got %d", result.StatusCode())
	}

	// Despite redirects consuming extra Proxy() calls, each retry attempt
	// should still land on a distinct proxy.
	mu.Lock()
	defer mu.Unlock()
	distinct := make(map[string]bool)
	for _, id := range attempted {
		distinct[id] = true
	}
	if len(distinct) < 2 {
		t.Errorf("expected rotation across >=2 proxies despite redirects, but only used %d distinct: %v (all: %v)",
			len(distinct), distinct, attempted)
	}
	t.Logf("Redirect-safe rotation: %d attempts across %d distinct proxies: %v",
		len(attempted), len(distinct), attempted)
}
