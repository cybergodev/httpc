package connection

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/cybergodev/httpc/internal/proxypool"
)

// TestPoolManager_ProxyPool verifies that a PoolManager with a proxy pool
// configures transport.Proxy and rotates through the pool's proxies.
func TestPoolManager_ProxyPool(t *testing.T) {
	config := &Config{
		ProxyPool: []string{
			"http://proxy1.example.com:8080",
			"http://proxy2.example.com:8080",
			"http://proxy3.example.com:8080",
		},
		ProxyPoolStrategy: proxypool.StrategyRoundRobin,
		DialTimeout:       10 * time.Second,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() failed: %v", err)
	}
	defer pm.Close()

	transport := pm.GetTransport()
	if transport.Proxy == nil {
		t.Fatal("transport.Proxy should be set for a proxy pool")
	}

	if pm.proxyPool == nil {
		t.Fatal("pm.proxyPool should be initialized")
	}

	// Round-robin should cycle through all three proxies
	testReq := &http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}}
	seen := make(map[string]bool)
	for i := 0; i < 3; i++ {
		proxyURL, err := transport.Proxy(testReq)
		if err != nil {
			t.Fatalf("Proxy() error: %v", err)
		}
		seen[proxyURL.Host] = true
	}
	if len(seen) != 3 {
		t.Errorf("round-robin visited %d distinct proxies, want 3 (got: %v)", len(seen), seen)
	}
}

// TestPoolManager_ProxyPool_AllHostsExempted verifies that every proxy host in
// the pool is seeded into proxyAddrs so SSRF validation bypasses them.
func TestPoolManager_ProxyPool_AllHostsExempted(t *testing.T) {
	config := &Config{
		ProxyPool: []string{
			"http://proxy1.example.com:8080",
			"http://proxy2.example.com:8080",
			"socks5://proxy3.example.com:1080",
		},
		DialTimeout: 10 * time.Second,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() failed: %v", err)
	}
	defer pm.Close()

	for _, want := range []string{
		"proxy1.example.com:8080",
		"proxy2.example.com:8080",
		"proxy3.example.com:1080",
	} {
		if !pm.isProxyAddr(want) {
			t.Errorf("proxy host %q not in proxyAddrs (SSRF would block it)", want)
		}
	}
}

// TestPoolManager_ProxyPool_PriorityOverSystemProxy verifies that ProxyPool
// takes priority over EnableSystemProxy.
func TestPoolManager_ProxyPool_PriorityOverSystemProxy(t *testing.T) {
	config := &Config{
		ProxyPool: []string{
			"http://pool-proxy.example.com:8080",
		},
		EnableSystemProxy: true,
		DialTimeout:       10 * time.Second,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() failed: %v", err)
	}
	defer pm.Close()

	// Proxy pool should be active, not system proxy
	if pm.proxyPool == nil {
		t.Error("proxy pool should be configured (takes priority over system proxy)")
	}

	testReq := &http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}}
	got, err := pm.GetTransport().Proxy(testReq)
	if err != nil {
		t.Fatalf("Proxy() error: %v", err)
	}
	if got.Host != "pool-proxy.example.com:8080" {
		t.Errorf("Proxy() returned %s, want pool-proxy.example.com:8080", got.Host)
	}
}

// TestPoolManager_ProxyURL_OverridesProxyPool verifies that a single ProxyURL
// wins over ProxyPool.
func TestPoolManager_ProxyURL_OverridesProxyPool(t *testing.T) {
	config := &Config{
		ProxyURL: "http://single-proxy.example.com:8080",
		ProxyPool: []string{
			"http://pool-proxy.example.com:8080",
			"http://pool-proxy2.example.com:8080",
		},
		DialTimeout: 10 * time.Second,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() failed: %v", err)
	}
	defer pm.Close()

	// Single ProxyURL should win — proxy pool not created
	if pm.proxyPool != nil {
		t.Error("proxy pool should NOT be created when ProxyURL is set (ProxyURL wins)")
	}

	testReq := &http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}}
	got, err := pm.GetTransport().Proxy(testReq)
	if err != nil {
		t.Fatalf("Proxy() error: %v", err)
	}
	if got.Host != "single-proxy.example.com:8080" {
		t.Errorf("Proxy() returned %s, want single-proxy.example.com:8080", got.Host)
	}
}

// TestPoolManager_ProxyPool_InvalidURL verifies that invalid proxy URLs in the
// pool are rejected at construction.
func TestPoolManager_ProxyPool_InvalidURL(t *testing.T) {
	config := &Config{
		ProxyPool: []string{
			"http://valid.example.com:8080",
			"ftp://invalid.example.com:8080", // unsupported scheme
		},
		DialTimeout: 10 * time.Second,
	}

	pm, err := NewPoolManager(config)
	if err == nil {
		pm.Close()
		t.Fatal("NewPoolManager() should reject invalid proxy pool entry")
	}
}
