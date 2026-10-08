package connection

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/cybergodev/httpc/internal/proxypool"
)

// TestProxyConfigurationPriority tests that proxy configuration follows the correct priority:
// 1. Manual ProxyURL (highest priority)
// 2. EnableSystemProxy (auto-detect)
// 3. Direct connection (no proxy)
func TestProxyConfigurationPriority(t *testing.T) {
	// Note: the pure "EnableSystemProxy with no manual URL" case is intentionally
	// omitted — its outcome depends on the host's OS-level proxy config (Windows
	// registry / macOS system settings), which cannot be asserted deterministically.
	// (The former TestPoolManager_SystemProxy only asserted transport creation,
	// true of every construction, so it was removed.) The cases below are all
	// deterministic.
	tests := []struct {
		name              string
		proxyURL          string
		enableSystemProxy bool
		expectProxySet    bool
		description       string
	}{
		{
			name:              "Manual proxy only",
			proxyURL:          "http://proxy.example.com:8080",
			enableSystemProxy: false,
			expectProxySet:    true,
			description:       "Manual proxy URL should be used",
		},
		{
			name:              "Direct connection (default)",
			enableSystemProxy: false,
			expectProxySet:    false,
			description:       "No proxy should be configured",
		},
		{
			name:              "Manual proxy overrides system proxy",
			proxyURL:          "http://proxy.example.com:8888",
			enableSystemProxy: true,
			expectProxySet:    true,
			description:       "Manual proxy should take priority over system proxy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProxyURL:          tt.proxyURL,
				EnableSystemProxy: tt.enableSystemProxy,
				DialTimeout:       10 * time.Second,
				KeepAlive:         30 * time.Second,
			}

			pm, err := NewPoolManager(config)
			if err != nil {
				t.Fatalf("NewPoolManager() failed: %v", err)
			}
			defer func() { _ = pm.Close() }()

			transport := pm.GetTransport()
			if transport == nil {
				t.Fatal("GetTransport() returned nil")
			}

			proxyFunc := transport.Proxy
			hasProxy := proxyFunc != nil

			// Assert in both directions: a proxy must be set exactly when expected.
			if tt.expectProxySet && !hasProxy {
				t.Errorf("%s: expected proxy to be set, but it was nil", tt.description)
			}
			if !tt.expectProxySet && hasProxy {
				t.Errorf("%s: expected no proxy, but one was configured", tt.description)
			}

			// When a manual proxy is configured, verify it resolves to that URL.
			if tt.proxyURL != "" && hasProxy {
				testURL, _ := url.Parse("https://www.example.com")
				testReq := &http.Request{URL: testURL}
				resolved, err := proxyFunc(testReq)
				if err != nil {
					t.Errorf("Proxy function returned error: %v", err)
					return
				}
				expectedURL, _ := url.Parse(tt.proxyURL)
				if resolved == nil || resolved.String() != expectedURL.String() {
					t.Errorf("Expected proxy URL %s, got %v", expectedURL.String(), resolved)
				}
			}
		})
	}
}

// TestDefaultConfigProxySettings tests that DefaultConfig does not enable system proxy
// to maintain backward compatibility
func TestDefaultConfigProxySettings(t *testing.T) {
	config := DefaultConfig()

	if config.EnableSystemProxy {
		t.Error("DefaultConfig should not enable system proxy by default")
	}

	if config.ProxyURL != "" {
		t.Error("DefaultConfig should not set a proxy URL by default")
	}

	t.Log("✓ DefaultConfig maintains backward compatibility (no proxy by default)")
}

// TestValidProxyURLs tests that valid proxy URLs are accepted
func TestValidProxyURLs(t *testing.T) {
	validURLs := []string{
		"http://proxy.example.com:8080",
		"https://proxy.example.com:8443",
		"http://proxy.example.com:7890",
		"http://proxy2.example.com:8080",
		// socks5 is supported natively by net/http.Transport; the pool must not
		// reject schemes the public Config validator already accepts.
		"socks5://proxy.example.com:1080",
		"socks5h://proxy.example.com:1080",
	}

	for _, validURL := range validURLs {
		t.Run(validURL, func(t *testing.T) {
			config := &Config{
				ProxyURL:          validURL,
				EnableSystemProxy: false,
				DialTimeout:       10 * time.Second,
			}

			pm, err := NewPoolManager(config)
			if err != nil {
				t.Errorf("Valid proxy URL '%s' was rejected: %v", validURL, err)
			} else {
				_ = pm.Close()
				t.Logf("✓ Valid proxy URL accepted: %s", validURL)
			}
		})
	}
}

// TestProxyConfigurationIsolation was removed: PoolManager instances hold no
// package-level mutable state — each transports its own Config, and the
// per-mode Proxy wiring is asserted by the mode tests above. The three
// constructors here only re-verified that construction succeeds.

// BenchmarkProxyConfiguration benchmarks the performance impact of proxy configuration
func BenchmarkProxyConfiguration(b *testing.B) {
	config := &Config{
		ProxyURL:    "http://proxy.example.com:8080",
		DialTimeout: 10 * time.Second,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm, err := NewPoolManager(config)
		if err != nil {
			b.Fatalf("NewPoolManager failed: %v", err)
		}
		_ = pm.Close()
	}
}

func BenchmarkSystemProxyDetection(b *testing.B) {
	config := &Config{
		EnableSystemProxy: true,
		DialTimeout:       10 * time.Second,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm, err := NewPoolManager(config)
		if err != nil {
			b.Fatalf("NewPoolManager failed: %v", err)
		}
		_ = pm.Close()
	}
}

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
	defer func() { _ = pm.Close() }()

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
	defer func() { _ = pm.Close() }()

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
	defer func() { _ = pm.Close() }()

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
	defer func() { _ = pm.Close() }()

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
		_ = pm.Close()
		t.Fatal("NewPoolManager() should reject invalid proxy pool entry")
	}
}
