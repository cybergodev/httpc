package connection

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// TestProxyConfigurationPriority tests that proxy configuration follows the correct priority:
// 1. Manual ProxyURL (highest priority)
// 2. EnableSystemProxy (auto-detect)
// 3. Direct connection (no proxy)
func TestProxyConfigurationPriority(t *testing.T) {
	// Note: the pure "EnableSystemProxy with no manual URL" case is intentionally
	// omitted — its outcome depends on the host's OS-level proxy config (Windows
	// registry / macOS system settings), which cannot be asserted deterministically.
	// It is covered, machine-agnostically, by TestPoolManager_SystemProxy which only
	// asserts that the transport is created. The cases below are all deterministic.
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
			defer pm.Close()

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
				pm.Close()
				t.Logf("✓ Valid proxy URL accepted: %s", validURL)
			}
		})
	}
}

// TestProxyConfigurationIsolation tests that different pool managers
// can have different proxy configurations
func TestProxyConfigurationIsolation(t *testing.T) {
	// Create first pool with manual proxy
	config1 := &Config{
		ProxyURL:    "http://proxy.example.com:8080",
		DialTimeout: 10 * time.Second,
	}

	pm1, err := NewPoolManager(config1)
	if err != nil {
		t.Fatalf("Failed to create first pool: %v", err)
	}
	defer pm1.Close()

	// Create second pool with system proxy enabled
	config2 := &Config{
		EnableSystemProxy: true,
		DialTimeout:       10 * time.Second,
	}

	pm2, err := NewPoolManager(config2)
	if err != nil {
		t.Fatalf("Failed to create second pool: %v", err)
	}
	defer pm2.Close()

	// Create third pool with no proxy
	config3 := &Config{
		DialTimeout: 10 * time.Second,
	}

	pm3, err := NewPoolManager(config3)
	if err != nil {
		t.Fatalf("Failed to create third pool: %v", err)
	}
	defer pm3.Close()

	// Verify each pool has its own configuration
	transport1 := pm1.GetTransport()
	transport2 := pm2.GetTransport()
	transport3 := pm3.GetTransport()

	if transport1 == nil || transport1.Proxy == nil {
		t.Error("First pool should have proxy configured")
	}

	if transport2 == nil {
		t.Error("Second pool transport should not be nil")
	}

	if transport3 == nil {
		t.Error("Third pool transport should not be nil")
	}

	t.Log("✓ Different pool managers can have different proxy configurations")
}

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
		pm.Close()
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
		pm.Close()
	}
}
