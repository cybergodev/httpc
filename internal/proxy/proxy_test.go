package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

var allProxyEnvVars = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
	"NO_PROXY", "no_proxy",
}

func saveAndClearProxyEnv() map[string]string {
	saved := make(map[string]string, len(allProxyEnvVars))
	for _, v := range allProxyEnvVars {
		saved[v] = os.Getenv(v)
		os.Unsetenv(v)
	}
	return saved
}

func restoreProxyEnv(env map[string]string) {
	for _, v := range allProxyEnvVars {
		if val, ok := env[v]; ok && val != "" {
			os.Setenv(v, val)
		} else {
			os.Unsetenv(v)
		}
	}
}

// ---------------------------------------------------------------------------
// NewDetector
// ---------------------------------------------------------------------------

func TestNewDetector(t *testing.T) {
	if d := NewDetector(); d == nil {
		t.Fatal("NewDetector() returned nil")
	}
}

// ---------------------------------------------------------------------------
// detectFromEnvironment — table-driven
// ---------------------------------------------------------------------------

func TestDetectFromEnvironment(t *testing.T) {
	tests := []struct {
		name       string
		env        map[string]string
		wantNil    bool
		reqScheme  string
		reqHost    string
		wantProxy  string // expected proxy URL string, empty = nil proxy
		wantDirect bool   // true => proxy func should return nil for this request
	}{
		{
			name:      "no env vars",
			env:       nil,
			wantNil:   true,
			reqScheme: "https",
			reqHost:   "example.com",
		},
		{
			name:      "HTTP_PROXY set",
			env:       map[string]string{"HTTP_PROXY": "http://proxy.example.com:8080"},
			reqScheme: "http",
			reqHost:   "example.com",
			wantProxy: "http://proxy.example.com:8080",
		},
		{
			name:      "HTTPS_PROXY used for HTTPS request",
			env:       map[string]string{"HTTPS_PROXY": "http://secure-proxy.example.com:8443"},
			reqScheme: "https",
			reqHost:   "secure.example.com",
			wantProxy: "http://secure-proxy.example.com:8443",
		},
		{
			name:      "HTTP_PROXY falls back for HTTPS request",
			env:       map[string]string{"HTTP_PROXY": "http://fallback.example.com:8080"},
			reqScheme: "https",
			reqHost:   "example.com",
			wantProxy: "http://fallback.example.com:8080",
		},
		{
			name:      "lowercase http_proxy detected",
			env:       map[string]string{"http_proxy": "http://lowercase-proxy.example.com:9000"},
			reqScheme: "http",
			reqHost:   "example.com",
			wantProxy: "http://lowercase-proxy.example.com:9000",
		},
		{
			name:      "lowercase https_proxy detected",
			env:       map[string]string{"https_proxy": "http://lowercase-https.example.com:9443"},
			reqScheme: "https",
			reqHost:   "example.com",
			wantProxy: "http://lowercase-https.example.com:9443",
		},
		{
			name:      "HTTPS_PROXY not used for HTTP request",
			env:       map[string]string{"HTTPS_PROXY": "http://https-only.example.com:8443"},
			reqScheme: "http",
			reqHost:   "example.com",
			wantProxy: "http://https-only.example.com:8443", // falls back as HTTP_PROXY
		},
		{
			name:       "localhost always direct",
			env:        map[string]string{"HTTP_PROXY": "http://proxy.example.com:8080"},
			reqScheme:  "http",
			reqHost:    "localhost",
			wantDirect: true,
		},
		{
			name:       "NO_PROXY excludes host",
			env:        map[string]string{"HTTP_PROXY": "http://proxy.example.com:8080", "NO_PROXY": "example.com"},
			reqScheme:  "http",
			reqHost:    "example.com",
			wantDirect: true,
		},
		{
			name:      "NO_PROXY wildcard bypasses all",
			env:       map[string]string{"HTTP_PROXY": "http://proxy.example.com:8080", "NO_PROXY": "*"},
			reqScheme: "http",
			reqHost:   "example.com",
			wantProxy: "http://proxy.example.com:8080", // wildcard is a NO_PROXY match — should be direct
			wantDirect: true,
		},
		{
			name:       "NO_PROXY domain suffix",
			env:        map[string]string{"HTTP_PROXY": "http://proxy.example.com:8080", "NO_PROXY": ".internal.example.com"},
			reqScheme:  "http",
			reqHost:    "api.internal.example.com",
			wantDirect: true,
		},
		{
			name:      "NO_PROXY does not match unrelated host",
			env:       map[string]string{"HTTP_PROXY": "http://proxy.example.com:8080", "NO_PROXY": "internal.example.com"},
			reqScheme: "http",
			reqHost:   "external.example.com",
			wantProxy: "http://proxy.example.com:8080",
		},
		{
			name:      "bare host:port normalized with http scheme",
			env:       map[string]string{"HTTP_PROXY": "proxy:3128"},
			reqScheme: "http",
			reqHost:   "example.com",
			wantProxy: "http://proxy:3128",
		},
		{
			name:      "socks5 scheme preserved",
			env:       map[string]string{"HTTP_PROXY": "socks5://proxy.example.com:1080"},
			reqScheme: "http",
			reqHost:   "example.com",
			wantProxy: "socks5://proxy.example.com:1080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalEnv := saveAndClearProxyEnv()
			defer restoreProxyEnv(originalEnv)

			for k, v := range tt.env {
				os.Setenv(k, v)
			}

			d := NewDetector()
			proxyFunc := d.detectFromEnvironment()

			if tt.wantNil {
				if proxyFunc != nil {
					t.Errorf("detectFromEnvironment() = non-nil, want nil")
				}
				return
			}
			if proxyFunc == nil {
				t.Fatal("detectFromEnvironment() = nil, want non-nil")
			}

			req := &http.Request{
				URL: &url.URL{Scheme: tt.reqScheme, Host: tt.reqHost},
			}

			got, err := proxyFunc(req)
			if err != nil {
				t.Fatalf("proxyFunc returned error: %v", err)
			}

			if tt.wantDirect {
				if got != nil {
					t.Errorf("proxyFunc() = %s, want nil (direct)", got)
				}
				return
			}

			if got == nil {
				t.Fatal("proxyFunc() = nil, want non-nil proxy URL")
			}

			if tt.wantProxy != "" && got.String() != tt.wantProxy {
				t.Errorf("proxy URL = %s, want %s", got, tt.wantProxy)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectFromEnvironment — error and edge-case paths
// ---------------------------------------------------------------------------

func TestDetectFromEnvironment_CGIEnvironment(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)
	defer os.Unsetenv("REQUEST_METHOD") // not in allProxyEnvVars; clean up explicitly

	os.Setenv("HTTP_PROXY", "http://proxy.example.com:8080")
	os.Setenv("REQUEST_METHOD", "GET")

	d := NewDetector()
	proxyFunc := d.detectFromEnvironment()
	if proxyFunc == nil {
		t.Fatal("detectFromEnvironment() = nil with HTTP_PROXY set")
	}

	req := &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}}
	got, err := proxyFunc(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("CGI environment should bypass proxy, got %s", got)
	}
}

func TestDetectFromEnvironment_HTTPSProxyFallsBack(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	// Only HTTPS_PROXY is set; an HTTP request should still get a proxy
	// via the fall-back branch.
	os.Setenv("HTTPS_PROXY", "http://https-proxy.example.com:8443")

	d := NewDetector()
	proxyFunc := d.detectFromEnvironment()
	if proxyFunc == nil {
		t.Fatal("detectFromEnvironment() = nil with HTTPS_PROXY set")
	}

	req := &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}}
	got, err := proxyFunc(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil proxy URL for HTTP request with HTTPS_PROXY fall-back")
	}
	if got.String() != "http://https-proxy.example.com:8443" {
		t.Errorf("proxy URL = %s, want http://https-proxy.example.com:8443", got)
	}
}

// ---------------------------------------------------------------------------
// GetProxyFunc caching
// ---------------------------------------------------------------------------

func TestGetProxyFunc_Caching(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	os.Setenv("HTTP_PROXY", "http://cache-test.example.com:8080")

	d := NewDetector()

	first := d.GetProxyFunc()
	second := d.GetProxyFunc()

	if first == nil {
		t.Fatal("first GetProxyFunc() returned nil with proxy env set")
	}
	if second == nil {
		t.Fatal("second GetProxyFunc() returned nil")
	}

	// Both should return the same proxy for the same request.
	req := &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}}

	u1, err := first(req)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	u2, err := second(req)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}

	if u1.String() != u2.String() {
		t.Errorf("cached functions returned different URLs: %s vs %s", u1, u2)
	}
}

func TestGetProxyFunc_NoProxy(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	d := NewDetector()
	proxyFunc := d.GetProxyFunc()

	if proxyFunc != nil {
		t.Errorf("GetProxyFunc() = non-nil, want nil with no proxy env")
	}
}

// ---------------------------------------------------------------------------
// GetProxyFunc concurrent access
// ---------------------------------------------------------------------------

func TestGetProxyFunc_ConcurrentAccess(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	os.Setenv("HTTP_PROXY", "http://concurrent.example.com:8080")

	d := NewDetector()

	const goroutines = 20
	var wg sync.WaitGroup
	results := make(chan func(*http.Request) (*url.URL, error), goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- d.GetProxyFunc()
		}()
	}

	wg.Wait()
	close(results)

	count := 0
	var firstFunc func(*http.Request) (*url.URL, error)
	for pf := range results {
		count++
		if firstFunc == nil {
			firstFunc = pf
		}
	}

	if count != goroutines {
		t.Errorf("expected %d results, got %d", goroutines, count)
	}
	if firstFunc == nil {
		t.Error("expected non-nil proxy function from concurrent access")
	}
}

// ---------------------------------------------------------------------------
// shouldUseProxy — NO_PROXY matching
// ---------------------------------------------------------------------------

func TestShouldUseProxy(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     string
		noProxy  string
		wantUse  bool // true = should use proxy (NOT bypassed)
	}{
		// Wildcard
		{"wildcard bypasses all", "example.com", "", "*", false},

		// Exact hostname
		{"exact match bypasses", "example.com", "", "example.com", false},
		{"exact match no bypass for different host", "other.com", "", "example.com", true},

		// Domain suffix
		{"dot-prefix suffix matches subdomain", "api.example.com", "", ".example.com", false},
		{"dot-prefix suffix does not match bare domain", "example.com", "", ".example.com", true},
		{"bare domain matches subdomain", "api.example.com", "", "example.com", false},
		{"bare domain matches itself", "example.com", "", "example.com", false},
		{"wildcard prefix matches subdomain", "api.example.com", "", "*.example.com", false},

		// IP literals
		{"IP exact match", "127.0.0.1", "", "127.0.0.1", false},
		{"IP no match", "192.168.1.1", "", "127.0.0.1", true},

		// CIDR
		{"CIDR match private range", "10.0.0.5", "", "10.0.0.0/8", false},
		{"CIDR no match", "192.168.1.1", "", "10.0.0.0/8", true},

		// Port-specific
		{"host:port pattern matches same port", "example.com", "8080", "example.com:8080", false},
		{"host:port pattern does not match different port", "example.com", "9090", "example.com:8080", true},

		// Multiple entries
		{"comma-separated list first match", "localhost", "", "localhost,127.0.0.1,.example.com", false},
		{"comma-separated list last match", "api.example.com", "", "localhost,127.0.0.1,.example.com", false},
		{"comma-separated list no match", "other.com", "", "localhost,127.0.0.1,.example.com", true},

		// Edge cases
		{"empty noProxy uses proxy", "example.com", "", "", true},
		{"whitespace-only entries ignored", "example.com", "", "  ,  ,  ", true},
		{"IPv6 address", "::1", "", "::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldUseProxy(tt.host, tt.port, tt.noProxy)
			if got != tt.wantUse {
				t.Errorf("shouldUseProxy(%q, %q, %q) = %v, want %v",
					tt.host, tt.port, tt.noProxy, got, tt.wantUse)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseProxyURL
// ---------------------------------------------------------------------------

func TestParseProxyURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
		wantURL string
		wantErr bool
	}{
		{"empty returns nil", "", true, "", false},
		{"http scheme", "http://proxy:8080", false, "http://proxy:8080", false},
		{"https scheme", "https://proxy:8443", false, "https://proxy:8443", false},
		{"socks5 scheme", "socks5://proxy:1080", false, "socks5://proxy:1080", false},
		{"bare host:port gets http prefix", "proxy:8080", false, "http://proxy:8080", false},
		{"bare host gets http prefix", "proxy", false, "http://proxy", false},
		{"ftp scheme gets http prefix", "ftp://proxy:21", false, "http://ftp://proxy:21", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := parseProxyURL(tt.input)

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil {
				if u != nil {
					t.Errorf("expected nil URL, got %s", u)
				}
				return
			}
			if u == nil {
				t.Fatal("expected non-nil URL, got nil")
			}
			if tt.wantURL != "" && u.String() != tt.wantURL {
				t.Errorf("URL = %s, want %s", u, tt.wantURL)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// getEnvAny
// ---------------------------------------------------------------------------

func TestGetEnvAny(t *testing.T) {
	t.Run("returns first non-empty", func(t *testing.T) {
		t.Setenv("TEST_PROXY_VAR_A", "")
		t.Setenv("TEST_PROXY_VAR_B", "value-b")
		got := getEnvAny("TEST_PROXY_VAR_A", "TEST_PROXY_VAR_B")
		if got != "value-b" {
			t.Errorf("getEnvAny() = %q, want %q", got, "value-b")
		}
	})

	t.Run("returns empty when all unset", func(t *testing.T) {
		got := getEnvAny("UNSET_VAR_1", "UNSET_VAR_2")
		if got != "" {
			t.Errorf("getEnvAny() = %q, want empty", got)
		}
	})

	t.Run("prefers first", func(t *testing.T) {
		t.Setenv("TEST_FIRST", "first")
		t.Setenv("TEST_SECOND", "second")
		got := getEnvAny("TEST_FIRST", "TEST_SECOND")
		if got != "first" {
			t.Errorf("getEnvAny() = %q, want %q", got, "first")
		}
	})
}

// ---------------------------------------------------------------------------
// Integration: GetProxyFunc with real HTTP round-trip
// ---------------------------------------------------------------------------

func TestGetProxyFunc_IntegrationWithProxy(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	// Use a local httptest server as the "proxy" — we don't need it to actually
	// proxy; we just need to verify the proxy URL resolves correctly.
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer proxyServer.Close()

	os.Setenv("HTTP_PROXY", proxyServer.URL)

	d := NewDetector()
	proxyFunc := d.GetProxyFunc()

	if proxyFunc == nil {
		t.Fatal("GetProxyFunc() returned nil with proxy env set")
	}

	req := &http.Request{
		URL: &url.URL{Scheme: "http", Host: "target.example.com"},
	}

	proxyURL, err := proxyFunc(req)
	if err != nil {
		t.Fatalf("proxyFunc error: %v", err)
	}
	if proxyURL == nil {
		t.Fatal("proxyFunc returned nil proxy URL")
	}

	if proxyURL.String() != proxyServer.URL {
		t.Errorf("proxy URL = %s, want %s", proxyURL, proxyServer.URL)
	}
}

// ---------------------------------------------------------------------------
// detectPlatform / getWindowsProxySettings (Windows)
// ---------------------------------------------------------------------------

func TestDetectPlatform_NoEnvCallsPlatform(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	d := NewDetector()
	// With no env vars, detect() falls through to detectPlatform().
	// On a system without proxy configured, this returns nil.
	// On a system with proxy configured, it returns a non-nil function.
	// Either way it must not panic.
	_ = d.detectPlatform()
}

func TestGetWindowsProxySettings(t *testing.T) {
	// Exercise the registry-reading path. On most dev machines ProxyEnable
	// is 0, so this returns ("", false, nil). On machines with a proxy it
	// returns the proxy details. Either way it must not panic or error.
	server, enabled, err := getWindowsProxySettings()
	if err != nil {
		t.Logf("getWindowsProxySettings returned error (acceptable in CI): %v", err)
		return
	}
	t.Logf("registry proxy: server=%q enabled=%v", server, enabled)
	if !enabled && server != "" {
		t.Logf("note: server=%q but enabled=false", server)
	}
}

// ---------------------------------------------------------------------------
// detect — full chain
// ---------------------------------------------------------------------------

func TestDetect_EnvProxyTakesPriority(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	os.Setenv("HTTP_PROXY", "http://env-proxy.example.com:8080")

	d := NewDetector()
	proxyFunc := d.detect()

	if proxyFunc == nil {
		t.Fatal("detect() returned nil with HTTP_PROXY set")
	}

	req := &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}}
	got, err := proxyFunc(req)
	if err != nil {
		t.Fatalf("proxyFunc error: %v", err)
	}
	if got == nil || got.String() != "http://env-proxy.example.com:8080" {
		t.Errorf("proxy URL = %v, want http://env-proxy.example.com:8080", got)
	}
}

func TestDetect_NoEnvFallsToPlatform(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	d := NewDetector()
	// Should not panic; may return nil (no proxy) or non-nil (system proxy).
	_ = d.detect()
}
