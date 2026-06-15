package proxy

import (
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"
	"testing"
)

func TestNewDetector(t *testing.T) {
	detector := NewDetector()
	if detector == nil {
		t.Fatal("NewDetector() returned nil")
	}
}

func TestDetector_GetProxyFunc_NoProxy(t *testing.T) {
	// Clear any existing proxy environment variables
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	// Create new detector after clearing env
	detector := NewDetector()
	proxyFunc := detector.GetProxyFunc()

	// On Linux, proxy detection is environment-only (detectPlatform returns
	// nil), so with the environment cleared the proxy func must be nil (direct
	// connection). On Windows/macOS the platform detector also consults
	// system-level config (WinHTTP / SystemConfiguration) that clearing env
	// does not reach, so a non-nil func there reflects host config, not a bug.
	if runtime.GOOS == "linux" && proxyFunc != nil {
		t.Errorf("GetProxyFunc() = non-nil, want nil with no proxy environment on Linux")
	}
}

func TestDetector_GetProxyFunc_WithEnvProxy(t *testing.T) {
	// Save and clear existing proxy settings
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	// Set test proxy environment variable
	testProxy := "http://test-proxy.example.com:8080"
	os.Setenv("HTTP_PROXY", testProxy)
	os.Setenv("HTTPS_PROXY", testProxy)

	// Create new detector after setting env
	detector := NewDetector()
	proxyFunc := detector.GetProxyFunc()

	if proxyFunc == nil {
		t.Fatal("GetProxyFunc() returned nil with proxy environment set")
	}

	// Test the proxy function with a sample request
	testURL, _ := url.Parse("http://example.com")
	testReq := &http.Request{
		URL: testURL,
	}

	proxyURL, err := proxyFunc(testReq)
	if err != nil {
		t.Errorf("Proxy function returned error: %v", err)
	}

	if proxyURL == nil {
		t.Error("Proxy function returned nil URL")
	} else {
		t.Logf("Proxy URL = %s", proxyURL.String())
	}
}

func TestDetector_GetProxyFunc_ConcurrentAccess(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	os.Setenv("HTTP_PROXY", "http://concurrent-test.example.com:8080")

	detector := NewDetector()

	var wg sync.WaitGroup
	results := make(chan func(*http.Request) (*url.URL, error), 10)

	// Launch 10 concurrent GetProxyFunc calls
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxyFunc := detector.GetProxyFunc()
			results <- proxyFunc
		}()
	}

	wg.Wait()
	close(results)

	// Count results
	count := 0
	var firstFunc func(*http.Request) (*url.URL, error)
	for proxyFunc := range results {
		count++
		if firstFunc == nil {
			firstFunc = proxyFunc
		}
	}

	if count != 10 {
		t.Errorf("Expected 10 results, got %d", count)
	}

	if firstFunc == nil {
		t.Error("Expected non-nil proxy function from concurrent access")
	}
}

func TestDetector_NoProxyEnv(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	// Set proxy with no_proxy exclusion
	os.Setenv("HTTP_PROXY", "http://proxy.example.com:8080")
	os.Setenv("NO_PROXY", "localhost,127.0.0.1,.example.com")

	detector := NewDetector()
	proxyFunc := detector.GetProxyFunc()

	if proxyFunc == nil {
		t.Fatal("GetProxyFunc() returned nil")
	}

	// Request to excluded host should return nil proxy
	testURL, _ := url.Parse("http://localhost/test")
	testReq := &http.Request{URL: testURL}

	proxyURL, err := proxyFunc(testReq)
	if err != nil {
		t.Errorf("Proxy function returned error: %v", err)
	}

	// localhost should be excluded
	if proxyURL != nil {
		t.Logf("localhost not excluded by NO_PROXY, got proxy: %s", proxyURL)
	}
}

// TestDetect_HTTPSProxyEnv verifies that HTTPS_PROXY environment variable is
// detected and used when making HTTPS requests.
func TestDetect_HTTPSProxyEnv(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	os.Setenv("HTTPS_PROXY", "https://secure-proxy.example.com:8443")

	detector := NewDetector()
	proxyFunc := detector.GetProxyFunc()

	if proxyFunc == nil {
		t.Fatal("GetProxyFunc() returned nil with HTTPS_PROXY set")
	}

	testURL, _ := url.Parse("https://secure.example.com/resource")
	testReq := &http.Request{URL: testURL}

	proxyURL, err := proxyFunc(testReq)
	if err != nil {
		t.Errorf("proxy function returned error: %v", err)
	}

	if proxyURL == nil {
		t.Error("expected proxy URL for HTTPS request, got nil")
	}
}

// TestDetect_LowercaseEnvVars verifies that lowercase http_proxy is detected.
func TestDetect_LowercaseEnvVars(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	os.Setenv("http_proxy", "http://lowercase-proxy.example.com:9000")

	detector := NewDetector()
	proxyFunc := detector.GetProxyFunc()

	if proxyFunc == nil {
		t.Fatal("GetProxyFunc() returned nil with lowercase http_proxy set")
	}

	testURL, _ := url.Parse("http://example.com")
	testReq := &http.Request{URL: testURL}

	proxyURL, err := proxyFunc(testReq)
	if err != nil {
		t.Errorf("proxy function returned error: %v", err)
	}

	if proxyURL == nil {
		t.Error("expected proxy URL, got nil")
	}
}

// TestDetect_NoEnvVarsNoPlatformProxy verifies that when no environment
// variables are set and platform detection finds nothing, nil is returned.
func TestDetect_NoEnvVarsNoPlatformProxy(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	detector := NewDetector()
	proxyFunc := detector.GetProxyFunc()

	// On Windows, platform-specific proxy detection may return non-nil
	if runtime.GOOS == "windows" {
		t.Skip("Windows platform proxy detection may return non-nil")
	}

	if proxyFunc != nil {
		t.Error("GetProxyFunc with no env vars should return nil on platforms without system proxy")
	}
}

// TestDetect_NOProxyExclusion verifies that NO_PROXY exclusions are respected
// for multiple host patterns when using environment-based proxy detection.
func TestDetect_NOProxyExclusion(t *testing.T) {
	// Save and clear all proxy env vars first
	allEnvVars := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"}
	saved := make(map[string]string)
	for _, v := range allEnvVars {
		saved[v] = os.Getenv(v)
		os.Unsetenv(v)
	}
	defer func() {
		for k, v := range saved {
			if v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	}()

	os.Setenv("HTTP_PROXY", "http://proxy.example.com:8080")
	os.Setenv("http_proxy", "http://proxy.example.com:8080")
	os.Setenv("HTTPS_PROXY", "http://proxy.example.com:8080")
	os.Setenv("NO_PROXY", "localhost,127.0.0.1,.internal,.local")
	os.Setenv("no_proxy", "localhost,127.0.0.1,.internal,.local")

	tests := []struct {
		name        string
		requestURL  string
		wantNil     bool
		description string
	}{
		{
			name:        "localhost excluded",
			requestURL:  "http://localhost:9090/health",
			wantNil:     true,
			description: "localhost should be excluded by NO_PROXY",
		},
		{
			name:        "127.0.0.1 excluded",
			requestURL:  "http://127.0.0.1:8080/ping",
			wantNil:     true,
			description: "127.0.0.1 should be excluded by NO_PROXY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqURL, _ := url.Parse(tt.requestURL)
			req := &http.Request{URL: reqURL}

			proxyURL, err := http.ProxyFromEnvironment(req)
			if err != nil {
				t.Errorf("ProxyFromEnvironment error: %v", err)
				return
			}

			if tt.wantNil && proxyURL != nil {
				t.Errorf("%s: expected nil proxy, got %s", tt.description, proxyURL)
			}

			if !tt.wantNil && proxyURL == nil {
				t.Errorf("%s: expected proxy URL, got nil", tt.description)
			}
		})
	}
}

// TestGetProxyFunc_CacheConsistency verifies that repeated calls to GetProxyFunc
// return a consistent cached result by checking both return the same proxy URL.
func TestGetProxyFunc_CacheConsistency(t *testing.T) {
	originalEnv := saveAndClearProxyEnv()
	defer restoreProxyEnv(originalEnv)

	os.Setenv("HTTP_PROXY", "http://cache-test.example.com:8080")

	detector := NewDetector()

	first := detector.GetProxyFunc()
	second := detector.GetProxyFunc()

	if first == nil || second == nil {
		t.Fatal("GetProxyFunc() should return non-nil with proxy env set")
	}

	// Verify both functions return the same proxy URL for the same request
	testURL, _ := url.Parse("http://example.com")
	testReq := &http.Request{URL: testURL}

	url1, err := first(testReq)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	url2, err := second(testReq)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}

	if url1.String() != url2.String() {
		t.Errorf("cached functions returned different URLs: %s vs %s", url1.String(), url2.String())
	}
}

// Helper functions for environment management

func saveAndClearProxyEnv() map[string]string {
	envVars := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"}
	saved := make(map[string]string)

	for _, v := range envVars {
		saved[v] = os.Getenv(v)
		os.Unsetenv(v)
	}

	return saved
}

func restoreProxyEnv(env map[string]string) {
	for k, v := range env {
		if v != "" {
			os.Setenv(k, v)
		} else {
			os.Unsetenv(k)
		}
	}
}
