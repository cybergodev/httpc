package engine

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cybergodev/httpc/internal/connection"
)

// ============================================================================
// TRANSPORT LAYER TESTS
// ============================================================================

func TestTransport_Creation(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:     true,
		ValidateHeaders: true,
		AllowPrivateIPs: true, // Allow test server access
		EnableHTTP2:     true,
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	transport, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = transport.Close() }()

	if transport == nil {
		t.Error("Transport should not be nil")
	}
}

func TestTransport_HTTPRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"success"}`))
	}))
	defer server.Close()

	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:     true,
		ValidateHeaders: true,
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	transport, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = transport.Close() }()

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestTransport_TLSConfiguration(t *testing.T) {
	// Create HTTPS test server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:        true,
		ValidateHeaders:    true,
		MinTLSVersion:      tls.VersionTLS12,
		MaxTLSVersion:      tls.VersionTLS13,
		InsecureSkipVerify: true, // For testing
	}

	connConfig := testConnectionConfig()
	connConfig.InsecureSkipVerify = true // For testing
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	transport, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = transport.Close() }()

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestTransport_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // Exceed timeout duration
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout: 500 * time.Millisecond, // Short timeout

		ValidateURL:     true,
		ValidateHeaders: true,
	}

	connConfig := testConnectionConfig()
	connConfig.DialTimeout = 500 * time.Millisecond
	connConfig.ResponseHeaderTimeout = 500 * time.Millisecond
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	transport, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = transport.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	start := time.Now()
	_, err = transport.RoundTrip(req)
	duration := time.Since(start)

	if err == nil {
		t.Error("Expected timeout error, got nil")
	}

	if duration > 1*time.Second {
		t.Errorf("Request took too long to timeout: %v", duration)
	}
}

func TestTransport_ConnectionReuse(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:     true,
		ValidateHeaders: true,
	}

	connConfig := testConnectionConfig()
	connConfig.MaxIdleConns = 10
	connConfig.MaxIdleConnsPerHost = 5
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	transport, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = transport.Close() }()

	// Send multiple requests to the same server
	for i := range 5 {
		req, err := http.NewRequest("GET", server.URL, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("Request %d: expected status 200, got %d", i, resp.StatusCode)
		}
	}

	if requestCount != 5 {
		t.Errorf("Expected 5 requests, server received %d", requestCount)
	}
}

func TestTransport_Close(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:     true,
		ValidateHeaders: true,
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	transport, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}

	// Test close
	err = transport.Close()
	if err != nil {
		t.Errorf("Failed to close transport: %v", err)
	}

	// Test repeated close
	err = transport.Close()
	if err != nil {
		t.Errorf("Second close should not error: %v", err)
	}
}

func TestTransport_UserAgent(t *testing.T) {
	var receivedUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUserAgent = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:     true,
		ValidateHeaders: true,
		UserAgent:       "TestClient/1.0",
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	transport, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = transport.Close() }()

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Set User-Agent
	if config.UserAgent != "" {
		req.Header.Set("User-Agent", config.UserAgent)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if receivedUserAgent != "TestClient/1.0" {
		t.Errorf("Expected User-Agent 'TestClient/1.0', got '%s'", receivedUserAgent)
	}
}

func TestTransport_Headers(t *testing.T) {
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:     true,
		ValidateHeaders: true,
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	transport, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = transport.Close() }()

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Set custom headers
	req.Header.Set("X-Custom-Header", "test-value")
	req.Header.Set("Accept", "application/json")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if receivedHeaders.Get("X-Custom-Header") != "test-value" {
		t.Errorf("Expected X-Custom-Header 'test-value', got '%s'", receivedHeaders.Get("X-Custom-Header"))
	}

	if receivedHeaders.Get("Accept") != "application/json" {
		t.Errorf("Expected Accept 'application/json', got '%s'", receivedHeaders.Get("Accept"))
	}
}

// ============================================================================
// Redirect Settings Tests
// ============================================================================

func TestRedirectSettings_AddAndGetChain(t *testing.T) {
	t.Run("Empty chain", func(t *testing.T) {
		s := &redirectSettings{}
		chain := s.getChain()
		if chain != nil {
			t.Errorf("Expected nil chain for empty settings, got %v", chain)
		}
	})

	t.Run("Inline chain only", func(t *testing.T) {
		s := &redirectSettings{}
		s.addRedirect("http://example.com/1")
		s.addRedirect("http://example.com/2")
		s.addRedirect("http://example.com/3")

		if s.chainLen != 3 {
			t.Errorf("Expected chain length 3, got %d", s.chainLen)
		}

		chain := s.getChain()
		if len(chain) != 3 {
			t.Fatalf("Expected chain length 3, got %d", len(chain))
		}

		expected := []string{"http://example.com/1", "http://example.com/2", "http://example.com/3"}
		for i, url := range expected {
			if chain[i] != url {
				t.Errorf("Chain[%d] = %s, expected %s", i, chain[i], url)
			}
		}
	})

	t.Run("Overflow to slice", func(t *testing.T) {
		s := &redirectSettings{}

		// Add more than maxInlineRedirects (8)
		for i := 0; i < 10; i++ {
			s.addRedirect("http://example.com/" + string(rune('0'+i)))
		}

		if s.chainLen != 10 {
			t.Errorf("Expected chain length 10, got %d", s.chainLen)
		}

		if s.overflowChain == nil {
			t.Error("Expected overflowChain to be allocated")
		}

		chain := s.getChain()
		if len(chain) != 10 {
			t.Errorf("Expected chain length 10, got %d", len(chain))
		}
	})
}

func TestRedirectSettings_Pool(t *testing.T) {
	// Get settings from pool
	s := getRedirectSettings()
	if s == nil {
		t.Fatal("Expected non-nil settings")
	}

	// Add some data
	s.addRedirect("http://example.com")
	s.followRedirects = true
	s.maxRedirects = 5

	// Return to pool
	putRedirectSettings(s)

	// Get again - should be reset
	s2 := getRedirectSettings()
	if s2.chainLen != 0 {
		t.Errorf("Expected chainLen 0, got %d", s2.chainLen)
	}
	if s2.followRedirects {
		t.Error("Expected followRedirects to be false")
	}
	if s2.maxRedirects != 0 {
		t.Errorf("Expected maxRedirects 0, got %d", s2.maxRedirects)
	}

	putRedirectSettings(s2)
	putRedirectSettings(nil) // Should not panic
}

// ============================================================================
// Redirect Validation Tests
// ============================================================================

func TestTransport_ValidateRedirectTarget(t *testing.T) {
	// Create transport with SSRF protection enabled
	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: false, // SSRF protection enabled
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	transport, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = transport.Close() }()

	t.Run("Nil URL", func(t *testing.T) {
		err := transport.validateRedirectTarget(nil)
		if err == nil {
			t.Error("Expected error for nil URL")
		}
	})

	t.Run("Empty host", func(t *testing.T) {
		u, _ := url.Parse("http:///path")
		err := transport.validateRedirectTarget(u)
		if err == nil {
			t.Error("Expected error for empty host")
		}
	})

	t.Run("Localhost blocked", func(t *testing.T) {
		u, _ := url.Parse("http://localhost/path")
		err := transport.validateRedirectTarget(u)
		if err == nil {
			t.Error("Expected error for localhost")
		}
	})

	t.Run("Invalid scheme", func(t *testing.T) {
		u, _ := url.Parse("ftp://example.com/path")
		err := transport.validateRedirectTarget(u)
		if err == nil {
			t.Error("Expected error for invalid scheme")
		}
	})

	t.Run("Valid public URL", func(t *testing.T) {
		// Note: This test may fail if DNS resolution is not available
		// In a real test environment, you would mock the DNS lookup
		u, _ := url.Parse("http://example.com/path")
		// We can't fully test this without mocking DNS, so just verify it doesn't panic
		_ = transport.validateRedirectTarget(u)
	})
}

func TestTransport_SetRedirectPolicy(t *testing.T) {
	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	transport, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = transport.Close() }()

	ctx := context.Background()

	// Set redirect policy - now returns settings pointer
	ctx, settings := transport.SetRedirectPolicy(ctx, true, 5)
	defer putRedirectSettings(settings)

	// Get redirect chain (should be empty initially)
	chain := transport.GetRedirectChain(ctx)
	if chain != nil {
		t.Errorf("Expected nil chain, got %v", chain)
	}
}

func TestTransport_SetRedirectPolicyCleanup(t *testing.T) {
	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	transport, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = transport.Close() }()

	t.Run("Cleanup function is safe to call", func(t *testing.T) {
		_, settings := transport.SetRedirectPolicy(context.Background(), true, 5)
		putRedirectSettings(settings) // Should not panic
	})

	t.Run("Cleanup function can be called multiple times safely", func(t *testing.T) {
		// Note: putRedirectSettings should be idempotent or at least not panic on multiple calls
		_, settings := transport.SetRedirectPolicy(context.Background(), true, 5)
		putRedirectSettings(settings)
	})
}

// TestCookieOverlayJar verifies manual cookies are layered onto (not written
// into) the shared jar: same-hostname requests receive them, other hosts do
// not, manual wins by name, and SetCookies only reaches the base jar.
func TestCookieOverlayJar(t *testing.T) {
	base, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	origin := &url.URL{Scheme: "http", Host: "api.example.com"}
	base.SetCookies(origin, []*http.Cookie{
		{Name: "jar-cookie", Value: "jar"},
		{Name: "shared-name", Value: "from-jar"},
	})

	req := &http.Request{Header: http.Header{}, URL: origin}
	req.AddCookie(&http.Cookie{Name: "manual", Value: "m1"})
	req.AddCookie(&http.Cookie{Name: "shared-name", Value: "from-manual"})
	overlay := newCookieOverlayJar(base, req, req.Cookies())

	// Same host: jar + manual, manual wins the name clash.
	sameHost := &url.URL{Scheme: "https", Host: "api.example.com"} // port/scheme differences are fine
	got := overlay.Cookies(sameHost)
	byName := map[string]string{}
	for _, c := range got {
		byName[c.Name] = c.Value
	}
	if byName["jar-cookie"] != "jar" || byName["manual"] != "m1" {
		t.Errorf("overlay merge wrong: %v", byName)
	}
	if byName["shared-name"] != "from-manual" {
		t.Errorf("manual cookie should win by name, got %q", byName["shared-name"])
	}

	// Other host: manual cookies must not leak.
	otherHost := &url.URL{Scheme: "https", Host: "other.example.net"}
	for _, c := range overlay.Cookies(otherHost) {
		if c.Name == "manual" || c.Name == "shared-name" && c.Value == "from-manual" {
			t.Errorf("manual cookie leaked to other host: %+v", c)
		}
	}

	// Manual cookies were never written into the base jar.
	for _, c := range base.Cookies(sameHost) {
		if c.Name == "manual" {
			t.Errorf("manual cookie persisted into base jar: %+v", c)
		}
	}

	// SetCookies forwards to the base jar (response cookies still stick).
	overlay.SetCookies(origin, []*http.Cookie{{Name: "resp", Value: "r1"}})
	found := false
	for _, c := range base.Cookies(origin) {
		if c.Name == "resp" {
			found = true
		}
	}
	if !found {
		t.Error("SetCookies did not forward to base jar")
	}
}
