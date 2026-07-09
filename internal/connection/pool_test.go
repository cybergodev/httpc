package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// CONNECTION POOL MANAGER UNIT TESTS
// ============================================================================

func TestPoolManager_New(t *testing.T) {
	t.Run("With default config", func(t *testing.T) {
		pm, err := NewPoolManager(nil)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		defer func() { _ = pm.Close() }()

		if pm.config == nil {
			t.Error("Config should not be nil")
		}

		if pm.transport == nil {
			t.Error("Transport should not be nil")
		}

	})

	t.Run("With custom config", func(t *testing.T) {
		config := &Config{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			MaxConnsPerHost:     25,
			DialTimeout:         5 * time.Second,
			EnableHTTP2:         true,
		}

		pm, err := NewPoolManager(config)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		defer func() { _ = pm.Close() }()

		if pm.config.MaxIdleConns != 100 {
			t.Errorf("Expected MaxIdleConns 100, got %d", pm.config.MaxIdleConns)
		}

		if pm.transport.MaxIdleConns != 100 {
			t.Errorf("Expected transport MaxIdleConns 100, got %d", pm.transport.MaxIdleConns)
		}
	})

	t.Run("With proxy URL", func(t *testing.T) {
		config := &Config{
			ProxyURL: "http://proxy.example.com:8080",
		}

		pm, err := NewPoolManager(config)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		defer func() { _ = pm.Close() }()

		if pm.transport.Proxy == nil {
			t.Error("Proxy should be configured")
		}
	})

	t.Run("With invalid proxy URL", func(t *testing.T) {
		config := &Config{
			ProxyURL: "://invalid-url",
		}

		_, err := NewPoolManager(config)
		if err == nil {
			t.Error("Expected error for invalid proxy URL")
		}
	})
}

func TestPoolManager_GetTransport(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	transport := pm.GetTransport()

	if transport == nil {
		t.Fatal("Transport should not be nil")
	}

	if transport != pm.transport {
		t.Error("GetTransport should return the same transport instance")
	}
}

func TestPoolManager_GetMetrics(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	metrics := pm.GetMetrics()

	// Initially should have zero connections
	if metrics.ActiveConnections != 0 {
		t.Errorf("Expected 0 active connections, got %d", metrics.ActiveConnections)
	}

	if metrics.TotalConnections != 0 {
		t.Errorf("Expected 0 total connections, got %d", metrics.TotalConnections)
	}
}

func TestPoolManager_HTTPRequest(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.AllowPrivateIPs = true // Allow localhost for testing
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Create HTTP client with our pool manager
	client := &http.Client{
		Transport: pm.GetTransport(),
		Timeout:   5 * time.Second,
	}

	// Make request
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify transport is working (connection tracking may not be immediate)
	// Just verify the request succeeded
}

func TestPoolManager_MultipleRequests(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.AllowPrivateIPs = true
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	client := &http.Client{
		Transport: pm.GetTransport(),
		Timeout:   5 * time.Second,
	}

	// Make multiple requests
	numRequests := 10
	successCount := 0
	for i := 0; i < numRequests; i++ {
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		_ = resp.Body.Close()
		successCount++
	}

	// Verify all requests succeeded
	if successCount != numRequests {
		t.Errorf("Expected %d successful requests, got %d", numRequests, successCount)
	}
}

func TestPoolManager_Close(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	err = pm.Close()
	if err != nil {
		t.Errorf("Expected no error on close, got: %v", err)
	}

	// Close again should be idempotent
	err = pm.Close()
	if err != nil {
		t.Errorf("Expected no error on double close, got: %v", err)
	}
}

func TestPoolManager_TLSConfig(t *testing.T) {
	t.Run("Default TLS config", func(t *testing.T) {
		pm, err := NewPoolManager(nil)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		defer func() { _ = pm.Close() }()

		tlsConfig := pm.transport.TLSClientConfig

		if tlsConfig == nil {
			t.Fatal("TLS config should not be nil")
		}

		if tlsConfig.MinVersion != tls.VersionTLS12 {
			t.Errorf("Expected MinVersion TLS 1.2, got %d", tlsConfig.MinVersion)
		}

		if tlsConfig.MaxVersion != tls.VersionTLS13 {
			t.Errorf("Expected MaxVersion TLS 1.3, got %d", tlsConfig.MaxVersion)
		}

		if tlsConfig.InsecureSkipVerify {
			t.Error("InsecureSkipVerify should be false by default")
		}
	})

	t.Run("Custom TLS config", func(t *testing.T) {
		customTLS := &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		}

		config := &Config{
			TLSConfig: customTLS,
		}

		pm, err := NewPoolManager(config)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		defer func() { _ = pm.Close() }()

		tlsConfig := pm.transport.TLSClientConfig

		if tlsConfig.MinVersion != tls.VersionTLS13 {
			t.Errorf("Expected MinVersion TLS 1.3, got %d", tlsConfig.MinVersion)
		}

		if !tlsConfig.InsecureSkipVerify {
			t.Error("InsecureSkipVerify should be true")
		}
	})
}

func TestPoolManager_Timeouts(t *testing.T) {
	config := &Config{
		DialTimeout:           2 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 4 * time.Second,
		IdleConnTimeout:       5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	transport := pm.transport

	if transport.TLSHandshakeTimeout != 3*time.Second {
		t.Errorf("Expected TLSHandshakeTimeout 3s, got %v", transport.TLSHandshakeTimeout)
	}

	if transport.ResponseHeaderTimeout != 4*time.Second {
		t.Errorf("Expected ResponseHeaderTimeout 4s, got %v", transport.ResponseHeaderTimeout)
	}

	if transport.IdleConnTimeout != 5*time.Second {
		t.Errorf("Expected IdleConnTimeout 5s, got %v", transport.IdleConnTimeout)
	}

	if transport.ExpectContinueTimeout != 1*time.Second {
		t.Errorf("Expected ExpectContinueTimeout 1s, got %v", transport.ExpectContinueTimeout)
	}
}

func TestPoolManager_ConnectionLimits(t *testing.T) {
	tests := []struct {
		name                string
		maxIdleConns        int
		maxIdleConnsPerHost int
		maxConnsPerHost     int
	}{
		{
			name:                "Standard limits",
			maxIdleConns:        50,
			maxIdleConnsPerHost: 5,
			maxConnsPerHost:     10,
		},
		{
			name:                "High limits",
			maxIdleConns:        1000,
			maxIdleConnsPerHost: 100,
			maxConnsPerHost:     200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				MaxIdleConns:        tt.maxIdleConns,
				MaxIdleConnsPerHost: tt.maxIdleConnsPerHost,
				MaxConnsPerHost:     tt.maxConnsPerHost,
			}

			pm, err := NewPoolManager(config)
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}
			defer func() { _ = pm.Close() }()

			transport := pm.transport

			if transport.MaxIdleConns != tt.maxIdleConns {
				t.Errorf("Expected MaxIdleConns %d, got %d", tt.maxIdleConns, transport.MaxIdleConns)
			}

			if transport.MaxIdleConnsPerHost != tt.maxIdleConnsPerHost {
				t.Errorf("Expected MaxIdleConnsPerHost %d, got %d", tt.maxIdleConnsPerHost, transport.MaxIdleConnsPerHost)
			}

			if transport.MaxConnsPerHost != tt.maxConnsPerHost {
				t.Errorf("Expected MaxConnsPerHost %d, got %d", tt.maxConnsPerHost, transport.MaxConnsPerHost)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.MaxIdleConns != 200 {
		t.Errorf("Expected MaxIdleConns 200, got %d", config.MaxIdleConns)
	}

	if config.MaxIdleConnsPerHost != 20 {
		t.Errorf("Expected MaxIdleConnsPerHost 20, got %d", config.MaxIdleConnsPerHost)
	}

	if config.MaxConnsPerHost != 50 {
		t.Errorf("Expected MaxConnsPerHost 50, got %d", config.MaxConnsPerHost)
	}

	if config.DialTimeout != 10*time.Second {
		t.Errorf("Expected DialTimeout 10s, got %v", config.DialTimeout)
	}

	if !config.EnableHTTP2 {
		t.Error("EnableHTTP2 should be true by default")
	}

	if config.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}
}

func TestPoolManager_ContextCancellation(t *testing.T) {
	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	client := &http.Client{
		Transport: pm.GetTransport(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)

	_, err = client.Do(req)
	if err == nil {
		t.Error("Expected error due to context cancellation")
	}
}

// ============================================================================
// SSRF Protection Tests
// ============================================================================

func TestPoolManager_SystemProxy(t *testing.T) {
	config := &Config{
		EnableSystemProxy: true,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Transport should be created (proxy detection may or may not find a proxy)
	if pm.transport == nil {
		t.Error("Transport should not be nil")
	}
}

func TestPoolManager_ConcurrentRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.AllowPrivateIPs = true
	config.MaxIdleConns = 50
	config.MaxConnsPerHost = 20
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	client := &http.Client{
		Transport: pm.GetTransport(),
		Timeout:   5 * time.Second,
	}

	const numRequests = 20
	var wg sync.WaitGroup
	errChan := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(server.URL)
			if err != nil {
				errChan <- err
				return
			}
			_ = resp.Body.Close()
		}()
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("Concurrent request failed: %v", err)
	}
}

func TestPoolManager_ConcurrentClose(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	const numClosers = 5
	var wg sync.WaitGroup
	wg.Add(numClosers)

	for i := 0; i < numClosers; i++ {
		go func() {
			defer wg.Done()
			_ = pm.Close() // Should be safe to call multiple times
		}()
	}

	wg.Wait()
}

// ============================================================================
// Edge Cases Tests
// ============================================================================

func TestPoolManager_HTTP2Disabled(t *testing.T) {
	config := &Config{
		EnableHTTP2: false,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// When HTTP/2 is disabled, ForceAttemptHTTP2 should be false
	if pm.transport.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should be false when HTTP/2 is disabled")
	}
}

// ============================================================================
// Address Validation Tests (SSRF Protection)
// ============================================================================

func TestPoolManager_ValidateAddressBeforeDial(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	tests := []struct {
		name        string
		address     string
		expectError bool
	}{
		{
			name:        "Loopback IP",
			address:     "127.0.0.1:8080",
			expectError: true, // Loopback should be blocked
		},
		{
			name:        "Private IP 10.x.x.x",
			address:     "10.0.0.1:443",
			expectError: true, // Private IP should be blocked
		},
		{
			name:        "Private IP 192.168.x.x",
			address:     "192.168.1.1:443",
			expectError: true, // Private IP should be blocked
		},
		{
			name:        "Private IP 172.16.x.x",
			address:     "172.16.0.1:443",
			expectError: true, // Private IP should be blocked
		},
		{
			name:        "Link-local IP",
			address:     "169.254.1.1:443",
			expectError: true, // Link-local should be blocked
		},
		{
			name:        "Public IP (simulated)",
			address:     "8.8.8.8:443",
			expectError: false, // Public IP should be allowed
		},
		{
			name:        "IP without port",
			address:     "127.0.0.1",
			expectError: true, // Loopback without port should be blocked
		},
		{
			name:        "IPv6 loopback",
			address:     "[::1]:8080",
			expectError: true, // IPv6 loopback should be blocked
		},
		{
			name:        "Invalid address format",
			address:     "not-an-ip-address",
			expectError: true, // DNS resolution failure should block
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pm.resolveAndValidateAddress(context.Background(), tt.address)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for address %s, got nil", tt.address)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Did not expect error for address %s, got: %v", tt.address, err)
			}
		})
	}
}

// ============================================================================
// Certificate Pinning Tests
// ============================================================================

func TestPoolManager_CreateVerifyPeerCertificate(t *testing.T) {
	t.Run("WithCertPinner", func(t *testing.T) {
		// Create a mock cert pinner
		pinner := &mockCertPinner{}

		config := &Config{
			certPinner: pinner,
		}

		pm, err := NewPoolManager(config)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		defer func() { _ = pm.Close() }()

		tlsConfig := pm.transport.TLSClientConfig
		if tlsConfig == nil {
			t.Fatal("TLS config should not be nil")
		}

		// VerifyPeerCertificate should be set when certPinner is configured
		if tlsConfig.VerifyPeerCertificate == nil {
			t.Error("VerifyPeerCertificate should be set when certPinner is configured")
		}
	})

	t.Run("WithoutCertPinner", func(t *testing.T) {
		pm, err := NewPoolManager(nil)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		defer func() { _ = pm.Close() }()

		tlsConfig := pm.transport.TLSClientConfig
		if tlsConfig == nil {
			t.Fatal("TLS config should not be nil")
		}

		// VerifyPeerCertificate should not be set without certPinner
		if tlsConfig.VerifyPeerCertificate != nil {
			t.Error("VerifyPeerCertificate should not be set without certPinner")
		}
	})

	t.Run("CustomTLSWithCertPinner", func(t *testing.T) {
		pinner := &mockCertPinner{}
		customTLS := &tls.Config{
			MinVersion: tls.VersionTLS13,
		}

		config := &Config{
			TLSConfig:  customTLS,
			certPinner: pinner,
		}

		pm, err := NewPoolManager(config)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		defer func() { _ = pm.Close() }()

		tlsConfig := pm.transport.TLSClientConfig
		if tlsConfig == nil {
			t.Fatal("TLS config should not be nil")
		}

		// Should preserve custom TLS config
		if tlsConfig.MinVersion != tls.VersionTLS13 {
			t.Errorf("Expected MinVersion TLS 1.3, got %d", tlsConfig.MinVersion)
		}

		// Should add cert pinning
		if tlsConfig.VerifyPeerCertificate == nil {
			t.Error("VerifyPeerCertificate should be set")
		}
	})
}

// mockCertPinner is a mock implementation of certificate pinner for testing
type mockCertPinner struct {
	shouldFail bool
}

func (m *mockCertPinner) Pin() string {
	return "mock-pinner"
}

func (m *mockCertPinner) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if m.shouldFail {
		return fmt.Errorf("mock certificate pinning failure")
	}
	return nil
}

func TestPoolManager_WithDoHResolver(t *testing.T) {
	config := &Config{
		AllowPrivateIPs: true,
		EnableDoH:       true,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Verify DoH resolver is initialized
	if pm.dohResolver == nil {
		t.Error("DoH resolver should be initialized when EnableDoH is true")
	}
}

func TestPoolManager_WithoutDoHResolver(t *testing.T) {
	config := &Config{
		AllowPrivateIPs: true,
		EnableDoH:       false,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Verify DoH resolver is NOT initialized
	if pm.dohResolver != nil {
		t.Error("DoH resolver should not be initialized when EnableDoH is false")
	}
}

// ============================================================================
// TLS Configuration Edge Cases
// ============================================================================

func TestPoolManager_TLSConfigWithCustomCiphers(t *testing.T) {
	config := &Config{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
			},
		},
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Verify custom TLS config is used
	if pm.transport.TLSClientConfig == nil {
		t.Fatal("TLS config should not be nil")
	}

	if pm.transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("Expected MinVersion TLS 1.3, got %d", pm.transport.TLSClientConfig.MinVersion)
	}
}

func TestPoolManager_TLSConfigWithInsecureSkipVerify(t *testing.T) {
	config := &Config{
		InsecureSkipVerify: true,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	if !pm.transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

// ============================================================================
// Connection Metrics Tests
// ============================================================================

func TestPoolManager_ConnectionMetrics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.AllowPrivateIPs = true
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	client := &http.Client{
		Transport: pm.GetTransport(),
		Timeout:   5 * time.Second,
	}

	// Make a request
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	_ = resp.Body.Close()

	// Check metrics
	metrics := pm.GetMetrics()
	t.Logf("Metrics: TotalConns=%d, ActiveConns=%d, RejectedConns=%d",
		metrics.TotalConnections, metrics.ActiveConnections, metrics.RejectedConnections)

	// A successful request must register at least one connection in the metrics.
	if metrics.TotalConnections < 1 {
		t.Errorf("TotalConnections = %d, want >= 1 after a successful request", metrics.TotalConnections)
	}
}

// ============================================================================
// Validate Address Tests - Additional Coverage
// ============================================================================

func TestPoolManager_ValidateAddress_DomainResolution(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	tests := []struct {
		name        string
		address     string
		expectError bool
	}{
		{
			name:        "IPv6 address",
			address:     "[2001:4860:4860::8888]:443",
			expectError: false, // Public IPv6
		},
		{
			name:        "IPv6 loopback",
			address:     "[::1]:8080",
			expectError: true, // Loopback should be blocked
		},
		{
			name:        "IPv4-mapped IPv6",
			address:     "[::ffff:127.0.0.1]:8080",
			expectError: true, // Should detect as loopback
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pm.resolveAndValidateAddress(context.Background(), tt.address)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for address %s, got nil", tt.address)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Did not expect error for address %s, got: %v", tt.address, err)
			}
		})
	}
}

func TestTrackedConn_DoubleClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.AllowPrivateIPs = true
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	client := &http.Client{
		Transport: pm.GetTransport(),
		Timeout:   5 * time.Second,
	}

	// Make a request to create a tracked connection
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// First close
	err = resp.Body.Close()
	if err != nil {
		t.Errorf("First body close failed: %v", err)
	}

	// Second close must be safe and idempotent: the body wrapper is designed so
	// that closing an already-closed body is a no-op returning nil.
	err = resp.Body.Close()
	if err != nil {
		t.Errorf("Second body close should be idempotent (nil error), got: %v", err)
	}
}

// ============================================================================
// HOST CONNECTION TRACKING EVICTION TESTS
// ============================================================================

func TestPoolManager_EvictStaleHosts(t *testing.T) {
	pm, err := NewPoolManager(DefaultConfig())
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Add multiple host entries directly
	hosts := []string{"host1.example.com", "host2.example.com", "host3.example.com"}
	for _, host := range hosts {
		pm.updateConnectionMetrics(host, true)
	}

	// Verify entries exist
	count := 0
	pm.hostConns.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != len(hosts) {
		t.Fatalf("expected %d host entries, got %d", len(hosts), count)
	}

	// Manually age out entries by setting LastUsed to the past
	// and clearing active connections (normally done by trackedConn.Close)
	oldTime := time.Now().Add(-hostConnMaxAge - time.Minute).Unix()
	pm.hostConns.Range(func(key, value any) bool {
		if stats, ok := value.(*hostStats); ok {
			atomic.StoreInt64(&stats.LastUsed, oldTime)
			atomic.StoreInt64(&stats.ActiveConns, 0)
		}
		return true
	})

	// Reset eviction timer so next call triggers eviction
	atomic.StoreInt64(&pm.lastEviction, 0)

	// Trigger eviction via updateConnectionMetrics
	pm.updateConnectionMetrics("newhost.example.com", true)

	// Stale entries should be evicted, only newhost remains
	remaining := 0
	pm.hostConns.Range(func(_, _ any) bool {
		remaining++
		return true
	})
	if remaining != 1 {
		t.Errorf("expected 1 remaining host entry after eviction, got %d", remaining)
	}
}

func TestPoolManager_EvictStaleHostsPreservesActive(t *testing.T) {
	pm, err := NewPoolManager(DefaultConfig())
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Add a stale entry with active connections
	stats := &hostStats{
		Host:        "active-stale.example.com",
		LastUsed:    time.Now().Add(-hostConnMaxAge - time.Minute).Unix(),
		ActiveConns: 3,
	}
	pm.hostConns.Store("active-stale.example.com", stats)

	// Reset eviction timer
	atomic.StoreInt64(&pm.lastEviction, 0)

	// Trigger eviction
	pm.updateConnectionMetrics("trigger.example.com", true)

	// The stale-but-active entry should NOT be evicted
	_, exists := pm.hostConns.Load("active-stale.example.com")
	if !exists {
		t.Error("stale host with active connections should not be evicted")
	}
}

func TestPoolManager_EvictionThrottling(t *testing.T) {
	pm, err := NewPoolManager(DefaultConfig())
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Set eviction as recently run
	atomic.StoreInt64(&pm.lastEviction, time.Now().Unix())

	// Add many hosts - eviction should be skipped
	for i := 0; i < 100; i++ {
		pm.updateConnectionMetrics(fmt.Sprintf("host%d.example.com", i), true)
	}

	// All 100 hosts should still exist (eviction was throttled)
	count := 0
	pm.hostConns.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != 100 {
		t.Errorf("expected 100 entries (eviction throttled), got %d", count)
	}
}

func TestConfig_SetCertPinner(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.certPinner != nil {
		t.Error("certPinner should be nil by default")
	}

	cfg.SetCertPinner(nil)

	if cfg.certPinner != nil {
		t.Error("certPinner should remain nil after setting nil")
	}
}

func TestNewPoolManager_InvalidProxyURL(t *testing.T) {
	tests := []struct {
		name    string
		proxy   string
		wantErr string
	}{
		{"empty host", "http://", "missing host"},
		{"bad scheme", "ftp://proxy.com", "unsupported proxy URL scheme"},
		{"invalid URL", "://", "invalid proxy URL"},
		// socks5 is valid; socks4 is not (regression guard for the scheme set).
		{"socks4 rejected", "socks4://proxy.com", "unsupported proxy URL scheme"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{ProxyURL: tc.proxy}
			_, err := NewPoolManager(config)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q should contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestCreateDialer_ClosedPool(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	pm.Close()

	dialer := pm.createDialer()
	_, err = dialer(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("expected error when dialing closed pool")
	}
	if err.Error() != "connection pool is closed" {
		t.Errorf("error = %q, want 'connection pool is closed'", err.Error())
	}
}

func TestNewPoolManager_MaxTotalConns(t *testing.T) {
	config := &Config{
		MaxTotalConns:   2,
		AllowPrivateIPs: true,
		DialTimeout:     5 * time.Second,
		IdleConnTimeout: 100 * time.Millisecond,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer pm.Close()

	// Use httptest server so the dialer can actually connect
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	pm.transport.CloseIdleConnections()
}
