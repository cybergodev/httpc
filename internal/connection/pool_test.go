package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

	// Invalid ProxyURL rejection is table-driven in TestNewPoolManager_InvalidProxyURL.
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

	t.Run("zero state", func(t *testing.T) {
		metrics := pm.GetMetrics()

		// Initially should have zero connections
		if metrics.ActiveConnections != 0 {
			t.Errorf("Expected 0 active connections, got %d", metrics.ActiveConnections)
		}

		if metrics.TotalConnections != 0 {
			t.Errorf("Expected 0 total connections, got %d", metrics.TotalConnections)
		}

		if metrics.ConnectionHitRate != 0 {
			t.Errorf("Expected 0 hit rate with no connections, got %f", metrics.ConnectionHitRate)
		}
	})

	// Hit-rate calculation (folded from the former coverage_test.go
	// TestGetMetrics_HitRateCalculation): cumulative accepted connections vs
	// rejected attempts.
	t.Run("hit rate calculation", func(t *testing.T) {
		pm.acceptedConns.Store(80)
		pm.rejectedConns.Store(20)

		m := pm.GetMetrics()
		wantHitRate := float64(80) / float64(80+20) // 0.8
		if m.ConnectionHitRate != wantHitRate {
			t.Errorf("hit rate = %f, want %f", m.ConnectionHitRate, wantHitRate)
		}
		if m.TotalConnections != 80 {
			t.Errorf("TotalConnections = %d, want 80 (cumulative accepted)", m.TotalConnections)
		}
	})

	// Active gauge (folded from TestGetMetrics_ActiveConnections).
	t.Run("active connections gauge", func(t *testing.T) {
		pm.activeConns.Store(42)

		m := pm.GetMetrics()
		if m.ActiveConnections != 42 {
			t.Errorf("ActiveConnections = %d, want 42", m.ActiveConnections)
		}
		if m.LastUpdate == 0 {
			t.Error("LastUpdate should be non-zero")
		}
	})
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

// TestPoolManager_MultipleRequests was removed: its success counter was
// tautological (any failure aborted via Fatalf), and connection reuse under
// load is asserted by TestPoolManager_ConcurrentRequests.

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

// TestPoolManager_SystemProxy was removed: it only asserted that a
// transport was created — true for every successful construction. The
// system-proxy selection order is asserted in proxy_test.go (priority table).

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

// TestPoolManager_ValidateAddressBeforeDial was removed: every row
// (private/loopback/link-local rejection, public-IP pass, IPv6 loopback,
// unresolvable host) is table-driven in TestResolveAndValidateAddress
// (coverage_test.go), which also covers the IPv4-mapped-IPv6 and
// IP-without-port variants.

// ============================================================================
// Certificate Pinning Tests
// ============================================================================

// TestPoolManager_CreateVerifyPeerCertificate was removed: all three subtests
// (WithCertPinner / WithoutCertPinner / CustomTLSWithCertPinner) asserted only
// non-nilness already covered — and actually invoked — by
// TestCreateTLSConfig_Custom and TestCreateVerifyPeerCertificate in
// coverage_test.go, which drive the verify callback itself.

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

// TestPoolManager_ValidateAddress_DomainResolution was removed: its
// IPv6 rows were folded into TestResolveAndValidateAddress (coverage_test.go).

// TestTrackedConn_DoubleClose was removed: the double-close idempotence and
// no-double-decrement contract is asserted directly (and under concurrency)
// by TestTrackedConn_Lifecycle and TestTrackedConn_ConcurrentClose in
// coverage_test.go; the HTTP-body-close route is incidental.

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
	_ = pm.Close()

	dialer := pm.createDialer()
	_, err = dialer(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("expected error when dialing closed pool")
	}
	if err.Error() != "connection pool is closed" {
		t.Errorf("error = %q, want 'connection pool is closed'", err.Error())
	}
}

// TestNewPoolManager_MaxTotalConns was removed: it created a server it never
// requested and asserted nothing. MaxTotalConns admission control (exhaustion,
// rejection) is asserted by TestCreateDialer_PoolExhaustion
// (pool_coverage_test.go).

// TestPoolManager_ProxyCallbackRecords verifies the transport's Proxy callback
// records its selection into the per-request ProxyRecorder for all configured
// proxy modes (pool deterministic, pool round-robin, single static URL), and
// that it tolerates a missing recorder (direct-connection wiring).
func TestPoolManager_ProxyCallbackRecords(t *testing.T) {
	newReq := func(ctx context.Context) *http.Request {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
		if err != nil {
			t.Fatalf("NewRequestWithContext: %v", err)
		}
		return req
	}

	poolCfg := &Config{
		ProxyPool: []string{
			"http://proxy1.example.com:8080",
			"http://proxy2.example.com:8080",
			"http://proxy3.example.com:8080",
		},
	}

	t.Run("pool deterministic path", func(t *testing.T) {
		pm, err := NewPoolManager(poolCfg)
		if err != nil {
			t.Fatalf("NewPoolManager: %v", err)
		}
		defer func() { _ = pm.Close() }()

		rec := &ProxyRecorder{}
		ctx := WithProxyRecorder(WithProxyAttempt(context.Background(), 0), rec)
		u, err := pm.transport.Proxy(newReq(ctx))
		if err != nil {
			t.Fatalf("Proxy: %v", err)
		}
		// SelectIndex(0) with all circuits closed returns the first entry.
		if want := "http://proxy1.example.com:8080"; u.String() != want || rec.Last() != want {
			t.Errorf("proxy = %q, recorded = %q, want %q", u.String(), rec.Last(), want)
		}
	})

	t.Run("pool round-robin path", func(t *testing.T) {
		pm, err := NewPoolManager(poolCfg)
		if err != nil {
			t.Fatalf("NewPoolManager: %v", err)
		}
		defer func() { _ = pm.Close() }()

		rec := &ProxyRecorder{}
		// No attempt index on ctx — falls back to round-robin Select.
		ctx := WithProxyRecorder(context.Background(), rec)
		u, err := pm.transport.Proxy(newReq(ctx))
		if err != nil {
			t.Fatalf("Proxy: %v", err)
		}
		if rec.Last() != u.String() {
			t.Errorf("recorded %q, want the returned proxy %q", rec.Last(), u.String())
		}
	})

	t.Run("single ProxyURL path", func(t *testing.T) {
		pm, err := NewPoolManager(&Config{ProxyURL: "http://static.example.com:3128"})
		if err != nil {
			t.Fatalf("NewPoolManager: %v", err)
		}
		defer func() { _ = pm.Close() }()

		rec := &ProxyRecorder{}
		ctx := WithProxyRecorder(context.Background(), rec)
		u, err := pm.transport.Proxy(newReq(ctx))
		if err != nil {
			t.Fatalf("Proxy: %v", err)
		}
		if want := "http://static.example.com:3128"; u.String() != want || rec.Last() != want {
			t.Errorf("proxy = %q, recorded = %q, want %q", u.String(), rec.Last(), want)
		}
	})

	t.Run("missing recorder does not panic", func(t *testing.T) {
		pm, err := NewPoolManager(poolCfg)
		if err != nil {
			t.Fatalf("NewPoolManager: %v", err)
		}
		defer func() { _ = pm.Close() }()

		if _, err := pm.transport.Proxy(newReq(context.Background())); err != nil {
			t.Fatalf("Proxy without recorder: %v", err)
		}
	})
}

// TestPoolManager_HasProxy verifies HasProxy reflects the configured proxy
// mode so the engine attaches a recorder only when a proxy may be selected.
func TestPoolManager_HasProxy(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{"default (direct)", nil, false},
		{"system proxy only", &Config{EnableSystemProxy: true}, false},
		{"single ProxyURL", &Config{ProxyURL: "http://static.example.com:3128"}, true},
		{"proxy pool", &Config{ProxyPool: []string{"http://proxy1.example.com:8080"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPoolManager(tt.cfg)
			if err != nil {
				t.Fatalf("NewPoolManager: %v", err)
			}
			defer func() { _ = pm.Close() }()
			if got := pm.HasProxy(); got != tt.want {
				t.Errorf("HasProxy() = %v, want %v", got, tt.want)
			}
		})
	}
}

// recordingPinner is a certPinner stub that records invocation.
type recordingPinner struct {
	called bool
}

func (p *recordingPinner) VerifyPeerCertificate(_ [][]byte, _ [][]*x509.Certificate) error {
	p.called = true
	return nil
}

// TestCreateTLSConfig_ChainsUserVerifyCallback verifies certificate pinning
// chains onto a user-supplied VerifyPeerCertificate callback instead of
// silently replacing it (custom CA validation / mTLS hooks keep working).
func TestCreateTLSConfig_ChainsUserVerifyCallback(t *testing.T) {
	userCalled := false
	cfg := &Config{
		TLSConfig: &tls.Config{
			VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
				userCalled = true
				return nil
			},
		},
		certPinner: &recordingPinner{},
	}
	pm := &PoolManager{config: cfg}

	tlsCfg := pm.createTLSConfig()
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Fatal("VerifyPeerCertificate not set")
	}
	if err := tlsCfg.VerifyPeerCertificate(nil, nil); err != nil {
		t.Fatalf("chained callback error: %v", err)
	}
	if !userCalled {
		t.Error("user VerifyPeerCertificate was not invoked")
	}
	if !cfg.certPinner.(*recordingPinner).called {
		t.Error("cert pinner was not invoked")
	}
}

// TestResolveAndValidateAddress_IPLiteralReturnsCandidate verifies the
// multi-candidate return contract: an IP-literal address validates to a
// single-element slice (callers dial candidates in turn for failover).
func TestResolveAndValidateAddress_IPLiteralReturnsCandidate(t *testing.T) {
	pm, err := NewPoolManager(&Config{
		ExemptNets: mustParseCIDRs(t, "8.8.8.0/24"),
	})
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer func() { _ = pm.Close() }()

	addrs, err := pm.resolveAndValidateAddress(context.Background(), "8.8.8.8:443")
	if err != nil {
		t.Fatalf("resolveAndValidateAddress: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "8.8.8.8:443" {
		t.Errorf("IP literal should validate to one candidate, got %v", addrs)
	}
}

// mustParseCIDRs parses CIDR strings for tests.
func mustParseCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", c, err)
		}
		nets = append(nets, n)
	}
	return nets
}
