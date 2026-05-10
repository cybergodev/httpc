package connection

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestUpdateConnectionMetrics verifies per-host connection statistics tracking
// including baseline latency, weighted moving average, and failure counting.
func TestUpdateConnectionMetrics(t *testing.T) {
	tests := []struct {
		name    string
		updates []struct {
			host     string
			connTime int64
			success  bool
		}
		wantTotalConns  int64
		wantFailedConns int64
		wantAvgLatency  int64
	}{
		{
			name: "First connection sets baseline latency",
			updates: []struct {
				host     string
				connTime int64
				success  bool
			}{
				{host: "api.example.com", connTime: 100, success: true},
			},
			wantTotalConns:  1,
			wantFailedConns: 0,
			wantAvgLatency:  100,
		},
		{
			name: "Second connection applies weighted average",
			updates: []struct {
				host     string
				connTime int64
				success  bool
			}{
				{host: "api.example.com", connTime: 1000, success: true},
				{host: "api.example.com", connTime: 1000, success: true},
			},
			wantTotalConns:  2,
			wantFailedConns: 0,
			wantAvgLatency:  (1000*9 + 1000) / 10, // (9000+1000)/10 = 1000
		},
		{
			name: "Failed connection increments FailedConns only",
			updates: []struct {
				host     string
				connTime int64
				success  bool
			}{
				{host: "fail.example.com", connTime: 0, success: false},
			},
			wantTotalConns:  0,
			wantFailedConns: 1,
			wantAvgLatency:  0,
		},
		{
			name: "Mixed success and failure on same host",
			updates: []struct {
				host     string
				connTime int64
				success  bool
			}{
				{host: "mixed.example.com", connTime: 500, success: true},
				{host: "mixed.example.com", connTime: 0, success: false},
			},
			wantTotalConns:  1,
			wantFailedConns: 1,
			wantAvgLatency:  500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPoolManager(nil)
			if err != nil {
				t.Fatalf("NewPoolManager() error: %v", err)
			}
			defer func() { _ = pm.Close() }()

			var lastStats *hostStats
			for _, u := range tt.updates {
				lastStats = pm.updateConnectionMetrics(u.host, u.connTime, u.success)
			}

			if lastStats == nil {
				t.Fatal("updateConnectionMetrics() returned nil stats")
			}

			if got := atomic.LoadInt64(&lastStats.TotalConns); got != tt.wantTotalConns {
				t.Errorf("TotalConns = %d, want %d", got, tt.wantTotalConns)
			}

			if got := atomic.LoadInt64(&lastStats.FailedConns); got != tt.wantFailedConns {
				t.Errorf("FailedConns = %d, want %d", got, tt.wantFailedConns)
			}

			if tt.wantAvgLatency != 0 {
				lastStats.mu.Lock()
				got := lastStats.AverageLatency
				lastStats.mu.Unlock()
				if got != tt.wantAvgLatency {
					t.Errorf("AverageLatency = %d, want %d", got, tt.wantAvgLatency)
				}
			}
		})
	}
}

// TestUpdateConnectionMetrics_WeightedAverage verifies the (current*9 + new)/10
// formula applied on successive updates to the same host.
func TestUpdateConnectionMetrics_WeightedAverage(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	host := "avg.example.com"

	// First update: sets baseline
	pm.updateConnectionMetrics(host, 100, true)

	// Second update: should compute (100*9 + 200) / 10 = 110
	pm.updateConnectionMetrics(host, 200, true)

	value, ok := pm.hostConns.Load(host)
	if !ok {
		t.Fatal("host entry not found")
	}
	stats := value.(*hostStats)

	stats.mu.Lock()
	got := stats.AverageLatency
	stats.mu.Unlock()

	want := int64((100*9 + 200) / 10) // 110
	if got != want {
		t.Errorf("AverageLatency after second update = %d, want %d", got, want)
	}
}

// TestTrackedConn_Lifecycle verifies that trackedConn properly tracks
// active connection counts on creation, decrement on Close, and handles
// double-close without double-decrementing.
func TestTrackedConn_Lifecycle(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Simulate the state that createDialer sets up
	var initialActive int64 = 0
	atomic.StoreInt64(&pm.activeConns, initialActive)

	// Create stats entry for the host
	stats := pm.updateConnectionMetrics("test.example.com:443", 100, true)

	if stats == nil {
		t.Fatal("updateConnectionMetrics returned nil stats")
	}

	// Verify stats show one active connection
	if got := atomic.LoadInt64(&stats.ActiveConns); got != 1 {
		t.Errorf("ActiveConns after creation = %d, want 1", got)
	}

	if got := atomic.LoadInt64(&pm.activeConns); got != 0 {
		t.Errorf("pool activeConns after metrics update = %d, want 0 (not yet incremented in pool)", got)
	}

	// Simulate what createDialer does: increment pool active conns
	atomic.AddInt64(&pm.activeConns, 1)

	// Create a trackedConn wrapping a fake connection
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()

	tc := &trackedConn{
		Conn:  client,
		pm:    pm,
		host:  "test.example.com:443",
		stats: stats,
	}

	// Verify active count before close
	if got := atomic.LoadInt64(&pm.activeConns); got != 1 {
		t.Errorf("pool activeConns before close = %d, want 1", got)
	}

	// Close the tracked connection
	err = tc.Close()
	if err != nil {
		t.Errorf("Close() error: %v", err)
	}

	// Verify active count decremented
	if got := atomic.LoadInt64(&pm.activeConns); got != 0 {
		t.Errorf("pool activeConns after close = %d, want 0", got)
	}

	if got := atomic.LoadInt64(&stats.ActiveConns); got != 0 {
		t.Errorf("stats ActiveConns after close = %d, want 0", got)
	}

	// Double close should not double-decrement
	err = tc.Close()
	if err != nil {
		t.Errorf("Second Close() error: %v", err)
	}

	if got := atomic.LoadInt64(&pm.activeConns); got != 0 {
		t.Errorf("pool activeConns after double close = %d, want 0 (no double-decrement)", got)
	}

	if got := atomic.LoadInt64(&stats.ActiveConns); got != 0 {
		t.Errorf("stats ActiveConns after double close = %d, want 0 (no double-decrement)", got)
	}
}

// TestTrackedConn_ConcurrentClose verifies that concurrent Close calls on a
// trackedConn do not cause double-decrement of active connection counters.
func TestTrackedConn_ConcurrentClose(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	stats := pm.updateConnectionMetrics("concurrent.example.com:443", 100, true)
	atomic.AddInt64(&pm.activeConns, 1)

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()

	tc := &trackedConn{
		Conn:  client,
		pm:    pm,
		host:  "concurrent.example.com:443",
		stats: stats,
	}

	var wg sync.WaitGroup
	const numClosers = 10
	wg.Add(numClosers)

	for i := 0; i < numClosers; i++ {
		go func() {
			defer wg.Done()
			_ = tc.Close()
		}()
	}

	wg.Wait()

	// Despite 10 Close calls, activeConns should only be decremented once
	if got := atomic.LoadInt64(&pm.activeConns); got != 0 {
		t.Errorf("pool activeConns after concurrent close = %d, want 0", got)
	}

	if got := atomic.LoadInt64(&stats.ActiveConns); got != 0 {
		t.Errorf("stats ActiveConns after concurrent close = %d, want 0", got)
	}
}

// TestCreateTLSConfig_Default verifies that the default TLS configuration has
// correct cipher suites, session cache, and curve preferences.
func TestCreateTLSConfig_Default(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	tlsConfig := pm.createTLSConfig()
	if tlsConfig == nil {
		t.Fatal("createTLSConfig() returned nil")
	}

	// Verify session cache is enabled
	if tlsConfig.SessionTicketsDisabled {
		t.Error("SessionTicketsDisabled should be false")
	}
	if tlsConfig.ClientSessionCache == nil {
		t.Error("ClientSessionCache should not be nil")
	}

	// Verify cipher suites
	wantCiphers := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	if len(tlsConfig.CipherSuites) != len(wantCiphers) {
		t.Errorf("CipherSuites len = %d, want %d", len(tlsConfig.CipherSuites), len(wantCiphers))
	}
	for i, want := range wantCiphers {
		if i < len(tlsConfig.CipherSuites) && tlsConfig.CipherSuites[i] != want {
			t.Errorf("CipherSuites[%d] = %d, want %d", i, tlsConfig.CipherSuites[i], want)
		}
	}

	// Verify curve preferences
	wantCurves := []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
	if len(tlsConfig.CurvePreferences) != len(wantCurves) {
		t.Errorf("CurvePreferences len = %d, want %d", len(tlsConfig.CurvePreferences), len(wantCurves))
	}
	for i, want := range wantCurves {
		if i < len(tlsConfig.CurvePreferences) && tlsConfig.CurvePreferences[i] != want {
			t.Errorf("CurvePreferences[%d] = %d, want %d", i, tlsConfig.CurvePreferences[i], want)
		}
	}

	// Verify renegotiation is disabled
	if tlsConfig.Renegotiation != tls.RenegotiateNever {
		t.Errorf("Renegotiation = %d, want RenegotiateNever", tlsConfig.Renegotiation)
	}
}

// TestCreateTLSConfig_Custom verifies that a custom TLS config is cloned and
// preserved, including the cert pinner integration.
func TestCreateTLSConfig_Custom(t *testing.T) {
	customTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{tls.TLS_AES_128_GCM_SHA256},
	}

	pinner := &mockCertPinner{}
	pm, err := NewPoolManager(&Config{
		TLSConfig:  customTLS,
		certPinner: pinner,
	})
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	tlsConfig := pm.createTLSConfig()
	if tlsConfig == nil {
		t.Fatal("createTLSConfig() returned nil")
	}

	// Custom TLS config values should be preserved
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want TLS 1.3", tlsConfig.MinVersion)
	}
	if !tlsConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true from custom config")
	}

	// VerifyPeerCertificate should be set by cert pinner
	if tlsConfig.VerifyPeerCertificate == nil {
		t.Error("VerifyPeerCertificate should be set when certPinner is configured")
	}
}

// TestCreateTLSConfig_NoCustom verifies default config has no VerifyPeerCertificate.
func TestCreateTLSConfig_NoCustom(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	tlsConfig := pm.createTLSConfig()
	if tlsConfig.VerifyPeerCertificate != nil {
		t.Error("VerifyPeerCertificate should be nil without certPinner")
	}
}

// TestCreateVerifyPeerCertificate_Success verifies the certificate verification
// callback succeeds when the cert pinner accepts the certificate.
func TestCreateVerifyPeerCertificate_Success(t *testing.T) {
	pinner := &mockCertPinner{shouldFail: false}
	config := &Config{
		certPinner: pinner,
	}
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	tlsConfig := pm.transport.TLSClientConfig
	verifyFn := tlsConfig.VerifyPeerCertificate
	if verifyFn == nil {
		t.Fatal("VerifyPeerCertificate should not be nil")
	}

	// Call with empty args — mock pinner succeeds
	err = verifyFn(nil, nil)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

// TestCreateVerifyPeerCertificate_PinnerFailure verifies the certificate verification
// callback returns an error when the cert pinner rejects the certificate.
func TestCreateVerifyPeerCertificate_PinnerFailure(t *testing.T) {
	pinner := &mockCertPinner{shouldFail: true}
	config := &Config{
		certPinner: pinner,
	}
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	tlsConfig := pm.transport.TLSClientConfig
	verifyFn := tlsConfig.VerifyPeerCertificate
	if verifyFn == nil {
		t.Fatal("VerifyPeerCertificate should not be nil")
	}

	err = verifyFn(nil, nil)
	if err == nil {
		t.Error("expected error from pinner failure, got nil")
	}
}

// TestCreateVerifyPeerCertificate_InsecureSkipVerify verifies that when
// InsecureSkipVerify is true, the verify function still runs pinning but
// returns nil after pinning succeeds.
func TestCreateVerifyPeerCertificate_InsecureSkipVerify(t *testing.T) {
	pinner := &mockCertPinner{shouldFail: false}
	customTLS := &tls.Config{
		InsecureSkipVerify: true,
	}
	config := &Config{
		TLSConfig:  customTLS,
		certPinner: pinner,
	}
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	tlsConfig := pm.transport.TLSClientConfig
	verifyFn := tlsConfig.VerifyPeerCertificate
	if verifyFn == nil {
		t.Fatal("VerifyPeerCertificate should not be nil")
	}

	// Should succeed — pinner passes and InsecureSkipVerify skips standard verification
	err = verifyFn(nil, nil)
	if err != nil {
		t.Errorf("expected no error with InsecureSkipVerify, got: %v", err)
	}
}

// TestCreateDialer_SSRFProtection verifies that the dialer rejects connections
// to private IP addresses when AllowPrivateIPs is false.
func TestCreateDialer_SSRFProtection(t *testing.T) {
	config := &Config{
		AllowPrivateIPs: false,
		DialTimeout:     1 * time.Second,
	}
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Get the dialer function from the transport
	dialFn := pm.createDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Try to dial a private IP — should be blocked by SSRF protection
	_, err = dialFn(ctx, "tcp", "127.0.0.1:8080")
	if err == nil {
		t.Error("expected error when dialing private IP with SSRF protection")
	}
}

// TestCreateDialer_AllowPrivateIPs verifies that the dialer permits connections
// to private IPs when AllowPrivateIPs is true.
func TestCreateDialer_AllowPrivateIPs(t *testing.T) {
	// Create a local listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	// Accept connections in background
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	config := &Config{
		AllowPrivateIPs: true,
		DialTimeout:     2 * time.Second,
		KeepAlive:       30 * time.Second,
	}
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	dialFn := pm.createDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialFn(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("expected successful connection to %s, got error: %v", listener.Addr().String(), err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connection")
	}

	// Verify the returned connection is a trackedConn
	tc, ok := conn.(*trackedConn)
	if !ok {
		t.Fatal("expected trackedConn wrapper")
	}

	// Verify active connection tracking
	if got := atomic.LoadInt64(&pm.activeConns); got != 1 {
		t.Errorf("activeConns = %d, want 1", got)
	}

	// Close the tracked connection
	_ = tc.Close()

	if got := atomic.LoadInt64(&pm.activeConns); got != 0 {
		t.Errorf("activeConns after close = %d, want 0", got)
	}
}

// TestCreateDialer_ContextCancellation verifies that the dialer respects
// context cancellation.
func TestCreateDialer_ContextCancellation(t *testing.T) {
	config := &Config{
		AllowPrivateIPs: true,
		DialTimeout:     5 * time.Second,
	}
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	dialFn := pm.createDialer()

	// Create an already-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = dialFn(ctx, "tcp", "192.0.2.1:12345") // RFC 5737 test address
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

// TestResolveAndValidateAddress verifies address resolution and validation
// including public IPs, private IP rejection, domain resolution, and error cases.
func TestResolveAndValidateAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
		skipOK  bool   // if true, a nil error is acceptable (skip instead of fail)
		want    string // expected result string (exact match, empty means custom validation)
	}{
		// Public IP with port
		{
			name:    "Public IP with port",
			address: "8.8.8.8:443",
			wantErr: false,
			want:    "8.8.8.8:443",
		},
		// Public IP without port (bare IP early return path)
		{
			name:    "Public IP without port",
			address: "8.8.8.8",
			wantErr: false,
			want:    "8.8.8.8",
		},
		// Private IPs are rejected
		{
			name:    "Private IP 10.x",
			address: "10.0.0.1:443",
			wantErr: true,
		},
		{
			name:    "Private IP 172.16.x",
			address: "172.16.0.1:443",
			wantErr: true,
		},
		{
			name:    "Private IP 192.168.x",
			address: "192.168.1.1:443",
			wantErr: true,
		},
		{
			name:    "Loopback 127.x",
			address: "127.0.0.1:443",
			wantErr: true,
		},
		{
			name:    "Link-local 169.254.x",
			address: "169.254.1.1:443",
			wantErr: true,
		},
		// Unresolvable domain
		{
			name:    "Domain resolution failure",
			address: "this-domain-does-not-exist-xyz123.invalid:443",
			wantErr: true,
			skipOK:  true, // DNS resolver may intercept queries
		},
		// Public domain resolution (custom validation in test body)
		{
			name:    "Public domain resolution",
			address: "public-domain",
			wantErr: false,
			want:    "", // custom validation below
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPoolManager(nil)
			if err != nil {
				t.Fatalf("NewPoolManager() error: %v", err)
			}
			defer func() { _ = pm.Close() }()

			// Special handling for public domain resolution test
			if tt.address == "public-domain" {
				domains := []string{
					"one.one.one.one:443",
					"dns.google:443",
					"cloudflare.com:443",
				}

				var lastErr error
				for _, domain := range domains {
					result, resolveErr := pm.resolveAndValidateAddress(domain)
					if resolveErr == nil {
						host, port, splitErr := net.SplitHostPort(result)
						if splitErr != nil {
							t.Fatalf("result %q is not a valid host:port: %v", result, splitErr)
						}
						if port != "443" {
							t.Errorf("port = %q, want %q", port, "443")
						}
						if net.ParseIP(host) == nil {
							t.Errorf("host %q is not a valid IP address", host)
						}
						return
					}
					lastErr = resolveErr
				}

				t.Logf("No test domain resolved to a public IP (likely network restriction): %v", lastErr)
				return
			}

			result, err := pm.resolveAndValidateAddress(tt.address)

			if tt.wantErr {
				if err == nil {
					if tt.skipOK {
						t.Skip("DNS resolver intercepts queries - unresolvable domain resolved to an IP")
					}
					t.Errorf("expected error for %s, got nil", tt.address)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.want != "" && result != tt.want {
				t.Errorf("result = %q, want %q", result, tt.want)
			}
		})
	}
}

// TestTrackedConn_NilStats verifies that trackedConn handles nil stats gracefully.
func TestTrackedConn_NilStats(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	atomic.AddInt64(&pm.activeConns, 1)

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()

	tc := &trackedConn{
		Conn:  client,
		pm:    pm,
		host:  "nilstats.example.com:443",
		stats: nil,
	}

	// Close should not panic with nil stats
	err = tc.Close()
	if err != nil {
		t.Errorf("Close() error: %v", err)
	}

	if got := atomic.LoadInt64(&pm.activeConns); got != 0 {
		t.Errorf("activeConns after close = %d, want 0", got)
	}
}

// TestCreateDialer_Integration verifies the full dialer path through an HTTP request,
// exercising SSRF validation, connection tracking, and metrics updates.
func TestCreateDialer_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.AllowPrivateIPs = true
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	client := &http.Client{
		Transport: pm.GetTransport(),
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()

	// Verify connection metrics were tracked
	metrics := pm.GetMetrics()
	if metrics.TotalConnections < 1 {
		t.Errorf("TotalConnections = %d, want at least 1", metrics.TotalConnections)
	}
}

// TestCreateDialer_SSRFRejectsPrivateIP verifies that the dialer function
// rejects connections to private IPs by calling it directly.
func TestCreateDialer_SSRFRejectsPrivateIP(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{"loopback", "127.0.0.1:8080"},
		{"private_10", "10.0.0.1:80"},
		{"private_172", "172.16.0.1:80"},
		{"private_192", "192.168.1.1:80"},
		{"link_local", "169.254.1.1:80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				AllowPrivateIPs: false,
				DialTimeout:     1 * time.Second,
			}
			pm, err := NewPoolManager(config)
			if err != nil {
				t.Fatalf("NewPoolManager() error: %v", err)
			}
			defer func() { _ = pm.Close() }()

			dialFn := pm.createDialer()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			_, err = dialFn(ctx, "tcp", tt.address)
			if err == nil {
				t.Errorf("expected SSRF rejection for %s, got nil error", tt.address)
			}

			// Verify rejected connection was tracked
			metrics := pm.GetMetrics()
			if metrics.RejectedConnections < 1 {
				t.Errorf("RejectedConnections = %d, want at least 1", metrics.RejectedConnections)
			}
		})
	}
}

// TestCreateDialer_ConnectionFailure verifies that connection failures are
// properly tracked in metrics when dialing an unreachable address.
func TestCreateDialer_ConnectionFailure(t *testing.T) {
	config := &Config{
		AllowPrivateIPs: true,
		DialTimeout:     50 * time.Millisecond,
	}
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	dialFn := pm.createDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Dial a non-existent port on a non-listening address
	// Using 192.0.2.1 (TEST-NET-1, RFC 5737) which should not be routable
	_, err = dialFn(ctx, "tcp", "192.0.2.1:1")
	if err == nil {
		// Connection may unexpectedly succeed in some environments
		t.Log("Connection did not fail — skipping failure metrics check")
		return
	}

	metrics := pm.GetMetrics()
	if metrics.RejectedConnections < 1 {
		t.Errorf("RejectedConnections = %d, want at least 1", metrics.RejectedConnections)
	}
}

// TestUpdateConnectionMetrics_InvalidType verifies the defensive nil check
// when LoadOrStore returns a value that is not *hostStats.
func TestUpdateConnectionMetrics_InvalidType(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	pm.hostConns.Store("bad-type.example.com", "not a hostStats")

	result := pm.updateConnectionMetrics("bad-type.example.com", 100, true)
	if result != nil {
		t.Errorf("expected nil result for invalid type, got %v", result)
	}
}

// TestUpdateConnectionMetrics_NilValue verifies the defensive nil check
// when LoadOrStore returns a nil *hostStats.
func TestUpdateConnectionMetrics_NilValue(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	var nilStats *hostStats = nil
	pm.hostConns.Store("nil-value.example.com", nilStats)

	result := pm.updateConnectionMetrics("nil-value.example.com", 100, true)
	if result != nil {
		t.Errorf("expected nil result for nil value, got %v", result)
	}
}

// TestClose_WithDoHResolver verifies that Close properly cleans up the DoH resolver.
func TestClose_WithDoHResolver(t *testing.T) {
	config := &Config{
		EnableDoH:       true,
		AllowPrivateIPs: true,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}

	if pm.dohResolver == nil {
		t.Fatal("DoH resolver should be initialized")
	}

	err = pm.Close()
	if err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

// TestCreateDialer_SSRFSuccessPath verifies that when SSRF protection is enabled
// and the target resolves to a public IP, the validated address is used.
func TestCreateDialer_SSRFSuccessPath(t *testing.T) {
	// Create a local listener
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()

	// Use AllowPrivateIPs=false but set up the address as a validated public IP
	// We test this by calling createDialer directly and using a public address
	config := &Config{
		AllowPrivateIPs: false,
		DialTimeout:     2 * time.Second,
		KeepAlive:       30 * time.Second,
	}
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	dialFn := pm.createDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Dial 8.8.8.8:443 — public IP, SSRF should allow
	conn, dialErr := dialFn(ctx, "tcp", "8.8.8.8:443")
	if dialErr != nil {
		// Network may be unavailable — this test is best-effort
		t.Logf("Could not connect to 8.8.8.8:443 (network may be restricted): %v", dialErr)
		return
	}
	defer func() { _ = conn.Close() }()

	// Verify it's a tracked connection
	if _, ok := conn.(*trackedConn); !ok {
		t.Error("expected trackedConn wrapper")
	}
}

// TestGetMetrics_HitRateCalculation verifies that the connection hit rate is
// correctly calculated from total and rejected connection counts.
func TestGetMetrics_HitRateCalculation(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Initially, hit rate should be 0 (no connections)
	m := pm.GetMetrics()
	if m.ConnectionHitRate != 0 {
		t.Errorf("initial hit rate = %f, want 0", m.ConnectionHitRate)
	}

	// Set some values to test hit rate calculation
	atomic.StoreInt64(&pm.totalConns, 80)
	atomic.StoreInt64(&pm.rejectedConns, 20)

	m = pm.GetMetrics()
	wantHitRate := float64(80) / float64(80+20) // 0.8
	if m.ConnectionHitRate != wantHitRate {
		t.Errorf("hit rate = %f, want %f", m.ConnectionHitRate, wantHitRate)
	}
}

// TestGetMetrics_ActiveConnections verifies active connection tracking
// through the metrics interface.
func TestGetMetrics_ActiveConnections(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	atomic.StoreInt64(&pm.activeConns, 42)

	m := pm.GetMetrics()
	if m.ActiveConnections != 42 {
		t.Errorf("ActiveConnections = %d, want 42", m.ActiveConnections)
	}

	if m.LastUpdate == 0 {
		t.Error("LastUpdate should be non-zero")
	}
}

// TestCreateDialer_DoHPath exercises the DoH resolver path in createDialer
// by enabling DoH and making an HTTP request to a local test server.
func TestCreateDialer_DoHPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DoH integration test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.AllowPrivateIPs = true
	config.EnableDoH = true

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	if pm.dohResolver == nil {
		t.Skip("DoH resolver not available")
	}

	client := &http.Client{
		Transport: pm.GetTransport(),
		Timeout:   10 * time.Second,
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		// DoH resolution may fail in restricted networks
		t.Logf("DoH path request failed (expected in restricted networks): %v", err)
		return
	}
	_ = resp.Body.Close()

	metrics := pm.GetMetrics()
	t.Logf("DoH path metrics: Total=%d, Active=%d, Rejected=%d, HitRate=%.2f",
		metrics.TotalConnections, metrics.ActiveConnections,
		metrics.RejectedConnections, metrics.ConnectionHitRate)
}

// TestCreateDialer_DoHPath_SSRFBlock verifies that the DoH path blocks
// connections to private IPs when SSRF protection is enabled.
func TestCreateDialer_DoHPath_SSRFBlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DoH integration test in short mode")
	}

	config := DefaultConfig()
	config.AllowPrivateIPs = false
	config.EnableDoH = true

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	if pm.dohResolver == nil {
		t.Skip("DoH resolver not available")
	}

	dialFn := pm.createDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// This will go through the DoH path and should block private IPs
	_, err = dialFn(ctx, "tcp", "127.0.0.1:8080")
	if err == nil {
		t.Error("expected SSRF block for private IP through DoH path")
	} else {
		t.Logf("DoH SSRF block: %v", err)
	}
}
