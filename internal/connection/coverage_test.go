package connection

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybergodev/httpc/internal/proxypool"
)

// TestTrackedConn_Lifecycle verifies that trackedConn properly tracks
// active connection counts on creation, decrement on Close, and handles
// double-close without double-decrementing.
func TestTrackedConn_Lifecycle(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Simulate the state that createDialer sets up: active gauge at zero.
	pm.activeConns.Store(0)

	// Simulate what createDialer does: increment pool active conns
	pm.activeConns.Add(1)

	// Create a trackedConn wrapping a fake connection
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()

	tc := &trackedConn{
		Conn: client,
		pm:   pm,
	}

	// Verify active count before close
	if got := pm.activeConns.Load(); got != 1 {
		t.Errorf("pool activeConns before close = %d, want 1", got)
	}

	// Close the tracked connection
	err = tc.Close()
	if err != nil {
		t.Errorf("Close() error: %v", err)
	}

	// Verify active count decremented
	if got := pm.activeConns.Load(); got != 0 {
		t.Errorf("pool activeConns after close = %d, want 0", got)
	}

	// Double close should not double-decrement
	err = tc.Close()
	if err != nil {
		t.Errorf("Second Close() error: %v", err)
	}

	if got := pm.activeConns.Load(); got != 0 {
		t.Errorf("pool activeConns after double close = %d, want 0 (no double-decrement)", got)
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

	pm.activeConns.Add(1)

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()

	tc := &trackedConn{
		Conn: client,
		pm:   pm,
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
	if got := pm.activeConns.Load(); got != 0 {
		t.Errorf("pool activeConns after concurrent close = %d, want 0", got)
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

// TestCreateTLSConfig_Custom and TestCreateTLSConfig_NoCustom were removed:
// their assertions (custom MinVersion/InsecureSkipVerify preserved;
// VerifyPeerCertificate nil without a pinner) match the "Custom TLS config"
// and "WithoutCertPinner" checks — see TestPoolManager_TLSConfig (pool_test.go)
// and the removed-subtest note in that file. The invoked-callback matrix
// survives in TestCreateVerifyPeerCertificate below.

// TestCreateVerifyPeerCertificate verifies the certificate verification
// callback across pinner success, pinner failure, and InsecureSkipVerify paths.
func TestCreateVerifyPeerCertificate(t *testing.T) {
	tests := []struct {
		name               string
		shouldFail         bool
		insecureSkipVerify bool
		wantErr            bool
	}{
		{"pinner accepts certificate", false, false, false},
		{"pinner rejects certificate", true, false, true},
		{"InsecureSkipVerify with accepting pinner", false, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				certPinner: &mockCertPinner{shouldFail: tt.shouldFail},
			}
			if tt.insecureSkipVerify {
				config.TLSConfig = &tls.Config{InsecureSkipVerify: true}
			}

			pm, err := NewPoolManager(config)
			if err != nil {
				t.Fatalf("NewPoolManager() error: %v", err)
			}
			defer func() { _ = pm.Close() }()

			verifyFn := pm.transport.TLSClientConfig.VerifyPeerCertificate
			if verifyFn == nil {
				t.Fatal("VerifyPeerCertificate should not be nil")
			}

			err = verifyFn(nil, nil)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			} else if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
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
	if got := pm.activeConns.Load(); got != 1 {
		t.Errorf("activeConns = %d, want 1", got)
	}

	// Close the tracked connection
	_ = tc.Close()

	if got := pm.activeConns.Load(); got != 0 {
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
		// IPv6 boundaries (IP literals — no DNS/network needed)
		{
			name:    "Public IPv6 with port",
			address: "[2001:4860:4860::8888]:443",
			wantErr: false,
		},
		{
			name:    "IPv6 loopback",
			address: "[::1]:8080",
			wantErr: true,
		},
		{
			name:    "IPv4-mapped IPv6 loopback",
			address: "[::ffff:127.0.0.1]:8080",
			wantErr: true,
		},
		{
			name:    "Private IP without port",
			address: "127.0.0.1",
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
					results, resolveErr := pm.resolveAndValidateAddress(context.Background(), domain)
					if resolveErr == nil {
						if len(results) == 0 {
							t.Fatalf("expected at least one validated address for %s", domain)
						}
						host, port, splitErr := net.SplitHostPort(results[0])
						if splitErr != nil {
							t.Fatalf("result %q is not a valid host:port: %v", results[0], splitErr)
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

			result, err := pm.resolveAndValidateAddress(context.Background(), tt.address)

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

			if tt.want != "" && (len(result) == 0 || result[0] != tt.want) {
				t.Errorf("result = %v, want first candidate %q", result, tt.want)
			}
		})
	}
}

// The full dialer path through a live HTTP request (SSRF validation,
// connection tracking, metric updates) is asserted by
// TestPoolManager_ConnectionMetrics in pool_test.go — no duplicate here.

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

// TestClose_WithDoHResolver verifies that Close properly cleans up the DoH resolver.
// TestClose_WithDoHResolver and TestCreateDialer_SSRFSuccessPath were removed:
// - Close-with-DoH is covered by TestPoolManager_CloseWithDoHResolver
//   (pool_coverage_test.go), which also varies DoHCacheTTL.
// - The SSRF success path dialed the real host 8.8.8.8:443 and silently
//   passed offline; the local public-IP dial path is covered by
//   TestCreateDialer_AllowPrivateIPs and the ProxyAddr tests.

// TestGetMetrics_HitRateCalculation and TestGetMetrics_ActiveConnections were
// folded into TestPoolManager_GetMetrics (pool_test.go) as subtests, next to
// the zero-state assertions of the same interface.

// TestCreateDialer_DoHPath was removed: it issued a request through the DoH
// resolver but only logged the resulting metrics (no assertion) and silently
// returned on network failure. The DoH dialer path with real assertions lives
// in TestCreateDialer_DoHResolutionFailure (pool_coverage_test.go) and
// TestCreateDialer_DoHPath_SSRFBlock below.

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

// Each test targets specific uncovered code paths identified by
// `go test -coverprofile`. Tests are organized by the function they cover.
// ============================================================================

// ---------------------------------------------------------------------------
// createDialer: pool exhaustion path (pool.go:341-345)
// ---------------------------------------------------------------------------

func TestCreateDialer_PoolExhaustion(t *testing.T) {
	// TCP listener that accepts and holds a connection so the first dial
	// stays open and occupies a pool slot.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	config := &Config{
		MaxTotalConns:   1,
		AllowPrivateIPs: true,
		DialTimeout:     5 * time.Second,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer func() { _ = pm.Close() }()

	dialer := pm.createDialer()

	// First connection succeeds and occupies the single slot.
	conn1, err := dialer(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("First dial failed: %v", err)
	}
	defer func() { _ = conn1.Close() }()

	// Accept on the server side so the connection completes.
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	// Second dial should be rejected: MaxTotalConns exceeded.
	_, err = dialer(context.Background(), "tcp", addr)
	if err == nil {
		t.Fatal("Expected ErrPoolExhausted, got nil")
	}
	if !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("Expected ErrPoolExhausted, got: %v", err)
	}

	// Verify rejected-connections counter was incremented.
	metrics := pm.GetMetrics()
	if metrics.RejectedConnections < 1 {
		t.Errorf("Expected RejectedConnections >= 1, got %d", metrics.RejectedConnections)
	}
}

// ---------------------------------------------------------------------------
// createDialer: proxy address bypass — success path (pool.go:349-373)
// ---------------------------------------------------------------------------

func TestCreateDialer_ProxyAddr_Success(t *testing.T) {
	// Stand up a raw TCP listener to represent a proxy server.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	proxyAddr := listener.Addr().String()

	config := &Config{
		ProxyURL:    "http://" + proxyAddr,
		DialTimeout: 5 * time.Second,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer func() { _ = pm.Close() }()

	if !pm.isProxyAddr(proxyAddr) {
		t.Fatalf("proxyAddr %q not registered in proxyAddrs", proxyAddr)
	}

	dialer := pm.createDialer()

	// Dial the proxy address — should bypass SSRF and succeed.
	conn, err := dialer(context.Background(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial to proxy address failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Accept on the listener side to complete the handshake.
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	// Verify active connection counter increased.
	metrics := pm.GetMetrics()
	if metrics.ActiveConnections < 1 {
		t.Errorf("Expected ActiveConnections >= 1, got %d", metrics.ActiveConnections)
	}
}

// ---------------------------------------------------------------------------
// createDialer: proxy address bypass — failure path (pool.go:353-361)
// ---------------------------------------------------------------------------

func TestCreateDialer_ProxyAddr_Failure(t *testing.T) {
	// Use a port that is virtually guaranteed to be closed.
	config := &Config{
		ProxyURL:    "http://127.0.0.1:1",
		DialTimeout: 500 * time.Millisecond,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer func() { _ = pm.Close() }()

	dialer := pm.createDialer()

	_, err = dialer(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("Expected error connecting to dead proxy")
	}
	if !errors.Is(err, ErrProxyConnectionFailed) {
		t.Errorf("Expected ErrProxyConnectionFailed, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// createDialer: proxy pool address — failure with reporting (pool.go:354-355)
// ---------------------------------------------------------------------------

func TestCreateDialer_ProxyPool_FailureReporting(t *testing.T) {
	config := &Config{
		ProxyPool: []string{
			"http://127.0.0.1:1", // dead proxy
		},
		ProxyFailureThreshold: 2,
		ProxyCooldown:         30 * time.Second,
		DialTimeout:           500 * time.Millisecond,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer func() { _ = pm.Close() }()

	dialer := pm.createDialer()

	_, err = dialer(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("Expected proxy connection failure")
	}
	if !errors.Is(err, ErrProxyConnectionFailed) {
		t.Errorf("Expected ErrProxyConnectionFailed, got: %v", err)
	}

	// Verify the proxy pool recorded the failure.
	// After ProxyFailureThreshold consecutive failures the proxy should
	// be circuit-broken. With threshold=2, one failure is not enough,
	// but the failure count should be > 0.
	metrics := pm.GetMetrics()
	if metrics.RejectedConnections < 1 {
		t.Errorf("Expected RejectedConnections >= 1, got %d", metrics.RejectedConnections)
	}
}

// ---------------------------------------------------------------------------
// createDialer: proxy pool address — success with reporting (pool.go:364-373)
// ---------------------------------------------------------------------------

func TestCreateDialer_ProxyPool_SuccessReporting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	proxyAddr := listener.Addr().String()

	config := &Config{
		ProxyPool: []string{
			"http://" + proxyAddr,
		},
		DialTimeout: 5 * time.Second,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer func() { _ = pm.Close() }()

	if !pm.isProxyAddr(proxyAddr) {
		t.Fatalf("proxyAddr %q not in proxyAddrs", proxyAddr)
	}

	dialer := pm.createDialer()

	conn, err := dialer(context.Background(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial to proxy pool address failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	metrics := pm.GetMetrics()
	if metrics.ActiveConnections < 1 {
		t.Errorf("Expected ActiveConnections >= 1, got %d", metrics.ActiveConnections)
	}
}

// ---------------------------------------------------------------------------
// createDialer: DoH resolution failure (pool.go:393-399)
// ---------------------------------------------------------------------------

func TestCreateDialer_DoHResolutionFailure(t *testing.T) {
	config := &Config{
		EnableDoH:       true,
		AllowPrivateIPs: false,
		DialTimeout:     5 * time.Second,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Close the DoH resolver so LookupIPAddr returns an error immediately.
	if err := pm.dohResolver.Close(); err != nil {
		t.Fatalf("DoH resolver close: %v", err)
	}

	dialer := pm.createDialer()

	_, err = dialer(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("Expected error from closed DoH resolver")
	}
	if !strings.Contains(err.Error(), "DoH DNS resolution failed") {
		t.Errorf("Expected DoH resolution failure, got: %v", err)
	}

	metrics := pm.GetMetrics()
	if metrics.RejectedConnections < 1 {
		t.Errorf("Expected RejectedConnections >= 1, got %d", metrics.RejectedConnections)
	}
}

// ---------------------------------------------------------------------------
// transport.Proxy: SelectIndex path via context (pool.go:275-280)
// ---------------------------------------------------------------------------

func TestProxyPool_TransportProxy_SelectIndex(t *testing.T) {
	config := &Config{
		ProxyPool: []string{
			"http://proxy0.example.com:8080",
			"http://proxy1.example.com:8080",
			"http://proxy2.example.com:8080",
		},
		ProxyPoolStrategy: proxypool.StrategyRoundRobin,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer func() { _ = pm.Close() }()

	transport := pm.GetTransport()
	if transport.Proxy == nil {
		t.Fatal("transport.Proxy should be set for proxy pool")
	}

	// Without ProxyAttempt on context → normal round-robin Select.
	reqNormal := &http.Request{
		URL: &url.URL{Scheme: "https", Host: "example.com"},
	}
	got, err := transport.Proxy(reqNormal.WithContext(context.Background()))
	if err != nil {
		t.Fatalf("Proxy() error: %v", err)
	}
	if got == nil {
		t.Fatal("Proxy() returned nil for normal request")
	}

	// With ProxyAttempt=1 on context → SelectIndex(1) should return proxy at index 1.
	reqWithAttempt := &http.Request{
		URL: &url.URL{Scheme: "https", Host: "example.com"},
	}
	ctx := WithProxyAttempt(context.Background(), 1)
	got, err = transport.Proxy(reqWithAttempt.WithContext(ctx))
	if err != nil {
		t.Fatalf("Proxy() with attempt error: %v", err)
	}
	if got.Host != "proxy1.example.com:8080" {
		t.Errorf("SelectIndex(1) returned %s, want proxy1.example.com:8080", got.Host)
	}

	// With ProxyAttempt=2 → SelectIndex(2).
	reqWithAttempt2 := &http.Request{
		URL: &url.URL{Scheme: "https", Host: "example.com"},
	}
	ctx2 := WithProxyAttempt(context.Background(), 2)
	got, err = transport.Proxy(reqWithAttempt2.WithContext(ctx2))
	if err != nil {
		t.Fatalf("Proxy() with attempt=2 error: %v", err)
	}
	if got.Host != "proxy2.example.com:8080" {
		t.Errorf("SelectIndex(2) returned %s, want proxy2.example.com:8080", got.Host)
	}
}

// ---------------------------------------------------------------------------
// resolveAndValidateAddress: DialTimeout < dnsTimeout branch, nil context,
// and domain-resolves-to-blocked (pool.go:510-515, 530-532)
// ---------------------------------------------------------------------------

func TestResolveAndValidateAddress_CoverageGaps(t *testing.T) {
	t.Run("DialTimeout shorter than DNS timeout", func(t *testing.T) {
		// DialTimeout=3s < dnsTimeout=10s → exercises the branch that
		// derives the DNS timeout from DialTimeout.
		config := DefaultConfig()
		config.DialTimeout = 3 * time.Second
		pm, err := NewPoolManager(config)
		if err != nil {
			t.Fatalf("NewPoolManager: %v", err)
		}
		defer func() { _ = pm.Close() }()

		// "localhost" resolves to 127.0.0.1 (loopback) → FilterAllowedIPs
		// returns empty → exercises the blocked-domain error path.
		_, err = pm.resolveAndValidateAddress(context.Background(), "localhost:443")
		if err == nil {
			t.Error("Expected error for localhost (blocked IP)")
		}
	})

	t.Run("nil context fallback", func(t *testing.T) {
		pm, err := NewPoolManager(nil)
		if err != nil {
			t.Fatalf("NewPoolManager: %v", err)
		}
		defer func() { _ = pm.Close() }()

		// Passing nil context must not panic; it falls back to context.Background().
		_, err = pm.resolveAndValidateAddress(nil, "localhost:443") //nolint:staticcheck // intentionally nil to test the fallback path
		if err == nil {
			t.Error("Expected error for localhost with nil context")
		}
	})

	t.Run("SplitHostPort failure fallback port", func(t *testing.T) {
		pm, err := NewPoolManager(nil)
		if err != nil {
			t.Fatalf("NewPoolManager: %v", err)
		}
		defer func() { _ = pm.Close() }()

		// Address without port → SplitHostPort fails → port defaults to "443".
		_, err = pm.resolveAndValidateAddress(context.Background(), "localhost")
		if err == nil {
			t.Error("Expected error for localhost without port")
		}
	})
}

// ---------------------------------------------------------------------------
// PoolManager.Close: DoH resolver close path (pool.go:787-791)
// ---------------------------------------------------------------------------

func TestPoolManager_CloseWithDoHResolver(t *testing.T) {
	config := &Config{
		EnableDoH:   true,
		DoHCacheTTL: 1 * time.Minute,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}

	if pm.dohResolver == nil {
		t.Fatal("DoH resolver should be initialized")
	}

	// Close should exercise the DoH resolver close path without error.
	if err := pm.Close(); err != nil {
		t.Errorf("Close with DoH resolver returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// trackedConn: Close after pool is closed (pool.go:621-630)
// ---------------------------------------------------------------------------

func TestTrackedConn_CloseAfterPoolClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	config := &Config{
		AllowPrivateIPs: true,
		DialTimeout:     5 * time.Second,
	}

	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}

	dialer := pm.createDialer()

	conn, err := dialer(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	// Close the pool while a connection is still active.
	// trackedConn.Close() must skip counter decrements when pool is closed.
	_ = pm.Close()

	// Closing the tracked connection after pool close must not panic
	// and must not drive counters negative.
	if err := conn.Close(); err != nil {
		t.Errorf("Close after pool close returned error: %v", err)
	}

	metrics := pm.GetMetrics()
	// Counters were reset by Close(); they must not be negative.
	if metrics.ActiveConnections < 0 {
		t.Errorf("ActiveConnections should not be negative, got %d", metrics.ActiveConnections)
	}
	if metrics.TotalConnections < 0 {
		t.Errorf("TotalConnections should not be negative, got %d", metrics.TotalConnections)
	}
}

// ---------------------------------------------------------------------------
// evictStaleHosts: re-insert when ActiveConns increments during eviction
// (pool.go:709-718)
//
// This tests the TOCTOU window where an entry passes the ActiveConns==0
// check but has ActiveConns>0 by the time LoadAndDelete returns. We
// simulate this by directly invoking eviction with a carefully crafted
// entry whose ActiveConns we bump at the right moment.
// TestEvictStaleHosts_ReInsertActiveConn, TestCloseIdleConnections_NoPanic,
// TestNextProxyIndex_NoPool, and TestNextProxyIndex_WithPool were removed:
// - The eviction race test only logged its outcome (could never fail);
//   eviction correctness is asserted by TestEvictStaleHosts_CASContention.
// - CloseIdleConnections/NextProxyIndex no-pool and advance/wrap behavior
//   is covered (stronger, incl. after-Close and modulo wrap) in
//   proxy_context_test.go.
