package connection

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cybergodev/httpc/internal/proxypool"
)

// ============================================================================
// Coverage-targeted tests for internal/connection/pool.go
//
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
	defer pm.Close()

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
	defer pm.Close()

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
	defer pm.Close()

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
	defer pm.Close()

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
	defer pm.Close()

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
	defer pm.Close()

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
	defer pm.Close()

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
		defer pm.Close()

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
		defer pm.Close()

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
		defer pm.Close()

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
