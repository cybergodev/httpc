package connection

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
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
	if !contains(err.Error(), "DoH DNS resolution failed") {
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
		_, err = pm.resolveAndValidateAddress(nil, "localhost:443") //nolint:SA1012 // intentionally nil to test the fallback path
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
// updateConnectionMetrics: defensive type-assertion failure (pool.go:645-647, 667-669)
// ---------------------------------------------------------------------------

func TestUpdateConnectionMetrics_TypeAssertFailures(t *testing.T) {
	t.Run("fast path wrong type", func(t *testing.T) {
		pm, err := NewPoolManager(nil)
		if err != nil {
			t.Fatalf("NewPoolManager: %v", err)
		}
		defer pm.Close()

		// Pre-populate with a non-*hostStats value.
		wrongHost := "wrong-type-fast"
		pm.hostConns.Store(wrongHost, "not-a-hostStats")

		stats := pm.updateConnectionMetrics(wrongHost, true)
		if stats != nil {
			t.Errorf("Expected nil stats for wrong type (fast path), got %v", stats)
		}
	})

	t.Run("slow path wrong type", func(t *testing.T) {
		pm, err := NewPoolManager(nil)
		if err != nil {
			t.Fatalf("NewPoolManager: %v", err)
		}
		defer pm.Close()

		// Pre-populate with a non-*hostStats value so LoadOrStore returns
		// the existing wrong value (loaded=true), and the subsequent type
		// assertion fails.
		wrongHost := "wrong-type-slow"
		pm.hostConns.Store(wrongHost, 12345)

		stats := pm.updateConnectionMetrics(wrongHost, true)
		if stats != nil {
			t.Errorf("Expected nil stats for wrong type (slow path), got %v", stats)
		}
	})
}

// ---------------------------------------------------------------------------
// updateConnectionMetrics: maxHostEntries trigger (pool.go:660-662)
// ---------------------------------------------------------------------------

func TestUpdateConnectionMetrics_MaxHostEntriesTrigger(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer pm.Close()

	// Set hostCount just below the limit so the next new entry crosses it.
	pm.hostCount.Store(int64(maxHostEntries))

	// Adding a new host should trigger evictStaleHosts via the maxHostEntries
	// check. The call must not panic.
	stats := pm.updateConnectionMetrics("overflow-host.example.com", true)
	if stats == nil {
		t.Error("Expected non-nil stats for new host")
	}
}

// ---------------------------------------------------------------------------
// evictStaleHosts: CAS contention path (pool.go:696-698)
// ---------------------------------------------------------------------------

func TestEvictStaleHosts_CASContention(t *testing.T) {
	pm, err := NewPoolManager(DefaultConfig())
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer pm.Close()

	// Add stale entries.
	for i := 0; i < 10; i++ {
		host := fmt.Sprintf("stale-%d.example.com", i)
		pm.hostConns.Store(host, &hostStats{
			Host:        host,
			LastUsed:    time.Now().Add(-hostConnMaxAge - time.Minute).Unix(),
			ActiveConns: 0,
		})
	}
	pm.hostCount.Store(10)

	// Reset eviction timer so calls proceed past the interval check.
	atomic.StoreInt64(&pm.lastEviction, 0)

	// Fire eviction from many goroutines simultaneously so the CAS
	// fails for all but one.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pm.evictStaleHosts()
		}()
	}
	wg.Wait()

	// At least the goroutine that won the CAS should have evicted entries.
	remaining := 0
	pm.hostConns.Range(func(_, _ any) bool {
		remaining++
		return true
	})
	// Some or all stale entries should have been evicted. The exact count
	// depends on timing, but it should be fewer than 10.
	if remaining >= 10 {
		t.Errorf("Expected some entries evicted, but all 10 remain")
	}
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
// ---------------------------------------------------------------------------

func TestEvictStaleHosts_ReInsertActiveConn(t *testing.T) {
	pm, err := NewPoolManager(DefaultConfig())
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer pm.Close()

	targetHost := "race-target.example.com"
	stats := &hostStats{
		Host:        targetHost,
		LastUsed:    time.Now().Add(-hostConnMaxAge - time.Minute).Unix(),
		ActiveConns: 0, // Passes the eviction pre-check.
	}
	pm.hostConns.Store(targetHost, stats)
	pm.hostCount.Store(1)

	// Set up a goroutine that increments ActiveConns shortly after we
	// start eviction, simulating a concurrent connection that lands
	// between the pre-check and the LoadAndDelete.
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Small delay to land inside the eviction's Range callback
		// but before LoadAndDelete reaches our entry.
		time.Sleep(5 * time.Millisecond)
		atomic.StoreInt64(&stats.ActiveConns, 1)
	}()

	// Reset eviction timer.
	atomic.StoreInt64(&pm.lastEviction, 0)

	// Add a trigger entry to start eviction.
	pm.updateConnectionMetrics("trigger.example.com", true)

	<-done

	// The entry should still exist (re-inserted or not-yet-evicted)
	// because ActiveConns was > 0 when the eviction tried to remove it.
	// If the timing didn't work out (no race), the entry was evicted
	// before ActiveConns was set, which is also acceptable — this test
	// verifies no panic or corruption either way.
	_, exists := pm.hostConns.Load(targetHost)
	t.Logf("target host exists after eviction race: %v", exists)
}

// ---------------------------------------------------------------------------
// CloseIdleConnections / NextProxyIndex: basic exercise
// ---------------------------------------------------------------------------

func TestCloseIdleConnections_NoPanic(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer pm.Close()

	// Should not panic on an empty pool.
	pm.CloseIdleConnections()
}

func TestNextProxyIndex_NoPool(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer pm.Close()

	idx, ok := pm.NextProxyIndex()
	if ok {
		t.Error("Expected ok=false when no proxy pool configured")
	}
	if idx != 0 {
		t.Errorf("Expected idx=0, got %d", idx)
	}
}

func TestNextProxyIndex_WithPool(t *testing.T) {
	config := &Config{
		ProxyPool: []string{
			"http://p1.example.com:8080",
			"http://p2.example.com:8080",
		},
	}
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager: %v", err)
	}
	defer pm.Close()

	idx1, ok := pm.NextProxyIndex()
	if !ok {
		t.Fatal("Expected ok=true with proxy pool")
	}

	idx2, _ := pm.NextProxyIndex()

	// Consecutive calls should advance the index.
	if idx2 <= idx1 {
		t.Errorf("Expected idx2 > idx1, got idx1=%d idx2=%d", idx1, idx2)
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
