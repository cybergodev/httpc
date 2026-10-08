package proxypool

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestNew_EmptyPool(t *testing.T) {
	if _, err := New(Config{}); err != ErrNoProxies {
		t.Errorf("New() with no proxies: got err=%v, want %v", err, ErrNoProxies)
	}
}

func TestNew_InvalidProxyURL(t *testing.T) {
	tests := []struct {
		name  string
		proxy string
	}{
		{"missing scheme", "proxy.example.com:8080"},
		{"unsupported scheme", "ftp://proxy.example.com:8080"},
		{"missing host", "http://"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Config{Proxies: []string{tt.proxy, "http://valid.example.com:8080"}})
			if err == nil {
				t.Errorf("New() with invalid proxy %q: expected error, got nil", tt.proxy)
			}
		})
	}
}

func TestNew_ValidSchemes(t *testing.T) {
	proxies := []string{
		"http://proxy.example.com:8080",
		"https://proxy.example.com:8443",
		"socks5://proxy.example.com:1080",
		"socks5h://proxy.example.com:1081",
	}
	pool, err := New(Config{Proxies: proxies})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if pool.Len() != 4 {
		t.Errorf("Len() = %d, want 4", pool.Len())
	}
}

func TestNew_DeduplicatesByHost(t *testing.T) {
	proxies := []string{
		"http://127.0.0.1:8080",
		"http://user:pass@127.0.0.1:8080", // same host:port, different creds
		"http://127.0.0.1:8081",           // different port
	}
	pool, err := New(Config{Proxies: proxies})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if pool.Len() != 2 {
		t.Errorf("Len() = %d, want 2 (duplicates collapsed)", pool.Len())
	}
}

func TestNew_AppliesDefaults(t *testing.T) {
	pool, err := New(Config{Proxies: []string{"http://proxy.example.com:8080"}})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if pool.failureThreshold != defaultFailureThreshold {
		t.Errorf("failureThreshold = %d, want %d", pool.failureThreshold, defaultFailureThreshold)
	}
	if pool.cooldown != defaultCooldown {
		t.Errorf("cooldown = %v, want %v", pool.cooldown, defaultCooldown)
	}
	if pool.strategy != StrategyRoundRobin {
		t.Errorf("strategy = %d, want %d (zero value default)", pool.strategy, StrategyRoundRobin)
	}
}

func TestSelect_RoundRobin(t *testing.T) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
		"http://proxy3.example.com:8080",
	}
	pool, err := New(Config{Proxies: proxies})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	expected := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
		"http://proxy3.example.com:8080",
		"http://proxy1.example.com:8080", // wraps around
	}

	for i, want := range expected {
		got, err := pool.Select(nil)
		if err != nil {
			t.Fatalf("Select() error: %v", err)
		}
		if got.String() != want {
			t.Errorf("Select() call %d: got %s, want %s", i, got.String(), want)
		}
	}
}

func TestSelect_SkipsCircuitOpen(t *testing.T) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
	}
	pool, err := New(Config{
		Proxies:          proxies,
		FailureThreshold: 1, // open on first failure for easy testing
		Cooldown:         10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Force proxy1's circuit open
	pool.ReportFailure("proxy1.example.com:8080")

	// All selects should skip proxy1 and return proxy2
	for i := 0; i < 5; i++ {
		got, err := pool.Select(nil)
		if err != nil {
			t.Fatalf("Select() error: %v", err)
		}
		if got.Host == "proxy1.example.com:8080" {
			t.Errorf("Select() returned circuit-open proxy1 on call %d", i)
		}
		if got.Host != "proxy2.example.com:8080" {
			t.Errorf("Select() call %d: got host %s, want proxy2.example.com:8080", i, got.Host)
		}
	}
}

func TestSelect_AllOpenReturnsClosestToRecovery(t *testing.T) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
	}
	pool, err := New(Config{
		Proxies:          proxies,
		FailureThreshold: 1,
		Cooldown:         10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Open both circuits
	pool.ReportFailure("proxy1.example.com:8080")
	time.Sleep(5 * time.Millisecond)
	pool.ReportFailure("proxy2.example.com:8080")

	// proxy1 opened earlier → its openUntil is smaller → closest to recovery
	got, err := pool.Select(nil)
	if err != nil {
		t.Fatalf("Select() error: %v", err)
	}
	if got.Host != "proxy1.example.com:8080" {
		t.Errorf("Select() with all open: got %s, want proxy1 (earliest open)", got.Host)
	}
}

func TestReportSuccess_ResetsCircuit(t *testing.T) {
	pool, err := New(Config{
		Proxies:          []string{"http://proxy1.example.com:8080"},
		FailureThreshold: 1,
		Cooldown:         10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Trip the breaker, then report success and verify it resets.
	pool.ReportFailure("proxy1.example.com:8080")
	pool.ReportSuccess("proxy1.example.com:8080")

	// Verify openUntil was reset
	e := pool.byHost["proxy1.example.com:8080"]
	if ou := e.openUntil.Load(); ou != 0 {
		t.Errorf("after ReportSuccess, openUntil = %d, want 0", ou)
	}
	if f := e.failures.Load(); f != 0 {
		t.Errorf("after ReportSuccess, failures = %d, want 0", f)
	}
}

func TestReportFailure_ThresholdNotReached(t *testing.T) {
	pool, err := New(Config{
		Proxies:          []string{"http://proxy1.example.com:8080", "http://proxy2.example.com:8080"},
		FailureThreshold: 3,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Two failures below threshold — circuit should stay closed
	pool.ReportFailure("proxy1.example.com:8080")
	pool.ReportFailure("proxy1.example.com:8080")

	e := pool.byHost["proxy1.example.com:8080"]
	if ou := e.openUntil.Load(); ou != 0 {
		t.Errorf("below threshold: openUntil = %d, want 0 (closed)", ou)
	}
	if f := e.failures.Load(); f != 2 {
		t.Errorf("failures = %d, want 2", f)
	}
}

func TestReportFailure_UnknownHost(t *testing.T) {
	pool, err := New(Config{Proxies: []string{"http://proxy1.example.com:8080"}})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Should be a no-op, not panic
	pool.ReportFailure("unknown.example.com:9999")
	pool.ReportSuccess("unknown.example.com:9999")
}

func TestCircuitBreak_HalfOpenRecovery(t *testing.T) {
	pool, err := New(Config{
		Proxies:          []string{"http://proxy1.example.com:8080", "http://proxy2.example.com:8080"},
		FailureThreshold: 1,
		Cooldown:         50 * time.Millisecond, // short for testing
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Open proxy1's circuit
	pool.ReportFailure("proxy1.example.com:8080")

	// Immediately: proxy1 is skipped
	got, _ := pool.Select(nil)
	if got.Host == "proxy1.example.com:8080" {
		t.Error("proxy1 should be skipped while circuit open")
	}

	// Wait for cooldown to expire
	time.Sleep(70 * time.Millisecond)

	// Now proxy1 is eligible again (half-open)
	// Under round-robin, eventually proxy1 will be selected
	found := false
	for i := 0; i < 10; i++ {
		got, _ := pool.Select(nil)
		if got.Host == "proxy1.example.com:8080" {
			found = true
			break
		}
	}
	if !found {
		t.Error("proxy1 should be selectable again after cooldown expired")
	}
}

func TestReportSuccess_BetweenFailuresResets(t *testing.T) {
	pool, err := New(Config{
		Proxies:          []string{"http://proxy1.example.com:8080"},
		FailureThreshold: 3,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Two failures, then a success resets the count
	pool.ReportFailure("proxy1.example.com:8080")
	pool.ReportFailure("proxy1.example.com:8080")
	pool.ReportSuccess("proxy1.example.com:8080")
	pool.ReportFailure("proxy1.example.com:8080")

	e := pool.byHost["proxy1.example.com:8080"]
	if f := e.failures.Load(); f != 1 {
		t.Errorf("failures = %d, want 1 (success reset count)", f)
	}
	if ou := e.openUntil.Load(); ou != 0 {
		t.Errorf("openUntil = %d, want 0 (circuit closed)", ou)
	}
}

func TestSelect_Random(t *testing.T) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
		"http://proxy3.example.com:8080",
	}
	pool, err := New(Config{Proxies: proxies, Strategy: StrategyRandom})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Over many selections, every proxy should appear at least once
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		got, err := pool.Select(nil)
		if err != nil {
			t.Fatalf("Select() error: %v", err)
		}
		seen[got.Host] = true
	}
	if len(seen) != 3 {
		t.Errorf("random selection visited %d distinct proxies, want 3 (got: %v)", len(seen), seen)
	}
}

func TestSelect_Random_AllOpenReturnsClosestToRecovery(t *testing.T) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
	}
	pool, err := New(Config{
		Proxies:          proxies,
		Strategy:         StrategyRandom,
		FailureThreshold: 1,
		Cooldown:         10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Open both circuits — proxy1 first (earlier open = closest to recovery).
	pool.ReportFailure("proxy1.example.com:8080")
	time.Sleep(5 * time.Millisecond)
	pool.ReportFailure("proxy2.example.com:8080")

	// With all circuits open, selectRandom falls back to the entry closest
	// to recovery (proxy1, whose openUntil is smaller).
	got, err := pool.Select(nil)
	if err != nil {
		t.Fatalf("Select() error: %v", err)
	}
	if got.Host != "proxy1.example.com:8080" {
		t.Errorf("Select() with all open: got %s, want proxy1 (earliest open)", got.Host)
	}
}

func TestHosts(t *testing.T) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
	}
	pool, err := New(Config{Proxies: proxies})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	hosts := pool.Hosts()
	if len(hosts) != 2 {
		t.Fatalf("Hosts() returned %d entries, want 2", len(hosts))
	}

	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	for _, want := range []string{"proxy1.example.com:8080", "proxy2.example.com:8080"} {
		if !hostSet[want] {
			t.Errorf("Hosts() missing %s", want)
		}
	}
}

func TestSelect_Concurrent(t *testing.T) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
		"http://proxy3.example.com:8080",
	}
	pool, err := New(Config{
		Proxies:          proxies,
		FailureThreshold: 2,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = pool.Select(&http.Request{})
			pool.ReportFailure("proxy1.example.com:8080")
			pool.ReportSuccess("proxy2.example.com:8080")
		}()
	}
	wg.Wait()
	// If we reach here without panicking or racing, the test passes.
	// Run with -race for full verification.
}

func TestNextIndex_RoundRobin(t *testing.T) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
		"http://proxy3.example.com:8080",
	}
	pool, err := New(Config{Proxies: proxies})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// NextIndex should return sequential indices: 0, 1, 2, 0, 1, ...
	for i := 0; i < 6; i++ {
		expected := i % 3
		got := pool.NextIndex()
		if got != expected {
			t.Errorf("NextIndex() call %d: got %d, want %d", i, got, expected)
		}
	}
}

func TestSelectIndex_Deterministic(t *testing.T) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
	}
	pool, err := New(Config{Proxies: proxies})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// SelectIndex with the same argument always returns the same proxy
	for attempt := 0; attempt < 4; attempt++ {
		expectedIdx := attempt % 2
		got := pool.SelectIndex(attempt)
		want := pool.entries[expectedIdx].url
		if got != want {
			t.Errorf("SelectIndex(%d): got %v, want %v", attempt, got, want)
		}
	}
}

func TestSelectIndex_DoesNotAdvanceCounter(t *testing.T) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
	}
	pool, err := New(Config{Proxies: proxies})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Calling SelectIndex should NOT advance the round-robin counter
	_ = pool.SelectIndex(0)
	_ = pool.SelectIndex(1)
	_ = pool.SelectIndex(0)

	// Next Select should still return entries[0] (counter at 0)
	got, _ := pool.Select(nil)
	if got.Host != "proxy1.example.com:8080" {
		t.Errorf("Select() after SelectIndex calls: got %s, want proxy1", got.Host)
	}
}

func TestSelectIndex_SkipsCircuitOpen(t *testing.T) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
	}
	pool, err := New(Config{Proxies: proxies, FailureThreshold: 1, Cooldown: time.Minute})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Open circuit on proxy1
	pool.ReportFailure("proxy1.example.com:8080")

	// SelectIndex(0) should skip proxy1 (circuit open) and return proxy2
	got := pool.SelectIndex(0)
	if got.Host != "proxy2.example.com:8080" {
		t.Errorf("SelectIndex(0) with proxy1 circuit open: got %s, want proxy2", got.Host)
	}
}

// TestSelectRandom_AlwaysFindsHealthyEntry verifies the random strategy
// returns the only healthy proxy whenever one exists. The previous bounded
// random probing missed it ~35% of the time (n=10, m=1) and fell back to a
// circuit-open entry.
func TestSelectRandom_AlwaysFindsHealthyEntry(t *testing.T) {
	const n = 10
	proxies := make([]string, 0, n)
	hosts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		proxies = append(proxies, fmt.Sprintf("http://proxy%d.example.com:8080", i))
		hosts = append(hosts, fmt.Sprintf("proxy%d.example.com:8080", i))
	}

	pool, err := New(Config{
		Proxies:          proxies,
		Strategy:         StrategyRandom,
		FailureThreshold: 1, // open on first failure for easy testing
		Cooldown:         10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Open circuits for every proxy except index 7.
	for i, host := range hosts {
		if i != 7 {
			pool.ReportFailure(host)
		}
	}

	for i := 0; i < 100; i++ {
		got, err := pool.Select(nil)
		if err != nil {
			t.Fatalf("Select() error: %v", err)
		}
		if got.Host != hosts[7] {
			t.Fatalf("iteration %d: Select() = %s, want the only healthy proxy %s", i, got.Host, hosts[7])
		}
	}
}

// TestSelectIndex_NegativeAttempt verifies the negative-modulo correction:
// a negative attempt (caller bug upstream of the API contract) must still map
// into the valid index range and return a configured proxy, never panic or
// index out of range.
func TestSelectIndex_NegativeAttempt(t *testing.T) {
	pool, err := New(Config{
		Proxies: []string{
			"http://proxy1.example.com:8080",
			"http://proxy2.example.com:8080",
			"http://proxy3.example.com:8080",
		},
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	byHost := map[string]bool{
		"http://proxy1.example.com:8080": true,
		"http://proxy2.example.com:8080": true,
		"http://proxy3.example.com:8080": true,
	}

	for _, attempt := range []int{-1, -2, -3, -4, -100} {
		got := pool.SelectIndex(attempt)
		if got == nil {
			t.Fatalf("SelectIndex(%d) = nil, want a configured proxy", attempt)
		}
		if !byHost[got.String()] {
			t.Errorf("SelectIndex(%d) = %s, not a configured proxy", attempt, got)
		}
	}
}

// TestPortlessProxyCanonicalKeys verifies that pool entries are keyed by the
// canonical dial address (default port appended) rather than the raw url.Host.
// net/http dials canonicalAddr (e.g. "socks5://p" → "p:1080"); before this
// normalization, ReportFailure with the dialed address never matched the
// portless key, so circuit breaking silently never fired for portless proxies.
func TestPortlessProxyCanonicalKeys(t *testing.T) {
	pool, err := New(Config{
		Proxies: []string{
			"http://http-proxy.example.com",
			"https://tls-proxy.example.com",
			"socks5://socks-proxy.example.com",
			"http://explicit.example.com:8080",
		},
		FailureThreshold: 1,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	want := map[string]bool{
		"http-proxy.example.com:80":    true,
		"tls-proxy.example.com:443":    true,
		"socks-proxy.example.com:1080": true,
		"explicit.example.com:8080":    true,
	}
	for _, h := range pool.Hosts() {
		if !want[h] {
			t.Errorf("unexpected host key %q (want one of the canonical forms)", h)
		}
		delete(want, h)
	}
	if len(want) > 0 {
		t.Errorf("missing canonical host keys: %v", want)
	}

	// Reporting with the address net/http actually dials must circuit-break
	// the portless socks proxy (threshold 1). Assert on the entry's internal
	// circuit state directly — selecting an index would trivially return the
	// earlier healthy http proxy regardless.
	pool.ReportFailure("socks-proxy.example.com:1080")
	e := pool.byHost["socks-proxy.example.com:1080"]
	if e == nil {
		t.Fatal("byHost missing canonical key socks-proxy.example.com:1080")
	}
	if ou := e.openUntil.Load(); ou == 0 {
		t.Error("portless socks proxy was not circuit-broken after canonical ReportFailure (openUntil = 0)")
	}
}
