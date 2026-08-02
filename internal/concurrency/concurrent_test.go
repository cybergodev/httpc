// Package concurrency_test provides concurrent safety tests for the httpc library.
// These tests verify thread-safety under high concurrency scenarios.
package concurrency_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybergodev/httpc"
	"github.com/cybergodev/httpc/internal/connection"
	"github.com/cybergodev/httpc/internal/dns"
	"github.com/cybergodev/httpc/internal/security"
	"github.com/cybergodev/httpc/internal/validation"
)

// TestConcurrentClientRequests tests concurrent requests using the same client.
func TestConcurrentClientRequests(t *testing.T) {
	// Create test server with mutex for thread safety
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, err := httpc.New(httpc.DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	const numGoroutines = 50
	const requestsPerGoroutine = 10

	var wg sync.WaitGroup
	var errors int64
	var success int64

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				result, err := client.Get(server.URL)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				if result.StatusCode() != 200 {
					atomic.AddInt64(&errors, 1)
					continue
				}
				atomic.AddInt64(&success, 1)
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Concurrent test completed: %d success, %d errors, %d server requests",
		atomic.LoadInt64(&success), atomic.LoadInt64(&errors), atomic.LoadInt64(&requestCount))
}

// TestConcurrentDomainClientSession tests concurrent session operations.
func TestConcurrentDomainClientSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back received cookies and headers
		cookies := r.Cookies()
		for _, c := range cookies {
			http.SetCookie(w, c)
		}
		w.Header().Set("X-Received", r.Header.Get("X-Session-Header"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dc, err := httpc.NewDomainDefault(server.URL)
	if err != nil {
		t.Fatalf("Failed to create domain client: %v", err)
	}
	defer dc.Close()

	const numGoroutines = 50
	const opsPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent header operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				// Set header
				headerKey := fmt.Sprintf("X-Session-Header-%d", id)
				headerValue := fmt.Sprintf("value-%d-%d", id, j)
				if err := dc.SetHeader(headerKey, headerValue); err != nil {
					t.Errorf("Failed to set header: %v", err)
					return
				}

				// Set cookie
				cookie := &http.Cookie{
					Name:  fmt.Sprintf("session-cookie-%d", id),
					Value: fmt.Sprintf("value-%d-%d", id, j),
				}
				if err := dc.SetCookie(cookie); err != nil {
					t.Errorf("Failed to set cookie: %v", err)
					return
				}

				// Read headers
				headers := dc.GetHeaders()
				if headers == nil {
					t.Errorf("GetHeaders returned nil")
					return
				}

				// Read cookies
				cookies := dc.GetCookies()
				_ = cookies // Just verify no panic

				// Delete header
				dc.DeleteHeader(headerKey)

				// Delete cookie
				dc.DeleteCookie(fmt.Sprintf("session-cookie-%d", id))
			}
		}(i)
	}

	wg.Wait()
}

// TestConcurrentSessionManager tests SessionManager under concurrent access.
func TestConcurrentSessionManager(t *testing.T) {
	sm, err := httpc.NewSessionManagerDefault()
	if err != nil {
		t.Fatalf("NewSessionManager error: %v", err)
	}

	const numGoroutines = 100
	const opsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent operations on SessionManager
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				// Set header
				if err := sm.SetHeader(fmt.Sprintf("X-Header-%d", id), fmt.Sprintf("value-%d", j)); err != nil {
					t.Errorf("SetHeader failed: %v", err)
					return
				}

				// Set cookie
				cookie := &http.Cookie{
					Name:  fmt.Sprintf("cookie-%d", id),
					Value: fmt.Sprintf("value-%d-%d", id, j),
				}
				if err := sm.SetCookie(cookie); err != nil {
					t.Errorf("SetCookie failed: %v", err)
					return
				}

				// Read operations
				_ = sm.GetHeaders()
				_ = sm.GetCookies()
				_ = sm.GetCookie(fmt.Sprintf("cookie-%d", id))

				// Delete operations
				sm.DeleteHeader(fmt.Sprintf("X-Header-%d", id))
				sm.DeleteCookie(fmt.Sprintf("cookie-%d", id))
			}
		}(i)
	}

	wg.Wait()

	// Verify final state is consistent
	headers := sm.GetHeaders()
	cookies := sm.GetCookies()

	t.Logf("Final state: %d headers, %d cookies", len(headers), len(cookies))
}

// TestConcurrentSessionManagerWithCookieSecurity tests concurrent SetCookie/SetCookieSecurity operations.
// This test verifies the fix for the TOCTOU race condition where cookieSecurity was accessed outside the lock.
func TestConcurrentSessionManagerWithCookieSecurity(t *testing.T) {
	// Create session manager without security first
	sm, err := httpc.NewSessionManagerDefault()
	if err != nil {
		t.Fatalf("NewSessionManager error: %v", err)
	}

	const numGoroutines = 50
	const opsPerGoroutine = 20

	var wg sync.WaitGroup
	var successCount int64
	var securityChangeCount int64

	wg.Add(numGoroutines + 1) // +1 for the security config changer

	// One goroutine that continuously changes cookie security config
	go func() {
		defer wg.Done()
		for i := 0; i < opsPerGoroutine; i++ {
			// Alternate between nil and non-nil security config
			if i%2 == 0 {
				sm.SetCookieSecurity(nil)
			} else {
				sm.SetCookieSecurity(&validation.CookieSecurityConfig{
					RequireSecure:   false, // Use false to allow non-secure cookies in test
					RequireHttpOnly: false,
				})
			}
			atomic.AddInt64(&securityChangeCount, 1)
			time.Sleep(time.Microsecond * 10) // Small delay to allow interleaving
		}
	}()

	// Multiple goroutines that set cookies concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				cookie := &http.Cookie{
					Name:  fmt.Sprintf("cookie-%d-%d", id, j),
					Value: fmt.Sprintf("value-%d-%d", id, j),
				}
				if err := sm.SetCookie(cookie); err == nil {
					atomic.AddInt64(&successCount, 1)
				}
				// Also test SetCookies
				cookies := []*http.Cookie{
					{Name: fmt.Sprintf("batch-%d-%d", id, j), Value: "batch-value"},
				}
				_ = sm.SetCookies(cookies)
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Cookie security test: %d successful SetCookie, %d security changes",
		atomic.LoadInt64(&successCount), atomic.LoadInt64(&securityChangeCount))
}

// TestConcurrentDoHResolverCache tests concurrent DNS cache access.
func TestConcurrentDoHResolverCache(t *testing.T) {
	providers := []*dns.DoHProvider{
		{Name: "test", Template: "https://example.com/dns-query?name={name}", Priority: 1},
	}
	resolver := dns.NewDoHResolver(providers, 5*time.Minute)

	const numGoroutines = 50
	const opsPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				// Test cache size access (atomic)
				_ = resolver.CacheSize()

				// Test TTL read (atomic)
				_ = resolver.GetCacheTTL()

				// Test cache clearing
				if j%10 == 0 {
					resolver.ClearCache()
				}

				// Test TTL setting (atomic - this was the race condition we fixed)
				if j%5 == 0 {
					resolver.SetCacheTTL(time.Minute)
				}
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Final cache size: %d", resolver.CacheSize())
}

// TestConcurrentConnectionPool tests concurrent connection pool operations.
func TestConcurrentConnectionPool(t *testing.T) {
	cfg := connection.DefaultConfig()
	cfg.MaxIdleConns = 100
	cfg.MaxIdleConnsPerHost = 20

	pm, err := connection.NewPoolManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer pm.Close()

	const numGoroutines = 50
	const opsPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				// Concurrent metrics access (atomic)
				_ = pm.GetMetrics()

				// Concurrent transport access (read-only after creation)
				transport := pm.GetTransport()
				if transport == nil {
					t.Error("GetTransport returned nil")
					return
				}
			}
		}(i)
	}

	wg.Wait()

	metrics := pm.GetMetrics()
	t.Logf("Final pool metrics: Active=%d, Total=%d, Rejected=%d, HitRate=%.2f",
		metrics.ActiveConnections, metrics.TotalConnections,
		metrics.RejectedConnections, metrics.ConnectionHitRate)
}

// TestConcurrentDomainWhitelist tests concurrent domain whitelist operations.
func TestConcurrentDomainWhitelist(t *testing.T) {
	dw := security.NewDomainWhitelist("example.com", "*.trusted.org")

	const numGoroutines = 50
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	var allowedCount int64
	var deniedCount int64

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				// Concurrent Add operations
				domain := fmt.Sprintf("domain-%d-%d.com", id, j)
				dw.Add(domain)

				// Concurrent IsAllowed checks
				if dw.IsAllowed(domain) {
					atomic.AddInt64(&allowedCount, 1)
				} else {
					atomic.AddInt64(&deniedCount, 1)
				}

				// Concurrent Domains read
				exact, wildcards := dw.Domains()
				_ = exact
				_ = wildcards

				// Concurrent Remove operations
				if j%10 == 0 {
					dw.Remove(domain)
				}
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Domain whitelist test: %d allowed, %d denied", allowedCount, deniedCount)
}

// TestConcurrentDefaultClient tests concurrent access to the default client.
func TestConcurrentDefaultClient(t *testing.T) {
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	// Reset default client
	httpc.CloseDefaultClient()

	const numGoroutines = 10
	const requestsPerGoroutine = 5

	var wg sync.WaitGroup
	var errors int64

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				// Package-level functions use default client
				_, err := httpc.Get(server.URL)
				if err != nil {
					atomic.AddInt64(&errors, 1)
				}
			}
		}()
	}

	wg.Wait()

	// Cleanup
	httpc.CloseDefaultClient()

	t.Logf("Default client test: %d errors, %d server requests",
		atomic.LoadInt64(&errors), atomic.LoadInt64(&requestCount))
}

// TestConcurrentContextCancellation tests proper handling of concurrent context cancellations.
func TestConcurrentContextCancellation(t *testing.T) {
	var requestCount int64
	// Slow server that takes time to respond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := httpc.New(httpc.DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	const numGoroutines = 10

	var wg sync.WaitGroup
	var cancelledCount int64
	var successCount int64
	var errorCount int64

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			// Create context with short timeout
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			result, err := client.Request(ctx, "GET", server.URL)
			if err != nil {
				if ctx.Err() == context.DeadlineExceeded {
					atomic.AddInt64(&cancelledCount, 1)
				} else {
					atomic.AddInt64(&errorCount, 1)
				}
			} else {
				_ = result
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}

	wg.Wait()

	t.Logf("Context cancellation test: %d cancelled, %d succeeded, %d other errors, %d server requests",
		atomic.LoadInt64(&cancelledCount), atomic.LoadInt64(&successCount),
		atomic.LoadInt64(&errorCount), atomic.LoadInt64(&requestCount))
}

// TestRaceConditionMetricsUpdate tests for race conditions in metrics updates.
func TestRaceConditionMetricsUpdate(t *testing.T) {
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		// Random latency to test rolling average calculation
		time.Sleep(time.Duration(1+hashString(r.URL.Path)%5) * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := httpc.New(httpc.DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	const numGoroutines = 20
	const requestsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				// Make requests with varying URLs to exercise metrics code
				url := fmt.Sprintf("%s/path/%d/%d", server.URL, id, j)
				_, _ = client.Get(url)
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Race condition test completed: %d server requests", atomic.LoadInt64(&requestCount))
}

// TestConcurrentClientClose tests closing client while requests are in flight.
func TestConcurrentClientClose(t *testing.T) {
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	const numAttempts = 10
	var closeErrors int64
	var requestErrors int64

	var wg sync.WaitGroup
	wg.Add(numAttempts)

	for i := 0; i < numAttempts; i++ {
		go func(id int) {
			defer wg.Done()

			client, err := httpc.New(httpc.DefaultConfig())
			if err != nil {
				atomic.AddInt64(&closeErrors, 1)
				return
			}

			// Start a request in a separate goroutine
			var reqWg sync.WaitGroup
			reqWg.Add(1)
			go func() {
				defer reqWg.Done()
				_, err := client.Get(server.URL)
				if err != nil {
					atomic.AddInt64(&requestErrors, 1)
				}
			}()

			// Close while request might be in flight
			time.Sleep(time.Duration(id%30) * time.Millisecond)
			if err := client.Close(); err != nil {
				atomic.AddInt64(&closeErrors, 1)
			}

			reqWg.Wait()
		}(i)
	}

	wg.Wait()

	// Some request errors are expected when closing during request
	t.Logf("Client close test: %d close errors, %d request errors, %d server requests",
		atomic.LoadInt64(&closeErrors), atomic.LoadInt64(&requestErrors), atomic.LoadInt64(&requestCount))
}

// TestConcurrentResultPool tests concurrent Result pooling operations.
func TestConcurrentResultPool(t *testing.T) {
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))
	defer server.Close()

	client, err := httpc.New(httpc.DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	const numGoroutines = 20
	const opsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				// Get result
				result, err := client.Get(server.URL)
				if err != nil {
					continue
				}

				// Access result data (concurrent read from pool)
				_ = result.StatusCode()
				_ = result.Body()
				// Access headers via Response struct field
				if result.Response != nil {
					_ = result.Response.Headers
				}

				// Release to pool
				// GC handles pool cleanup in external test packages
			}
		}()
	}

	wg.Wait()

	t.Logf("Result pool test: %d server requests", atomic.LoadInt64(&requestCount))
}

// TestConcurrentCookieJar tests concurrent cookie jar operations.
func TestConcurrentCookieJar(t *testing.T) {
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		// Set cookies and echo back
		http.SetCookie(w, &http.Cookie{
			Name:  "server-cookie",
			Value: "server-value",
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := httpc.DefaultConfig()
	cfg.Connection.EnableCookies = true

	client, err := httpc.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	const numGoroutines = 10
	const requestsPerGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				_, _ = client.Get(server.URL)
			}
		}()
	}

	wg.Wait()

	t.Logf("Cookie jar test: %d server requests", atomic.LoadInt64(&requestCount))
}

// TestConcurrentRedirectHandling tests concurrent redirect handling.
func TestConcurrentRedirectHandling(t *testing.T) {
	var requestCount int64
	var redirectCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		if r.URL.Path == "/redirect" {
			atomic.AddInt64(&redirectCount, 1)
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, err := httpc.New(httpc.DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	const numGoroutines = 10
	const requestsPerGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				_, _ = client.Get(server.URL + "/redirect")
			}
		}()
	}

	wg.Wait()

	t.Logf("Redirect handling test: %d server requests, %d redirects",
		atomic.LoadInt64(&requestCount), atomic.LoadInt64(&redirectCount))
}

// Helper function for deterministic pseudo-random
func hashString(s string) int {
	h := 0
	for _, c := range s {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h
}

// TestConcurrentMiddlewareExecution tests concurrent middleware execution.
func TestConcurrentMiddlewareExecution(t *testing.T) {
	var callCount int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := httpc.DefaultConfig()
	cfg.Security.AllowPrivateIPs = true
	logCfg := httpc.DefaultLoggingConfig()
	logCfg.LogFunc = func(format string, args ...any) {
		atomic.AddInt64(&callCount, 1)
	}
	cfg.Middleware.Middlewares = []httpc.MiddlewareFunc{
		httpc.LoggingMiddleware(logCfg),
		httpc.RecoveryMiddleware(),
		httpc.HeaderMiddleware(&httpc.HeaderConfig{
			Headers: map[string]string{
				"X-Custom-Header": "test-value",
			},
		}),
	}

	client, err := httpc.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	const numRequests = 50
	var wg sync.WaitGroup
	wg.Add(numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			defer wg.Done()
			_, err := client.Get(server.URL)
			if err != nil {
				t.Errorf("Request failed: %v", err)
			}
		}()
	}

	wg.Wait()

	if callCount != numRequests {
		t.Errorf("Expected %d middleware calls, got %d", numRequests, callCount)
	}
}

// TestConcurrentMixedOperations tests concurrent mixed HTTP operations.
func TestConcurrentMixedOperations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	cfg := httpc.DefaultConfig()
	cfg.Security.AllowPrivateIPs = true
	client, err := httpc.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	const duration = 200 * time.Millisecond
	var stop int32
	var wg sync.WaitGroup

	// GET requests
	wg.Add(1)
	go func() {
		defer wg.Done()
		for atomic.LoadInt32(&stop) == 0 {
			client.Get(server.URL)
		}
	}()

	// POST requests
	wg.Add(1)
	go func() {
		defer wg.Done()
		for atomic.LoadInt32(&stop) == 0 {
			client.Post(server.URL, httpc.WithJSON(map[string]string{"key": "value"}))
		}
	}()

	// Context requests
	wg.Add(1)
	go func() {
		defer wg.Done()
		for atomic.LoadInt32(&stop) == 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			client.Request(ctx, "GET", server.URL)
			cancel()
		}
	}()

	time.Sleep(duration)
	atomic.StoreInt32(&stop, 1)
	wg.Wait()
}
