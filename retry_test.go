package httpc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// RETRY INTEGRATION TESTS - Client-level retry behavior
// Tests the retry mechanism through the public API
// ============================================================================

// ----------------------------------------------------------------------------
// Basic Retry Behavior
// ----------------------------------------------------------------------------

func TestRetry_Behavior(t *testing.T) {
	tests := []struct {
		name             string
		maxRetries       int
		successAfter     int32 // succeed on Nth attempt (0 = always succeed)
		delay            time.Duration
		expectedStatus   int
		expectedAttempts int32
	}{
		{"SuccessOnFirstAttempt", 3, 0, 0, http.StatusOK, 1},
		{"SuccessOnRetry", 3, 3, 10 * time.Millisecond, http.StatusOK, 3},
		{"MaxRetriesExceeded", 3, -1, 10 * time.Millisecond, http.StatusInternalServerError, 4},
		{"NoRetries", 0, -1, 0, http.StatusInternalServerError, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attemptCount := int32(0)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count := atomic.AddInt32(&attemptCount, 1)
				if tt.successAfter == 0 {
					w.WriteHeader(http.StatusOK)
				} else if tt.successAfter > 0 && count >= tt.successAfter {
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer server.Close()

			config := DefaultConfig()
			config.Retry.MaxRetries = tt.maxRetries
			config.Retry.Delay = tt.delay
			config.Security.AllowPrivateIPs = true
			client, _ := New(config)
			defer func() { _ = client.Close() }()

			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			if resp.StatusCode() != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode())
			}
			if atomic.LoadInt32(&attemptCount) != tt.expectedAttempts {
				t.Errorf("Expected %d attempts, got %d", tt.expectedAttempts, atomic.LoadInt32(&attemptCount))
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Status Code Handling
// ----------------------------------------------------------------------------

func TestRetry_StatusCodes(t *testing.T) {
	t.Run("RetryableStatusCodes", func(t *testing.T) {
		retryableStatuses := []int{
			http.StatusInternalServerError, // 500
			http.StatusBadGateway,          // 502
			http.StatusServiceUnavailable,  // 503
			http.StatusGatewayTimeout,      // 504
			http.StatusTooManyRequests,     // 429
			http.StatusRequestTimeout,      // 408
		}

		for _, status := range retryableStatuses {
			t.Run(http.StatusText(status), func(t *testing.T) {
				attemptCount := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&attemptCount, 1)
					w.WriteHeader(status)
				}))
				defer server.Close()

				config := DefaultConfig()
				config.Retry.MaxRetries = 2
				config.Retry.Delay = 10 * time.Millisecond
				config.Security.AllowPrivateIPs = true
				client, _ := New(config)
				defer func() { _ = client.Close() }()

				resp, err := client.Get(server.URL)
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}
				if resp.StatusCode() != status {
					t.Errorf("Expected status %d, got %d", status, resp.StatusCode())
				}
				if atomic.LoadInt32(&attemptCount) < 2 {
					t.Errorf("Expected at least 2 attempts for status %d, got %d", status, atomic.LoadInt32(&attemptCount))
				}
			})
		}
	})

	t.Run("NonRetryableStatusCodes", func(t *testing.T) {
		nonRetryableStatuses := []int{
			http.StatusBadRequest,          // 400
			http.StatusUnauthorized,        // 401
			http.StatusForbidden,           // 403
			http.StatusNotFound,            // 404
			http.StatusMethodNotAllowed,    // 405
			http.StatusNotAcceptable,       // 406
			http.StatusConflict,            // 409
			http.StatusUnprocessableEntity, // 422
		}

		for _, status := range nonRetryableStatuses {
			t.Run(http.StatusText(status), func(t *testing.T) {
				attemptCount := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&attemptCount, 1)
					w.WriteHeader(status)
				}))
				defer server.Close()

				config := DefaultConfig()
				config.Retry.MaxRetries = 2
				config.Retry.Delay = 10 * time.Millisecond
				config.Security.AllowPrivateIPs = true
				client, _ := New(config)
				defer func() { _ = client.Close() }()

				resp, err := client.Get(server.URL)
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}
				if resp.StatusCode() != status {
					t.Errorf("Expected status %d, got %d", status, resp.StatusCode())
				}
				if atomic.LoadInt32(&attemptCount) != 1 {
					t.Errorf("Expected 1 attempt for status %d, got %d", status, atomic.LoadInt32(&attemptCount))
				}
			})
		}
	})
}

// ----------------------------------------------------------------------------
// Backoff Behavior
// ----------------------------------------------------------------------------

func TestRetry_Backoff(t *testing.T) {
	attemptCount := int32(0)
	attemptTimes := make([]time.Time, 0)
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attemptTimes = append(attemptTimes, time.Now())
		mu.Unlock()
		atomic.AddInt32(&attemptCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Retry.MaxRetries = 3
	config.Retry.Delay = 100 * time.Millisecond
	config.Retry.BackoffFactor = 2.0
	config.Retry.EnableJitter = false // Disable jitter for predictable testing
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer func() { _ = client.Close() }()

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode() != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", resp.StatusCode())
	}

	mu.Lock()
	defer mu.Unlock()

	if len(attemptTimes) < 2 {
		t.Fatal("Not enough attempts to verify backoff")
	}

	// Verify delays increase exponentially
	expectedDelays := []time.Duration{
		100 * time.Millisecond, // First retry
		200 * time.Millisecond, // Second retry
		400 * time.Millisecond, // Third retry
	}

	for i := 1; i < len(attemptTimes) && i <= len(expectedDelays); i++ {
		delay := attemptTimes[i].Sub(attemptTimes[i-1])
		expectedMin := time.Duration(float64(expectedDelays[i-1]) * 0.9) // Allow 10% tolerance
		expectedMax := time.Duration(float64(expectedDelays[i-1]) * 1.1)

		if delay < expectedMin || delay > expectedMax {
			t.Errorf("Delay %d: %v (expected ~%v)", i, delay, expectedDelays[i-1])
		}
	}
}

// ----------------------------------------------------------------------------
// Context Cancellation
// ----------------------------------------------------------------------------

func TestRetry_ContextCancellation(t *testing.T) {
	attemptCount := int32(0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attemptCount, 1)
		// Always return error to trigger retry
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Error"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Retry.MaxRetries = 10 // Set higher retry count
	config.Retry.Delay = 200 * time.Millisecond
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer func() { _ = client.Close() }()

	// Create a context that will be cancelled
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	resp, err := client.Request(ctx, "GET", server.URL)
	duration := time.Since(start)

	// Should fail due to context cancellation
	if err == nil {
		t.Error("Expected context cancellation error, got nil")
		if resp != nil {
			t.Logf("Unexpected success response: %d", resp.StatusCode())
		}
	}

	// Check if cancelled within reasonable time
	if duration > 1*time.Second {
		t.Errorf("Request took too long to cancel: %v", duration)
	}

	// Check attempt count (should be less than max retries)
	attempts := atomic.LoadInt32(&attemptCount)
	if attempts >= 10 {
		t.Errorf("Too many attempts before cancellation: %d", attempts)
	}

	t.Logf("Request cancelled after %d attempts in %v", attempts, duration)
}

// ----------------------------------------------------------------------------
// Retry-After Header
// ----------------------------------------------------------------------------

func TestRetry_RetryAfterHeader(t *testing.T) {
	attemptCount := int32(0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := atomic.AddInt32(&attemptCount, 1)

		if attempt == 1 {
			// First request returns 429 and sets Retry-After header
			w.Header().Set("Retry-After", "1") // Retry after 1 second
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("Rate Limited"))
		} else {
			// Subsequent requests succeed
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Success"))
		}
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Retry.MaxRetries = 3
	config.Retry.Delay = 100 * time.Millisecond
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer func() { _ = client.Close() }()

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := client.Request(ctx, "GET", server.URL)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode() != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}

	if resp.Body() != "Success" {
		t.Errorf("Expected body 'Success', got '%s'", resp.Body())
	}

	// Check if retry was performed
	if resp.Meta.Attempts != 2 {
		t.Errorf("Expected 2 attempts, got %d", resp.Meta.Attempts)
	}

	// Check total time (should have waited at least the time specified by Retry-After)
	if duration < 1*time.Second {
		t.Errorf("Expected to wait at least 1 second due to Retry-After, but took %v", duration)
	}

	t.Logf("Request completed in %v with %d attempts", duration, resp.Meta.Attempts)
}

// TestRetry_PerRequestMaxRetriesOption covers the WithMaxRetries per-request
// knob (moved from request_test.go: it is retry behavior — only the knob is
// option-layer). A flaky 500-then-200 server must recover via retries.
func TestRetry_PerRequestMaxRetriesOption(t *testing.T) {
	attempts := int32(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer func() { _ = client.Close() }()

	resp, err := client.Get(server.URL, WithMaxRetries(3))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode())
	}
	if resp.Meta.Attempts < 2 {
		t.Errorf("Expected at least 2 attempts with retries, got %d", resp.Meta.Attempts)
	}
}
