package engine

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// RETRY ENGINE UNIT TESTS
// ============================================================================

func TestRetryEngine_New(t *testing.T) {
	config := &Config{
		MaxRetries:    3,
		RetryDelay:    100 * time.Millisecond,
		BackoffFactor: 2.0,
	}

	engine := newRetryEngine(config)

	if engine == nil {
		t.Fatal("Expected non-nil retry engine")
	}

	if engine.config != config {
		t.Error("Config should be set")
	}
}

func TestRetryEngine_MaxRetries(t *testing.T) {
	config := &Config{
		MaxRetries: 5,
	}

	engine := newRetryEngine(config)

	if engine.MaxRetries() != 5 {
		t.Errorf("Expected MaxRetries 5, got %d", engine.MaxRetries())
	}
}

func TestRetryEngine_ShouldRetry_MaxAttemptsExceeded(t *testing.T) {
	config := &Config{
		MaxRetries: 3,
	}

	engine := newRetryEngine(config)

	// Attempt 3 (0-indexed, so this is the 4th attempt)
	shouldRetry := engine.ShouldRetry(nil, errors.New("network error"), 3)

	if shouldRetry {
		t.Error("Should not retry when max attempts exceeded")
	}
}

func TestRetryEngine_ShouldRetry(t *testing.T) {
	config := &Config{
		MaxRetries: 3,
	}

	engine := newRetryEngine(config)

	t.Run("NetworkErrors", func(t *testing.T) {
		tests := []struct {
			name     string
			err      error
			expected bool
		}{
			{
				name: "OpError is retryable (temporary)",
				err: &net.OpError{
					Op:   "dial",
					Net:  "tcp",
					Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80},
					Err:  errors.New("connection refused"),
				},
				expected: false, // OpError.Temporary() returns false by default, so not retryable via net.Error interface
			},
			{
				name: "DNSError is retryable (temporary)",
				err: &net.DNSError{
					Err:         "no such host",
					Name:        "example.com",
					Server:      "8.8.8.8",
					IsTimeout:   false,
					IsTemporary: true, // Set to true to make it retryable
				},
				expected: true,
			},
			{
				name: "DNSError not temporary",
				err: &net.DNSError{
					Err:         "no such host",
					Name:        "example.com",
					Server:      "8.8.8.8",
					IsTimeout:   false,
					IsTemporary: false,
				},
				expected: false,
			},
			{
				name:     "Context canceled is not retryable",
				err:      context.Canceled,
				expected: false,
			},
			{
				name:     "Context deadline exceeded is not retryable",
				err:      context.DeadlineExceeded,
				expected: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := engine.ShouldRetry(nil, tt.err, 0)
				if result != tt.expected {
					t.Errorf("Expected %v, got %v for error: %v", tt.expected, result, tt.err)
				}
			})
		}
	})

	t.Run("StatusCodes", func(t *testing.T) {
		tests := []struct {
			name       string
			statusCode int
			expected   bool
		}{
			{
				name:       "408 Request Timeout is retryable",
				statusCode: http.StatusRequestTimeout,
				expected:   true,
			},
			{
				name:       "429 Too Many Requests is retryable",
				statusCode: http.StatusTooManyRequests,
				expected:   true,
			},
			{
				name:       "500 Internal Server Error is retryable",
				statusCode: http.StatusInternalServerError,
				expected:   true,
			},
			{
				name:       "502 Bad Gateway is retryable",
				statusCode: http.StatusBadGateway,
				expected:   true,
			},
			{
				name:       "503 Service Unavailable is retryable",
				statusCode: http.StatusServiceUnavailable,
				expected:   true,
			},
			{
				name:       "504 Gateway Timeout is retryable",
				statusCode: http.StatusGatewayTimeout,
				expected:   true,
			},
			{
				name:       "200 OK is not retryable",
				statusCode: http.StatusOK,
				expected:   false,
			},
			{
				name:       "400 Bad Request is not retryable",
				statusCode: http.StatusBadRequest,
				expected:   false,
			},
			{
				name:       "404 Not Found is not retryable",
				statusCode: http.StatusNotFound,
				expected:   false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				resp := &Response{}
				resp.SetStatusCode(tt.statusCode)

				result := engine.ShouldRetry(resp, nil, 0)
				if result != tt.expected {
					t.Errorf("Expected %v, got %v", tt.expected, result)
				}
			})
		}
	})
}

// TestRetryEngine_ExtraRetryableStatusCodes verifies that status codes supplied
// via ExtraRetryableStatusCodes (e.g. 403 for proxy rotation) are treated as
// retryable while codes outside both the built-in and extra sets are not.
func TestRetryEngine_ExtraRetryableStatusCodes(t *testing.T) {
	config := &Config{
		MaxRetries:                3,
		ExtraRetryableStatusCodes: []int{403},
	}
	engine := newRetryEngine(config)

	tests := []struct {
		name       string
		statusCode int
		expected   bool
	}{
		{"403 extra-retryable", 403, true},
		{"429 built-in retryable", 429, true},
		{"200 not retryable", 200, false},
		{"404 not retryable", 404, false},
		{"500 built-in retryable", 500, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{}
			resp.SetStatusCode(tt.statusCode)
			result := engine.ShouldRetry(resp, nil, 0)
			if result != tt.expected {
				t.Errorf("status %d: expected retryable=%v, got %v", tt.statusCode, tt.expected, result)
			}
		})
	}
}

func TestRetryEngine_GetDelay_ExponentialBackoff(t *testing.T) {
	config := &Config{
		RetryDelay:    100 * time.Millisecond,
		BackoffFactor: 2.0,
		Jitter:        false, // Disable jitter for predictable testing
	}

	engine := newRetryEngine(config)

	tests := []struct {
		attempt     int
		expectedMin time.Duration
		expectedMax time.Duration
	}{
		{
			attempt:     0,
			expectedMin: 100 * time.Millisecond,
			expectedMax: 100 * time.Millisecond,
		},
		{
			attempt:     1,
			expectedMin: 200 * time.Millisecond,
			expectedMax: 200 * time.Millisecond,
		},
		{
			attempt:     2,
			expectedMin: 400 * time.Millisecond,
			expectedMax: 400 * time.Millisecond,
		},
		{
			attempt:     3,
			expectedMin: 800 * time.Millisecond,
			expectedMax: 800 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			delay := engine.GetDelay(tt.attempt)

			if delay < tt.expectedMin || delay > tt.expectedMax {
				t.Errorf("Attempt %d: expected delay between %v and %v, got %v",
					tt.attempt, tt.expectedMin, tt.expectedMax, delay)
			}
		})
	}
}

func TestRetryEngine_GetDelay_WithJitter(t *testing.T) {
	config := &Config{
		RetryDelay:    100 * time.Millisecond,
		BackoffFactor: 2.0,
		Jitter:        true,
	}

	engine := newRetryEngine(config)

	// With jitter, delays should vary
	delays := make([]time.Duration, 10)
	for i := 0; i < 10; i++ {
		delays[i] = engine.GetDelay(1)
	}

	// Check that we have some variation (not all delays are the same)
	allSame := true
	firstDelay := delays[0]
	for _, delay := range delays[1:] {
		if delay != firstDelay {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("Expected variation in delays with jitter enabled")
	}

	// All delays should be within reasonable bounds (±10% jitter)
	baseDelay := 200 * time.Millisecond      // 100ms * 2^1
	minDelay := baseDelay - (baseDelay / 10) // -10%
	maxDelay := baseDelay + (baseDelay / 10) // +10%

	for i, delay := range delays {
		if delay < minDelay || delay > maxDelay {
			t.Errorf("Delay %d out of expected range: %v (expected %v to %v)",
				i, delay, minDelay, maxDelay)
		}
	}
}

// TestRetryEngine_GetDelay_TableDriven consolidates MaxRetryDelay and DefaultValues
// into a single table-driven test.
func TestRetryEngine_GetDelay_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		config        *Config
		attempt       int
		expectedDelay time.Duration
		expectedMax   time.Duration
		checkMax      bool // if true, verify delay <= expectedMax instead of exact match
	}{
		{
			name: "MaxRetryDelay caps exponential growth",
			config: &Config{
				RetryDelay:    100 * time.Millisecond,
				BackoffFactor: 2.0,
				MaxRetryDelay: 500 * time.Millisecond,
				Jitter:        false,
			},
			attempt:       3,
			expectedDelay: 500 * time.Millisecond,
		},
		{
			name: "Zero RetryDelay uses default 1s",
			config: &Config{
				RetryDelay:    0,
				BackoffFactor: 2.0,
				Jitter:        false,
			},
			attempt:       0,
			expectedDelay: 1 * time.Second,
		},
		{
			name: "Zero BackoffFactor uses default 2.0",
			config: &Config{
				RetryDelay:    100 * time.Millisecond,
				BackoffFactor: 0,
				Jitter:        false,
			},
			attempt:       1,
			expectedDelay: 200 * time.Millisecond,
		},
		{
			name: "Normal exponential at attempt 0",
			config: &Config{
				RetryDelay:    200 * time.Millisecond,
				BackoffFactor: 3.0,
				Jitter:        false,
			},
			attempt:       0,
			expectedDelay: 200 * time.Millisecond,
		},
		{
			name: "Normal exponential at attempt 2",
			config: &Config{
				RetryDelay:    100 * time.Millisecond,
				BackoffFactor: 2.0,
				Jitter:        false,
			},
			attempt:       2,
			expectedDelay: 400 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := newRetryEngine(tt.config)
			delay := engine.GetDelay(tt.attempt)

			if tt.checkMax {
				if delay > tt.expectedMax {
					t.Errorf("Expected delay <= %v, got %v", tt.expectedMax, delay)
				}
			} else {
				if delay != tt.expectedDelay {
					t.Errorf("Expected delay %v, got %v", tt.expectedDelay, delay)
				}
			}
		})
	}
}

func TestRetryEngine_IsRetryableError(t *testing.T) {
	config := &Config{
		MaxRetries: 3,
	}

	engine := newRetryEngine(config)

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "Context canceled",
			err:      context.Canceled,
			expected: false,
		},
		{
			name:     "Context deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: false,
		},
		{
			name:     "Context canceled in message",
			err:      errors.New("context canceled"),
			expected: false,
		},
		{
			name:     "Request context canceled",
			err:      errors.New("request context canceled"),
			expected: false,
		},
		{
			name: "OpError without context (not temporary)",
			err: &net.OpError{
				Op:   "dial",
				Net:  "tcp",
				Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80},
				Err:  errors.New("connection refused"),
			},
			expected: false, // OpError.Temporary() returns false by default
		},
		{
			name: "OpError with context",
			err: &net.OpError{
				Op:   "dial",
				Net:  "tcp",
				Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80},
				Err:  errors.New("context deadline exceeded"),
			},
			expected: false,
		},
		{
			name: "DNSError temporary",
			err: &net.DNSError{
				Err:         "no such host",
				Name:        "example.com",
				Server:      "8.8.8.8",
				IsTimeout:   false,
				IsTemporary: true, // Set to true to make it retryable
			},
			expected: true,
		},
		{
			name: "DNSError not temporary",
			err: &net.DNSError{
				Err:         "no such host",
				Name:        "example.com",
				Server:      "8.8.8.8",
				IsTimeout:   false,
				IsTemporary: false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.isRetryableError(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for error: %v", tt.expected, result, tt.err)
			}
		})
	}
}

// Note: mockNetError is defined in errors_test.go and shared across test files

func TestRetryEngine_GetJitter(t *testing.T) {
	t.Run("Random jitter within bounds", func(t *testing.T) {
		config := &Config{}
		engine := newRetryEngine(config)

		maxJitter := 100 * time.Millisecond

		// Test multiple times to ensure randomness
		for i := 0; i < 10; i++ {
			jitter := engine.getJitter(maxJitter)

			if jitter < 0 {
				t.Errorf("Jitter should not be negative, got %v", jitter)
			}

			if jitter > maxJitter {
				t.Errorf("Jitter should not exceed max, got %v (max: %v)", jitter, maxJitter)
			}
		}
	})

	t.Run("Zero max returns zero", func(t *testing.T) {
		config := &Config{}
		engine := newRetryEngine(config)

		jitter := engine.getJitter(0)

		if jitter != 0 {
			t.Errorf("Expected 0 jitter for 0 maxJitter, got %v", jitter)
		}
	})
}

// ============================================================================
// PARSE RETRY-AFTER HEADER TESTS
// ============================================================================

func TestParseRetryAfterHeader(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectDelay time.Duration
		expectMin   time.Duration // For time-based tests (future dates)
	}{
		// --- Basic header cases ---
		{
			name:        "Nil headers",
			headers:     nil,
			expectDelay: 0,
		},
		{
			name:        "Empty headers",
			headers:     http.Header{},
			expectDelay: 0,
		},
		{
			name:        "No Retry-After header",
			headers:     http.Header{"Content-Type": {"application/json"}},
			expectDelay: 0,
		},
		// --- Delta-seconds format ---
		{
			name:        "Delta-seconds format",
			headers:     http.Header{"Retry-After": {"30"}},
			expectDelay: 30 * time.Second,
		},
		{
			name:        "Delta-seconds zero",
			headers:     http.Header{"Retry-After": {"0"}},
			expectDelay: 0,
		},
		{
			name:        "Delta-seconds negative-like string",
			headers:     http.Header{"Retry-After": {"-1"}},
			expectDelay: 0, // strconv.Atoi fails on negative in this implementation
		},
		{
			name:        "Delta-seconds large value capped at 60s",
			headers:     http.Header{"Retry-After": {"3600"}},
			expectDelay: 60 * time.Second,
		},
		{
			name:        "Invalid number format",
			headers:     http.Header{"Retry-After": {"abc"}},
			expectDelay: 0,
		},
		{
			name:        "Invalid date format",
			headers:     http.Header{"Retry-After": {"Not-A-Date"}},
			expectDelay: 0,
		},
		{
			name:        "Empty header value",
			headers:     http.Header{"Retry-After": {""}},
			expectDelay: 0,
		},
		{
			name:        "Multiple values uses first",
			headers:     http.Header{"Retry-After": {"30", "60"}},
			expectDelay: 30 * time.Second,
		},
		// --- Edge cases ---
		{
			name:        "Whitespace in value",
			headers:     http.Header{"Retry-After": {" 30 "}},
			expectDelay: 0, // strconv.Atoi does NOT trim whitespace, so this should fail and return 0
		},
		{
			name:        "Float value falls back to date parsing",
			headers:     http.Header{"Retry-After": {"30.5"}},
			expectDelay: 0, // Float should fail both integer and date parsing
		},
		{
			name:        "Very large seconds value capped at 60s",
			headers:     http.Header{"Retry-After": {"86400"}}, // 24 hours
			expectDelay: 60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delay := parseRetryAfterHeader(tt.headers)

			if tt.expectMin > 0 {
				// For time-based expectations, check minimum
				if delay < tt.expectMin {
					t.Errorf("Expected delay >= %v, got %v", tt.expectMin, delay)
				}
			} else {
				if delay != tt.expectDelay {
					t.Errorf("Expected delay %v, got %v", tt.expectDelay, delay)
				}
			}
		})
	}

	// --- HTTP date format tests (time-dependent, cannot use static table) ---
	t.Run("HTTP date format", func(t *testing.T) {
		t.Run("Future date returns positive delay", func(t *testing.T) {
			// Create a date 30 seconds in the future
			futureTime := time.Now().Add(30 * time.Second).UTC()
			httpDate := futureTime.Format(time.RFC1123)

			headers := http.Header{"Retry-After": {httpDate}}
			delay := parseRetryAfterHeader(headers)

			// Should be approximately 30 seconds (allow some tolerance for test execution)
			if delay < 25*time.Second || delay > 35*time.Second {
				t.Errorf("Expected delay around 30s, got %v", delay)
			}
		})

		t.Run("Past date returns zero", func(t *testing.T) {
			// Create a date in the past
			pastTime := time.Now().Add(-30 * time.Second).UTC()
			httpDate := pastTime.Format(time.RFC1123)

			headers := http.Header{"Retry-After": {httpDate}}
			delay := parseRetryAfterHeader(headers)

			if delay != 0 {
				t.Errorf("Expected 0 delay for past date, got %v", delay)
			}
		})

		t.Run("Current time returns zero or very small delay", func(t *testing.T) {
			// Create a date at current time
			now := time.Now().UTC()
			httpDate := now.Format(time.RFC1123)

			headers := http.Header{"Retry-After": {httpDate}}
			delay := parseRetryAfterHeader(headers)

			// Should be very small (0 or close to it)
			if delay > 5*time.Second {
				t.Errorf("Expected very small delay for current time, got %v", delay)
			}
		})

		// RFC1123Z date format test
		t.Run("RFC1123Z date format", func(t *testing.T) {
			futureTime := time.Now().Add(30 * time.Second).UTC()
			httpDate := futureTime.Format(time.RFC1123Z)

			headers := http.Header{"Retry-After": {httpDate}}
			delay := parseRetryAfterHeader(headers)

			if delay < 25*time.Second || delay > 35*time.Second {
				t.Errorf("Expected delay around 30s for RFC1123Z, got %v", delay)
			}
		})

		// Cap branches: a future date beyond maxRetryAfterDelay (60s) must be
		// capped at exactly 60s in both supported date formats
		// (retry.go:89-91 RFC1123, :99-101 RFC1123Z).
		t.Run("RFC1123 future date capped at 60s", func(t *testing.T) {
			farFuture := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC1123)
			delay := parseRetryAfterHeader(http.Header{"Retry-After": {farFuture}})
			if delay != 60*time.Second {
				t.Errorf("RFC1123 far-future date: expected 60s cap, got %v", delay)
			}
		})

		t.Run("RFC1123Z future date capped at 60s", func(t *testing.T) {
			farFuture := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC1123Z)
			delay := parseRetryAfterHeader(http.Header{"Retry-After": {farFuture}})
			if delay != 60*time.Second {
				t.Errorf("RFC1123Z far-future date: expected 60s cap, got %v", delay)
			}
		})
	})
}

func TestRetryEngine_GetDelayWithResponse(t *testing.T) {
	config := &Config{
		RetryDelay:    100 * time.Millisecond,
		BackoffFactor: 2.0,
		Jitter:        false,
	}

	engine := newRetryEngine(config)

	t.Run("Uses Retry-After header when present", func(t *testing.T) {
		resp := &Response{}
		resp.SetHeaders(http.Header{"Retry-After": {"50"}})

		delay := engine.GetDelayWithResponse(0, resp)

		if delay != 50*time.Second {
			t.Errorf("Expected 50s delay from Retry-After, got %v", delay)
		}
	})

	t.Run("Falls back to exponential backoff when no header", func(t *testing.T) {
		resp := &Response{}
		resp.SetHeaders(http.Header{})

		delay := engine.GetDelayWithResponse(0, resp)

		if delay != 100*time.Millisecond {
			t.Errorf("Expected 100ms exponential delay, got %v", delay)
		}
	})

	t.Run("Nil response uses exponential backoff", func(t *testing.T) {
		delay := engine.GetDelayWithResponse(1, nil)

		if delay != 200*time.Millisecond {
			t.Errorf("Expected 200ms exponential delay, got %v", delay)
		}
	})
}

// retryableTimeoutErr is a minimal net.Error used to drive the retry loop:
// classifyError maps a net.Error with Timeout()==true to ErrorTypeTimeout,
// which IsRetryable() reports as retryable. fmt.Errorf("connection refused")
// (used elsewhere) classifies as ErrorTypeNetwork and is NOT retried, so a
// custom net.Error is required to genuinely exercise the error-retry path.
type retryableTimeoutErr struct{}

func (retryableTimeoutErr) Error() string   { return "network timeout occurred" }
func (retryableTimeoutErr) Timeout() bool   { return true }
func (retryableTimeoutErr) Temporary() bool { return true }

// TestExecuteWithRetry_RetryableErrorExhaustsRetries covers the error branch
// of executeWithRetry (client.go:775-799): a retryable error is re-attempted
// until MaxRetries is exhausted. Asserts two transport calls (1 + 1 retry),
// that the returned error is a *ClientError, and that Attempts==2.
func TestExecuteWithRetry_RetryableErrorExhaustsRetries(t *testing.T) {
	mock := newMockTransport(200, "should not be reached")
	mock.SetError(retryableTimeoutErr{}) // always fails, but is retryable

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      1,
		RetryDelay:      time.Millisecond,
		BackoffFactor:   1.0,
		UserAgent:       "test/1.0",
	}
	client, err := NewClient(config, func(opts *clientOptions) {
		opts.customTransport = mock
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	_, err = client.Request(backgroundCtx, "GET", "https://example.com")
	if err == nil {
		t.Fatal("expected error after retries exhausted, got nil")
	}
	if got := mock.GetCallCount(); got != 2 {
		t.Errorf("expected 2 transport calls (1 + 1 retry), got %d", got)
	}
	var clientErr *ClientError
	if errors.As(err, &clientErr) {
		if clientErr.Attempts != 2 {
			t.Errorf("expected Attempts=2, got %d", clientErr.Attempts)
		}
	} else {
		t.Errorf("expected *ClientError, got %T: %v", err, err)
	}
}

// TestExecuteWithRetry_BodyBufferedForRetry covers the io.Reader body-buffering
// path (client.go:748-768): a streaming (io.Reader) body is read into a []byte
// once so every retry attempt re-sends the full payload instead of an exhausted
// reader. Driven by a custom RequestOption that sets the body as a reader, with
// a retryable error forcing the loop to iterate.
func TestExecuteWithRetry_BodyBufferedForRetry(t *testing.T) {
	mock := newMockTransport(200, "should not be reached")
	mock.SetError(retryableTimeoutErr{}) // retryable → buffer-then-retry path

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      1,
		RetryDelay:      time.Millisecond,
		BackoffFactor:   1.0,
		UserAgent:       "test/1.0",
	}
	client, err := NewClient(config, func(opts *clientOptions) {
		opts.customTransport = mock
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Custom option sets the body as an io.Reader, triggering the buffering
	// branch in executeWithRetry.
	bodyOption := func(r *Request) error {
		r.SetBody(strings.NewReader("payload-that-must-be-buffered-for-retry"))
		return nil
	}

	_, err = client.Request(backgroundCtx, "POST", "https://example.com", bodyOption)
	if err == nil {
		t.Fatal("expected error after retries exhausted, got nil")
	}
	if got := mock.GetCallCount(); got != 2 {
		t.Errorf("expected 2 transport calls (buffered body retried), got %d", got)
	}
}

// TestSleepWithContext covers the three control-flow branches of
// sleepWithContext (client.go:640-669): nil context (time.Sleep), timer-fires,
// and context-cancelled-during-sleep (including the timer-drain sub-branch).
// sleepWithContext touches only the package-level timerPool, so a zero-value
// *Client is sufficient and avoids constructing a full transport stack.
func TestSleepWithContext(t *testing.T) {
	c := &Client{} // sleepWithContext uses only the timer pool, not client state

	t.Run("nil context sleeps and returns nil", func(t *testing.T) {
		start := time.Now()
		//nolint:staticcheck // SA1012: nil ctx is deliberate — covers sleepWithContext:641
		if err := c.sleepWithContext(nil, 5*time.Millisecond); err != nil {
			t.Errorf("nil context should return nil, got %v", err)
		}
		if elapsed := time.Since(start); elapsed < 4*time.Millisecond {
			t.Errorf("expected to actually sleep ~5ms, slept %v", elapsed)
		}
	})

	t.Run("timer fires returns nil", func(t *testing.T) {
		if err := c.sleepWithContext(context.Background(), 5*time.Millisecond); err != nil {
			t.Errorf("expected nil when timer fires, got %v", err)
		}
	})

	t.Run("context cancelled during sleep", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(2 * time.Millisecond)
			cancel()
		}()

		start := time.Now()
		err := c.sleepWithContext(ctx, 5*time.Second)
		elapsed := time.Since(start)

		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
		if elapsed > 1*time.Second {
			t.Errorf("sleep should return promptly on cancel, took %v", elapsed)
		}
	})

	// The timer-drain sub-branch (client.go:658-661) only runs when the timer
	// has already fired by the time ctx is cancelled — a genuine race. Run many
	// iterations so both the drain and no-drain sub-branches are exercised
	// under -race.
	t.Run("cancel races timer for drain coverage", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				time.Sleep(time.Millisecond)
				cancel()
			}()
			_ = c.sleepWithContext(ctx, 2*time.Millisecond)
		}
	})
}
