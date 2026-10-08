package engine

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"

	"github.com/cybergodev/httpc/internal/types"
)

type retryEngine struct {
	config         *Config
	extraRetryable map[int]bool
}

// Compile-time interface check
var _ types.RetryPolicy = (*retryEngine)(nil)

func newRetryEngine(config *Config) *retryEngine {
	// Pre-build the extra-retryable set once so isRetryableStatus stays a
	// pair of map lookups with no per-call allocation.
	extra := make(map[int]bool, len(config.ExtraRetryableStatusCodes))
	for _, code := range config.ExtraRetryableStatusCodes {
		extra[code] = true
	}
	return &retryEngine{
		config:         config,
		extraRetryable: extra,
	}
}

// ShouldRetry implements types.RetryPolicy interface.
func (r *retryEngine) ShouldRetry(resp types.ResponseReader, err error, attempt int) bool {
	if err != nil {
		return r.isRetryableError(err)
	}

	if resp != nil {
		return r.isRetryableStatus(resp.StatusCode())
	}

	return false
}

func (r *retryEngine) GetDelay(attempt int) time.Duration {
	return r.GetDelayWithResponse(attempt, nil)
}

// GetDelayWithResponse returns the delay for the given attempt, considering response headers.
// It first checks for Retry-After header, then falls back to exponential backoff.
func (r *retryEngine) GetDelayWithResponse(attempt int, resp *Response) time.Duration {
	// Check Retry-After header first
	if resp != nil {
		if retryAfterDelay := parseRetryAfterHeader(resp.Headers()); retryAfterDelay > 0 {
			return retryAfterDelay
		}
	}

	return r.calculateExponentialDelay(attempt)
}

// parseRetryAfterHeader parses the Retry-After header and returns the delay duration.
// Returns 0 if the header is not present or cannot be parsed.
// Supports both delta-seconds and HTTP-date formats per RFC 7231.
// SECURITY: The delay is capped at maxRetryAfterDelay (60s) to prevent a malicious
// server from causing indefinite waits via unreasonably large Retry-After values.
func parseRetryAfterHeader(headers http.Header) time.Duration {
	const maxRetryAfterDelay = 60 * time.Second

	if headers == nil {
		return 0
	}

	retryAfterValues := headers["Retry-After"]
	if len(retryAfterValues) == 0 {
		return 0
	}

	retryAfter := retryAfterValues[0]

	// Try parsing as seconds (delta-seconds format)
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
		delay := time.Duration(seconds) * time.Second
		if delay > maxRetryAfterDelay {
			delay = maxRetryAfterDelay
		}
		return delay
	}

	// Try parsing as HTTP date (RFC1123 format)
	if retryTime, err := time.Parse(time.RFC1123, retryAfter); err == nil {
		if delay := time.Until(retryTime); delay > 0 {
			if delay > maxRetryAfterDelay {
				delay = maxRetryAfterDelay
			}
			return delay
		}
	}

	// Try RFC1123 with numeric timezone (e.g., "Mon, 02 Jan 2006 15:04:05 -0700")
	if retryTime, err := time.Parse(time.RFC1123Z, retryAfter); err == nil {
		if delay := time.Until(retryTime); delay > 0 {
			if delay > maxRetryAfterDelay {
				delay = maxRetryAfterDelay
			}
			return delay
		}
	}

	return 0
}

// maxClampDelay saturates an overflown backoff product. 1e18 ns ≈ 31.7 years
// — far beyond any sane retry delay, exactly representable as float64, and
// safely inside time.Duration's int64 range. float64(math.MaxInt64) itself
// rounds UP to 2^63, which converts back to minInt64 on amd64 and would
// reproduce the overflow this constant exists to prevent.
const maxClampDelay = 1e18

// calculateExponentialDelay calculates the exponential backoff delay with optional jitter.
// Uses iterative multiplication instead of math.Pow for better performance.
func (r *retryEngine) calculateExponentialDelay(attempt int) time.Duration {
	delay := r.config.RetryDelay
	if delay <= 0 {
		delay = time.Second
	}

	backoffFactor := r.config.BackoffFactor
	if backoffFactor <= 0 {
		backoffFactor = 2.0
	}

	// Iterative multiplication avoids math.Pow's transcendental function overhead
	exponentialDelay := float64(delay)
	for i := 0; i < attempt; i++ {
		exponentialDelay *= backoffFactor
		// A validated-but-extreme configuration (RetryDelay=30m × BackoffFactor=10
		// at attempt ≥ 7) grows the product past int64's range. Converting an
		// out-of-range float to time.Duration is implementation-defined (negative
		// on amd64), and a negative result slips past the MaxRetryDelay cap below,
		// turning the backoff into an immediate retry. Saturate at maxClampDelay;
		// the cap below then reduces it to MaxRetryDelay as intended.
		if math.IsInf(exponentialDelay, 0) || exponentialDelay > maxClampDelay {
			exponentialDelay = maxClampDelay
			break
		}
	}
	result := time.Duration(exponentialDelay)

	// Apply max delay cap
	if r.config.MaxRetryDelay > 0 && result > r.config.MaxRetryDelay {
		result = r.config.MaxRetryDelay
	}

	// Apply jitter to prevent thundering herd. NOTE: jitter runs AFTER the
	// cap, so an actual sleep can exceed MaxRetryDelay by up to +10% (the
	// jitter range is ±10% of the capped delay). Callers using MaxRetryDelay
	// for strict deadline math must account for the overshoot.
	if r.config.Jitter {
		result = r.applyJitter(result)
	}

	return result
}

// applyJitter adds randomization to the delay to prevent thundering herd problems.
func (r *retryEngine) applyJitter(delay time.Duration) time.Duration {
	if delay <= 0 {
		return delay
	}

	jitterRange := delay / 10
	jitter := r.getJitter(jitterRange * 2)
	return delay - jitterRange + jitter
}

func (r *retryEngine) MaxRetries() int {
	return r.config.MaxRetries
}

// isRetryableError determines if an error is retryable by delegating to
// the centralized error classification in ClientError.IsRetryable().
// This ensures consistent retry behavior across the codebase.
func (r *retryEngine) isRetryableError(err error) bool {
	// Fast path: context errors are never retryable — avoid full classification.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	clientErr := classifyError(err, "", "", 0)
	if clientErr == nil {
		return false
	}
	return clientErr.IsRetryable()
}

// getJitter generates pseudo-random jitter for retry delays.
// Uses math/rand/v2 for high-quality randomness without security concerns.
func (r *retryEngine) getJitter(maxJitter time.Duration) time.Duration {
	if maxJitter <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(maxJitter)))
}

func (r *retryEngine) isRetryableStatus(statusCode int) bool {
	return retryableStatusCodes[statusCode] || r.extraRetryable[statusCode]
}

// idempotentMethods lists the HTTP methods that are idempotent per RFC 9110
// §9.2.1 (safe methods plus PUT and DELETE). Requests using any other
// method — POST, PATCH, CONNECT, or a custom extension method — are treated
// as non-idempotent: the server may have committed side effects before the
// failure that triggered the retry, so replaying the request is not safe by
// default. executeWithRetry zeroes the retry budget for such methods unless
// the caller opts in via Config.RetryNonIdempotent or
// WithRetryNonIdempotent.
func isIdempotentMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace,
		http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}
