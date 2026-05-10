package httpc

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/cybergodev/httpc/internal/validation"
)

// AuditEvent represents a security audit event for high-security scenarios.
// It captures request/response details for compliance logging in financial,
// medical, and government applications.
type AuditEvent struct {
	Timestamp     time.Time           `json:"timestamp"`
	Method        string              `json:"method"`
	URL           string              `json:"url"` // Sanitized (credentials removed)
	StatusCode    int                 `json:"statusCode"`
	Duration      time.Duration       `json:"duration"`
	Attempts      int                 `json:"attempts"`
	Error         error               `json:"error,omitempty"`
	SourceIP      string              `json:"sourceIP,omitempty"`
	UserID        string              `json:"userID,omitempty"`
	RedirectChain []string            `json:"redirectChain,omitempty"`
	ReqHeaders    map[string][]string `json:"reqHeaders,omitempty"`
	RespHeaders   map[string][]string `json:"respHeaders,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for AuditEvent.
// It handles the error field specially to avoid exposing sensitive error details.
func (e AuditEvent) MarshalJSON() ([]byte, error) {
	type Alias AuditEvent
	aux := &struct {
		Alias
		DurationMs int64  `json:"durationMs"`
		ErrorStr   string `json:"error,omitempty"`
	}{
		Alias:      (Alias)(e),
		DurationMs: e.Duration.Milliseconds(),
	}
	if e.Error != nil {
		aux.ErrorStr = e.Error.Error()
	}
	return json.Marshal(aux)
}

// AuditMiddlewareConfig configures the audit middleware behavior.
type AuditMiddlewareConfig struct {
	// Format specifies the output format: "text" (default) or "json"
	Format string

	// IncludeHeaders includes request/response headers in the audit log
	IncludeHeaders bool

	// MaskHeaders is a list of header names to mask (e.g., "Authorization", "Cookie")
	MaskHeaders []string

	// SanitizeError removes sensitive information from error messages
	SanitizeError bool
}

// DefaultAuditMiddlewareConfig returns the default audit middleware configuration.
func DefaultAuditMiddlewareConfig() *AuditMiddlewareConfig {
	return &AuditMiddlewareConfig{
		Format:         "text",
		IncludeHeaders: false,
		MaskHeaders:    sensitiveHeaderNames(),
		SanitizeError:  true,
	}
}

// auditContextKey is the type for context keys used in audit middleware.
type auditContextKey string

const (
	// SourceIPKey is the context key for source IP address in audit events.
	SourceIPKey auditContextKey = "source_ip"
	// UserIDKey is the context key for user identifier in audit events.
	UserIDKey auditContextKey = "user_id"
)

// Chain combines multiple middlewares into a single middleware.
// Middlewares are executed in the order they are provided (first to last).
// The final handler is executed after all middlewares have processed the request.
func Chain(middlewares ...MiddlewareFunc) MiddlewareFunc {
	return func(final Handler) Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

// LoggingMiddleware creates a middleware that logs request and response information.
// The log function receives formatted log messages (similar to log.Printf).
// SECURITY: URLs are sanitized to remove credentials before logging.
func LoggingMiddleware(log func(format string, args ...any)) MiddlewareFunc {
	if log == nil {
		log = func(string, ...any) {}
	}
	return func(next Handler) Handler {
		return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
			start := time.Now()
			resp, err := next(ctx, req)
			duration := time.Since(start)

			status := 0
			if resp != nil {
				status = resp.StatusCode()
			}

			sanitizedURL := validation.SanitizeURL(req.URL())

			if err != nil {
				log("%s %s -> error: %v (%v)", req.Method(), sanitizedURL, err, duration)
			} else {
				log("%s %s -> %d (%v)", req.Method(), sanitizedURL, status, duration)
			}

			return resp, err
		}
	}
}

// RecoveryMiddleware creates a middleware that recovers from panics in the request handler.
// If a panic occurs, it is converted to an error and returned.
func RecoveryMiddleware() MiddlewareFunc {
	return func(next Handler) Handler {
		return func(ctx context.Context, req RequestMutator) (resp ResponseMutator, err error) {
			defer func() {
				if r := recover(); r != nil {
					stack := debug.Stack()
					if e, ok := r.(error); ok {
						err = fmt.Errorf("panic recovered: %w\n%s", e, stack)
					} else {
						err = fmt.Errorf("panic recovered: %v\n%s", r, stack)
					}
				}
			}()
			return next(ctx, req)
		}
	}
}

// RequestIDMiddleware creates a middleware that adds a unique request ID to each request.
// The request ID is added to the request headers with the specified header name.
// If generator is nil, a cryptographically secure random ID generator is used.
//
// SECURITY: The default generator uses crypto/rand to produce unpredictable request IDs,
// preventing request ID guessing attacks in security-sensitive applications.
func RequestIDMiddleware(headerName string, generator func() string) MiddlewareFunc {
	if generator == nil {
		generator = func() string {
			// SECURITY: Use cryptographically secure random for unpredictable request IDs
			var b [16]byte
			_, _ = cryptorand.Read(b[:])
			return hex.EncodeToString(b[:])
		}
	}

	return func(next Handler) Handler {
		return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
			headers := req.Headers()
			if _, exists := headers[headerName]; !exists {
				req.SetHeader(headerName, generator())
			}

			return next(ctx, req)
		}
	}
}

// TimeoutMiddleware creates a middleware that enforces a maximum duration for requests.
// If the request exceeds the timeout, the context is canceled and an error is returned.
// This timeout applies at the middleware level, before the client's built-in timeout.
func TimeoutMiddleware(timeout time.Duration) MiddlewareFunc {
	return func(next Handler) Handler {
		return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
			if timeout <= 0 {
				return next(ctx, req)
			}

			timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			// Also set the request timeout so the engine respects it
			req.SetTimeout(timeout)

			return next(timeoutCtx, req)
		}
	}
}

// HeaderMiddleware creates a middleware that adds static headers to every request.
// Existing headers with the same keys will be overwritten.
// Headers are validated for security (CRLF injection prevention) before being set.
func HeaderMiddleware(headers map[string]string) MiddlewareFunc {
	// Defensive copy to prevent concurrent mutation by caller
	copied := make(map[string]string, len(headers))
	for key, value := range headers {
		copied[key] = value
	}

	// Pre-validate all headers at middleware creation time
	for key, value := range copied {
		if err := validation.ValidateHeaderKeyValue(key, value); err != nil {
			// Return a middleware that always returns the validation error
			return func(next Handler) Handler {
				return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
					return nil, fmt.Errorf("invalid header %s: %w", key, err)
				}
			}
		}
	}

	return func(next Handler) Handler {
		return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
			for key, value := range copied {
				req.SetHeader(key, value)
			}

			return next(ctx, req)
		}
	}
}

// MetricsMiddleware creates a middleware that collects request metrics.
// The onMetrics callback is invoked with metrics after each request completes.
func MetricsMiddleware(onMetrics func(method, url string, statusCode int, duration time.Duration, err error)) MiddlewareFunc {
	return func(next Handler) Handler {
		return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
			start := time.Now()
			resp, err := next(ctx, req)
			duration := time.Since(start)

			if onMetrics != nil {
				statusCode := 0
				if resp != nil {
					statusCode = resp.StatusCode()
				}
				sanitizedURL := validation.SanitizeURL(req.URL())
				sanitizedErr := sanitizeCallbackError(err, req.URL(), sanitizedURL)
				onMetrics(req.Method(), sanitizedURL, statusCode, duration, sanitizedErr)
			}

			return resp, err
		}
	}
}

// sanitizeCallbackError prevents credential leakage in callback errors.
// ClientError already sanitizes URLs; for other error types, it replaces
// the raw URL in the error message with the sanitized version.
func sanitizeCallbackError(err error, rawURL, sanitizedURL string) error {
	if err == nil || rawURL == "" || rawURL == sanitizedURL {
		return err
	}
	errStr := err.Error()
	if strings.Contains(errStr, rawURL) {
		return fmt.Errorf("%s", strings.ReplaceAll(errStr, rawURL, sanitizedURL))
	}
	return err
}

// AuditMiddleware creates a middleware that generates security audit events.
// This is designed for high-security scenarios (financial, medical, government)
// where comprehensive request logging is required for compliance.
//
// The onAudit callback receives an AuditEvent with sanitized URL (credentials removed),
// request metadata, and response information. SourceIP and UserID are extracted from
// the request context using SourceIPKey and UserIDKey.
//
// Example:
//
//	auditMiddleware := httpc.AuditMiddleware(func(event httpc.AuditEvent) {
//	    log.Printf("[AUDIT] %s %s -> %d (%v) user=%s ip=%s",
//	        event.Method, event.URL, event.StatusCode, event.Duration,
//	        event.UserID, event.SourceIP)
//	})
func AuditMiddleware(onAudit func(event AuditEvent)) MiddlewareFunc {
	return AuditMiddlewareWithConfig(onAudit, nil)
}

// AuditMiddlewareWithConfig creates a middleware that generates security audit events
// with configurable output format and options.
//
// Example:
//
//	config := &httpc.AuditMiddlewareConfig{
//	    Format: "json",
//	    IncludeHeaders: true,
//	}
//	auditMiddleware := httpc.AuditMiddlewareWithConfig(func(event httpc.AuditEvent) {
//	    // event will be formatted according to config.Format
//	    log.Printf("[AUDIT] %v", event)
//	}, config)
func AuditMiddlewareWithConfig(onAudit func(event AuditEvent), config *AuditMiddlewareConfig) MiddlewareFunc {
	if config == nil {
		config = DefaultAuditMiddlewareConfig()
	}

	// Pre-compute mask set once at middleware creation time instead of per-request.
	precomputedMaskSet := buildMaskSet(config.MaskHeaders)

	return func(next Handler) Handler {
		return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
			start := time.Now()
			resp, err := next(ctx, req)
			duration := time.Since(start)

			// Build audit event with sanitized URL
			event := AuditEvent{
				Timestamp: start,
				Method:    req.Method(),
				URL:       validation.SanitizeURL(req.URL()),
				Duration:  duration,
				Error:     err,
			}

			// Extract context values
			if sourceIP, ok := ctx.Value(SourceIPKey).(string); ok {
				event.SourceIP = sourceIP
			}
			if userID, ok := ctx.Value(UserIDKey).(string); ok {
				event.UserID = userID
			}

			// Extract response data if available
			if resp != nil {
				event.StatusCode = resp.StatusCode()
				event.Attempts = resp.Attempts()
				event.RedirectChain = resp.RedirectChain()
			}

			// Include headers if configured
			if config.IncludeHeaders {
				event.ReqHeaders = maskStringHeaders(req.Headers(), precomputedMaskSet)
				if resp != nil {
					event.RespHeaders = maskHTTPHeaders(resp.Headers(), precomputedMaskSet)
				}
			}

			// Sanitize error if configured
			if config.SanitizeError && event.Error != nil {
				event.Error = fmt.Errorf("[sanitized]")
			}

			if onAudit != nil {
				onAudit(event)
			}

			return resp, err
		}
	}
}

// buildMaskSet creates a set of canonical header names for masking.
func buildMaskSet(maskList []string) map[string]bool {
	maskSet := make(map[string]bool, len(maskList))
	for _, h := range maskList {
		maskSet[http.CanonicalHeaderKey(h)] = true
	}
	return maskSet
}

// maskStringHeaders masks sensitive values in a map[string]string header map.
// Converts string values to single-element slices for uniform output format.
// Accepts a pre-computed mask set for zero per-request overhead.
func maskStringHeaders(headers map[string]string, maskSet map[string]bool) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	result := make(map[string][]string, len(headers))
	for k, v := range headers {
		if maskSet[http.CanonicalHeaderKey(k)] {
			result[k] = []string{"[REDACTED]"}
		} else {
			result[k] = []string{v}
		}
	}
	return result
}

// maskHTTPHeaders masks sensitive values in an http.Header.
// Accepts a pre-computed mask set for zero per-request overhead.
func maskHTTPHeaders(headers http.Header, maskSet map[string]bool) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	result := make(map[string][]string, len(headers))
	for k, vv := range headers {
		if maskSet[http.CanonicalHeaderKey(k)] {
			result[k] = []string{"[REDACTED]"}
		} else {
			result[k] = vv
		}
	}
	return result
}
