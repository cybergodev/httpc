package httpc

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/cybergodev/httpc/internal/validation"
)

// sanitizedURLer is an unexported interface for per-request sanitized URL caching.
// engine.Request implements this to deduplicate SanitizeURL across middleware.
type sanitizedURLer interface {
	SanitizedURL() string
	SetSanitizedURL(string)
}

// getOrComputeSanitizedURL returns a cached sanitized URL if available,
// otherwise computes and caches it on the request for subsequent middleware.
func getOrComputeSanitizedURL(req RequestMutator) string {
	if r, ok := req.(sanitizedURLer); ok {
		if u := r.SanitizedURL(); u != "" {
			return u
		}
		u := validation.SanitizeURL(req.URL())
		r.SetSanitizedURL(u)
		return u
	}
	return validation.SanitizeURL(req.URL())
}

// AuditEvent represents a security audit event for high-security scenarios.
// It captures request/response details for compliance logging in financial,
// medical, and government applications.
type AuditEvent struct {
	// Timestamp is when the request started; add Duration for the end time.
	Timestamp time.Time `json:"timestamp"`
	// Method is the HTTP method of the request.
	Method string `json:"method"`
	// URL is the request URL, sanitized (credentials removed).
	URL string `json:"url"`
	// StatusCode is the final HTTP status code (0 when the request errored).
	StatusCode int `json:"statusCode"`
	// Duration covers all attempts, including retry delays; serialized as
	// durationMs by MarshalJSON.
	Duration time.Duration `json:"-"`
	// Attempts is the number of requests sent (1 when no retry occurred).
	Attempts int `json:"attempts"`
	// Error is the request error, if any; marshaled as a string with
	// sensitive details removed.
	Error error `json:"error,omitempty"`
	// SourceIP is an application-supplied caller identifier, if known.
	SourceIP string `json:"sourceIP,omitempty"`
	// UserID is an application-supplied user identifier, if known.
	UserID string `json:"userID,omitempty"`
	// RedirectChain lists the URLs followed before the final response.
	RedirectChain []string `json:"redirectChain,omitempty"`
	// ReqHeaders contains the final request headers (may be nil for early
	// failures).
	ReqHeaders map[string][]string `json:"reqHeaders,omitempty"`
	// RespHeaders contains the final response headers (nil when the request
	// errored before a response arrived).
	RespHeaders map[string][]string `json:"respHeaders,omitempty"`
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

// AuditConfig configures the audit middleware.
// Use DefaultAuditConfig() as the starting point.
type AuditConfig struct {
	// OnAudit receives an AuditEvent for each completed request/response cycle.
	// If nil, the middleware is a no-op.
	OnAudit func(event AuditEvent)

	// Format specifies the output format: "text" (default) or "json"
	Format string

	// IncludeHeaders includes request/response headers in the audit log
	IncludeHeaders bool

	// MaskHeaders is a list of header names to mask (e.g., "Authorization", "Cookie")
	MaskHeaders []string

	// SanitizeError removes sensitive information from error messages
	SanitizeError bool
}

// DefaultAuditConfig returns an AuditConfig with default settings.
//
//	Format:         "text"
//	IncludeHeaders: false
//	MaskHeaders:    sensitive header names (Authorization, Cookie, etc.)
//	SanitizeError:  true
func DefaultAuditConfig() *AuditConfig {
	return &AuditConfig{
		Format:         "text",
		IncludeHeaders: false,
		// Clone the shared default list: handing out the package-level slice
		// would let one caller's in-place mutation change every subsequently
		// created default config.
		MaskHeaders:   slices.Clone(cachedSensitiveHeaderNames),
		SanitizeError: true,
	}
}

// LoggingConfig configures the logging middleware.
// Use DefaultLoggingConfig() as the starting point.
type LoggingConfig struct {
	// LogFunc receives formatted log messages (similar to log.Printf).
	// If nil, logging is disabled.
	LogFunc func(format string, args ...any)
}

// DefaultLoggingConfig returns a LoggingConfig with logging disabled.
// Set LogFunc to enable logging.
func DefaultLoggingConfig() *LoggingConfig {
	return &LoggingConfig{}
}

// MetricsConfig configures the metrics middleware.
// Use DefaultMetricsConfig() as the starting point.
type MetricsConfig struct {
	// OnMetrics is invoked with request metrics after each request completes.
	// If nil, metrics collection is disabled.
	OnMetrics func(method, url string, statusCode int, duration time.Duration, err error)
}

// DefaultMetricsConfig returns a MetricsConfig with metrics disabled.
// Set OnMetrics to enable metrics collection.
func DefaultMetricsConfig() *MetricsConfig {
	return &MetricsConfig{}
}

// RequestIDConfig configures the request ID middleware.
// Use DefaultRequestIDConfig() as the starting point.
type RequestIDConfig struct {
	// HeaderName is the HTTP header name for the request ID.
	// Default: "X-Request-ID".
	HeaderName string

	// Generator produces the request ID string. If nil, a cryptographically
	// secure random generator is used (crypto/rand, 16 bytes hex-encoded).
	Generator func() string
}

// DefaultRequestIDConfig returns a RequestIDConfig with sensible defaults.
// HeaderName defaults to "X-Request-ID"; Generator defaults to crypto/rand.
func DefaultRequestIDConfig() *RequestIDConfig {
	return &RequestIDConfig{
		HeaderName: "X-Request-ID",
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
		for _, mw := range slices.Backward(middlewares) {
			final = mw(final)
		}
		return final
	}
}

// LoggingMiddleware creates a logging middleware with the given configuration.
// A nil config selects DefaultLoggingConfig() (logging disabled).
// SECURITY: URLs are sanitized to remove credentials before logging.
func LoggingMiddleware(config *LoggingConfig) MiddlewareFunc {
	if config == nil {
		config = DefaultLoggingConfig()
	}
	log := config.LogFunc
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

			sanitizedURL := getOrComputeSanitizedURL(req)

			if err != nil {
				log("%s %s -> error: %v (%v)", req.Method(), sanitizedURL, err, duration)
			} else {
				log("%s %s -> %d (%v)", req.Method(), sanitizedURL, status, duration)
			}

			return resp, err
		}
	}
}

// panicToError converts a recovered panic value into a descriptive error that
// includes a stack trace. It is the single conversion routine shared by the
// default recover safety net (clientImpl.Request / downloadFile) and
// RecoveryMiddleware, so the public API never propagates a panic to the caller.
//
// The recovered value is inspected only to format the message; it is never
// re-panicked. Fatal runtime conditions (concurrent map access, stack overflow)
// bypass recover entirely and are unaffected by this helper.
func panicToError(r any) error {
	stack := debug.Stack()
	if e, ok := r.(error); ok {
		return fmt.Errorf("panic recovered: %w\n%s", e, stack)
	}
	return fmt.Errorf("panic recovered: %v\n%s", r, stack)
}

// RecoveryMiddleware creates a middleware that recovers from panics in the request handler.
// If a panic occurs, it is converted to an error and returned.
func RecoveryMiddleware() MiddlewareFunc {
	return func(next Handler) Handler {
		return func(ctx context.Context, req RequestMutator) (resp ResponseMutator, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = panicToError(r)
				}
			}()
			return next(ctx, req)
		}
	}
}

// RequestIDMiddleware creates a middleware that adds a unique request ID
// to each request using the given configuration. A nil config selects
// DefaultRequestIDConfig() ("X-Request-ID" header, crypto/rand generator).
//
// SECURITY: When Generator is nil, the default uses crypto/rand to produce
// unpredictable request IDs, preventing request ID guessing attacks.
func RequestIDMiddleware(config *RequestIDConfig) MiddlewareFunc {
	if config == nil {
		config = DefaultRequestIDConfig()
	}
	headerName := config.HeaderName
	if headerName == "" {
		headerName = "X-Request-ID"
	}
	generator := config.Generator
	if generator == nil {
		generator = func() string {
			// SECURITY: Use cryptographically secure random for unpredictable request IDs
			var b [16]byte
			// crypto/rand.Read never fails on any supported Go platform
			// (Linux getrandom, Windows ProcessPrng, macOS getentropy, etc.)
			_, _ = cryptorand.Read(b[:])
			return hex.EncodeToString(b[:])
		}
	}

	return func(next Handler) Handler {
		return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
			// Header keys are stored with the caller's original casing, so a
			// case-insensitive scan is required to respect a header set as
			// e.g. "x-request-id" instead of adding a duplicate.
			exists := false
			for k := range req.Headers() {
				if strings.EqualFold(k, headerName) {
					exists = true
					break
				}
			}
			if !exists {
				req.SetHeader(headerName, generator())
			}

			return next(ctx, req)
		}
	}
}

// TimeoutMiddlewareConfig configures the timeout middleware.
// The name includes "Middleware" to distinguish it from the client-level
// TimeoutConfig in types.go. Use DefaultTimeoutMiddlewareConfig() as the
// starting point.
type TimeoutMiddlewareConfig struct {
	// Duration is the maximum time allowed for the request. Zero or negative
	// disables the timeout (the middleware passes the request through unchanged).
	// Default: 0 (disabled).
	Duration time.Duration
}

// DefaultTimeoutMiddlewareConfig returns a TimeoutMiddlewareConfig with the
// timeout disabled. Set Duration to a positive value to enable the timeout.
func DefaultTimeoutMiddlewareConfig() *TimeoutMiddlewareConfig {
	return &TimeoutMiddlewareConfig{}
}

// TimeoutMiddleware creates a middleware that enforces a maximum duration for
// requests, configured via TimeoutMiddlewareConfig. A nil config selects
// DefaultTimeoutMiddlewareConfig() (timeout disabled — the middleware is a pass-through).
// If the request exceeds the timeout, the context is canceled and an error is
// returned. This timeout applies at the middleware level, before the client's
// built-in timeout.
//
// Caveat — streaming and Download: this middleware cancels its derived context as soon
// as the handler returns (defer cancel()), which for Download happens once the response
// headers have been received but before the body stream is consumed. The cancel therefore
// fires immediately on the first byte of the body, surfacing as a "context canceled"
// error long before the requested timeout elapses. Do NOT wrap Download (or any
// WithStreamBody request) with this middleware; use WithTimeout instead, whose deadline
// is applied on the engine's overall context and survives the body read.
func TimeoutMiddleware(config *TimeoutMiddlewareConfig) MiddlewareFunc {
	if config == nil {
		config = DefaultTimeoutMiddlewareConfig()
	}
	timeout := config.Duration
	return func(next Handler) Handler {
		return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
			if timeout <= 0 {
				return next(ctx, req)
			}

			// Streaming responses outlive this middleware's handler call:
			// defer cancel() fires as soon as headers arrive and aborts the
			// body stream mid-read. Reject loudly at configuration time
			// instead of letting the request fail with a misleading
			// "context canceled" on the first body byte.
			if req.StreamBody() {
				return nil, fmt.Errorf("TimeoutMiddleware is incompatible with streaming responses (WithStreamBody/Download): its context is canceled before the body stream is consumed; use WithTimeout instead")
			}

			// Derive from the request's own context (which may carry a user-supplied
			// deadline or cancellation) rather than the middleware chain's ctx, so that
			// a pre-cancelled WithContext is not silently overwritten.
			baseCtx := req.Context()
			if baseCtx == nil {
				baseCtx = ctx
			}

			timeoutCtx, cancel := context.WithTimeout(baseCtx, timeout)
			defer cancel()

			// Propagate the middleware context deadline to the engine via the
			// request's context field. The finalHandler in clientImpl reads
			// req.Context() rather than the middleware chain's ctx parameter,
			// so the deadline must be set on the RequestMutator itself.
			req.SetContext(timeoutCtx)

			return next(timeoutCtx, req)
		}
	}
}

// HeaderConfig configures the header middleware.
// Use DefaultHeaderConfig() as the starting point.
type HeaderConfig struct {
	// Headers contains static headers added to every request. Existing headers
	// with the same keys are overwritten. Headers are validated for security
	// (CRLF injection prevention) at middleware creation time.
	// Default: empty (no headers added — the middleware is a pass-through).
	Headers map[string]string
}

// DefaultHeaderConfig returns a HeaderConfig with no headers.
func DefaultHeaderConfig() *HeaderConfig {
	return &HeaderConfig{}
}

// HeaderMiddleware creates a middleware that adds static headers to every request,
// configured via HeaderConfig. A nil config selects DefaultHeaderConfig() (no
// headers — effectively a pass-through). Existing headers with the same keys will
// be overwritten. Headers are validated for security (CRLF injection prevention)
// at middleware creation time.
func HeaderMiddleware(config *HeaderConfig) MiddlewareFunc {
	if config == nil {
		config = DefaultHeaderConfig()
	}
	headers := config.Headers

	// Defensive copy to prevent concurrent mutation by caller
	copied := make(map[string]string, len(headers))
	maps.Copy(copied, headers)

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

// MetricsMiddleware creates a metrics middleware with the given configuration.
// A nil config selects DefaultMetricsConfig() (metrics disabled).
func MetricsMiddleware(config *MetricsConfig) MiddlewareFunc {
	if config == nil {
		config = DefaultMetricsConfig()
	}
	onMetrics := config.OnMetrics
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
				sanitizedURL := getOrComputeSanitizedURL(req)
				sanitizedErr := sanitizeCallbackError(err, req.URL(), sanitizedURL)
				onMetrics(req.Method(), sanitizedURL, statusCode, duration, sanitizedErr)
			}

			return resp, err
		}
	}
}

// sanitizedCallbackError carries a redacted error message while preserving
// the original error for errors.Is/errors.As via Unwrap.
type sanitizedCallbackError struct {
	msg     string
	origErr error
}

// contextStringValue looks up a string context value on the middleware chain's
// ctx first, then on the request's own context (set via WithContext). See the
// AuditMiddleware call site for why both must be consulted.
func contextStringValue(ctx context.Context, req RequestMutator, key auditContextKey) (string, bool) {
	if v, ok := ctx.Value(key).(string); ok {
		return v, true
	}
	if reqCtx := req.Context(); reqCtx != nil {
		if v, ok := reqCtx.Value(key).(string); ok {
			return v, true
		}
	}
	return "", false
}

func (e *sanitizedCallbackError) Error() string { return e.msg }
func (e *sanitizedCallbackError) Unwrap() error { return e.origErr }

// sanitizeCallbackError prevents credential leakage in callback errors.
// ClientError already sanitizes URLs; for other error types, it replaces
// the raw URL in the error message with the sanitized version. The returned
// error still unwraps to the original, so consumers keep error classification.
func sanitizeCallbackError(err error, rawURL, sanitizedURL string) error {
	if err == nil || rawURL == "" || rawURL == sanitizedURL {
		return err
	}
	errStr := err.Error()
	if strings.Contains(errStr, rawURL) {
		return &sanitizedCallbackError{
			msg:     strings.ReplaceAll(errStr, rawURL, sanitizedURL),
			origErr: err,
		}
	}
	return err
}

// AuditMiddleware creates a middleware that generates security audit events
// with configurable output format and options. The callback is supplied via
// config.OnAudit; if nil, the middleware is a no-op. A nil config selects
// DefaultAuditConfig().
//
// This middleware is designed for high-security scenarios (financial, medical,
// government) where comprehensive request logging is required for compliance.
// SourceIP and UserID are extracted using SourceIPKey and UserIDKey from the
// context passed to Client.Request, falling back to the request's own context
// when set via WithContext.
//
// Example:
//
//	cfg := httpc.DefaultAuditConfig()
//	cfg.OnAudit = func(event httpc.AuditEvent) {
//	    log.Printf("[AUDIT] %v", event)
//	}
//	cfg.Format = "json"
//	cfg.IncludeHeaders = true
//	auditMiddleware := httpc.AuditMiddleware(cfg)
func AuditMiddleware(config *AuditConfig) MiddlewareFunc {
	if config == nil {
		config = DefaultAuditConfig()
	}
	cb := config.OnAudit
	if cb == nil {
		return func(next Handler) Handler { return next }
	}

	// Pre-compute mask set once at middleware creation time instead of per-request.
	precomputedMaskSet := buildMaskSet(config.MaskHeaders)

	// Snapshot the config flags alongside the callback and mask set: keeping
	// the live *AuditConfig pointer would race with a caller mutating these
	// fields while requests are in flight.
	includeHeaders := config.IncludeHeaders
	sanitizeError := config.SanitizeError

	return func(next Handler) Handler {
		return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
			start := time.Now()
			resp, err := next(ctx, req)
			duration := time.Since(start)

			// Build audit event with sanitized URL
			event := AuditEvent{
				Timestamp: start,
				Method:    req.Method(),
				URL:       getOrComputeSanitizedURL(req),
				Duration:  duration,
				Error:     err,
			}

			// Extract context values. Audit values may be attached either to the
			// context passed to Client.Request (the middleware chain's ctx) or to
			// the request's own context via WithContext — the engine reads the
			// latter, so without this fallback audit events would silently drop
			// values supplied through WithContext. The chain ctx wins when both
			// carry a value (backward-compatible).
			if sourceIP, ok := contextStringValue(ctx, req, SourceIPKey); ok {
				event.SourceIP = sourceIP
			}
			if userID, ok := contextStringValue(ctx, req, UserIDKey); ok {
				event.UserID = userID
			}

			// Extract response data if available
			if resp != nil {
				event.StatusCode = resp.StatusCode()
				event.Attempts = resp.Attempts()
				event.RedirectChain = resp.RedirectChain()
			}

			// Include headers if configured
			if includeHeaders {
				event.ReqHeaders = maskStringHeaders(req.Headers(), precomputedMaskSet)
				if resp != nil {
					event.RespHeaders = maskHTTPHeaders(resp.Headers(), precomputedMaskSet)
				}
			}

			// Sanitize error if configured
			if sanitizeError && event.Error != nil {
				event.Error = fmt.Errorf("[sanitized]")
			}

			cb(event)

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
			// Copy the slice: the source headers may belong to a pooled
			// response that gets reset and reused once the audit event's
			// synchronous callback returns.
			result[k] = append([]string(nil), vv...)
		}
	}
	return result
}
