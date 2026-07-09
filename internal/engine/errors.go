package engine

import (
	"context"
	"errors"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/cybergodev/httpc/internal/connection"
	"github.com/cybergodev/httpc/internal/validation"
)

// retryableStatusCodes is the single source of truth for HTTP status codes
// that warrant automatic retry. Used by both retry.go and errors.go.
// Read-only after initialization — must not be mutated (concurrent reads).
var retryableStatusCodes = map[int]bool{
	408: true, // Request Timeout
	429: true, // Too Many Requests
	500: true, // Internal Server Error
	502: true, // Bad Gateway
	503: true, // Service Unavailable
	504: true, // Gateway Timeout
}

// retryableStatusPrefixes are pre-built search strings for fallback status
// detection, derived from retryableStatusCodes so the two declarations cannot
// drift. Sorted for deterministic iteration. Avoids fmt.Sprintf allocation in
// the isRetryableHTTPStatus fallback path.
var retryableStatusPrefixes = func() []string {
	codes := make([]int, 0, len(retryableStatusCodes))
	for code := range retryableStatusCodes {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	prefixes := make([]string, len(codes))
	for i, code := range codes {
		prefixes[i] = "HTTP " + strconv.Itoa(code)
	}
	return prefixes
}()

// ErrorType represents the classification of an HTTP client error.
type ErrorType int

const (
	// ErrorTypeUnknown indicates an unknown or unclassified error.
	ErrorTypeUnknown ErrorType = iota
	// ErrorTypeNetwork indicates a network-level error.
	ErrorTypeNetwork
	// ErrorTypeTimeout indicates a timeout occurred during the request.
	ErrorTypeTimeout
	// ErrorTypeContextCanceled indicates the request context was canceled.
	ErrorTypeContextCanceled
	// ErrorTypeResponseRead indicates an error reading the response body.
	ErrorTypeResponseRead
	// ErrorTypeTransport indicates an HTTP transport-level error.
	ErrorTypeTransport
	// ErrorTypeRetryExhausted indicates all retry attempts have been exhausted.
	ErrorTypeRetryExhausted
	// ErrorTypeTLS indicates a TLS handshake or protocol error.
	ErrorTypeTLS
	// ErrorTypeCertificate indicates a certificate validation error.
	ErrorTypeCertificate
	// ErrorTypeDNS indicates a DNS resolution error.
	ErrorTypeDNS
	// ErrorTypeValidation indicates a request validation error.
	ErrorTypeValidation
	// ErrorTypeHTTP indicates an HTTP-level error (4xx, 5xx responses).
	ErrorTypeHTTP
)

// ClientError objects escape to callers who may hold references indefinitely,
// so they cannot be safely pooled. Direct allocation avoids pool overhead
// for objects that are never returned.

// ClientError represents a classified HTTP client error with context about the failed request.
type ClientError struct {
	Type       ErrorType
	Message    string
	Cause      error
	URL        string
	Method     string
	Attempts   int
	StatusCode int    // HTTP status code if applicable
	Host       string // Host for circuit breaker errors
}

// errorBuilderPool reduces allocations for strings.Builder in ClientError.Error()
var errorBuilderPool = sync.Pool{
	New: func() any {
		sb := &strings.Builder{}
		return sb
	},
}

func (e *ClientError) Error() string {
	// Estimate capacity: method (~8) + URL (~64) + message (~64) + cause (~64) + overhead
	b, _ := errorBuilderPool.Get().(*strings.Builder)
	if b == nil {
		b = &strings.Builder{}
	}
	b.Reset()
	b.Grow(220)

	var numBuf [12]byte

	if e.URL != "" && e.Method != "" {
		sanitizedURL := validation.SanitizeURL(e.URL)
		b.WriteString(e.Method)
		b.WriteByte(' ')
		b.WriteString(sanitizedURL)
		b.WriteString(": ")
		b.WriteString(e.Message)
	} else {
		b.WriteString(e.Message)
	}

	if e.Cause != nil {
		b.WriteString(": ")
		b.WriteString(e.Cause.Error())
	}

	if e.Attempts > 0 {
		b.WriteString(" (attempt ")
		b.Write(strconv.AppendInt(numBuf[:0], int64(e.Attempts), 10))
		b.WriteByte(')')
	}

	result := b.String()
	if b.Cap() <= 1024 {
		errorBuilderPool.Put(b)
	}
	return result
}

func (e *ClientError) Unwrap() error {
	return e.Cause
}

// WithType returns a copy of the error with the specified type set.
func (e *ClientError) WithType(t ErrorType) *ClientError {
	cp := &ClientError{}
	*cp = *e
	cp.Type = t
	return cp
}

// IsRetryable determines if the error is retryable based on its type and cause.
func (e *ClientError) IsRetryable() bool {
	// Check for context errors first - they are never retryable
	if e.isContextError() {
		return false
	}

	switch e.Type {
	case ErrorTypeContextCanceled, ErrorTypeValidation, ErrorTypeTLS, ErrorTypeCertificate:
		return false
	case ErrorTypeDNS:
		return e.isRetryableDNSError()
	case ErrorTypeNetwork:
		return e.isRetryableNetworkError()
	case ErrorTypeTimeout, ErrorTypeTransport:
		return true
	case ErrorTypeResponseRead:
		return e.isRetryableResponseReadError()
	case ErrorTypeHTTP:
		return e.isRetryableHTTPStatus()
	default:
		return false
	}
}

// isContextError checks if the cause is a context-related error.
func (e *ClientError) isContextError() bool {
	if e.Cause == nil {
		return false
	}
	return errors.Is(e.Cause, context.Canceled) || errors.Is(e.Cause, context.DeadlineExceeded)
}

// isRetryableDNSError checks if DNS error is temporary or timeout.
func (e *ClientError) isRetryableDNSError() bool {
	if e.Cause == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(e.Cause, &dnsErr) {
		return dnsErr.IsTemporary || dnsErr.IsTimeout
	}
	return false
}

// isRetryableNetworkError determines if a network error is retryable.
func (e *ClientError) isRetryableNetworkError() bool {
	if e.Cause == nil {
		return false
	}

	// Check for wrapped ClientError
	var innerClientErr *ClientError
	if errors.As(e.Cause, &innerClientErr) {
		return e.isRetryableWrappedError(innerClientErr)
	}

	// Check for OpError
	var opErr *net.OpError
	if errors.As(e.Cause, &opErr) {
		return e.isRetryableOpError(opErr)
	}

	// Check for generic net.Error — network errors with net.Error causes
	// are retryable by default (transient network failures like server
	// connection close, EOF, etc.). Context errors are handled by the
	// isContextError check in IsRetryable().
	var netErr net.Error
	if errors.As(e.Cause, &netErr) {
		return true
	}

	// Check error message patterns
	return isRetryableNetworkMessage(e.Cause.Error())
}

// isRetryableWrappedError checks if a wrapped ClientError is retryable.
func (e *ClientError) isRetryableWrappedError(innerClientErr *ClientError) bool {
	if innerClientErr.Cause != nil {
		if isRetryableNetworkMessage(innerClientErr.Cause.Error()) {
			return true
		}
	}
	return innerClientErr.IsRetryable()
}

// isRetryableOpError determines if a net.OpError is retryable.
func (e *ClientError) isRetryableOpError(opErr *net.OpError) bool {
	// Context errors are not retryable
	if opErr.Err != nil && (errors.Is(opErr.Err, context.Canceled) || errors.Is(opErr.Err, context.DeadlineExceeded)) {
		return false
	}
	// Timeout is retryable
	if opErr.Timeout() {
		return true
	}
	// Check for syscall errors
	if opErr.Err != nil {
		var errno syscall.Errno
		if errors.As(opErr.Err, &errno) {
			if isRetryableSyscallError(errno) {
				return true
			}
		}
		// Check error message patterns
		if isRetryableNetworkMessage(opErr.Err.Error()) {
			return true
		}
	}
	return false
}

// isRetryableSyscallError checks if a syscall errno indicates a retryable condition.
func isRetryableSyscallError(errno syscall.Errno) bool {
	switch errno {
	case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EPIPE,
		syscall.ETIMEDOUT, syscall.ENETUNREACH, syscall.EHOSTUNREACH:
		return true
	default:
		return false
	}
}

// isRetryableNetworkMessage checks if an error message indicates a retryable network condition.
// Uses containsFold for zero-allocation case-insensitive matching.
func isRetryableNetworkMessage(errMsg string) bool {
	return validation.ContainsFold(errMsg, "connection reset") ||
		validation.ContainsFold(errMsg, "eof") ||
		validation.ContainsFold(errMsg, "connection closed") ||
		validation.ContainsFold(errMsg, "broken pipe") ||
		validation.ContainsFold(errMsg, "network error") ||
		validation.ContainsFold(errMsg, "transport failed")
}

// isRetryableResponseReadError determines if a response read error is retryable.
// Only read-related network operations qualify; file or write OpErrors are excluded.
func (e *ClientError) isRetryableResponseReadError() bool {
	if e.Cause == nil {
		return false
	}
	var netErr *net.OpError
	if errors.As(e.Cause, &netErr) {
		return netErr.Op == "read" || netErr.Op == "readfrom"
	}
	errMsg := e.Cause.Error()
	return validation.ContainsFold(errMsg, "eof") || validation.ContainsFold(errMsg, "connection") || validation.ContainsFold(errMsg, "timeout")
}

// isRetryableHTTPStatus checks if HTTP status code indicates a retryable condition.
func (e *ClientError) isRetryableHTTPStatus() bool {
	if retryableStatusCodes[e.StatusCode] {
		return true
	}
	// Fallback: check message for retryable status patterns using pre-built strings
	if e.StatusCode == 0 {
		for _, prefix := range retryableStatusPrefixes {
			if validation.ContainsFold(e.Message, prefix) {
				return true
			}
		}
	}
	return false
}

// Code returns a short string code identifying the error type (e.g., "NETWORK_ERROR", "TIMEOUT").
func (e *ClientError) Code() string {
	switch e.Type {
	case ErrorTypeNetwork:
		return "NETWORK_ERROR"
	case ErrorTypeTimeout:
		return "TIMEOUT"
	case ErrorTypeContextCanceled:
		return "CONTEXT_CANCELED"
	case ErrorTypeResponseRead:
		return "RESPONSE_READ_ERROR"
	case ErrorTypeTransport:
		return "TRANSPORT_ERROR"
	case ErrorTypeRetryExhausted:
		return "RETRY_EXHAUSTED"
	case ErrorTypeTLS:
		return "TLS_ERROR"
	case ErrorTypeCertificate:
		return "CERTIFICATE_ERROR"
	case ErrorTypeDNS:
		return "DNS_ERROR"
	case ErrorTypeValidation:
		return "VALIDATION_ERROR"
	case ErrorTypeHTTP:
		return "HTTP_ERROR"
	default:
		return "UNKNOWN_ERROR"
	}
}

func classifyError(err error, reqURL, method string, attempts int) *ClientError {
	if err == nil {
		return nil
	}

	sanitizedURL := validation.SanitizeURL(reqURL)
	return classifyErrorWithSanitizedURL(err, sanitizedURL, method, attempts)
}

// classifyErrorWithSanitizedURL classifies an error using a pre-sanitized URL.
// Use this when the same URL is reused across retry attempts to avoid re-sanitizing.
func classifyErrorWithSanitizedURL(err error, sanitizedURL, method string, attempts int) *ClientError {
	if err == nil {
		return nil
	}

	// Return a copy for already-classified errors to prevent shared-pointer mutation.
	// Copy is created without re-wrapping to avoid circular Unwrap chains:
	// cp.Cause retains the original chain, not err (which wraps existingErr).
	var existingErr *ClientError
	if errors.As(err, &existingErr) {
		cp := &ClientError{}
		*cp = *existingErr
		cp.URL = sanitizedURL
		cp.Method = method
		if attempts > 0 {
			cp.Attempts = attempts
		}
		return cp
	}

	clientErr := &ClientError{}
	clientErr.Cause = err
	clientErr.URL = sanitizedURL
	clientErr.Method = method
	clientErr.Attempts = attempts

	if errors.Is(err, context.Canceled) {
		clientErr.Type = ErrorTypeContextCanceled
		clientErr.Message = "request was canceled"
		return clientErr
	}

	if errors.Is(err, context.DeadlineExceeded) {
		clientErr.Type = ErrorTypeTimeout
		clientErr.Message = "request timeout"
		return clientErr
	}

	if errors.Is(err, connection.ErrPoolExhausted) {
		clientErr.Type = ErrorTypeNetwork
		clientErr.Message = "connection pool exhausted"
		return clientErr
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		errMsg := urlErr.Error()
		if validation.ContainsFold(errMsg, "http2") && validation.ContainsFold(errMsg, "invalid") {
			clientErr.Type = ErrorTypeValidation
			clientErr.Message = "invalid HTTP/2 request header"
			return clientErr
		}
		if validation.ContainsFold(errMsg, "parse") || validation.ContainsFold(errMsg, "invalid url") || validation.ContainsFold(errMsg, "missing protocol") {
			clientErr.Type = ErrorTypeValidation
			clientErr.Message = "URL validation failed"
			return clientErr
		}
		// Unwrap *url.Error to classify the actual underlying error.
		// *url.Error implements net.Error, which would match the net.Error
		// check below and produce a generic "network error occurred" message.
		// By unwrapping here, we get to the real error type.
		if urlErr.Err != nil {
			err = urlErr.Err
		}
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		clientErr.Type = ErrorTypeDNS
		if dnsErr.IsTimeout {
			clientErr.Message = "DNS resolution timed out"
		} else {
			clientErr.Message = "DNS resolution failed"
		}
		return clientErr
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		clientErr.Type = ErrorTypeNetwork
		if opErr.Timeout() {
			clientErr.Message = "network operation timed out"
		} else {
			clientErr.Message = "network operation failed"
		}
		return clientErr
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			clientErr.Type = ErrorTypeTimeout
			clientErr.Message = "network timeout occurred"
		} else {
			clientErr.Type = ErrorTypeNetwork
			clientErr.Message = "network error occurred"
		}
		return clientErr
	}

	errMsg := err.Error()
	clientErr.Type = ErrorTypeUnknown
	clientErr.Message = errMsg

	switch {
	case validation.ContainsFold(errMsg, "context canceled"):
		clientErr.Type = ErrorTypeContextCanceled
		clientErr.Message = "request context was canceled"
	case validation.ContainsFold(errMsg, "context deadline exceeded"):
		clientErr.Type = ErrorTypeTimeout
		clientErr.Message = "request context deadline exceeded"
	case validation.ContainsFold(errMsg, "stopped after") && validation.ContainsFold(errMsg, "redirect"):
		clientErr.Type = ErrorTypeValidation
		clientErr.Message = "redirect limit exceeded"
	case validation.ContainsFold(errMsg, "circular redirect"):
		clientErr.Type = ErrorTypeValidation
		clientErr.Message = "circular redirect detected"
	case validation.ContainsFold(errMsg, "redirect blocked"):
		clientErr.Type = ErrorTypeValidation
		clientErr.Message = "redirect blocked by policy"
	case validation.ContainsFold(errMsg, "http2") && validation.ContainsFold(errMsg, "invalid"):
		clientErr.Type = ErrorTypeValidation
		clientErr.Message = "invalid HTTP/2 request header"
	case validation.ContainsFold(errMsg, "connection refused"):
		clientErr.Type = ErrorTypeNetwork
		clientErr.Message = "connection refused by server"
	case validation.ContainsFold(errMsg, "no such host"):
		clientErr.Type = ErrorTypeDNS
		clientErr.Message = "DNS resolution failed"
	case validation.ContainsFold(errMsg, "connection reset"):
		clientErr.Type = ErrorTypeNetwork
		clientErr.Message = "connection reset by peer"
	case validation.ContainsFold(errMsg, "connection closed") || validation.ContainsFold(errMsg, "peer closed"):
		clientErr.Type = ErrorTypeNetwork
		clientErr.Message = "connection closed by peer"
	case validation.ContainsFold(errMsg, "broken pipe"):
		clientErr.Type = ErrorTypeNetwork
		clientErr.Message = "broken pipe"
	case validation.ContainsFold(errMsg, "network unreachable"):
		clientErr.Type = ErrorTypeNetwork
		clientErr.Message = "network unreachable"
	case validation.ContainsFold(errMsg, "host unreachable"):
		clientErr.Type = ErrorTypeNetwork
		clientErr.Message = "host unreachable"
	case (validation.ContainsFold(errMsg, "tls") || validation.ContainsFold(errMsg, "ssl")) && validation.ContainsFold(errMsg, "handshake"):
		clientErr.Type = ErrorTypeTLS
		clientErr.Message = "TLS handshake error"
	case validation.ContainsFold(errMsg, "certificate") || validation.ContainsFold(errMsg, "x509"):
		clientErr.Type = ErrorTypeCertificate
		clientErr.Message = "certificate validation error"
	case validation.ContainsFold(errMsg, "transport"):
		clientErr.Type = ErrorTypeTransport
		clientErr.Message = "HTTP transport error"
	case validation.ContainsFold(errMsg, "protocol error"):
		clientErr.Type = ErrorTypeTransport
		clientErr.Message = "HTTP protocol error"
	case validation.ContainsFold(errMsg, "failed to read response body"):
		clientErr.Type = ErrorTypeResponseRead
		clientErr.Message = "failed to read response body"
	case validation.ContainsFold(errMsg, "unexpected eof"):
		clientErr.Type = ErrorTypeResponseRead
		clientErr.Message = "unexpected end of response"
	case validation.ContainsFold(errMsg, "validation failed"):
		clientErr.Type = ErrorTypeValidation
		clientErr.Message = "request validation failed"
	case validation.ContainsFold(errMsg, "invalid url") || validation.ContainsFold(errMsg, "missing protocol scheme"):
		clientErr.Type = ErrorTypeValidation
		clientErr.Message = "URL validation failed"
	case validation.ContainsFold(errMsg, "http 4") || validation.ContainsFold(errMsg, "http 5"):
		clientErr.Type = ErrorTypeHTTP
		clientErr.StatusCode = extractStatusCode(errMsg)
	case validation.ContainsFold(errMsg, "timeout") || validation.ContainsFold(errMsg, "timed out"):
		if !validation.ContainsFold(errMsg, "context") {
			clientErr.Type = ErrorTypeTimeout
			clientErr.Message = "operation timed out"
		}
	}

	// Fallback: if we unwrapped a *url.Error but the inner error didn't match
	// any specific type or string pattern, classify as network error.
	// This handles cases like io.EOF from server connection close where
	// the inner error is not a typed net error but the outer *url.Error
	// (which implements net.Error) indicates a network-level failure.
	if clientErr.Type == ErrorTypeUnknown && urlErr != nil {
		clientErr.Type = ErrorTypeNetwork
		clientErr.Message = "network error occurred"
	}

	return clientErr
}

// extractStatusCode extracts a 3-digit HTTP status code from an error message.
// Matches a space-prefixed 3-digit code in the 400-599 range that is not
// part of a longer number (e.g., avoids matching "404" inside "4043").
func extractStatusCode(msg string) int {
	for i := 0; i <= len(msg)-3; i++ {
		c := msg[i]
		if c >= '4' && c <= '5' && isDigit(msg[i+1]) && isDigit(msg[i+2]) {
			// Must be preceded by space (or start of string)
			if i > 0 && msg[i-1] != ' ' {
				continue
			}
			// Must NOT be followed by another digit (avoid matching inside "4043")
			if i+3 < len(msg) && isDigit(msg[i+3]) {
				continue
			}
			code := int(c-'0')*100 + int(msg[i+1]-'0')*10 + int(msg[i+2]-'0')
			if code >= 400 && code <= 599 {
				return code
			}
		}
	}
	return 0
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
