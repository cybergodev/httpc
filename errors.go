package httpc

import (
	"errors"

	"github.com/cybergodev/httpc/internal/engine"
)

// ClientError represents a classified HTTP client error with context.
// It provides detailed error information including error type, retryability,
// and request context.
//
// Use errors.As to check for ClientError:
//
//	var clientErr *httpc.ClientError
//	if errors.As(err, &clientErr) {
//	    fmt.Println(clientErr.Code())
//	    fmt.Println(clientErr.IsRetryable())
//	}
type ClientError = engine.ClientError

// ErrorType represents the classification of an error.
type ErrorType = engine.ErrorType

// Error type constants for error classification.
const (
	// ErrorTypeUnknown indicates an unknown or unclassified error.
	ErrorTypeUnknown ErrorType = engine.ErrorTypeUnknown
	// ErrorTypeNetwork indicates a network-level error (connection refused, DNS failure, etc.).
	ErrorTypeNetwork ErrorType = engine.ErrorTypeNetwork
	// ErrorTypeTimeout indicates a timeout occurred during the request.
	ErrorTypeTimeout ErrorType = engine.ErrorTypeTimeout
	// ErrorTypeContextCanceled indicates the request context was canceled.
	ErrorTypeContextCanceled ErrorType = engine.ErrorTypeContextCanceled
	// ErrorTypeResponseRead indicates an error reading the response body.
	ErrorTypeResponseRead ErrorType = engine.ErrorTypeResponseRead
	// ErrorTypeTransport indicates an HTTP transport-level error.
	ErrorTypeTransport ErrorType = engine.ErrorTypeTransport
	// ErrorTypeRetryExhausted indicates all retry attempts have been exhausted.
	ErrorTypeRetryExhausted ErrorType = engine.ErrorTypeRetryExhausted
	// ErrorTypeTLS indicates a TLS handshake or protocol error.
	ErrorTypeTLS ErrorType = engine.ErrorTypeTLS
	// ErrorTypeCertificate indicates a certificate validation error.
	ErrorTypeCertificate ErrorType = engine.ErrorTypeCertificate
	// ErrorTypeDNS indicates a DNS resolution error.
	ErrorTypeDNS ErrorType = engine.ErrorTypeDNS
	// ErrorTypeValidation indicates a request validation error.
	ErrorTypeValidation ErrorType = engine.ErrorTypeValidation
	// ErrorTypeHTTP indicates an HTTP-level error (4xx, 5xx responses).
	ErrorTypeHTTP ErrorType = engine.ErrorTypeHTTP
)

var (
	// ErrClientClosed is returned when attempting to use a closed client.
	// This occurs after calling Close() on a client instance.
	// Use errors.Is(err, httpc.ErrClientClosed) to detect this condition.
	ErrClientClosed = engine.ErrClientClosed

	// ErrNilConfig is returned when a nil configuration is provided.
	// Always provide a valid Config or use DefaultConfig().
	ErrNilConfig = errors.New("config cannot be nil")

	// ErrInvalidHeader is returned when header validation fails.
	// Headers must not contain control characters or exceed size limits.
	ErrInvalidHeader = errors.New("invalid header")

	// ErrInvalidTimeout is returned when timeout is negative or exceeds limits.
	// Timeout must be between 0 and 30 minutes.
	ErrInvalidTimeout = errors.New("invalid timeout")

	// ErrInvalidRetry is returned when retry configuration is invalid.
	// MaxRetries must be 0-10, BackoffFactor must be 1.0-10.0.
	ErrInvalidRetry = errors.New("invalid retry configuration")

	// ErrInvalidConnection is returned when connection configuration is invalid.
	// MaxIdleConns and MaxConnsPerHost must be within allowed ranges.
	ErrInvalidConnection = errors.New("invalid connection configuration")

	// ErrInvalidSecurity is returned when security configuration is invalid.
	// MaxResponseBodySize and MaxDecompressedBodySize must be within allowed ranges.
	ErrInvalidSecurity = errors.New("invalid security configuration")

	// ErrInvalidMiddleware is returned when middleware configuration is invalid.
	// MaxRedirects must be 0-50, UserAgent must not exceed length limit.
	ErrInvalidMiddleware = errors.New("invalid middleware configuration")

	// ErrEmptyFilePath is returned when file path is empty.
	// Provide a valid file path for download operations.
	ErrEmptyFilePath = errors.New("file path cannot be empty")

	// ErrFileExists is returned when file already exists and Overwrite is false.
	// Set Overwrite=true or ResumeDownload=true in DownloadConfig.
	ErrFileExists = errors.New("file already exists")

	// ErrResponseBodyEmpty is returned when attempting to parse empty response body.
	// Check response.RawBody before calling Unmarshal() or other parsing methods.
	ErrResponseBodyEmpty = errors.New("response body is empty")

	// ErrResponseBodyTooLarge is returned when response body exceeds size limit.
	// Increase MaxResponseBodySize in Config or reduce response size.
	ErrResponseBodyTooLarge = errors.New("response body too large")
)
