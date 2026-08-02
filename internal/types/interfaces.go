// Package types provides shared type definitions used across the httpc library.
// This package eliminates interface duplication between public and internal layers,
// enabling compile-time type checking without runtime type assertions.
package types

import (
	"context"
	"net/http"
	"time"
)

// requestReader provides read-only access to request data for middleware.
// It is embedded in the exported RequestMutator, so middleware automatically
// gains full read access to all request properties.
type requestReader interface {
	Method() string
	URL() string
	Headers() map[string]string
	QueryParams() map[string]any
	Body() any
	Timeout() time.Duration
	MaxRetries() int
	Context() context.Context
	Cookies() []http.Cookie
	FollowRedirects() *bool
	MaxRedirects() *int
	StreamBody() bool
}

// requestWriter provides write-only access to request data for middleware.
// It is embedded in the exported RequestMutator, so middleware automatically
// gains full write access to all request properties.
type requestWriter interface {
	SetMethod(string)
	SetURL(string)
	SetHeaders(map[string]string)
	SetHeader(key, value string)
	SetQueryParams(map[string]any)
	SetBody(any)
	SetTimeout(time.Duration)
	SetMaxRetries(int)
	SetContext(context.Context)
	SetCookies([]http.Cookie)
	SetFollowRedirects(*bool)
	SetMaxRedirects(*int)
	SetStreamBody(bool)
}

// RequestMutator provides read-write access to request data for middleware.
// It embeds requestReader and requestWriter for full access to request properties.
// Middleware can inspect and modify request properties before the request is sent.
type RequestMutator interface {
	requestReader
	requestWriter
}

// ResponseReader provides read-only access to response data for middleware.
// Use this interface when middleware only needs to inspect response properties
// without modifying them.
type ResponseReader interface {
	StatusCode() int
	Status() string
	Proto() string
	Headers() http.Header
	Body() string
	RawBody() []byte
	ContentLength() int64
	Duration() time.Duration
	Attempts() int
	Cookies() []*http.Cookie
	RedirectChain() []string
	RedirectCount() int
	RequestHeaders() http.Header
	RequestURL() string
	RequestMethod() string
}

// responseWriter provides write-only access to response data for middleware.
// It is embedded in the exported ResponseMutator, so middleware automatically
// gains full write access to all response properties.
type responseWriter interface {
	SetStatusCode(int)
	SetStatus(string)
	SetProto(string)
	SetHeaders(http.Header)
	SetBody(string)
	SetRawBody([]byte)
	SetContentLength(int64)
	SetDuration(time.Duration)
	SetAttempts(int)
	SetCookies([]*http.Cookie)
	SetRedirectChain([]string)
	SetRedirectCount(int)
	SetRequestHeaders(http.Header)
	SetRequestURL(string)
	SetRequestMethod(string)
	SetHeader(key string, values ...string)
}

// ResponseMutator provides read-write access to response data for middleware.
// It embeds ResponseReader and responseWriter for full access to response properties.
// Middleware can inspect and modify response properties after the request completes.
// This is useful for:
//   - Response caching middleware
//   - Response transformation (e.g., JSON pretty-printing)
//   - Content encoding/decoding
//   - Response filtering
type ResponseMutator interface {
	ResponseReader
	responseWriter
}

// Handler processes an HTTP request and returns a response.
// This is the core function signature for request processing in the middleware chain.
type Handler func(ctx context.Context, req RequestMutator) (ResponseMutator, error)

// MiddlewareFunc wraps a Handler with additional functionality.
// Middleware can inspect/modify requests, handle responses, add logging, etc.
type MiddlewareFunc func(Handler) Handler

// RetryPolicy defines the interface for custom retry behavior.
// Implementations can provide custom retry strategies beyond the default
// exponential backoff with jitter.
//
// Example implementation:
//
//	type CustomRetryPolicy struct {
//	    maxRetries int
//	}
//
//	func (p *CustomRetryPolicy) ShouldRetry(resp ResponseReader, err error, attempt int) bool {
//	    if err != nil {
//	        return true // Retry on errors
//	    }
//	    if resp.StatusCode() >= 500 && resp.StatusCode() < 600 {
//	        return attempt < p.maxRetries
//	    }
//	    return false
//	}
//
//	func (p *CustomRetryPolicy) GetDelay(attempt int) time.Duration {
//	    return time.Second * time.Duration(attempt+1)
//	}
//
//	func (p *CustomRetryPolicy) MaxRetries() int {
//	    return p.maxRetries
//	}
type RetryPolicy interface {
	// ShouldRetry determines if a request should be retried based on the
	// response, error, and current attempt number (0-indexed).
	// Return true to retry, false to stop.
	ShouldRetry(resp ResponseReader, err error, attempt int) bool

	// GetDelay returns the delay duration before the next retry attempt.
	GetDelay(attempt int) time.Duration

	// MaxRetries returns the maximum number of retry attempts.
	MaxRetries() int
}
