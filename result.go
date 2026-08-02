package httpc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// resultBuilderPool reduces allocations for strings.Builder used in Result.String().
// A separate pool exists in engine/request.go for engine-internal use; kept
// separate to avoid cross-package pool contention.
var resultBuilderPool = sync.Pool{
	New: func() any {
		sb := &strings.Builder{}
		return sb
	},
}

const (
	maxBodyPreview   = 200 // Maximum body preview length in String()
	truncationMarker = "...[truncated]"
	// maxResultBuilderCap bounds the backing array retained by resultBuilderPool.
	// Mirrors the cap guards on formBuilderPool / errorBuilderPool so a result
	// with an unusually large header set cannot bloat the pooled builder.
	maxResultBuilderCap = 4096
)

// sensitiveHeaders contains header names that should be masked in String() and audit output.
// Keys use http.CanonicalHeaderKey form (Title-Case).
// Read-only after initialization — must not be mutated (concurrent reads).
var sensitiveHeaders = map[string]bool{
	"Authorization":       true,
	"Cookie":              true,
	"Set-Cookie":          true,
	"X-Api-Key":           true,
	"X-Auth-Token":        true,
	"Proxy-Authorization": true,
}

// cachedSensitiveHeaderNames is a pre-computed slice of sensitive header names.
// Avoids map iteration and allocation on every DefaultAuditConfig() call.
var cachedSensitiveHeaderNames = func() []string {
	names := make([]string, 0, len(sensitiveHeaders))
	for k := range sensitiveHeaders {
		names = append(names, k)
	}
	return names
}()

// Result wraps an HTTP response with request metadata and convenience methods.
// Obtain a Result from Client.Request() or package-level functions like Get(), Post(), etc.
// Each Result is freshly allocated per request; GC reclaims it automatically, so
// callers need not release it. (The internal engine.Response is pooled separately
// for performance, but that is transparent to the caller.)
//
// Access style: prefer the nil-safe accessor methods (StatusCode, Body, RawBody,
// IsSuccess, GetCookie, etc.). The Request, Response, and Meta struct fields are
// exported primarily so callers can construct Result values directly in tests and
// mocks; reading them on a client-returned Result requires a nil-check on the
// nested pointer (e.g. Response may be nil when the request errored).
type Result struct {
	Request  *RequestInfo
	Response *ResponseInfo
	Meta     *RequestMeta
}

// RequestInfo contains details about the HTTP request that was sent.
type RequestInfo struct {
	// URL is the request URL.
	URL string
	// Method is the HTTP method used.
	Method string
	// Headers contains the request headers.
	Headers http.Header
	// Cookies contains the request cookies.
	Cookies []*http.Cookie
}

// ResponseInfo contains the HTTP response data including status, headers, body, and cookies.
type ResponseInfo struct {
	// StatusCode is the HTTP status code.
	StatusCode int
	// Status is the HTTP status text.
	Status string
	// Proto is the HTTP protocol version.
	Proto string
	// Headers contains the response headers.
	Headers http.Header
	// Body is the response body as a string.
	Body string
	// RawBody is the raw response body bytes.
	RawBody []byte
	// ContentLength is the Content-Length from the response.
	ContentLength int64
	// Cookies contains the response cookies.
	Cookies []*http.Cookie
}

// RequestMeta contains metadata about the request execution including timing and redirect info.
type RequestMeta struct {
	// Duration is the total time from request start to response completion.
	Duration time.Duration
	// Attempts is the number of request attempts including retries.
	Attempts int
	// RedirectChain contains the URLs followed during redirects.
	RedirectChain []string
	// RedirectCount is the number of redirects followed.
	RedirectCount int
}

// Body returns the response body as a string.
// Returns an empty string if the Result or Response is nil.
func (r *Result) Body() string {
	if r == nil || r.Response == nil {
		return ""
	}
	return r.Response.Body
}

// RawBody returns the response body as a byte slice.
// Returns nil if the Result or Response is nil.
func (r *Result) RawBody() []byte {
	if r == nil || r.Response == nil {
		return nil
	}
	return r.Response.RawBody
}

// StatusCode returns the HTTP status code from the response.
// Returns 0 if the Result or Response is nil.
func (r *Result) StatusCode() int {
	if r == nil || r.Response == nil {
		return 0
	}
	return r.Response.StatusCode
}

// Proto returns the HTTP protocol version (e.g., "HTTP/1.1", "HTTP/2.0").
func (r *Result) Proto() string {
	if r == nil || r.Response == nil {
		return ""
	}
	return r.Response.Proto
}

// RequestCookies returns the cookies that were sent with the request.
// Returns nil if the Result or Request is nil.
func (r *Result) RequestCookies() []*http.Cookie {
	if r == nil || r.Request == nil {
		return nil
	}
	return r.Request.Cookies
}

// ResponseCookies returns the cookies from the response.
// Returns nil if the Result or Response is nil.
func (r *Result) ResponseCookies() []*http.Cookie {
	if r == nil || r.Response == nil {
		return nil
	}
	return r.Response.Cookies
}

// Unmarshal parses the JSON-encoded response body and stores the result
// in the value pointed to by v. It follows the same conventions as json.Unmarshal.
//
// Returns ErrResponseBodyEmpty if the body is nil or empty.
// Returns ErrResponseBodyTooLarge if the body exceeds 50MB.
func (r *Result) Unmarshal(v any) error {
	if r == nil || r.Response == nil {
		return ErrResponseBodyEmpty
	}

	bodyLen := len(r.Response.RawBody)
	if bodyLen == 0 {
		return ErrResponseBodyEmpty
	}

	if bodyLen > maxJSONSize {
		return fmt.Errorf("%w: %d bytes exceeds 50MB", ErrResponseBodyTooLarge, bodyLen)
	}

	return json.Unmarshal(r.Response.RawBody, v)
}

// statusInRange returns true if the response status code is in [lo, hi).
func (r *Result) statusInRange(lo, hi int) bool {
	if r == nil || r.Response == nil {
		return false
	}
	return r.Response.StatusCode >= lo && r.Response.StatusCode < hi
}

// IsSuccess returns true if the response status code indicates success (2xx).
func (r *Result) IsSuccess() bool {
	return r.statusInRange(200, 300)
}

// IsRedirect returns true if the response status code indicates a redirect (3xx).
func (r *Result) IsRedirect() bool {
	return r.statusInRange(300, 400)
}

// IsClientError returns true if the response status code indicates a client error (4xx).
func (r *Result) IsClientError() bool {
	return r.statusInRange(400, 500)
}

// IsServerError returns true if the response status code indicates a server error (5xx).
func (r *Result) IsServerError() bool {
	return r.statusInRange(500, 600)
}

// GetCookie returns a response cookie by name, or nil if not found.
func (r *Result) GetCookie(name string) *http.Cookie {
	if r == nil || r.Response == nil {
		return nil
	}
	for _, cookie := range r.Response.Cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

// HasCookie returns true if a response cookie with the given name exists.
func (r *Result) HasCookie(name string) bool {
	return r.GetCookie(name) != nil
}

// GetRequestCookie returns a request cookie by name, or nil if not found.
func (r *Result) GetRequestCookie(name string) *http.Cookie {
	if r == nil || r.Request == nil {
		return nil
	}
	for _, cookie := range r.Request.Cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

// HasRequestCookie returns true if a request cookie with the given name exists.
func (r *Result) HasRequestCookie(name string) bool {
	return r.GetRequestCookie(name) != nil
}

// String returns a human-readable representation of the Result.
// Sensitive headers are masked. Body is truncated to 200 characters.
func (r *Result) String() string {
	if r == nil || r.Response == nil {
		return "Result{}"
	}

	// Pre-calculate approximate size to reduce allocations
	estimatedSize := 128 + len(r.Response.Status) // Base size for status, content length
	if r.Meta != nil {
		estimatedSize += 64 // Duration and attempts
	}
	if len(r.Response.Headers) > 0 {
		estimatedSize += 32 + len(r.Response.Headers)*16 // Headers
	}
	if len(r.Response.Cookies) > 0 {
		estimatedSize += 32 // Cookies count
	}
	if len(r.Response.Body) > 0 {
		bodyPreview := min(len(r.Response.Body), maxBodyPreview)
		estimatedSize += 16 + bodyPreview + len(truncationMarker)
	}

	// Use pooled strings.Builder to reduce allocations
	b, ok := resultBuilderPool.Get().(*strings.Builder)
	if !ok || b == nil {
		b = &strings.Builder{}
	}
	b.Reset()
	b.Grow(estimatedSize)

	var numBuf [20]byte

	b.WriteString("Result{Status: ")
	b.Write(strconv.AppendInt(numBuf[:0], int64(r.Response.StatusCode), 10))
	b.WriteByte(' ')
	b.WriteString(r.Response.Status)
	b.WriteString(", ContentLength: ")
	b.Write(strconv.AppendInt(numBuf[:0], r.Response.ContentLength, 10))

	if r.Meta != nil {
		b.WriteString(", Duration: ")
		b.WriteString(r.Meta.Duration.String())
		b.WriteString(", Attempts: ")
		b.Write(strconv.AppendInt(numBuf[:0], int64(r.Meta.Attempts), 10))
	}

	if len(r.Response.Headers) > 0 {
		b.WriteString(", Headers: ")
		b.Write(strconv.AppendInt(numBuf[:0], int64(len(r.Response.Headers)), 10))
		b.WriteString(" [")
		first := true
		for key := range r.Response.Headers {
			if !first {
				b.WriteString(", ")
			}
			first = false
			if sensitiveHeaders[key] {
				b.WriteString(key)
				b.WriteString(": ***")
			} else {
				b.WriteString(key)
			}
		}
		b.WriteByte(']')
	}

	if len(r.Response.Cookies) > 0 {
		b.WriteString(", Cookies: ")
		b.Write(strconv.AppendInt(numBuf[:0], int64(len(r.Response.Cookies)), 10))
	}

	if len(r.Response.Body) > 0 {
		b.WriteString(", Body: ")
		if len(r.Response.Body) > maxBodyPreview {
			b.WriteString(r.Response.Body[:maxBodyPreview])
			b.WriteString(truncationMarker)
		} else {
			b.WriteString(r.Response.Body)
		}
	}

	b.WriteByte('}')

	result := b.String()
	// Guard against retaining an oversized backing array in the pool — matches
	// the cap guards on formBuilderPool and errorBuilderPool.
	if b.Cap() <= maxResultBuilderCap {
		resultBuilderPool.Put(b)
	}
	return result
}

// SaveToFile saves the response body to a file at the specified path.
// Returns ErrResponseBodyEmpty if the response body is nil or empty.
// The file path is validated for security (path traversal, symlinks, etc.).
func (r *Result) SaveToFile(filePath string) error {
	if r == nil || r.Response == nil || r.Response.RawBody == nil {
		return ErrResponseBodyEmpty
	}

	validatedPath, err := prepareFilePath(filePath)
	if err != nil {
		return fmt.Errorf("file path validation failed: %w", err)
	}

	if err := os.WriteFile(validatedPath, r.Response.RawBody, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
