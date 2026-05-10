package httpc

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/cybergodev/httpc/internal/engine"
	"github.com/cybergodev/httpc/internal/validation"
)

// WithHeader sets a single HTTP header on the request.
// Returns ErrInvalidHeader if the key or value contains invalid characters
// (CRLF injection prevention).
func WithHeader(key, value string) RequestOption {
	return func(r *engine.Request) error {
		if err := validation.ValidateHeaderKeyValue(key, value); err != nil {
			return fmt.Errorf("invalid header: %w", err)
		}
		r.SetHeader(key, value)
		return nil
	}
}

// WithHeaderMap sets multiple headers from a map.
// Returns ErrInvalidHeader if any key or value contains invalid characters
// (CRLF injection prevention).
func WithHeaderMap(headers map[string]string) RequestOption {
	return func(r *engine.Request) error {
		for k, v := range headers {
			if err := validation.ValidateHeaderKeyValue(k, v); err != nil {
				return fmt.Errorf("invalid header %q: %w", k, err)
			}
			r.SetHeader(k, v)
		}
		return nil
	}
}

// WithUserAgent sets the User-Agent header.
// This is kept as a convenience function since it's commonly used.
func WithUserAgent(userAgent string) RequestOption {
	return WithHeader("User-Agent", userAgent)
}

// WithBasicAuth sets HTTP Basic Authentication using the provided username and password.
func WithBasicAuth(username, password string) RequestOption {
	return func(r *engine.Request) error {
		if username == "" {
			return fmt.Errorf("username cannot be empty")
		}
		if err := validation.ValidateCredential(username, validation.MaxCredLen, true, "username"); err != nil {
			return fmt.Errorf("invalid username: %w", err)
		}
		if err := validation.ValidateCredential(password, validation.MaxCredLen, false, "password"); err != nil {
			return fmt.Errorf("invalid password: %w", err)
		}

		// Efficient string concatenation and encoding
		creds := username + ":" + password
		r.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
		return nil
	}
}

// WithBearerToken sets the Authorization header to "Bearer <token>".
func WithBearerToken(token string) RequestOption {
	return func(r *engine.Request) error {
		if token == "" {
			return fmt.Errorf("token cannot be empty")
		}
		if err := validation.ValidateToken(token); err != nil {
			return err
		}

		r.SetHeader("Authorization", "Bearer "+token)
		return nil
	}
}

// WithQuery sets a single query parameter on the request.
func WithQuery(key string, value any) RequestOption {
	return func(r *engine.Request) error {
		if err := validation.ValidateQueryKey(key); err != nil {
			return err
		}

		if value != nil {
			if valueLen := queryValueLength(value); valueLen > validation.MaxValueLen {
				return fmt.Errorf("query value too long (max %d)", validation.MaxValueLen)
			}
		}

		params := r.QueryParams()
		if params == nil {
			// Pre-allocate with capacity for typical query params
			params = make(map[string]any, 4)
			r.SetQueryParams(params)
		}
		params[key] = value
		return nil
	}
}

// WithQueryMap sets multiple query parameters from a map.
func WithQueryMap(params map[string]any) RequestOption {
	return func(r *engine.Request) error {
		existing := r.QueryParams()
		if existing == nil {
			existing = make(map[string]any, len(params))
		}

		for k, v := range params {
			if err := validation.ValidateQueryKey(k); err != nil {
				return fmt.Errorf("invalid key %s: %w", k, err)
			}

			if v != nil {
				if valueLen := queryValueLength(v); valueLen > validation.MaxValueLen {
					return fmt.Errorf("query value too long for key %s (max %d)", k, validation.MaxValueLen)
				}
			}
			existing[k] = v
		}
		r.SetQueryParams(existing)
		return nil
	}
}

// queryValueLength returns the string length of a formatted query value.
func queryValueLength(v any) int {
	return len(engine.FormatQueryParam(v))
}

// WithJSON sets the request body as JSON and sets Content-Type to application/json.
func WithJSON(data any) RequestOption {
	return func(r *engine.Request) error {
		if data == nil {
			return fmt.Errorf("JSON data cannot be nil")
		}
		r.SetBody(data)
		r.SetHeader("Content-Type", "application/json")
		return nil
	}
}

// WithXML sets the request body as XML and sets Content-Type to application/xml.
func WithXML(data any) RequestOption {
	return func(r *engine.Request) error {
		if data == nil {
			return fmt.Errorf("XML data cannot be nil")
		}
		r.SetBody(data)
		r.SetHeader("Content-Type", "application/xml")
		return nil
	}
}

// WithBody sets the request body with automatic or explicit type detection.
// When kind is BodyAuto (or omitted), the body type is auto-detected based on the input:
//   - string → text/plain
//   - []byte → application/octet-stream
//   - map[string]string → application/x-www-form-urlencoded
//   - *FormData → multipart/form-data
//   - io.Reader → passed through (no Content-Type set)
//   - other types → application/json (default)
//
// Note: io.Reader bodies bypass request body size validation. For untrusted sources,
// wrap with io.LimitReader to prevent resource exhaustion:
//
//	limited := io.LimitReader(untrustedReader, 10<<20) // 10 MB cap
//
// Explicit kinds (BodyJSON, BodyXML, BodyForm, BodyBinary, BodyMultipart) override auto-detection.
//
// Example:
//
//	// Auto-detect (JSON for struct/map)
//	result, err := client.Post(ctx, url, httpc.WithBody(data, httpc.BodyAuto))
//
//	// Explicit XML
//	result, err := client.Post(ctx, url, httpc.WithBody(data, httpc.BodyXML))
//
//	// Auto-detect omitted (same as BodyAuto)
//	result, err := client.Post(ctx, url, httpc.WithBody(data))
func WithBody(data any, kind ...BodyKind) RequestOption {
	return func(r *engine.Request) error {
		if data == nil {
			return fmt.Errorf("request body cannot be nil")
		}

		bodyKind := BodyAuto
		if len(kind) > 0 {
			bodyKind = kind[0]
		}

		switch bodyKind {
		case BodyJSON:
			r.SetBody(data)
			r.SetHeader("Content-Type", "application/json")
		case BodyXML:
			r.SetBody(data)
			r.SetHeader("Content-Type", "application/xml")
		case BodyForm:
			formData, err := convertToForm(data)
			if err != nil {
				return fmt.Errorf("convert to form data: %w", err)
			}
			r.SetBody(formData)
			r.SetHeader("Content-Type", "application/x-www-form-urlencoded")
		case BodyBinary:
			binaryData, err := convertToBinary(data)
			if err != nil {
				return fmt.Errorf("convert to binary: %w", err)
			}
			r.SetBody(binaryData)
			r.SetHeader("Content-Type", "application/octet-stream")
		case BodyMultipart:
			formData, ok := data.(*FormData)
			if !ok {
				return fmt.Errorf("multipart body requires *FormData, got %T", data)
			}
			r.SetBody(formData)
		case BodyAuto:
			fallthrough
		default:
			contentType, err := setAutoDetectedBody(r, data)
			if err != nil {
				return err
			}
			if contentType != "" {
				r.SetHeader("Content-Type", contentType)
			}
		}

		return nil
	}
}

// encodeFormFields encodes a map[string]string to url-encoded form string.
func encodeFormFields(data map[string]string) string {
	values := make(url.Values, len(data))
	for k, v := range data {
		values.Set(k, v)
	}
	return values.Encode()
}

// convertToForm converts data to url-encoded form string.
func convertToForm(data any) (string, error) {
	switch v := data.(type) {
	case map[string]string:
		if v == nil {
			return "", fmt.Errorf("form data cannot be nil")
		}
		return encodeFormFields(v), nil
	case url.Values:
		if v == nil {
			return "", fmt.Errorf("form data cannot be nil")
		}
		return v.Encode(), nil
	default:
		return "", fmt.Errorf("form body requires map[string]string or url.Values, got %T", data)
	}
}

// convertToBinary converts data to []byte for binary body.
func convertToBinary(data any) ([]byte, error) {
	switch v := data.(type) {
	case []byte:
		if len(v) == 0 {
			return nil, fmt.Errorf("binary data cannot be empty")
		}
		return v, nil
	case string:
		if v == "" {
			return nil, fmt.Errorf("binary data cannot be empty")
		}
		return []byte(v), nil
	default:
		return nil, fmt.Errorf("binary body requires []byte or string, got %T", data)
	}
}

// setAutoDetectedBody sets body with auto-detected content type.
// Returns the content type to set, or empty string if no Content-Type should be set.
func setAutoDetectedBody(r *engine.Request, data any) (string, error) {
	switch v := data.(type) {
	case string:
		r.SetBody(v)
		return "text/plain; charset=utf-8", nil
	case []byte:
		if v == nil {
			return "", fmt.Errorf("binary data cannot be nil")
		}
		r.SetBody(v)
		return "application/octet-stream", nil
	case *FormData:
		if v == nil {
			return "", fmt.Errorf("form data cannot be nil")
		}
		r.SetBody(v)
		// Content-Type will be set by multipart writer with boundary
		return "", nil
	case io.Reader:
		r.SetBody(v)
		// Don't set Content-Type for raw reader, let caller handle it
		return "", nil
	case map[string]string:
		if v == nil {
			return "", fmt.Errorf("form data cannot be nil")
		}
		r.SetBody(encodeFormFields(v))
		return "application/x-www-form-urlencoded", nil
	default:
		// Default to JSON for all other types
		r.SetBody(data)
		return "application/json", nil
	}
}

// WithForm sets the request body as URL-encoded form data.
// Each field key and value is validated for control characters and size limits.
func WithForm(data map[string]string) RequestOption {
	return func(r *engine.Request) error {
		if data == nil {
			return fmt.Errorf("form data cannot be nil")
		}
		for k, v := range data {
			if err := validateFormField(k, v); err != nil {
				return err
			}
		}
		encoded, err := convertToForm(data)
		if err != nil {
			return err
		}
		r.SetBody(encoded)
		r.SetHeader("Content-Type", "application/x-www-form-urlencoded")
		return nil
	}
}

// validateFormField checks form field key and value for control characters
// and size limits. Less restrictive than header validation — allows
// underscores, dots, brackets, and other characters valid in form field names.
func validateFormField(key, value string) error {
	if key == "" {
		return fmt.Errorf("form field key cannot be empty")
	}
	if len(key) > validation.MaxHeaderKeyLen {
		return fmt.Errorf("form field key too long: %s (max %d)", key, validation.MaxHeaderKeyLen)
	}
	if len(value) > validation.MaxValueLen {
		return fmt.Errorf("form field value too long for key %s (max %d)", key, validation.MaxValueLen)
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x20 || key[i] == 0x7F {
			return fmt.Errorf("form field key %q contains control characters", key)
		}
	}
	for i := 0; i < len(value); i++ {
		if (value[i] < 0x20 && value[i] != 0x09) || value[i] == 0x7F {
			return fmt.Errorf("form field value for key %q contains control characters", key)
		}
	}
	return nil
}

// WithFormData sets the request body as multipart/form-data.
func WithFormData(data *FormData) RequestOption {
	return func(r *engine.Request) error {
		if data == nil {
			return fmt.Errorf("form data cannot be nil")
		}
		r.SetBody(data)
		return nil
	}
}

// WithFile adds a file upload to the request as multipart/form-data.
func WithFile(fieldName, filename string, content []byte) RequestOption {
	return func(r *engine.Request) error {
		if fieldName == "" {
			return fmt.Errorf("field name cannot be empty")
		}
		if filename == "" {
			return fmt.Errorf("filename cannot be empty")
		}
		if err := validation.ValidateFieldName(fieldName, "field name"); err != nil {
			return fmt.Errorf("invalid field name: %w", err)
		}
		if err := validation.ValidateFieldName(filename, "filename"); err != nil {
			return fmt.Errorf("invalid filename: %w", err)
		}

		cleanFilename := filepath.Base(filename)
		if cleanFilename == "." || cleanFilename == ".." || cleanFilename == "" {
			return fmt.Errorf("invalid filename")
		}

		r.SetBody(&FormData{
			Fields: make(map[string]string, 1), // Pre-allocate for typical case
			Files: map[string]*FileData{
				fieldName: {
					Filename: cleanFilename,
					Content:  content,
				},
			},
		})
		return nil
	}
}

// WithTimeout sets a per-request timeout that overrides the client's default timeout.
func WithTimeout(timeout time.Duration) RequestOption {
	return func(r *engine.Request) error {
		if timeout < 0 {
			return fmt.Errorf("%w: cannot be negative", ErrInvalidTimeout)
		}
		if timeout > maxTimeout {
			return fmt.Errorf("%w: exceeds %v", ErrInvalidTimeout, maxTimeout)
		}
		r.SetTimeout(timeout)
		return nil
	}
}

// WithContext sets the context for the request, enabling timeout and cancellation control.
// The context overrides the client's default timeout for this request.
func WithContext(ctx context.Context) RequestOption {
	return func(r *engine.Request) error {
		if ctx == nil {
			return fmt.Errorf("context cannot be nil")
		}
		r.SetContext(ctx)
		return nil
	}
}

// WithMaxRetries sets the maximum number of retry attempts for this request.
func WithMaxRetries(maxRetries int) RequestOption {
	return func(r *engine.Request) error {
		if maxRetries < 0 || maxRetries > 10 {
			return fmt.Errorf("%w: must be 0-10, got %d", ErrInvalidRetry, maxRetries)
		}
		r.SetMaxRetries(maxRetries)
		return nil
	}
}

// WithFollowRedirects controls whether HTTP redirects are followed for this request.
func WithFollowRedirects(follow bool) RequestOption {
	return func(r *engine.Request) error {
		r.SetFollowRedirects(&follow)
		return nil
	}
}

// WithStreamBody enables streaming mode where the response body is not buffered
// into memory. The caller reads the body directly via the engine Response's
// RawBodyReader. Used internally for file downloads to avoid buffering large files.
func WithStreamBody(stream bool) RequestOption {
	return func(r *engine.Request) error {
		r.SetStreamBody(stream)
		return nil
	}
}

// WithMaxRedirects sets the maximum number of redirects to follow for this request.
func WithMaxRedirects(maxRedirects int) RequestOption {
	return func(r *engine.Request) error {
		if maxRedirects < 0 {
			return fmt.Errorf("maxRedirects cannot be negative")
		}
		if maxRedirects > 50 {
			return fmt.Errorf("maxRedirects exceeds maximum 50")
		}
		r.SetMaxRedirects(&maxRedirects)
		return nil
	}
}

// WithBinary sets binary data as the request body with an optional content type.
func WithBinary(data []byte, contentType ...string) RequestOption {
	return func(r *engine.Request) error {
		if data == nil {
			return fmt.Errorf("binary data cannot be nil")
		}

		r.SetBody(data)

		ct := "application/octet-stream"
		if len(contentType) > 0 && contentType[0] != "" {
			ct = contentType[0]
		}
		r.SetHeader("Content-Type", ct)
		return nil
	}
}

// WithCookie adds a cookie to the request after validation.
func WithCookie(cookie http.Cookie) RequestOption {
	return func(r *engine.Request) error {
		if err := validation.ValidateCookie(&cookie); err != nil {
			return fmt.Errorf("invalid cookie: %w", err)
		}

		r.SetCookies(append(r.Cookies(), cookie))
		return nil
	}
}

// WithCookies adds multiple cookies to the request after validation.
// It is more efficient than calling WithCookie multiple times, as it
// pre-allocates capacity and validates all cookies in a single pass.
//
// Example:
//
//	cookies := []http.Cookie{
//	    {Name: "session_id", Value: "abc123"},
//	    {Name: "user_pref", Value: "dark_mode"},
//	    {Name: "lang", Value: "en"},
//	}
//	result, err := client.Get("https://api.example.com",
//	    httpc.WithCookies(cookies),
//	)
func WithCookies(cookies []http.Cookie) RequestOption {
	return func(r *engine.Request) error {
		if len(cookies) == 0 {
			return nil
		}

		existing := r.Cookies()
		if cap(existing) < len(existing)+len(cookies) {
			newCookies := make([]http.Cookie, len(existing), len(existing)+len(cookies))
			copy(newCookies, existing)
			existing = newCookies
		}

		for i := range cookies {
			if err := validation.ValidateCookie(&cookies[i]); err != nil {
				return fmt.Errorf("invalid cookie %s: %w", cookies[i].Name, err)
			}
			existing = append(existing, cookies[i])
		}

		r.SetCookies(existing)
		return nil
	}
}

// WithCookieMap sets multiple cookies from a map of name-value pairs.
// This is a convenience method for setting multiple simple cookies at once.
// For cookies with additional attributes (Domain, Path, Secure, etc.),
// use WithCookie or WithCookieString instead.
//
// Example:
//
//	cookies := map[string]string{
//	    "session_id": "abc123",
//	    "user_pref":  "dark_mode",
//	    "lang":       "en",
//	}
//	result, err := client.Get("https://api.example.com",
//	    httpc.WithCookieMap(cookies),
//	)
func WithCookieMap(cookies map[string]string) RequestOption {
	return func(r *engine.Request) error {
		if cookies == nil {
			return nil
		}

		existing := r.Cookies()
		// Pre-allocate capacity to avoid multiple allocations
		if cap(existing) < len(existing)+len(cookies) {
			newCookies := make([]http.Cookie, len(existing), len(existing)+len(cookies))
			copy(newCookies, existing)
			existing = newCookies
		}

		for name, value := range cookies {
			cookie := http.Cookie{
				Name:  name,
				Value: value,
			}
			if err := validation.ValidateCookie(&cookie); err != nil {
				return fmt.Errorf("invalid cookie %s: %w", name, err)
			}
			existing = append(existing, cookie)
		}

		r.SetCookies(existing)
		return nil
	}
}

// WithCookieString adds cookies from a raw Cookie header string to the request.
func WithCookieString(cookieString string) RequestOption {
	return func(r *engine.Request) error {
		if cookieString == "" {
			return nil
		}

		cookies, err := parseCookieString(cookieString)
		if err != nil {
			return fmt.Errorf("failed to parse cookie string: %w", err)
		}

		if len(cookies) == 0 {
			return nil
		}

		existing := r.Cookies()
		combined := make([]http.Cookie, len(existing), len(existing)+len(cookies))
		copy(combined, existing)
		for i := range cookies {
			if err := validation.ValidateCookie(&cookies[i]); err != nil {
				return fmt.Errorf("invalid cookie %s: %w", cookies[i].Name, err)
			}
			combined = append(combined, cookies[i])
		}
		r.SetCookies(combined)

		return nil
	}
}

func parseCookieString(cookieString string) ([]http.Cookie, error) {
	// Quick validation for common malformed cases
	if strings.IndexByte(cookieString, '=') < 0 {
		return nil, fmt.Errorf("malformed cookie: missing '=' separator")
	}

	if strings.HasPrefix(cookieString, "=") {
		return nil, fmt.Errorf("malformed cookie: empty name before '='")
	}

	parsedCookies := parseCookieHeader(cookieString)
	if parsedCookies == nil {
		return nil, nil
	}

	cookies := make([]http.Cookie, 0, len(parsedCookies))
	for _, cookie := range parsedCookies {
		cookies = append(cookies, http.Cookie{
			Name:  cookie.Name,
			Value: cookie.Value,
		})
	}

	return cookies, nil
}

// WithOnRequest registers a callback invoked before the request is sent.
// The callback receives the request mutator, allowing inspection or modification
// of the request before it's transmitted.
//
// Multiple callbacks can be chained - they are executed in the order added.
// If any callback returns an error, the request is aborted.
//
// Example:
//
//	result, err := client.Get("https://api.example.com",
//	    httpc.WithOnRequest(func(req httpc.RequestMutator) error {
//	        log.Printf("Sending %s request to %s", req.Method(), req.URL())
//	        return nil
//	    }),
//	)
func WithOnRequest(callback func(req RequestMutator) error) RequestOption {
	return func(r *engine.Request) error {
		if callback == nil {
			return fmt.Errorf("onRequest callback cannot be nil")
		}

		existing := r.OnRequest()
		r.SetOnRequest(func(req *engine.Request) error {
			if existing != nil {
				if err := existing(req); err != nil {
					return err
				}
			}
			return callback(req)
		})
		return nil
	}
}

// WithOnResponse registers a callback invoked after the response is received.
// The callback receives the response mutator, allowing inspection or modification
// of the response before it's returned to the caller.
//
// Multiple callbacks can be chained - they are executed in the order added.
// If any callback returns an error, the request fails with that error.
//
// Example:
//
//	result, err := client.Get("https://api.example.com",
//	    httpc.WithOnResponse(func(resp httpc.ResponseMutator) error {
//	        log.Printf("Received response: %d %s", resp.StatusCode(), resp.Status())
//	        return nil
//	    }),
//	)
func WithOnResponse(callback func(resp ResponseMutator) error) RequestOption {
	return func(r *engine.Request) error {
		if callback == nil {
			return fmt.Errorf("onResponse callback cannot be nil")
		}

		existing := r.OnResponse()
		r.SetOnResponse(func(resp *engine.Response) error {
			if existing != nil {
				if err := existing(resp); err != nil {
					return err
				}
			}
			return callback(resp)
		})
		return nil
	}
}

// WithSecureCookie creates a request option that enforces cookie security attributes
// on cookies already added to the request. The securityConfig defines the required
// security attributes (Secure, HttpOnly, SameSite).
//
// IMPORTANT: This option validates only cookies present at the time it is applied.
// Place WithSecureCookie AFTER all WithCookie/WithCookieMap options:
//
//	// Correct order: add cookies first, then validate
//	result, err := client.Get(url,
//	    httpc.WithCookie(sessionCookie),
//	    httpc.WithCookieMap(otherCookies),
//	    httpc.WithSecureCookie(securityConfig),
//	)
//
// For session-level cookie security that validates all cookies regardless of order,
// use SessionManager.SetCookieSecurity instead.
//
// Example:
//
//	security := &validation.CookieSecurityConfig{
//	    RequireSecure:     true,
//	    RequireHttpOnly:   true,
//	    RequireSameSite:   "Strict",
//	    AllowSameSiteNone: false,
//	}
//	result, err := client.Get("https://api.example.com",
//	    httpc.WithSecureCookie(security),
//	)
func WithSecureCookie(securityConfig *validation.CookieSecurityConfig) RequestOption {
	return func(r *engine.Request) error {
		if securityConfig == nil {
			return fmt.Errorf("security config cannot be nil")
		}

		// IMPORTANT: This option validates only cookies already added at the time it is applied.
		// Place WithSecureCookie AFTER all WithCookie/WithCookieMap options to ensure
		// all cookies are validated. Example:
		//   httpc.WithCookie(c), httpc.WithSecureCookie(sec)
		existing := r.Cookies()
		for i := range existing {
			if err := validation.ValidateCookieSecurity(&existing[i], securityConfig); err != nil {
				return fmt.Errorf("cookie '%s' failed security validation: %w", existing[i].Name, err)
			}
		}

		return nil
	}
}
