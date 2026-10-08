package httpc

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
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
			return fmt.Errorf("%w: %w", ErrInvalidHeader, err)
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
		// Validate in sorted key order so the reported offending key is
		// deterministic regardless of map iteration order.
		for _, k := range sortedKeys(headers) {
			if err := validation.ValidateHeaderKeyValue(k, headers[k]); err != nil {
				return fmt.Errorf("%w %q: %w", ErrInvalidHeader, k, err)
			}
			r.SetHeader(k, headers[k])
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
// Returns ErrInvalidCredentials if username is empty, or if username or password
// exceeds the maximum length or contains invalid characters.
func WithBasicAuth(username, password string) RequestOption {
	return func(r *engine.Request) error {
		if username == "" {
			return fmt.Errorf("%w: username cannot be empty", ErrInvalidCredentials)
		}
		if err := validation.ValidateCredential(username, validation.MaxCredLen, true, "username"); err != nil {
			return fmt.Errorf("%w: invalid username: %w", ErrInvalidCredentials, err)
		}
		if err := validation.ValidateCredential(password, validation.MaxCredLen, false, "password"); err != nil {
			return fmt.Errorf("%w: invalid password: %w", ErrInvalidCredentials, err)
		}

		// Efficient string concatenation and encoding
		creds := username + ":" + password
		r.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
		return nil
	}
}

// WithBearerToken sets the Authorization header to "Bearer <token>".
// Returns ErrInvalidCredentials if token is empty or fails token format validation.
func WithBearerToken(token string) RequestOption {
	return func(r *engine.Request) error {
		if token == "" {
			return fmt.Errorf("%w: token cannot be empty", ErrInvalidCredentials)
		}
		if err := validation.ValidateToken(token); err != nil {
			return fmt.Errorf("%w: invalid token: %w", ErrInvalidCredentials, err)
		}

		r.SetHeader("Authorization", "Bearer "+token)
		return nil
	}
}

// WithQuery sets a single query parameter on the request.
// Returns an error if the key is empty, too long, or contains invalid characters,
// or if the formatted value exceeds the maximum allowed length.
func WithQuery(key string, value any) RequestOption {
	return func(r *engine.Request) error {
		if err := validation.ValidateQueryKey(key); err != nil {
			return err
		}

		// Skip nil values: a nil value emits no parameter, consistent with
		// engine.FormatQueryParam (which formats nil as ""). Previously nil was
		// stored raw and later rendered as the literal "<nil>" in the URL.
		if value == nil {
			return nil
		}
		if valueLen := queryValueLength(value); valueLen > validation.MaxValueLen {
			return fmt.Errorf("query value too long (max %d)", validation.MaxValueLen)
		}

		params := r.EnsureQueryParams()
		params[key] = value
		return nil
	}
}

// WithQueryMap sets multiple query parameters from a map.
// Returns an error if any key is empty, too long, or contains invalid characters,
// or if any formatted value exceeds the maximum allowed length.
func WithQueryMap(params map[string]any) RequestOption {
	return func(r *engine.Request) error {
		existing := r.EnsureQueryParams()

		// Validate in sorted key order so the reported offending key is
		// deterministic regardless of map iteration order (see WithHeaderMap).
		for _, k := range sortedKeys(params) {
			v := params[k]
			if err := validation.ValidateQueryKey(k); err != nil {
				return fmt.Errorf("invalid key %s: %w", k, err)
			}

			// Skip nil values (see WithQuery): a nil value emits no parameter
			// rather than rendering as the literal "<nil>".
			if v == nil {
				continue
			}
			if valueLen := queryValueLength(v); valueLen > validation.MaxValueLen {
				return fmt.Errorf("query value too long for key %s (max %d)", k, validation.MaxValueLen)
			}
			existing[k] = v
		}
		return nil
	}
}

// queryValueLength returns the formatted length of a query parameter value
// WITHOUT materializing the formatted string. For numeric and bool types it
// formats into a stack-allocated buffer (strconv.Append*) and measures the
// result, avoiding the heap allocation that FormatQueryParam (strconv.Itoa/
// FormatFloat) would incur. The value is formatted again later during encoding,
// so computing the length this way removes a redundant per-WithQuery allocation.
// The returned length is identical to len(FormatQueryParam(v)) for all inputs.
//
// MAINTENANCE: This type switch mirrors engine.FormatQueryParam (request.go)
// and engine.writeQueryParamValue (pools.go). If a new type is added to one,
// add it to all three so validation and encoding stay consistent.
func queryValueLength(v any) int {
	switch val := v.(type) {
	case nil:
		return 0
	case string:
		return len(val)
	case bool:
		if val {
			return 4 // "true"
		}
		return 5 // "false"
	case int:
		var buf [20]byte
		return len(strconv.AppendInt(buf[:0], int64(val), 10))
	case int64:
		var buf [20]byte
		return len(strconv.AppendInt(buf[:0], val, 10))
	case int32:
		var buf [20]byte
		return len(strconv.AppendInt(buf[:0], int64(val), 10))
	case uint:
		var buf [20]byte
		return len(strconv.AppendUint(buf[:0], uint64(val), 10))
	case uint64:
		var buf [20]byte
		return len(strconv.AppendUint(buf[:0], val, 10))
	case uint32:
		var buf [20]byte
		return len(strconv.AppendUint(buf[:0], uint64(val), 10))
	case float64:
		var buf [32]byte
		return len(strconv.AppendFloat(buf[:0], val, 'f', -1, 64))
	case float32:
		var buf [32]byte
		return len(strconv.AppendFloat(buf[:0], float64(val), 'f', -1, 32))
	default:
		// fmt.Stringer and other types: fall back to FormatQueryParam.
		return len(engine.FormatQueryParam(v))
	}
}

// WithJSON sets the request body as JSON and sets Content-Type to application/json.
// This is a convenience method; the equivalent is WithBody(data, BodyJSON).
// Returns an error if data is nil.
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
// This is a convenience method; the equivalent is WithBody(data, BodyXML).
// Returns an error if data is nil.
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
//	result, err := client.Post(url,httpc.WithBody(data, httpc.BodyAuto))
//
//	// Explicit XML
//	result, err := client.Post(url,httpc.WithBody(data, httpc.BodyXML))
//
//	// Auto-detect omitted (same as BodyAuto)
//	result, err := client.Post(url,httpc.WithBody(data))
//
// Returns an error if data is nil, or if the body type is incompatible with the
// specified BodyKind (e.g., BodyMultipart requires *FormData, BodyForm requires
// map[string]string or url.Values, BodyBinary requires []byte or string).
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
			// Shared validate-then-encode path with WithForm (see applyFormBody),
			// so both entry points use identical ordering and cannot drift.
			if err := applyFormBody(r, data); err != nil {
				return err
			}
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

// formBuilderPool reduces allocations for building form-encoded strings.
var formBuilderPool = sync.Pool{
	New: func() any { return &strings.Builder{} },
}

// encodeFormFields encodes a map[string]string to url-encoded form string.
// Uses a pooled strings.Builder to avoid the intermediate url.Values map allocation.
// Writes escaped keys/values straight into the builder via AppendQueryEscape,
// avoiding the intermediate string allocations that QueryEscape would incur.
//
// Keys are sorted alphabetically before encoding, producing deterministic output
// for the same input — matching url.Values.Encode() semantics. This ensures
// consistent wire format across calls, which is important for test determinism,
// request signing/HMAC, and caching.
func encodeFormFields(data map[string]string) string {
	if len(data) == 0 {
		return ""
	}
	// Sort keys for deterministic encoding (matches url.Values.Encode behavior).
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	sb, ok := formBuilderPool.Get().(*strings.Builder)
	if !ok || sb == nil {
		sb = &strings.Builder{}
	}
	sb.Reset()
	sb.Grow(len(data) * 32)

	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		engine.AppendQueryEscape(sb, k)
		sb.WriteByte('=')
		engine.AppendQueryEscape(sb, data[k])
	}

	result := sb.String()
	if sb.Cap() <= 4096 {
		formBuilderPool.Put(sb)
	}
	return result
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

// applyFormBody validates, URL-encodes, and sets a form body on the request.
// It is the single shared implementation for the two form-body entry points
// (WithForm and WithBody(data, BodyForm)). Both now use the same
// validate-then-encode ordering — validation runs first, so invalid input is
// rejected before any encoding work — which removes the previous duplication
// and the inconsistent ordering that existed between the two paths.
func applyFormBody(r *engine.Request, data any) error {
	if err := validateFormInput(data); err != nil {
		return err
	}
	encoded, err := convertToForm(data)
	if err != nil {
		return err
	}
	r.SetBody(encoded)
	r.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	return nil
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
		// Reuse the shared validate-then-encode path (applyFormBody) so the
		// auto-detected form body gets the same field validation as WithForm /
		// WithBody(BodyForm). Previously this branch called encodeFormFields
		// directly, skipping control-character and size validation.
		// Returns "" because applyFormBody already sets the Content-Type header,
		// avoiding a redundant SetHeader call by the caller.
		if err := applyFormBody(r, v); err != nil {
			return "", err
		}
		return "", nil
	default:
		// Default to JSON for all other types
		r.SetBody(data)
		return "application/json", nil
	}
}

// WithForm sets the request body as URL-encoded form data.
// Each field key and value is validated for control characters and size limits.
// This is a convenience method with per-field validation; the general-purpose
// alternative is WithBody(data, BodyForm).
// Returns an error if data is nil, or if any field key or value contains control
// characters or exceeds the maximum length.
func WithForm(data map[string]string) RequestOption {
	return func(r *engine.Request) error {
		if data == nil {
			return fmt.Errorf("form data cannot be nil")
		}
		// Shared validate-then-encode path with WithBody(BodyForm) (see applyFormBody).
		return applyFormBody(r, data)
	}
}

// validateFormKey checks a form field key (name) for emptiness, length, and
// control characters. Less restrictive than header validation — allows
// underscores, dots, brackets, and other characters valid in form field names.
func validateFormKey(key string) error {
	if key == "" {
		return fmt.Errorf("form field key cannot be empty")
	}
	if len(key) > validation.MaxHeaderKeyLen {
		return fmt.Errorf("form field key too long: %s (max %d)", key, validation.MaxHeaderKeyLen)
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x20 || key[i] == 0x7F {
			return fmt.Errorf("form field key %q contains control characters", key)
		}
	}
	return nil
}

// validateFormValue checks a single form field value for size and control
// characters. The key is used only for error context.
func validateFormValue(key, value string) error {
	if len(value) > validation.MaxValueLen {
		return fmt.Errorf("form field value too long for key %s (max %d)", key, validation.MaxValueLen)
	}
	for i := 0; i < len(value); i++ {
		if (value[i] < 0x20 && value[i] != 0x09) || value[i] == 0x7F {
			return fmt.Errorf("form field value for key %q contains control characters", key)
		}
	}
	return nil
}

// validateFormField checks form field key and value for control characters
// and size limits. Convenience wrapper around validateFormKey + validateFormValue.
func validateFormField(key, value string) error {
	if err := validateFormKey(key); err != nil {
		return err
	}
	return validateFormValue(key, value)
}

// validateFormInput validates all fields in form input data.
// Handles both map[string]string and url.Values to ensure consistent
// validation regardless of the input type used. Rejects nil inputs so that
// validation (not encoding) is the single gatekeeper for invalid data.
// Fields are validated in sorted key order so the reported offending field is
// deterministic regardless of map iteration order (see WithHeaderMap).
func validateFormInput(data any) error {
	switch v := data.(type) {
	case map[string]string:
		if v == nil {
			return fmt.Errorf("form data cannot be nil")
		}
		keys := sortedKeys(v)
		for _, k := range keys {
			if err := validateFormField(k, v[k]); err != nil {
				return err
			}
		}
	case url.Values:
		if v == nil {
			return fmt.Errorf("form data cannot be nil")
		}
		keys := sortedKeys(v)
		for _, k := range keys {
			// Validate the key once (covers the case of a key with no values,
			// which the per-value loop below would skip).
			if err := validateFormKey(k); err != nil {
				return err
			}
			for _, val := range v[k] {
				if err := validateFormValue(k, val); err != nil {
					return err
				}
			}
		}
	default:
		return fmt.Errorf("form data must be map[string]string or url.Values, got %T", data)
	}
	return nil
}

// sortedKeys returns the keys of m in ascending order. Shared by the
// sorted-validation paths (WithHeaderMap, WithQueryMap, WithCookieMap,
// validateFormInput, SessionManager.SetHeaders) so the first offending key
// reported is stable across runs.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// WithFormData sets the request body as multipart/form-data.
// This is a convenience method; the equivalent is WithBody(data, BodyMultipart).
//
// Concurrency: the *FormData is used as-is, not copied. A single FormData
// value must not be shared across concurrently executing requests — the
// WithFile option mutates its Files map in place, and concurrent requests
// sharing one value would race on that map.
//
// Validation: field names, filenames, and per-file ContentType values
// containing control characters (CR/LF/NUL/DEL, etc.) are rejected — they
// would otherwise allow MIME header injection in the outgoing body. The same
// check runs at the encoding layer, so a FormData constructed directly (not
// via WithFile) is subject to identical limits. A nil *FileData map entry
// fails the request rather than silently dropping the file.
// Returns an error if data is nil.
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
// Multiple WithFile options merge their files into a single multipart body;
// the same field name is overwritten. Any non-form body set earlier is replaced.
// The merge mutates the request's existing *FormData in place — see the
// WithFormData doc for why a FormData value must not be shared across
// concurrent requests.
// Returns an error if fieldName or filename is empty, contains invalid characters,
// or resolves to an invalid path (e.g., ".." or ".").
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

		// Merge into an existing FormData body so multiple WithFile options
		// upload together; any other body type is replaced as before.
		if existing, ok := r.Body().(*FormData); ok {
			if existing.Files == nil {
				existing.Files = make(map[string]*FileData, 1)
			}
			existing.Files[fieldName] = &FileData{
				Filename: cleanFilename,
				Content:  content,
			}
		} else {
			r.SetBody(&FormData{
				Files: map[string]*FileData{
					fieldName: {
						Filename: cleanFilename,
						Content:  content,
					},
				},
			})
		}
		return nil
	}
}

// WithTimeout sets a per-request timeout that overrides the client's default timeout.
// Returns ErrInvalidTimeout if timeout is negative or exceeds 30 minutes.
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
// Returns an error if ctx is nil.
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
// Returns ErrInvalidRetry if maxRetries is negative or exceeds 10.
//
// Note: retrying follows the client's idempotency policy — non-idempotent
// methods (POST, PATCH, custom) are not retried unless the client sets
// Retry.RetryNonIdempotent or this request passes WithRetryNonIdempotent(true);
// in that case MaxRetries only bounds idempotent requests.
func WithMaxRetries(maxRetries int) RequestOption {
	return func(r *engine.Request) error {
		if maxRetries < 0 || maxRetries > maxRetryAttempts {
			return fmt.Errorf("%w: must be 0-%d, got %d", ErrInvalidRetry, maxRetryAttempts, maxRetries)
		}
		r.SetMaxRetries(maxRetries)
		return nil
	}
}

// WithRetryNonIdempotent overrides, for this single request, whether
// non-idempotent methods (POST, PATCH, custom methods) may be retried. It
// takes precedence over the client-level Retry.RetryNonIdempotent setting in
// both directions: WithRetryNonIdempotent(true) retries a POST on a
// client that otherwise forbids it, and WithRetryNonIdempotent(false) pins a
// single attempt on a client that allows it.
//
// SAFETY: enabling retries for a non-idempotent request means a timeout or
// retryable 5xx may cause the request body to be sent more than once. Only
// use it against endpoints that tolerate replay (or protect them with an
// idempotency key). See RetryConfig.RetryNonIdempotent for the default policy.
func WithRetryNonIdempotent(allow bool) RequestOption {
	return func(r *engine.Request) error {
		r.SetRetryNonIdempotent(&allow)
		return nil
	}
}

// WithNoTimeout disables the client-level request timeout (Config.Timeouts.Request)
// for this single request, allowing it to run as long as the server takes.
// It does not affect dial/TLS/response-header timeouts, and two limits still
// apply: an explicit WithTimeout on the same request, and any deadline on the
// caller-provided context (via WithContext or the ctx parameter) are always
// honored.
//
// Use for long-running calls (large uploads/downloads, slow reports) on a
// client whose default timeout would otherwise cut them off.
func WithNoTimeout() RequestOption {
	return func(r *engine.Request) error {
		r.SetNoTimeout(true)
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

// WithAllowPrivateIPs overrides the client's SSRF policy for this single request.
// When allow is true, the request may target localhost and private/reserved IP
// ranges (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, 169.254.0.0/16, etc.) and may
// follow redirects to such addresses. When allow is false, SSRF protection is
// enforced for this request even if the client was configured with
// Security.AllowPrivateIPs=true.
//
// This is a per-request escape hatch from SSRF protection. It is intended for
// cases where a client that uses secure defaults (AllowPrivateIPs=false) must
// occasionally reach an internal service, loopback address, or local development
// server — without relaxing the security posture of the whole client.
//
// SECURITY: Only enable this on requests whose URL is trusted and not derived
// from untrusted user input. SSRF protection exists to prevent an attacker from
// making your process reach private/internal endpoints; disabling it per request
// reopens that risk for this call. For whole-client access to internal services,
// prefer setting Security.AllowPrivateIPs=true on the Config.
//
// Example (default client blocks private IPs; this call opts in per request):
//
//	result, err := httpc.Get("http://localhost:8080/health",
//	    httpc.WithAllowPrivateIPs(true),
//	)
func WithAllowPrivateIPs(allow bool) RequestOption {
	return func(r *engine.Request) error {
		r.SetAllowPrivateIPs(&allow)
		return nil
	}
}

// WithStreamBody enables streaming mode where the response body is not buffered
// into memory; the body is read directly via the engine Response's RawBodyReader.
//
// IMPORTANT: streaming is only effective through Download (and any other path
// that consumes the engine Response directly). When used with the standard
// request methods — Get, Post, Put, Patch, Delete, Head, Options, or Request —
// the request fails with ErrStreamBodyRequiresDownload: those methods buffer
// the body into a Result and cannot hand the stream to the caller, so an empty
// body would be returned silently. To stream a large body without buffering,
// use Download.
func WithStreamBody(stream bool) RequestOption {
	return func(r *engine.Request) error {
		r.SetStreamBody(stream)
		return nil
	}
}

// WithMaxRedirects sets the maximum number of redirects to follow for this request.
// Returns ErrInvalidMaxRedirects if maxRedirects is negative or exceeds 50.
//
// Note: a value of 0 does NOT disable redirects. The engine treats 0 as the
// "not explicitly set" sentinel and falls back to the default limit (10), so
// WithMaxRedirects(0) is equivalent to omitting the option. To disable redirect
// following entirely, use WithFollowRedirects(false) instead.
//
// Counting matches net/http: the limit includes the initial request, so
// WithMaxRedirects(n) follows at most n-1 redirects (the default 10 follows 9).
func WithMaxRedirects(maxRedirects int) RequestOption {
	return func(r *engine.Request) error {
		if maxRedirects < 0 {
			return fmt.Errorf("%w: cannot be negative, got %d", ErrInvalidMaxRedirects, maxRedirects)
		}
		if maxRedirects > maxRedirectLimit {
			return fmt.Errorf("%w: exceeds maximum %d", ErrInvalidMaxRedirects, maxRedirectLimit)
		}
		r.SetMaxRedirects(&maxRedirects)
		return nil
	}
}

// WithBinary sets binary data as the request body with an optional content type.
// Returns an error if data is empty (nil or zero length — matching
// WithBody(BodyBinary)) or the content type contains invalid characters.
func WithBinary(data []byte, contentType ...string) RequestOption {
	return func(r *engine.Request) error {
		if len(data) == 0 {
			return fmt.Errorf("binary data cannot be empty")
		}

		ct := "application/octet-stream"
		if len(contentType) > 0 && contentType[0] != "" {
			ct = contentType[0]
		}
		if err := validation.ValidateHeaderKeyValue("Content-Type", ct); err != nil {
			return fmt.Errorf("invalid content type: %w", err)
		}

		r.SetBody(data)
		r.SetHeader("Content-Type", ct)
		return nil
	}
}

// ensureCookieCapacity grows the slice if needed to accommodate additional entries.
// The minimum capacity of 4 avoids repeated regrowth when cookies are added in
// several small options (the per-request slice starts empty every time).
func ensureCookieCapacity(existing []http.Cookie, additional int) []http.Cookie {
	if cap(existing) < len(existing)+additional {
		newCap := max(len(existing)+additional, 4)
		grown := make([]http.Cookie, len(existing), newCap)
		copy(grown, existing)
		return grown
	}
	return existing
}

// WithCookies adds one or more cookies to the request after validation.
// It pre-allocates capacity and validates all cookies in a single pass.
// Returns an error if any cookie fails validation (empty name, control
// characters, or invalid characters). The error message includes the
// cookie name that failed.
//
// Example:
//
//	// Single cookie
//	result, err := client.Get("https://api.example.com",
//	    httpc.WithCookies([]http.Cookie{{Name: "session_id", Value: "abc123"}}),
//	)
//
//	// Multiple cookies
//	cookies := []http.Cookie{
//	    {Name: "session_id", Value: "abc123"},
//	    {Name: "user_pref", Value: "dark_mode"},
//	    {Name: "lang", Value: "en"},
//	}
//	result, err = client.Get("https://api.example.com",
//	    httpc.WithCookies(cookies),
//	)
func WithCookies(cookies []http.Cookie) RequestOption {
	return func(r *engine.Request) error {
		if len(cookies) == 0 {
			return nil
		}

		existing := ensureCookieCapacity(r.Cookies(), len(cookies))

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
// use WithCookies or WithCookieString instead.
// Returns an error if any cookie name or value fails validation. The error
// message includes the cookie name that failed.
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

		existing := ensureCookieCapacity(r.Cookies(), len(cookies))

		// Iterate in sorted name order so both the reported offending cookie
		// and the resulting Cookie header order are deterministic regardless
		// of map iteration order (see WithHeaderMap).
		for _, name := range sortedKeys(cookies) {
			cookie := http.Cookie{
				Name:  name,
				Value: cookies[name],
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
// Returns an error if the cookie string is malformed (missing '=' separator,
// empty name) or if any parsed cookie fails validation.
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

		existing := ensureCookieCapacity(r.Cookies(), len(cookies))
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
//
// Returns an error if callback is nil.
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
//
// Returns an error if callback is nil.
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
// Place WithSecureCookie AFTER all WithCookies/WithCookieMap options:
//
//	// Correct order: add cookies first, then validate
//	result, err := client.Get(url,
//	    httpc.WithCookies(sessionCookies),
//	    httpc.WithCookieMap(otherCookies),
//	    httpc.WithSecureCookie(securityConfig),
//	)
//
// For session-level cookie security that validates all cookies regardless of order,
// use SessionManager.SetCookieSecurity instead.
//
// Example:
//
//	security := &httpc.CookieSecurityConfig{
//	    RequireSecure:     true,
//	    RequireHttpOnly:   true,
//	    RequireSameSite:   "Strict",
//	    AllowSameSiteNone: false,
//	}
//	result, err := client.Get("https://api.example.com",
//	    httpc.WithSecureCookie(security),
//	)
//
// Returns an error if securityConfig is nil, or if any cookie on the request
// fails the security validation check.
func WithSecureCookie(securityConfig *CookieSecurityConfig) RequestOption {
	return func(r *engine.Request) error {
		if securityConfig == nil {
			return fmt.Errorf("security config cannot be nil")
		}

		existing := r.Cookies()
		for i := range existing {
			if err := validation.ValidateCookieSecurity(&existing[i], securityConfig); err != nil {
				return fmt.Errorf("cookie '%s' failed security validation: %w", existing[i].Name, err)
			}
		}

		return nil
	}
}
