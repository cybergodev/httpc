package validation

import (
	"net/url"
	"strings"
	"sync"
)

// sensitiveQueryParamNames contains query parameter names whose values should be
// redacted when sanitizing URLs for logging and error messages.
// Shared across packages to avoid duplicate definitions.
// Read-only after initialization — must not be mutated (concurrent reads).
var sensitiveQueryParamNames = map[string]bool{
	// OAuth and authentication tokens
	"token": true, "access_token": true, "refresh_token": true,
	"id_token": true, "idtoken": true, "bearer": true,
	// API keys and secrets
	"api_key": true, "apikey": true, "api-key": true,
	"secret": true, "secret_key": true, "client_secret": true,
	"private_key": true, "privatekey": true, "private-key": true,
	// Passwords and credentials
	"password": true, "passwd": true, "pass": true, "pwd": true,
	"credential": true, "credentials": true,
	// Session identifiers
	"session_id": true, "sessionid": true,
	// JWT and signatures
	"jwt": true, "signature": true, "sign": true, "sig": true,
}

// asciiToLower converts ASCII uppercase letters to lowercase in-place using a
// stack-allocated buffer. Avoids heap allocation from strings.ToLower for
// typical short query parameter names.
func asciiToLower(s string) string {
	// Fast path: check if any uppercase exists
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	var buf [128]byte
	if len(s) > len(buf) {
		return strings.ToLower(s)
	}
	b := buf[:len(s)]
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// isSensitiveQueryParamCI performs case-insensitive lookup for sensitive query param names.
func isSensitiveQueryParamCI(name string) bool {
	return sensitiveQueryParamNames[asciiToLower(name)]
}

// IsSensitiveQueryParam reports whether the given query parameter name is
// considered sensitive and should be redacted from logs and cache keys.
func IsSensitiveQueryParam(name string) bool {
	return isSensitiveQueryParamCI(name)
}

// redactSensitiveParams replaces values of sensitive query parameters with [REDACTED].
// Operates directly on the raw query string to avoid url.Values allocation.
func redactSensitiveParams(rawQuery string) string {
	b := getSanitizeBuilder()
	b.Grow(len(rawQuery) + 64)

	start := 0
	for start <= len(rawQuery) {
		// Find the end of this parameter (next & or end of string)
		end := len(rawQuery)
		if ampIdx := strings.IndexByte(rawQuery[start:], '&'); ampIdx >= 0 {
			end = start + ampIdx
		}

		// Split into key=value at the first =
		param := rawQuery[start:end]
		if key, _, found := strings.Cut(param, "="); found {
			if isSensitiveQueryParamCI(key) {
				b.WriteString(key)
				b.WriteString("=[REDACTED]")
			} else {
				b.WriteString(param)
			}
		} else {
			// Key without value
			if isSensitiveQueryParamCI(param) {
				b.WriteString(param)
				b.WriteString("=[REDACTED]")
			} else {
				b.WriteString(param)
			}
		}

		if end < len(rawQuery) {
			b.WriteByte('&')
			start = end + 1
		} else {
			break
		}
	}

	result := b.String()
	putSanitizeBuilder(b)
	return result
}

// SanitizeURL removes credentials and redacts sensitive query parameters from a URL
// for safe logging. URLs with credentials are transformed from user:pass@host to
// ***:***@host. Sensitive query parameters (token, api_key, password, etc.) have
// their values replaced with [REDACTED].
//
// SECURITY: this function must FAIL CLOSED. It exists to keep credentials out
// of logs and error messages, so an input that url.Parse rejects — or parses
// into an opaque form that hides userinfo — is best-effort redacted by
// redactUnparseableURL instead of being returned verbatim (returning the raw
// string would leak user:pass@... precisely on the malformed inputs most
// likely to come from untrusted sources).
//
// This function is used to prevent credential leakage in:
//   - Log messages
//   - Error messages
//   - Audit events
//   - Debug output
//
// Example:
//
//	SanitizeURL("https://user:pass@example.com/path?token=secret")
//	// Returns "https://***:***@example.com/path?token=[REDACTED]"
func SanitizeURL(urlStr string) string {
	if urlStr == "" {
		return ""
	}

	// Fast path: skip parsing if URL has no credentials, query params, fragments,
	// or characters that would be escaped by url.Parse (spaces).
	// Most real URLs pass this check and avoid the expensive url.Parse call.
	// Single scan replaces 4 separate strings.Contains calls.
	// Also skip if URL contains query params but none are sensitive — avoids
	// url.Parse + Query() + Encode() round-trip for the common case.
	if !strings.ContainsAny(urlStr, "@?# ") {
		return urlStr
	}

	// If there are query params, check if any are sensitive before parsing.
	// This avoids the expensive url.Parse + query encode cycle for non-sensitive URLs.
	if _, query, found := strings.Cut(urlStr, "?"); found {
		if !HasSensitiveQueryParams(query) && !strings.ContainsAny(urlStr, "@# ") {
			return urlStr
		}
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return redactUnparseableURL(urlStr)
	}

	// Redact sensitive query parameters directly on raw query string
	// to avoid url.Values map allocation from Query()/Encode() round-trip.
	if parsedURL.RawQuery != "" && HasSensitiveQueryParams(parsedURL.RawQuery) {
		parsedURL.RawQuery = redactSensitiveParams(parsedURL.RawQuery)
	}

	// Clear fragment to prevent credential leakage (e.g., OAuth implicit grants)
	parsedURL.Fragment = ""
	parsedURL.RawFragment = ""
	if parsedURL.User == nil {
		// Opaque URLs ("user:pass@host/path" parses as Scheme="user",
		// Opaque="pass@host/path", User=nil) carry the password verbatim in
		// Opaque. Redact it instead of returning parsedURL.String() as-is.
		if parsedURL.Opaque != "" && strings.Contains(parsedURL.Opaque, "@") {
			return redactUnparseableURL(urlStr)
		}
		return parsedURL.String()
	}

	_, hasPassword := parsedURL.User.Password()
	parsedURL.User = nil

	// Estimate size: scheme (8) + ://***:***@ (10) + host + path + query
	estimatedLen := 18 + len(parsedURL.Scheme) + len(parsedURL.Host) + len(parsedURL.Path) + len(parsedURL.RawQuery)
	b := getSanitizeBuilder()
	b.Grow(estimatedLen)
	if parsedURL.Scheme != "" {
		b.WriteString(parsedURL.Scheme)
		b.WriteString("://")
	} else {
		// Scheme-less URLs (e.g. "//u:p@h/p"): keep the protocol-relative
		// "//" form instead of emitting a malformed "://..." prefix.
		b.WriteString("//")
	}
	if hasPassword {
		b.WriteString("***:***")
	} else {
		b.WriteString("***")
	}
	b.WriteByte('@')
	b.WriteString(parsedURL.Host)
	b.WriteString(parsedURL.Path)
	if parsedURL.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(parsedURL.RawQuery)
	}
	result := b.String()
	putSanitizeBuilder(b)
	return result
}

// redactUnparseableURL best-effort redacts credentials in a URL string that
// url.Parse rejected (or that parsed into an opaque form). Without a parsed
// structure the only reliable signal is the '@' separating userinfo from the
// host, so everything from the scheme separator up to the LAST '@' is
// replaced with "***@". Sensitive query parameters are redacted when a query
// string is present. The result is safe for logging even though it may not be
// a parseable URL — diagnostics beat a verbatim credential leak.
func redactUnparseableURL(s string) string {
	at := strings.LastIndexByte(s, '@')
	if at < 0 {
		// No userinfo separator: nothing that looks like a credential.
		return s
	}

	// Preserve the scheme ("https://") if it precedes the credentials.
	prefix := ""
	if i := strings.Index(s, "://"); i >= 0 && i+3 <= at {
		prefix = s[:i+3]
		s = s[i+3:]
		at -= i + 3
	} else if i := strings.Index(s, ":"); i >= 0 && i+1 <= at && !strings.Contains(s[:i], "/") {
		// Opaque-style "scheme:userinfo@rest" (no "//"): keep "scheme:".
		prefix = s[:i+1]
		s = s[i+1:]
		at -= i + 1
	}

	// An '@' lying after the first path separator is an ordinary path byte,
	// not the userinfo delimiter — userinfo cannot contain '/'. Truncating
	// there would mangle "http://host/p@th\x01" into "http://***@th\x01";
	// with no userinfo-shaped credential, return the string intact.
	if slash := strings.IndexByte(s, '/'); slash >= 0 && slash < at {
		return prefix + s
	}

	redacted := prefix + "***@" + s[at+1:]
	if idx := strings.IndexByte(redacted, '?'); idx >= 0 {
		if q := redacted[idx+1:]; HasSensitiveQueryParams(q) {
			redacted = redacted[:idx+1] + redactSensitiveParams(q)
		}
	}
	return redacted
}

// sanitizeBuilderPool reduces allocations for strings.Builder in SanitizeURL.
var sanitizeBuilderPool = sync.Pool{
	New: func() any {
		return &strings.Builder{}
	},
}

// HasSensitiveQueryParams checks if any key-value pair in the query string
// has a sensitive parameter name. Uses byte-level ASCII lowercase to avoid
// allocations from strings.ToLower.
// HasSensitiveQueryParams reports whether any parameter key in the raw query
// string looks sensitive. Parsing is segment-based (&-split, then strip the
// value after '=') so it matches redactSensitiveParams exactly: a bare key
// without '=' is still treated as a key.
func HasSensitiveQueryParams(query string) bool {
	for len(query) > 0 {
		segment := query
		if ampIdx := strings.IndexByte(query, '&'); ampIdx >= 0 {
			segment = query[:ampIdx]
			query = query[ampIdx+1:]
		} else {
			query = ""
		}
		key := segment
		if eqIdx := strings.IndexByte(segment, '='); eqIdx >= 0 {
			key = segment[:eqIdx]
		}
		if isSensitiveQueryParamCI(key) {
			return true
		}
	}
	return false
}

func getSanitizeBuilder() *strings.Builder {
	b, ok := sanitizeBuilderPool.Get().(*strings.Builder)
	if !ok || b == nil {
		return &strings.Builder{}
	}
	b.Reset()
	return b
}

func putSanitizeBuilder(b *strings.Builder) {
	if b == nil || b.Cap() > 2048 {
		return
	}
	b.Reset()
	sanitizeBuilderPool.Put(b)
}
