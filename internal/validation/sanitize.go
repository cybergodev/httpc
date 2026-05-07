package validation

import (
	"net/url"
	"strings"
)

// sensitiveQueryParamNames contains query parameter names whose values should be
// redacted when sanitizing URLs for logging and error messages.
// Shared across packages to avoid duplicate definitions.
var sensitiveQueryParamNames = map[string]bool{
	// OAuth and authentication tokens
	"token": true, "access_token": true, "refresh_token": true,
	"id_token": true, "idtoken": true, "bearer": true,
	// API keys and secrets
	"api_key": true, "apikey": true,
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

// isSensitiveQueryParamCI performs case-insensitive lookup for sensitive query param names.
func isSensitiveQueryParamCI(name string) bool {
	return sensitiveQueryParamNames[strings.ToLower(name)]
}

// IsSensitiveQueryParam reports whether the given query parameter name is
// considered sensitive and should be redacted from logs and cache keys.
func IsSensitiveQueryParam(name string) bool {
	return sensitiveQueryParamNames[strings.ToLower(name)]
}

// SensitiveQueryParamNames returns the set of sensitive query parameter names.
// Used internally to check URLs for sensitive content without importing the map directly.
func SensitiveQueryParamNames() map[string]bool {
	return sensitiveQueryParamNames
}

// SanitizeURL removes credentials and redacts sensitive query parameters from a URL
// for safe logging. URLs with credentials are transformed from user:pass@host to
// ***:***@host. Sensitive query parameters (token, api_key, password, etc.) have
// their values replaced with [REDACTED].
//
// Returns the original string if the URL cannot be parsed.
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
	if !strings.ContainsAny(urlStr, "@?# ") {
		return urlStr
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	// Redact sensitive query parameters
	if parsedURL.RawQuery != "" {
		query := parsedURL.Query()
		redacted := false
		for key := range query {
			if isSensitiveQueryParamCI(key) {
				query.Set(key, "[REDACTED]")
				redacted = true
			}
		}
		if redacted {
			parsedURL.RawQuery = query.Encode()
		}
	}

	// Clear fragment to prevent credential leakage (e.g., OAuth implicit grants)
	parsedURL.Fragment = ""
	parsedURL.RawFragment = ""
	if parsedURL.User == nil {
		return parsedURL.String()
	}

	_, hasPassword := parsedURL.User.Password()
	parsedURL.User = nil

	// Estimate size: scheme (8) + ://***:***@ (10) + host + path + query
	estimatedLen := 18 + len(parsedURL.Scheme) + len(parsedURL.Host) + len(parsedURL.Path) + len(parsedURL.RawQuery)
	var b strings.Builder
	b.Grow(estimatedLen)
	b.WriteString(parsedURL.Scheme)
	b.WriteString("://")
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
	return b.String()
}
