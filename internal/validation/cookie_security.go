package validation

import (
	"fmt"
	"net/http"
	"strings"
)

// CookieSecurityConfig defines the security requirements for cookies.
// This is used to enforce security attributes like Secure, HttpOnly, and SameSite
// to protect against CSRF, XSS, and session hijacking attacks.
type CookieSecurityConfig struct {
	// RequireSecure requires the Secure attribute to be set.
	// Secure cookies are only sent over HTTPS connections.
	// Recommended: true for production environments.
	RequireSecure bool

	// RequireHttpOnly requires the HttpOnly attribute to be set.
	// HttpOnly cookies cannot be accessed via JavaScript, preventing XSS attacks.
	// Recommended: true for session cookies.
	RequireHttpOnly bool

	// RequireSameSite requires a specific SameSite attribute.
	// Valid values: "Strict", "Lax", "None", "" (empty means no requirement).
	// - Strict: Cookie only sent in first-party context (most secure)
	// - Lax: Cookie sent in first-party context and top-level navigations
	// - None: Cookie sent in all contexts (requires Secure)
	RequireSameSite string

	// AllowSameSiteNone allows SameSite=None attribute.
	// This is useful for cross-site cookies but reduces security.
	// If false and RequireSameSite is empty, cookies with SameSite=None are rejected.
	// Recommended: false for high-security applications.
	AllowSameSiteNone bool

	// RequireSecureForSameSiteNone requires the Secure attribute when
	// SameSite=None. Modern browsers reject SameSite=None without Secure,
	// so this catches misconfigured cookies early. Default: true.
	RequireSecureForSameSiteNone bool
}

// DefaultCookieSecurityConfig returns a recommended security configuration.
// This provides a good balance between security and compatibility.
func DefaultCookieSecurityConfig() *CookieSecurityConfig {
	return &CookieSecurityConfig{
		RequireSecure:                false, // Allow non-HTTPS for development
		RequireHttpOnly:              false, // Allow JavaScript access for flexibility
		RequireSameSite:              "",    // No SameSite requirement
		AllowSameSiteNone:            true,  // Allow cross-site cookies
		RequireSecureForSameSiteNone: true,  // SameSite=None requires Secure per RFC 6265bis
	}
}

// StrictCookieSecurityConfig returns a strict security configuration.
// Use this for high-security applications (financial, medical, government).
func StrictCookieSecurityConfig() *CookieSecurityConfig {
	return &CookieSecurityConfig{
		RequireSecure:     true,
		RequireHttpOnly:   true,
		RequireSameSite:   "Strict",
		AllowSameSiteNone: false,
	}
}

// sameSiteToString converts http.SameSite to a string representation.
func sameSiteToString(sameSite http.SameSite) string {
	switch sameSite {
	case http.SameSiteDefaultMode:
		return "Default"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

// isSameSiteNone checks if the SameSite value represents None mode.
func isSameSiteNone(sameSite http.SameSite) bool {
	return sameSite == http.SameSiteNoneMode
}

// ValidateCookieSecurity validates a cookie against the security configuration.
// Returns an error if the cookie does not meet the security requirements.
// This is the standard validation for general use.
func ValidateCookieSecurity(cookie *http.Cookie, config *CookieSecurityConfig) error {
	if cookie == nil {
		return fmt.Errorf("cookie is nil")
	}
	if config == nil {
		return nil // No security requirements
	}

	var errors []string

	// Check Secure requirement
	if config.RequireSecure && !cookie.Secure {
		errors = append(errors, "missing Secure attribute")
	}

	// Check HttpOnly requirement
	if config.RequireHttpOnly && !cookie.HttpOnly {
		errors = append(errors, "missing HttpOnly attribute")
	}

	// Check SameSite requirement
	if config.RequireSameSite != "" {
		if err := validateSameSite(cookie, config.RequireSameSite, config.AllowSameSiteNone); err != nil {
			errors = append(errors, err.Error())
		}
	}

	// Check if SameSite=None is allowed
	if !config.AllowSameSiteNone && isSameSiteNone(cookie.SameSite) {
		errors = append(errors, "SameSite=None is not allowed")
	}

	// Require Secure when SameSite=None (RFC 6265bis requirement)
	if config.RequireSecureForSameSiteNone && isSameSiteNone(cookie.SameSite) && !cookie.Secure {
		errors = append(errors, "SameSite=None requires Secure attribute")
	}

	if len(errors) > 0 {
		return fmt.Errorf("cookie '%s' failed security validation: %s", cookie.Name, strings.Join(errors, ", "))
	}

	return nil
}

// validateSameSite checks if the cookie's SameSite attribute matches the required value.
func validateSameSite(cookie *http.Cookie, required string, allowNone bool) error {
	cookieSameSite := sameSiteToString(cookie.SameSite)

	// Handle empty/unknown SameSite
	if cookieSameSite == "" || cookieSameSite == "Default" {
		// Default mode in modern browsers is Lax
		if equalFold(required, "lax") {
			return nil // Default is acceptable for Lax requirement
		}
		return fmt.Errorf("missing SameSite attribute (required: %s)", required)
	}

	// Check if SameSite=None is allowed
	if isSameSiteNone(cookie.SameSite) && !allowNone {
		return fmt.Errorf("SameSite=None is not allowed")
	}

	// Validate match using zero-allocation case-insensitive comparison
	if !equalFold(cookieSameSite, required) {
		return fmt.Errorf("invalid SameSite value '%s' (required: %s)", cookieSameSite, required)
	}

	return nil
}
