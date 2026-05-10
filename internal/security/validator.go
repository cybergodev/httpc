// Package security provides request validation, SSRF protection,
// domain whitelisting, and certificate pinning for the httpc library.
package security

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/cybergodev/httpc/internal/types"
	"github.com/cybergodev/httpc/internal/validation"
)

// Validator validates HTTP requests for URL, header, and SSRF security.
type Validator struct {
	config *Config
}

// Compile-time interface check for requestValidator
var _ requestValidator = (*Validator)(nil)

// requestValidator defines the interface for request validation.
type requestValidator interface {
	ValidateRequest(req *Request) error
}

// Config defines security validation settings.
type Config struct {
	ValidateURL         bool
	ValidateHeaders     bool
	MaxResponseBodySize int64
	MaxRequestBodySize  int64
	AllowPrivateIPs     bool
	ExemptNets          []*net.IPNet
}

// Request represents a security validation request with method, URL, headers, and body.
type Request struct {
	Method      string
	URL         string
	Headers     map[string]string
	QueryParams map[string]any
	Body        any
}

// NewValidator creates a new Validator with default security settings.
func NewValidator() *Validator {
	secConfig := &Config{
		ValidateURL:         true,
		ValidateHeaders:     true,
		MaxResponseBodySize: 50 * 1024 * 1024,
		AllowPrivateIPs:     false,
	}

	return &Validator{
		config: secConfig,
	}
}

// NewValidatorWithConfig creates a new Validator with the given security configuration.
func NewValidatorWithConfig(config *Config) *Validator {
	if config == nil {
		return NewValidator()
	}

	cfg := *config
	if config.ExemptNets != nil {
		cfg.ExemptNets = make([]*net.IPNet, len(config.ExemptNets))
		copy(cfg.ExemptNets, config.ExemptNets)
	}

	return &Validator{
		config: &cfg,
	}
}

// ValidateRequest validates an HTTP request against the configured security rules.
func (v *Validator) ValidateRequest(req *Request) error {
	if v.config.ValidateURL {
		if err := v.validateURL(req.URL); err != nil {
			return err
		}
	}

	if v.config.ValidateHeaders {
		for key, value := range req.Headers {
			if err := v.validateHeader(key, value); err != nil {
				return fmt.Errorf("invalid header %s: %w", key, err)
			}
		}
	}

	if req.Body != nil {
		if err := v.validateRequestBodySize(req.Body); err != nil {
			return err
		}
	}

	return nil
}

func (v *Validator) validateURL(urlStr string) error {
	// Validate and parse in one call to avoid double url.Parse
	parsedURL, err := validation.ValidateAndParseURL(urlStr)
	if err != nil {
		return err
	}
	return v.validateHost(parsedURL.Host)
}

// validateHost performs comprehensive host validation to prevent SSRF attacks.
// Delegates to the shared validation.ValidateSSRFHost for consistent behavior.
func (v *Validator) validateHost(host string) error {
	if v.config.AllowPrivateIPs {
		return nil
	}

	// Do not resolve DNS here; the connection pool dialer resolves and
	// validates to prevent DNS rebinding TOCTOU.
	return validation.ValidateSSRFHost(host, v.config.ExemptNets, false)
}

func (v *Validator) validateHeader(key, value string) error {
	// Use common validation from validation package
	if err := validation.ValidateHeaderKeyValue(key, value); err != nil {
		return err
	}

	// Additional validation for specific header values
	return validateCommonHeaderValue(key, value)
}

// validateHeaderValueTokens validates that all comma-separated tokens in a header
// value are within the allowed set. Supports RFC 9110 multi-token header values
// (e.g., "Connection: keep-alive, Upgrade").
func validateHeaderValueTokens(value string, allowed []string, headerName string) error {
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return fmt.Errorf("invalid %s header value: %q", headerName, value)
		}
		found := false
		for _, a := range allowed {
			if asciiEqualFold(token, a) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid %s header value: %q", headerName, value)
		}
	}
	return nil
}

var (
	connectionAllowed       = []string{"keep-alive", "close", "upgrade"}
	transferEncodingAllowed = []string{"chunked", "compress", "deflate", "gzip", "identity"}
)

func validateCommonHeaderValue(key, value string) error {
	// Fast path: check first byte to avoid strings.EqualFold overhead for most headers.
	// "connection" starts with 'c'/'C', "transfer-encoding" starts with 't'/'T'.
	// Most headers won't match either, so the byte check short-circuits immediately.
	if len(key) == 0 {
		return nil
	}
	switch key[0] | 0x20 {
	case 'c':
		if asciiEqualFold(key, "connection") {
			return validateHeaderValueTokens(value, connectionAllowed, "Connection")
		}
	case 't':
		if asciiEqualFold(key, "transfer-encoding") {
			return validateHeaderValueTokens(value, transferEncodingAllowed, "Transfer-Encoding")
		}
	}
	return nil
}

// asciiEqualFold reports whether s and t are equal under ASCII case-folding.
// Avoids strings.EqualFold allocation and unicode overhead for simple ASCII comparison.
func asciiEqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		sc := s[i]
		tc := t[i]
		if sc >= 'A' && sc <= 'Z' {
			sc += 32
		}
		if tc >= 'A' && tc <= 'Z' {
			tc += 32
		}
		if sc != tc {
			return false
		}
	}
	return true
}

// validateRequestBodySize checks the request body against the configured size limit.
// Only validates when MaxRequestBodySize is explicitly set; does not fall back to
// MaxResponseBodySize since they serve different purposes.
func (v *Validator) validateRequestBodySize(body any) error {
	limit := v.config.MaxRequestBodySize
	if limit <= 0 {
		return nil
	}

	var size int64
	switch b := body.(type) {
	case string:
		size = int64(len(b))
	case []byte:
		size = int64(len(b))
	case url.Values:
		for k, vs := range b {
			size += int64(len(k)) + 1
			for _, v := range vs {
				size += int64(len(v)) + 1
			}
		}
	case *types.FormData:
		for _, v := range b.Fields {
			size += int64(len(v))
		}
		for _, f := range b.Files {
			size += int64(len(f.Content))
		}
	default:
		// For io.Reader and other types, caller is responsible for size control.
		// Use io.LimitReader to cap untrusted io.Reader sources:
		//   limited := io.LimitReader(untrustedReader, maxBytes)
		return nil
	}

	if size > limit {
		return fmt.Errorf("request body size %d exceeds limit %d bytes", size, limit)
	}

	return nil
}
