// Package security provides request validation, SSRF protection,
// domain whitelisting, and certificate pinning for the httpc library.
package security

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/cybergodev/httpc/internal/types"
	"github.com/cybergodev/httpc/internal/validation"
)

// urlCacheSize limits the number of validated URLs cached to prevent
// unbounded memory growth in high-cardinality URL workloads (e.g., crawlers).
const urlCacheSize = 1024

// Validator validates HTTP requests for URL, header, and SSRF security.
type Validator struct {
	config        *Config
	validatedURLs sync.Map // url string → struct{}; avoids redundant url.Parse for repeated URLs
	urlKeys       []string // insertion order for FIFO eviction (cache hits do NOT refresh position)
	urlMu         sync.Mutex
}

// Config defines security validation settings.
type Config struct {
	ValidateURL        bool
	ValidateHeaders    bool
	MaxRequestBodySize int64
	AllowPrivateIPs    bool
	ExemptNets         []*net.IPNet
}

// Request represents a security validation request with method, URL, headers, and body.
//
// NOTE: Method and QueryParams are populated by the engine but are currently
// NOT read by ValidateRequest (validation covers URL, headers, and body size
// only). They are kept as future extension points for method-specific rules
// and query-parameter checks.
type Request struct {
	Method      string
	URL         string
	Headers     map[string]string
	QueryParams map[string]any
	Body        any
	// AllowPrivateIPs carries a per-request override of the client's SSRF policy.
	// A non-nil value overrides the Validator's configured AllowPrivateIPs for this
	// request only. nil means "use the client-level policy".
	AllowPrivateIPs *bool
}

// newValidator creates a new Validator with default security settings.
func newValidator() *Validator {
	secConfig := &Config{
		ValidateURL:     true,
		ValidateHeaders: true,
		AllowPrivateIPs: false,
	}

	return &Validator{
		config: secConfig,
	}
}

// NewValidatorWithConfig creates a new Validator with the given security configuration.
func NewValidatorWithConfig(config *Config) *Validator {
	if config == nil {
		return newValidator()
	}

	cfg := *config
	if config.ExemptNets != nil {
		// Deep copy: copying only the slice of pointers would leave the
		// caller free to mutate the shared *net.IPNet values concurrently
		// with validation (CIDR.Contains reads IP and Mask), racing every
		// in-flight request. Copy the pointed-to values so the validator
		// owns its snapshot.
		cfg.ExemptNets = make([]*net.IPNet, len(config.ExemptNets))
		for i, n := range config.ExemptNets {
			if n == nil {
				continue
			}
			cn := *n
			cfg.ExemptNets[i] = &cn
		}
	}

	return &Validator{
		config: &cfg,
	}
}

// ValidateRequest validates an HTTP request against the configured security rules.
func (v *Validator) ValidateRequest(req *Request) error {
	if v.config.ValidateURL {
		if err := v.validateURL(req.URL, req.AllowPrivateIPs); err != nil {
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

func (v *Validator) validateURL(urlStr string, override *bool) error {
	// Fast path: skip re-parsing URLs that have already been validated.
	// Most workloads reuse the same base URL across many requests.
	//
	// The cache is keyed by URL string only, so it is only valid when the
	// validation result is stable — i.e. when there is no per-request override.
	// A per-request AllowPrivateIPs override changes the host-validation result
	// for the same URL, so it must bypass the cache (both read and write).
	if override == nil {
		if _, ok := v.validatedURLs.Load(urlStr); ok {
			return nil
		}
	}

	parsedURL, err := validation.ValidateAndParseURL(urlStr)
	if err != nil {
		return err
	}
	if err := v.validateHost(parsedURL.Host, override); err != nil {
		return err
	}

	// Only cache the result when it is stable for this client: no per-request
	// override, and no embedded credentials. The cache is keyed by the raw urlStr,
	// so a URL carrying userinfo (user:pass@host) would persist those credentials
	// in the validatedURLs map and urlKeys slice; validation depends only on the
	// host, so credentialed URLs are simply revalidated on each call instead.
	if override != nil || parsedURL.User != nil {
		return nil
	}

	// Evict oldest entries when cache exceeds limit.
	v.urlMu.Lock()
	// Re-check under lock to avoid duplicate entries from concurrent goroutines
	if _, exists := v.validatedURLs.Load(urlStr); !exists {
		v.validatedURLs.Store(urlStr, struct{}{})
		v.urlKeys = append(v.urlKeys, urlStr)
	}
	if len(v.urlKeys) > urlCacheSize {
		// Evict oldest 25% to amortize lock contention.
		evictCount := urlCacheSize / 4
		for i := 0; i < evictCount; i++ {
			v.validatedURLs.Delete(v.urlKeys[i])
		}
		// Shift remaining keys, allow GC of evicted strings.
		remaining := v.urlKeys[evictCount:]
		newKeys := make([]string, len(remaining), len(remaining)*2)
		copy(newKeys, remaining)
		v.urlKeys = newKeys
	}
	v.urlMu.Unlock()

	return nil
}

// validateHost performs comprehensive host validation to prevent SSRF attacks.
// Delegates to the shared validation.ValidateSSRFHost for consistent behavior.
// A non-nil override takes precedence over the Validator's configured AllowPrivateIPs.
func (v *Validator) validateHost(host string, override *bool) error {
	allowPrivate := v.config.AllowPrivateIPs
	if override != nil {
		allowPrivate = *override
	}
	if allowPrivate {
		return nil
	}

	// Do not resolve DNS here; the connection pool dialer resolves and
	// validates to prevent DNS rebinding TOCTOU.
	return validation.ValidateSSRFHost(host, v.config.ExemptNets)
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
			if validation.EqualFold(token, a) {
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
		if validation.EqualFold(key, "connection") {
			return validateHeaderValueTokens(value, connectionAllowed, "Connection")
		}
	case 't':
		if validation.EqualFold(key, "transfer-encoding") {
			return validateHeaderValueTokens(value, transferEncodingAllowed, "Transfer-Encoding")
		}
	}
	return nil
}

// validateRequestBodySize checks the request body against the configured size limit.
// Only validates when MaxRequestBodySize is explicitly set. (Response body size
// limits are enforced by the engine on its own config, not here.)
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
		for k, v := range b.Fields {
			// Account for: field key + value + Content-Disposition overhead (~60 bytes per field).
			size += int64(len(k)) + int64(len(v)) + 60
		}
		for _, f := range b.Files {
			// Account for: filename + content + MIME headers (~120 bytes per file part).
			size += int64(len(f.Filename)) + int64(len(f.Content)) + 120
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
