package httpc

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cybergodev/httpc/internal/engine"
	"github.com/cybergodev/httpc/internal/proxypool"
	"github.com/cybergodev/httpc/internal/types"
	"github.com/cybergodev/httpc/internal/validation"
)

const (
	maxJSONSize             = 50 * 1024 * 1024   // 50MB
	maxTimeout              = 30 * time.Minute   // 30 minutes
	maxIdleConns            = 1000               // Connection pool limit
	maxConnsPerHost         = 1000               // Per-host connection limit
	maxResponseBodySize     = 1024 * 1024 * 1024 // 1GB
	maxDecompressedBodySize = 100 * 1024 * 1024  // 100MB default for decompressed bodies
	maxRetryAttempts        = 10                 // Maximum retry attempts
	minBackoffFactor        = 1.0                // Minimum backoff multiplier
	maxBackoffFactor        = 10.0               // Maximum backoff multiplier
	maxUserAgentLen         = 512                // User-Agent header limit
	maxRedirectLimit        = 50                 // Maximum redirect limit
)

// TimeoutConfig configures timeout behavior for HTTP requests.
// All duration values use time.Duration (e.g., 30 * time.Second).
type TimeoutConfig struct {
	// Request is the overall request timeout including retries.
	// Default: 180s. Set to 0 for no timeout (not recommended for production).
	Request time.Duration

	// Dial is the maximum time to wait for a TCP connection.
	// Default: 10s.
	Dial time.Duration

	// TLSHandshake is the maximum time to wait for TLS handshake.
	// Default: 10s. Only applies to HTTPS connections.
	TLSHandshake time.Duration

	// ResponseHeader is the maximum time to wait for response headers after
	// the request is fully written. This timeout is enforced at the transport
	// level and applies to ALL requests sharing the same client — it CANNOT
	// be overridden per-request via WithTimeout.
	//
	// When set to 0 (default), the context-level timeout from Timeouts.Request
	// or WithTimeout() serves as the sole timeout mechanism, giving per-request
	// control over how long to wait for a response.
	//
	// Set to a positive value ONLY when you want a hard transport-level cap
	// independent of the request timeout (e.g., defense-in-depth against
	// slowloris attacks). Be aware this will override WithTimeout if the
	// ResponseHeader value is shorter.
	ResponseHeader time.Duration

	// IdleConn is the maximum time an idle connection remains open.
	// Default: 90s.
	IdleConn time.Duration
}

// ProxyStrategy selects the algorithm for choosing a proxy from a proxy pool.
// Alias for proxypool.Strategy to avoid importing the internal package.
type ProxyStrategy = proxypool.Strategy

const (
	// ProxyStrategyRoundRobin cycles through proxies in order (default).
	// Each selection advances to the next proxy, so a retry naturally lands on
	// a different IP without any extra wiring.
	ProxyStrategyRoundRobin = proxypool.StrategyRoundRobin
	// ProxyStrategyRandom picks a healthy proxy uniformly at random.
	ProxyStrategyRandom = proxypool.StrategyRandom
)

// ConnectionConfig configures connection pooling and proxy behavior.
type ConnectionConfig struct {
	// MaxIdleConns is the maximum number of idle connections across all hosts.
	// Default: 50.
	MaxIdleConns int

	// MaxConnsPerHost is the maximum connections per host (idle + active).
	// Default: 10.
	MaxConnsPerHost int

	// ProxyURL specifies an explicit proxy server URL (e.g., "http://proxy:8080").
	// Takes precedence over EnableSystemProxy. Default: "" (no proxy).
	ProxyURL string

	// EnableSystemProxy enables automatic detection of system proxy settings.
	// Default: false.
	EnableSystemProxy bool

	// ProxyPool specifies a list of proxy servers for rotation. When set,
	// requests are distributed across the proxies using ProxyPoolStrategy.
	// Connection failures (dial/TLS) to a proxy trigger passive circuit
	// breaking: after ProxyFailureThreshold consecutive failures the proxy is
	// temporarily removed from rotation and restored after ProxyCooldown.
	//
	// Priority: lower than ProxyURL, higher than EnableSystemProxy. If both
	// ProxyURL and ProxyPool are set, ProxyURL wins (single-proxy mode).
	// Default: nil (no proxy pool).
	ProxyPool []string

	// ProxyPoolStrategy selects how proxies are chosen from ProxyPool.
	// Default: ProxyStrategyRoundRobin.
	ProxyPoolStrategy ProxyStrategy

	// ProxyFailureThreshold is the number of consecutive connection failures
	// (dial/TLS) to a proxy before it is temporarily removed from rotation.
	// Zero defaults to 3. HTTP status codes do NOT trigger this — use
	// ProxyRotateOnStatus for status-based rotation.
	ProxyFailureThreshold int

	// ProxyCooldown is how long a circuit-broken proxy stays out of rotation
	// before being retried (half-open probe). Zero defaults to 30s.
	ProxyCooldown time.Duration

	// ProxyRotateOnStatus specifies HTTP status codes that trigger a retry with
	// a different proxy. When a response returns one of these codes and
	// Retry.MaxRetries > 0, the request is retried; under round-robin or random
	// strategy the retry naturally selects a different proxy IP.
	//
	// Typical use: []int{403} for CF/WAF IP-based blocking. Unlike
	// connection failures, status-based rotation does NOT circuit-break the
	// proxy — blocks are often target-specific (a proxy blocked on one site may
	// work fine on another). Requires Retry.MaxRetries > 0 to take effect.
	// Default: nil.
	ProxyRotateOnStatus []int

	// EnableHTTP2 enables HTTP/2 protocol support.
	// Default: true.
	EnableHTTP2 bool

	// EnableCookies enables automatic cookie handling with a cookie jar.
	// Default: false.
	EnableCookies bool

	// EnableDoH enables DNS-over-HTTPS for DNS resolution.
	// Default: false.
	EnableDoH bool

	// DoHCacheTTL is the cache duration for DoH DNS responses.
	// Default: 5 minutes.
	DoHCacheTTL time.Duration

	// MaxResponseHeaderBytes limits the maximum size of the server's response headers.
	// This protects against malicious servers sending excessively large headers.
	// Default: 0 (uses Go stdlib default of 10MB).
	MaxResponseHeaderBytes int64
}

// SecurityConfig configures TLS, validation, and SSRF protection.
type SecurityConfig struct {
	// TLSConfig provides custom TLS configuration. If set, MinTLSVersion and
	// MaxTLSVersion are ignored. Default: nil.
	TLSConfig *tls.Config

	// MinTLSVersion is the minimum TLS version. Default: TLS 1.2.
	MinTLSVersion uint16

	// MaxTLSVersion is the maximum TLS version. Default: TLS 1.3.
	MaxTLSVersion uint16

	// InsecureSkipVerify disables TLS certificate verification.
	// WARNING: Only use in testing. Default: false.
	InsecureSkipVerify bool

	// MaxResponseBodySize limits response body size in bytes. Default: 10MB.
	MaxResponseBodySize int64

	// MaxRequestBodySize limits request body size in bytes.
	// Default: 0 (no request body limit). Unlike MaxResponseBodySize there is
	// NO automatic fallback — set it explicitly to enforce an upload cap.
	MaxRequestBodySize int64

	// MaxDecompressedBodySize limits decompressed response body size in bytes.
	// This prevents decompression bomb (zip bomb) attacks. Default: 100MB.
	// Only applies when MaxResponseBodySize is not explicitly set; when set,
	// MaxResponseBodySize takes precedence as the stricter limit.
	MaxDecompressedBodySize int64

	// AllowPrivateIPs disables ALL SSRF protection when set to true, including
	// localhost, loopback, link-local, and private/reserved IP checks.
	// Default: false (SSRF protection enabled). Set to true only when
	// connecting to internal services (VPNs, proxies, corporate networks).
	// WARNING: This completely bypasses the connection-level SSRF dialer validation,
	// not just private IP blocking. Use SSRFExemptCIDRs for selective allowlisting instead.
	AllowPrivateIPs bool

	// SSRFExemptCIDRs specifies CIDR ranges exempted from SSRF blocking.
	// When AllowPrivateIPs is false, IPs matching these CIDRs are still allowed.
	// Useful for VPN/Tailscale (100.64.0.0/10) or VPC (10.0.0.0/8) access.
	// Invalid CIDRs cause New() to return an error.
	SSRFExemptCIDRs []string

	// ValidateURL enables URL validation. Default: true.
	ValidateURL bool

	// ValidateHeaders enables header validation. Default: true.
	ValidateHeaders bool

	// StrictContentLength enables strict Content-Length validation. Default: true.
	StrictContentLength bool

	// CookieSecurity enables cookie security attribute validation.
	// Default: nil (no validation).
	CookieSecurity *CookieSecurityConfig

	// CertificatePinner, when set, enables certificate pinning: the TLS
	// handshake is rejected unless the server presents a pinned key/certificate,
	// defending against MITM even if a trusted CA is compromised.
	// Construct one with NewSPKIHashPinner, NewPublicKeyPinner, or
	// NewCertificatePinnerChain. Default: nil (pinning disabled).
	//
	// The pinner is shared by reference across clients created from the same
	// Config (it is not deep-copied); pinner implementations are safe for
	// concurrent use by multiple clients.
	CertificatePinner CertificatePinner

	// RedirectWhitelist specifies allowed domains for redirects.
	// Default: nil (all redirects allowed).
	RedirectWhitelist []string
}

// RetryConfig configures retry behavior for transient failures.
type RetryConfig struct {
	// MaxRetries is the maximum retry attempts. Default: 3. Set to 0 to disable.
	MaxRetries int

	// Delay is the initial retry delay. Default: 1s.
	Delay time.Duration

	// BackoffFactor multiplies Delay after each failed attempt. Default: 2.0.
	BackoffFactor float64

	// EnableJitter enables jitter in retry delay. Default: true.
	EnableJitter bool

	// MaxRetryDelay caps the maximum delay between retry attempts.
	// Default: 30s. Set to 0 for no cap (not recommended).
	MaxRetryDelay time.Duration

	// CustomPolicy overrides the built-in retry logic. Default: nil.
	CustomPolicy RetryPolicy
}

// MiddlewareConfig configures the per-request defaults and the middleware chain
// applied to every outgoing request. It groups two related concerns: the
// middleware chain (Middlewares) and the request defaults — User-Agent, default
// headers, and the redirect policy.
//
// Only Middlewares is strictly "middleware"; UserAgent, Headers, FollowRedirects,
// and MaxRedirects are request defaults colocated here for historical reasons and
// may move to a dedicated options struct in a future major version. Use
// DefaultConfig() to obtain sensible values for all fields.
type MiddlewareConfig struct {
	// Middlewares contains middleware functions for request/response interception.
	// Default: nil.
	Middlewares []MiddlewareFunc

	// UserAgent sets the User-Agent header. Default: "httpc/1.0".
	UserAgent string

	// Headers contains default headers added to every request.
	Headers map[string]string

	// FollowRedirects controls automatic redirect following. Default: true.
	FollowRedirects bool

	// MaxRedirects limits automatic redirects. Default: 10.
	MaxRedirects int
}

// Config defines the HTTP client configuration organized into logical groups.
// Use DefaultConfig() for sensible defaults, or use preset configurations
// like SecureConfig(), PerformanceConfig(), or MinimalConfig().
//
// Example:
//
//	cfg := httpc.DefaultConfig()
//	cfg.Timeouts.Request = 60 * time.Second
//	cfg.Retry.MaxRetries = 5
//	cfg.Connection.ProxyURL = "http://proxy:8080"
//	client, err := httpc.New(cfg)
type Config struct {
	Timeouts   *TimeoutConfig
	Connection *ConnectionConfig
	Security   *SecurityConfig
	Retry      *RetryConfig
	Middleware *MiddlewareConfig

	// parsedCIDRs caches parsed SSRFExemptCIDRs to avoid double parsing.
	// Filled by parseSSRFExemptCIDRs; consumed by convertToEngineConfig.
	parsedCIDRs []*net.IPNet
}

// RequestOption is a function that modifies a request before it is sent.
// Alias for engine.RequestOption to avoid importing the internal package.
type RequestOption = engine.RequestOption

// RetryPolicy defines the interface for custom retry behavior.
// Alias for types.RetryPolicy to avoid importing the internal package.
type RetryPolicy = types.RetryPolicy

// CookieSecurityConfig configures cookie security attribute validation.
// Use DefaultCookieSecurityConfig() or StrictCookieSecurityConfig() to create instances.
// Alias for validation.CookieSecurityConfig to avoid importing the internal package.
//
// Example:
//
//	cfg := httpc.DefaultCookieSecurityConfig()
//	cfg.RequireSecure = true
//	config.Security.CookieSecurity = cfg
type CookieSecurityConfig = validation.CookieSecurityConfig

// DefaultCookieSecurityConfig returns a CookieSecurityConfig with default settings.
// By default, no security attributes are required.
func DefaultCookieSecurityConfig() *CookieSecurityConfig {
	return validation.DefaultCookieSecurityConfig()
}

// StrictCookieSecurityConfig returns a CookieSecurityConfig with strict security settings.
// Requires Secure, HttpOnly, and SameSite=Strict attributes.
func StrictCookieSecurityConfig() *CookieSecurityConfig {
	return validation.StrictCookieSecurityConfig()
}

// FormData represents multipart form data for HTTP requests.
// Alias for types.FormData to avoid importing the internal package.
//
// Example:
//
//	form := &httpc.FormData{
//	    Fields: map[string]string{"key": "value"},
//	    Files: map[string]*httpc.FileData{
//	        "file": {Filename: "test.txt", Content: []byte("hello")},
//	    },
//	}
type FormData = types.FormData

// FileData represents a file to be uploaded in a multipart form.
// Alias for types.FileData to avoid importing the internal package.
type FileData = types.FileData

// RequestMutator provides read-write access to request data for middleware.
// Alias for types.RequestMutator to avoid importing the internal package.
type RequestMutator = types.RequestMutator

// ResponseMutator provides read-write access to response data for middleware.
// Alias for types.ResponseMutator to avoid importing the internal package.
type ResponseMutator = types.ResponseMutator

// Handler processes an HTTP request and returns a response.
// Alias for types.Handler to avoid importing the internal package.
type Handler = types.Handler

// MiddlewareFunc wraps a Handler with pre/post-processing logic.
// Alias for types.MiddlewareFunc to avoid importing the internal package.
type MiddlewareFunc = types.MiddlewareFunc

// BodyKind represents the type of request body for WithBody.
type BodyKind int

const (
	// BodyAuto auto-detects body type based on input data.
	// Auto-detection rules:
	//   - string → text/plain
	//   - []byte → application/octet-stream
	//   - map[string]string → application/x-www-form-urlencoded
	//   - *FormData → multipart/form-data
	//   - io.Reader → passed through (no Content-Type set)
	//   - other types → application/json
	BodyAuto BodyKind = iota

	// BodyJSON forces JSON encoding regardless of input type.
	BodyJSON

	// BodyXML forces XML encoding regardless of input type.
	BodyXML

	// BodyForm forces application/x-www-form-urlencoded encoding.
	// Input must be map[string]string or compatible type.
	BodyForm

	// BodyBinary forces binary/octet-stream encoding.
	// Input must be []byte or string.
	BodyBinary

	// BodyMultipart forces multipart/form-data encoding.
	// Input must be *FormData.
	BodyMultipart
)

// DefaultConfig returns a Config with sensible defaults.
// The returned config is safe for modification.
//
// SSRF Protection:
// AllowPrivateIPs defaults to false, blocking connections to private/reserved IPs
// (127.0.0.1, 10.x, 192.168.x, 169.254.x, etc.). Setting to true disables ALL SSRF
// protection including localhost checks — use SSRFExemptCIDRs for selective allowlisting.
func DefaultConfig() *Config {
	return &Config{
		Timeouts: &TimeoutConfig{
			Request:        180 * time.Second,
			Dial:           10 * time.Second,
			TLSHandshake:   10 * time.Second,
			ResponseHeader: 0, // Disabled: rely on context timeout (Timeouts.Request / WithTimeout)
			IdleConn:       90 * time.Second,
		},
		Connection: &ConnectionConfig{
			MaxIdleConns:      50,
			MaxConnsPerHost:   10,
			ProxyURL:          "",
			EnableSystemProxy: false,
			EnableHTTP2:       true,
			EnableCookies:     false,
			EnableDoH:         false,
			DoHCacheTTL:       5 * time.Minute,
		},
		Security: &SecurityConfig{
			TLSConfig:               nil,
			MinTLSVersion:           tls.VersionTLS12,
			MaxTLSVersion:           tls.VersionTLS13,
			InsecureSkipVerify:      false,
			MaxResponseBodySize:     10 * 1024 * 1024,  // 10MB
			MaxDecompressedBodySize: 100 * 1024 * 1024, // 100MB
			AllowPrivateIPs:         false,
			ValidateURL:             true,
			ValidateHeaders:         true,
			StrictContentLength:     true,
		},
		Retry: &RetryConfig{
			MaxRetries:    3,
			Delay:         1 * time.Second,
			BackoffFactor: 2.0,
			EnableJitter:  true,
			MaxRetryDelay: 30 * time.Second,
			CustomPolicy:  nil,
		},
		Middleware: &MiddlewareConfig{
			Middlewares:     nil,
			UserAgent:       "httpc/1.0",
			Headers:         make(map[string]string),
			FollowRedirects: true,
			MaxRedirects:    10,
		},
	}
}

// newCookieJar creates a new cookie jar for cookie management.
func newCookieJar() (http.CookieJar, error) {
	return cookiejar.New(&cookiejar.Options{
		PublicSuffixList: nil,
	})
}

// validateDuration validates that a duration is within [0, max].
func validateDuration(field string, d, max time.Duration) error {
	if d < 0 || d > max {
		return fmt.Errorf("%w: %s must be 0-%v, got %v", ErrInvalidTimeout, field, max, d)
	}
	return nil
}

// validateRange validates that an integer is within [0, max].
func validateRange(field string, v, max int) error {
	if v < 0 || v > max {
		return fmt.Errorf("%w: %s must be 0-%d, got %d", ErrInvalidConnection, field, max, v)
	}
	return nil
}

// ValidateConfig validates the configuration and returns an error if invalid.
// This is called internally by New() but can also be called explicitly.
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return ErrNilConfig
	}

	// Validate timeouts
	if cfg.Timeouts != nil {
		for _, err := range []error{
			validateDuration("Timeouts.Request", cfg.Timeouts.Request, maxTimeout),
			validateDuration("Timeouts.Dial", cfg.Timeouts.Dial, maxTimeout),
			validateDuration("Timeouts.TLSHandshake", cfg.Timeouts.TLSHandshake, maxTimeout),
			validateDuration("Timeouts.ResponseHeader", cfg.Timeouts.ResponseHeader, maxTimeout),
			validateDuration("Timeouts.IdleConn", cfg.Timeouts.IdleConn, maxTimeout),
		} {
			if err != nil {
				return err
			}
		}
	}

	// Validate connection settings
	if cfg.Connection != nil {
		for _, err := range []error{
			validateRange("Connection.MaxIdleConns", cfg.Connection.MaxIdleConns, maxIdleConns),
			validateRange("Connection.MaxConnsPerHost", cfg.Connection.MaxConnsPerHost, maxConnsPerHost),
		} {
			if err != nil {
				return err
			}
		}
		if cfg.Connection.ProxyURL != "" {
			// Delegate to the shared validator so the public Config layer and the
			// internal connection pool enforce identical rules (scheme set, host
			// presence). Previously these two layers drifted on socks5.
			if _, err := validation.ValidateProxyURL(cfg.Connection.ProxyURL); err != nil {
				return fmt.Errorf("%w: Connection.ProxyURL: %w", ErrInvalidConnection, err)
			}
		}
		// Validate proxy pool entries — each must pass the same validator as
		// ProxyURL so the public Config layer and internal pool cannot drift.
		for _, proxyURL := range cfg.Connection.ProxyPool {
			if _, err := validation.ValidateProxyURL(proxyURL); err != nil {
				return fmt.Errorf("%w: Connection.ProxyPool entry %q: %w", ErrInvalidConnection, proxyURL, err)
			}
		}
		if cfg.Connection.ProxyFailureThreshold < 0 {
			return fmt.Errorf("%w: Connection.ProxyFailureThreshold cannot be negative, got %d", ErrInvalidConnection, cfg.Connection.ProxyFailureThreshold)
		}
		if cfg.Connection.ProxyCooldown < 0 || cfg.Connection.ProxyCooldown > maxTimeout {
			return fmt.Errorf("%w: Connection.ProxyCooldown must be 0-%v, got %v", ErrInvalidConnection, maxTimeout, cfg.Connection.ProxyCooldown)
		}
		for _, code := range cfg.Connection.ProxyRotateOnStatus {
			if code < 100 || code > 599 {
				return fmt.Errorf("%w: Connection.ProxyRotateOnStatus contains invalid HTTP status code %d (must be 100-599)", ErrInvalidConnection, code)
			}
		}
		if cfg.Connection.DoHCacheTTL < 0 {
			return fmt.Errorf("%w: Connection.DoHCacheTTL cannot be negative, got %v", ErrInvalidConnection, cfg.Connection.DoHCacheTTL)
		}
		if cfg.Connection.MaxResponseHeaderBytes < 0 {
			return fmt.Errorf("%w: Connection.MaxResponseHeaderBytes cannot be negative, got %d", ErrInvalidConnection, cfg.Connection.MaxResponseHeaderBytes)
		}
	}

	// Validate security settings
	if cfg.Security != nil {
		if cfg.Security.MaxResponseBodySize < 0 || cfg.Security.MaxResponseBodySize > maxResponseBodySize {
			return fmt.Errorf("%w: Security.MaxResponseBodySize must be 0-1GB, got %d", ErrInvalidSecurity, cfg.Security.MaxResponseBodySize)
		}
		if cfg.Security.MaxDecompressedBodySize < 0 || cfg.Security.MaxDecompressedBodySize > maxDecompressedBodySize {
			return fmt.Errorf("%w: Security.MaxDecompressedBodySize must be 0-100MB, got %d", ErrInvalidSecurity, cfg.Security.MaxDecompressedBodySize)
		}
		if cfg.Security.MaxRequestBodySize < 0 || cfg.Security.MaxRequestBodySize > maxResponseBodySize {
			return fmt.Errorf("%w: Security.MaxRequestBodySize must be 0-%d, got %d", ErrInvalidSecurity, maxResponseBodySize, cfg.Security.MaxRequestBodySize)
		}

		// Validate TLS version ordering
		if cfg.Security.MinTLSVersion != 0 && cfg.Security.MaxTLSVersion != 0 {
			if cfg.Security.MinTLSVersion > cfg.Security.MaxTLSVersion {
				return fmt.Errorf("Security.MinTLSVersion (%d) must not exceed MaxTLSVersion (%d)", cfg.Security.MinTLSVersion, cfg.Security.MaxTLSVersion)
			}
		}

		// Validate CIDR format only — parsing deferred to parseSSRFExemptCIDRs
		// to avoid mutating the caller's Config (parsedCIDRs field).
		for _, cidr := range cfg.Security.SSRFExemptCIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("Security.SSRFExemptCIDRs: invalid CIDR %q: %w", cidr, err)
			}
		}
	}

	// Validate retry settings
	if cfg.Retry != nil {
		if cfg.Retry.MaxRetries < 0 || cfg.Retry.MaxRetries > maxRetryAttempts {
			return fmt.Errorf("%w: Retry.MaxRetries must be 0-%d, got %d", ErrInvalidRetry, maxRetryAttempts, cfg.Retry.MaxRetries)
		}
		if cfg.Retry.Delay < 0 || cfg.Retry.Delay > maxTimeout {
			return fmt.Errorf("%w: Retry.Delay must be 0-%v, got %v", ErrInvalidRetry, maxTimeout, cfg.Retry.Delay)
		}
		if cfg.Retry.BackoffFactor < minBackoffFactor || cfg.Retry.BackoffFactor > maxBackoffFactor {
			return fmt.Errorf("%w: Retry.BackoffFactor must be %.1f-%.1f, got %.1f", ErrInvalidRetry, minBackoffFactor, maxBackoffFactor, cfg.Retry.BackoffFactor)
		}
		if cfg.Retry.MaxRetryDelay < 0 || cfg.Retry.MaxRetryDelay > maxTimeout {
			return fmt.Errorf("%w: Retry.MaxRetryDelay must be 0-%v, got %v", ErrInvalidRetry, maxTimeout, cfg.Retry.MaxRetryDelay)
		}
	}

	// Validate middleware settings
	if cfg.Middleware != nil {
		if cfg.Middleware.MaxRedirects < 0 || cfg.Middleware.MaxRedirects > maxRedirectLimit {
			return fmt.Errorf("%w: Middleware.MaxRedirects must be 0-%d, got %d", ErrInvalidMiddleware, maxRedirectLimit, cfg.Middleware.MaxRedirects)
		}
		if len(cfg.Middleware.UserAgent) > maxUserAgentLen || !validation.IsValidHeaderString(cfg.Middleware.UserAgent) {
			return fmt.Errorf("%w: Middleware.UserAgent invalid: max %d chars, no control characters", ErrInvalidMiddleware, maxUserAgentLen)
		}

		for key, value := range cfg.Middleware.Headers {
			if err := validation.ValidateHeaderKeyValue(key, value); err != nil {
				return fmt.Errorf("%w: %s: %w", ErrInvalidHeader, key, err)
			}
		}
	}

	return nil
}

// parseSSRFExemptCIDRs parses and caches CIDR networks from SSRFExemptCIDRs.
// Called after deepCopyConfig to avoid mutating the caller's original Config.
func (c *Config) parseSSRFExemptCIDRs() error {
	if c.Security == nil || len(c.Security.SSRFExemptCIDRs) == 0 {
		return nil
	}
	c.parsedCIDRs = make([]*net.IPNet, 0, len(c.Security.SSRFExemptCIDRs))
	for _, cidr := range c.Security.SSRFExemptCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("Security.SSRFExemptCIDRs: invalid CIDR %q: %w", cidr, err)
		}
		c.parsedCIDRs = append(c.parsedCIDRs, network)
	}
	return nil
}

// String returns a safe string representation of the Config.
// Sensitive values are masked:
//   - ProxyURL credentials (user:pass@host -> ***:***@host)
//   - TLSConfig displays as <configured> or <default>
//   - Headers are not displayed (may contain sensitive data)
func (c *Config) String() string {
	if c == nil {
		return "Config{<nil>}"
	}

	b, ok := configBuilderPool.Get().(*strings.Builder)
	if !ok || b == nil {
		b = &strings.Builder{}
	}
	b.Reset()
	b.Grow(512)

	var numBuf [20]byte

	b.WriteString("Config{Timeouts:{Request: ")
	if c.Timeouts != nil {
		b.WriteString(c.Timeouts.Request.String())
		b.WriteString(", Dial: ")
		b.WriteString(c.Timeouts.Dial.String())
		b.WriteString(", TLSHandshake: ")
		b.WriteString(c.Timeouts.TLSHandshake.String())
	} else {
		b.WriteString("<nil>")
	}

	b.WriteString("}, Connection:{MaxIdleConns: ")
	if c.Connection != nil {
		b.Write(strconv.AppendInt(numBuf[:0], int64(c.Connection.MaxIdleConns), 10))
		b.WriteString(", MaxConnsPerHost: ")
		b.Write(strconv.AppendInt(numBuf[:0], int64(c.Connection.MaxConnsPerHost), 10))
		b.WriteString(", ProxyURL: ")
		b.WriteString(maskProxyURL(c.Connection.ProxyURL))
		b.WriteString(", ProxyPool: ")
		b.Write(strconv.AppendInt(numBuf[:0], int64(len(c.Connection.ProxyPool)), 10))
	} else {
		b.WriteString("<nil>")
	}

	b.WriteString("}, Security:{TLSConfig: ")
	if c.Security != nil {
		if c.Security.TLSConfig != nil {
			b.WriteString("<configured>")
		} else {
			b.WriteString("<default>")
		}
		b.WriteString(", InsecureSkipVerify: ")
		b.WriteString(strconv.FormatBool(c.Security.InsecureSkipVerify))
		b.WriteString(", AllowPrivateIPs: ")
		b.WriteString(strconv.FormatBool(c.Security.AllowPrivateIPs))
		b.WriteString(", CertPinning: ")
		if c.Security.CertificatePinner != nil {
			b.WriteString("<configured>")
		} else {
			b.WriteString("<disabled>")
		}
	} else {
		b.WriteString("<nil>")
	}

	b.WriteString("}, Retry:{MaxRetries: ")
	if c.Retry != nil {
		b.Write(strconv.AppendInt(numBuf[:0], int64(c.Retry.MaxRetries), 10))
		b.WriteString(", BackoffFactor: ")
		b.WriteString(strconv.FormatFloat(c.Retry.BackoffFactor, 'f', 1, 64))
	} else {
		b.WriteString("<nil>")
	}

	b.WriteString("}, Middleware:{UserAgent: ")
	if c.Middleware != nil {
		ua := c.Middleware.UserAgent
		if len(ua) > 50 {
			ua = ua[:50] + "..."
		}
		b.WriteString(ua)
		b.WriteString(", FollowRedirects: ")
		b.WriteString(strconv.FormatBool(c.Middleware.FollowRedirects))
	} else {
		b.WriteString("<nil>")
	}

	b.WriteString("}}")
	result := b.String()
	configBuilderPool.Put(b)
	return result
}

// configBuilderPool reduces allocations for strings.Builder in Config.String().
var configBuilderPool = sync.Pool{
	New: func() any {
		return &strings.Builder{}
	},
}

// maskProxyURL masks credentials in a proxy URL for safe logging.
// Returns the URL with credentials replaced by "***:***".
func maskProxyURL(proxyURL string) string {
	return validation.SanitizeURL(proxyURL)
}
