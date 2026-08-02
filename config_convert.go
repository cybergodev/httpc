package httpc

import (
	"crypto/tls"
	"time"

	"github.com/cybergodev/httpc/internal/engine"
	"github.com/cybergodev/httpc/internal/security"
)

const (
	minIdleConnsPerHost    = 2                // Minimum idle connections per host
	maxIdleConnsPerHostCap = 10               // Maximum cap for idle connections per host
	defaultKeepAlive       = 30 * time.Second // TCP keep-alive interval for connection pooling
)

// calculateIdleConnsPerHost calculates the optimal number of idle connections per host
// based on MaxConnsPerHost configuration.
func calculateIdleConnsPerHost(maxConnsPerHost int) int {
	if maxConnsPerHost == 0 {
		// Unlimited max connections - use reasonable default for idle
		return maxIdleConnsPerHostCap
	}
	idleConns := maxConnsPerHost / 2
	if idleConns < minIdleConnsPerHost {
		idleConns = minIdleConnsPerHost
	}
	if idleConns > maxIdleConnsPerHostCap {
		idleConns = maxIdleConnsPerHostCap
	}
	// Don't exceed max total connections per host
	if idleConns > maxConnsPerHost {
		idleConns = maxConnsPerHost
	}
	return idleConns
}

// resolveTLSVersions returns the minimum and maximum TLS versions from config.
// Falls back to TLS 1.2 and TLS 1.3 if not specified.
func resolveTLSVersions(cfg *Config) (min, max uint16) {
	if cfg.Security == nil {
		return tls.VersionTLS12, tls.VersionTLS13
	}
	min = cfg.Security.MinTLSVersion
	if min == 0 {
		min = tls.VersionTLS12
	}
	max = cfg.Security.MaxTLSVersion
	if max == 0 {
		max = tls.VersionTLS13
	}
	return min, max
}

// calculateMaxRetryDelay returns the maximum retry delay from configuration.
// Uses the user-provided MaxRetryDelay if set (> 0), otherwise defaults to 30s.
func calculateMaxRetryDelay(cfg *Config) time.Duration {
	if cfg.Retry != nil && cfg.Retry.MaxRetryDelay > 0 {
		return cfg.Retry.MaxRetryDelay
	}
	return 30 * time.Second
}

// calculateMaxRetries returns the effective MaxRetries, automatically raising
// it when proxy-rotation-on-status is configured so that every proxy in the
// pool is tried at least once before retries are exhausted.
//
// Without this adjustment, a user with 5 proxies and the default MaxRetries=3
// would only try 4 of the 5 proxies before giving up on a 403. When
// ProxyRotateOnStatus is set, the intent is explicitly to rotate through all
// proxies, so the retry budget is raised to len(ProxyPool)-1 (capped at
// maxRetryAttempts to respect the hard ceiling enforced by ValidateConfig).
func calculateMaxRetries(cfg *Config) int {
	maxRetries := 0
	if cfg.Retry != nil {
		maxRetries = cfg.Retry.MaxRetries
	}

	if len(cfg.Connection.ProxyRotateOnStatus) > 0 && len(cfg.Connection.ProxyPool) > 1 {
		needed := len(cfg.Connection.ProxyPool) - 1 // retries beyond the initial attempt
		if needed > maxRetries {
			if needed > maxRetryAttempts {
				needed = maxRetryAttempts
			}
			maxRetries = needed
		}
	}

	return maxRetries
}

// convertToEngineConfig converts public Config to engine Config.
// It uses helper functions for cleaner separation of concerns.
func convertToEngineConfig(cfg *Config) (*engine.Config, error) {
	idleConnsPerHost := calculateIdleConnsPerHost(cfg.Connection.MaxConnsPerHost)
	minTLSVersion, maxTLSVersion := resolveTLSVersions(cfg)
	maxRetryDelay := calculateMaxRetryDelay(cfg)

	cookieJar, err := createCookieJar(cfg.Connection.EnableCookies)
	if err != nil {
		return nil, err
	}

	engineConfig := &engine.Config{
		// Timeout settings
		Timeout:               cfg.Timeouts.Request,
		DialTimeout:           cfg.Timeouts.Dial,
		KeepAlive:             defaultKeepAlive,
		TLSHandshakeTimeout:   cfg.Timeouts.TLSHandshake,
		ResponseHeaderTimeout: cfg.Timeouts.ResponseHeader,
		IdleConnTimeout:       cfg.Timeouts.IdleConn,

		// Connection settings
		MaxIdleConns:           cfg.Connection.MaxIdleConns,
		MaxIdleConnsPerHost:    idleConnsPerHost,
		MaxConnsPerHost:        cfg.Connection.MaxConnsPerHost,
		MaxResponseHeaderBytes: cfg.Connection.MaxResponseHeaderBytes,
		ProxyURL:               cfg.Connection.ProxyURL,
		EnableSystemProxy:      cfg.Connection.EnableSystemProxy,
		ProxyPool:              cfg.Connection.ProxyPool,
		ProxyPoolStrategy:      cfg.Connection.ProxyPoolStrategy,
		ProxyFailureThreshold:  cfg.Connection.ProxyFailureThreshold,
		ProxyCooldown:          cfg.Connection.ProxyCooldown,
		EnableHTTP2:            cfg.Connection.EnableHTTP2,
		CookieJar:              cookieJar,
		EnableCookies:          cfg.Connection.EnableCookies,
		EnableDoH:              cfg.Connection.EnableDoH,
		DoHCacheTTL:            cfg.Connection.DoHCacheTTL,

		// Security settings
		TLSConfig:               cfg.Security.TLSConfig,
		MinTLSVersion:           minTLSVersion,
		MaxTLSVersion:           maxTLSVersion,
		InsecureSkipVerify:      cfg.Security.InsecureSkipVerify,
		MaxResponseBodySize:     cfg.Security.MaxResponseBodySize,
		MaxRequestBodySize:      cfg.Security.MaxRequestBodySize,
		MaxDecompressedBodySize: cfg.Security.MaxDecompressedBodySize,
		ValidateURL:             cfg.Security.ValidateURL,
		ValidateHeaders:         cfg.Security.ValidateHeaders,
		AllowPrivateIPs:         cfg.Security.AllowPrivateIPs,
		StrictContentLength:     cfg.Security.StrictContentLength,
		CertificatePinner:       cfg.Security.CertificatePinner,

		// Retry settings
		MaxRetries:                calculateMaxRetries(cfg),
		RetryDelay:                cfg.Retry.Delay,
		MaxRetryDelay:             maxRetryDelay,
		BackoffFactor:             cfg.Retry.BackoffFactor,
		Jitter:                    cfg.Retry.EnableJitter,
		ExtraRetryableStatusCodes: cfg.Connection.ProxyRotateOnStatus,
		CustomRetryPolicy:         cfg.Retry.CustomPolicy,

		// Middleware settings
		UserAgent:       cfg.Middleware.UserAgent,
		Headers:         cfg.Middleware.Headers,
		FollowRedirects: cfg.Middleware.FollowRedirects,
		MaxRedirects:    cfg.Middleware.MaxRedirects,
	}

	if len(cfg.Security.RedirectWhitelist) > 0 {
		engineConfig.RedirectWhitelist = security.NewDomainWhitelist(cfg.Security.RedirectWhitelist...)
	}

	// Use cached parsed CIDRs from parseSSRFExemptCIDRs (no re-parsing)
	engineConfig.ExemptNets = cfg.parsedCIDRs

	return engineConfig, nil
}
