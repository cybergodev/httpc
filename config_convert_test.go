package httpc

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/cybergodev/httpc/internal/types"
)

func TestCalculateMaxRetries(t *testing.T) {
	tests := []struct {
		name            string
		retryMaxRetries int
		proxyPool       []string
		rotateOnStatus  []int
		expectedRetries int
	}{
		{
			name:            "no proxy pool, no rotation",
			retryMaxRetries: 3,
			proxyPool:       nil,
			rotateOnStatus:  nil,
			expectedRetries: 3,
		},
		{
			name:            "proxy pool without rotation — no adjustment",
			retryMaxRetries: 2,
			proxyPool:       []string{"http://p1:8080", "http://p2:8080", "http://p3:8080"},
			rotateOnStatus:  nil,
			expectedRetries: 2,
		},
		{
			name:            "rotation with 2 proxies, MaxRetries=3 — no change needed",
			retryMaxRetries: 3,
			proxyPool:       []string{"http://p1:8080", "http://p2:8080"},
			rotateOnStatus:  []int{403},
			expectedRetries: 3, // 3 >= 2-1=1, no adjustment
		},
		{
			name:            "rotation with 5 proxies, MaxRetries=2 — raised to 4",
			retryMaxRetries: 2,
			proxyPool: []string{
				"http://p1:8080", "http://p2:8080", "http://p3:8080",
				"http://p4:8080", "http://p5:8080",
			},
			rotateOnStatus:  []int{403},
			expectedRetries: 4, // 5-1=4 > 2, raised
		},
		{
			name:            "rotation with 12 proxies — capped at maxRetryAttempts(10)",
			retryMaxRetries: 1,
			proxyPool: []string{
				"http://p1:8080", "http://p2:8080", "http://p3:8080",
				"http://p4:8080", "http://p5:8080", "http://p6:8080",
				"http://p7:8080", "http://p8:8080", "http://p9:8080",
				"http://p10:8080", "http://p11:8080", "http://p12:8080",
			},
			rotateOnStatus:  []int{403},
			expectedRetries: 10, // capped
		},
		{
			name:            "single proxy with rotation — no adjustment",
			retryMaxRetries: 3,
			proxyPool:       []string{"http://p1:8080"},
			rotateOnStatus:  []int{403},
			expectedRetries: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Retry.MaxRetries = tt.retryMaxRetries
			cfg.Retry.Delay = 50 * time.Millisecond
			cfg.Connection.ProxyPool = tt.proxyPool
			cfg.Connection.ProxyRotateOnStatus = tt.rotateOnStatus

			got := calculateMaxRetries(&cfg)
			if got != tt.expectedRetries {
				t.Errorf("calculateMaxRetries() = %d, want %d", got, tt.expectedRetries)
			}
		})
	}
}

// ============================================================================
// Boundary condition tests for config_convert helpers
// ============================================================================

func TestParseExemptCIDRs_TableDriven(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		wantLen int
		wantErr bool
	}{
		{"nil slice", nil, 0, false},
		{"empty slice", []string{}, 0, false},
		{"valid CIDR", []string{"10.0.0.0/8"}, 1, false},
		{"multiple valid", []string{"10.0.0.0/8", "172.16.0.0/12"}, 2, false},
		{"invalid CIDR", []string{"not-a-cidr"}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Security.SSRFExemptCIDRs = tt.cidrs

			// ValidateConfig only checks CIDR format; parseSSRFExemptCIDRs
			// does the actual parsing and fills parsedCIDRs.
			err := ValidateConfig(&cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig with CIDRs %v error = %v, wantErr %v", tt.cidrs, err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			err = cfg.parseSSRFExemptCIDRs()
			if err != nil {
				t.Errorf("parseSSRFExemptCIDRs unexpected error: %v", err)
				return
			}
			if len(cfg.parsedCIDRs) != tt.wantLen {
				t.Errorf("parsedCIDRs for %v returned %d nets, want %d", tt.cidrs, len(cfg.parsedCIDRs), tt.wantLen)
			}
		})
	}
}

func TestCalculateIdleConnsPerHost_TableDriven(t *testing.T) {
	tests := []struct {
		name            string
		maxConnsPerHost int
		want            int
	}{
		{"unlimited uses cap", 0, 10},
		{"very small capped to max", 1, 1},
		{"small rounds to min", 3, 2},
		{"medium value halved", 8, 4},
		{"large capped", 30, 10},
		{"exact min", 4, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateIdleConnsPerHost(tt.maxConnsPerHost)
			if got != tt.want {
				t.Errorf("calculateIdleConnsPerHost(%d) = %d, want %d", tt.maxConnsPerHost, got, tt.want)
			}
		})
	}
}

func TestCalculateMaxRetryDelay_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		maxRetryDelay time.Duration
		wantMin       time.Duration
		wantMax       time.Duration
	}{
		{"default when not set", 0, 30 * time.Second, 30 * time.Second},
		{"user override", 60 * time.Second, 60 * time.Second, 60 * time.Second},
		{"short override", 5 * time.Second, 5 * time.Second, 5 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Retry: RetryConfig{}}
			cfg.Retry.MaxRetryDelay = tt.maxRetryDelay
			got := calculateMaxRetryDelay(cfg)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("calculateMaxRetryDelay() = %v, want between %v and %v", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

// TestConvertToEngineConfig_NilConfig was removed: despite its name it never
// passed nil, and its three hollow assertions are the first three lines of
// TestConvertToEngineConfig_DerivedDefaults below.

// driftTestRetryPolicy is a no-op RetryPolicy used only to assert that
// RetryConfig.CustomPolicy propagates through convertToEngineConfig.
type driftTestRetryPolicy struct{}

func (driftTestRetryPolicy) ShouldRetry(types.ResponseReader, error, int) bool { return false }
func (driftTestRetryPolicy) GetDelay(int) time.Duration                        { return 0 }
func (driftTestRetryPolicy) MaxRetries() int                                   { return 9 }

// TestConvertToEngineConfig_PropagatesAllFields is the configuration drift guard.
//
// It sets every public Config field that maps into engine.Config to a distinctive
// sentinel value and asserts the value arrives unchanged. A silently un-mapped
// field is exactly the failure this test exists to catch.
//
// WHEN YOU ADD A NEW PUBLIC Config FIELD THAT MUST REACH THE ENGINE: add an
// assertion here. New fields silently missing from convertToEngineConfig are
// the top configuration risk this suite guards against.
//
// Derived fields (with no 1:1 source field) are asserted against their
// documented derivation rule so the mapping contract stays explicit:
//   - KeepAlive: hard-coded defaultKeepAlive (30s) — no public knob
//   - MaxIdleConnsPerHost: derived from MaxConnsPerHost via calculateIdleConnsPerHost
//   - MinTLSVersion/MaxTLSVersion: defaulted to TLS 1.2/1.3 when zero
//   - MaxRetryDelay: defaulted to 30s when zero
//   - CookieJar: created when EnableCookies is true
//   - ExemptNets: parsed from SSRFExemptCIDRs via parseSSRFExemptCIDRs
//   - RedirectWhitelist: built from Security.RedirectWhitelist when non-empty
func TestConvertToEngineConfig_PropagatesAllFields(t *testing.T) {
	cfg := DefaultConfig()

	// --- Distinctive sentinel values (chosen to differ from DefaultConfig) ---
	cfg.Timeouts.Request = 111 * time.Second
	cfg.Timeouts.Dial = 112 * time.Second
	cfg.Timeouts.TLSHandshake = 113 * time.Second
	cfg.Timeouts.ResponseHeader = 114 * time.Second
	cfg.Timeouts.IdleConn = 115 * time.Second

	cfg.Connection.MaxIdleConns = 31
	cfg.Connection.MaxConnsPerHost = 21
	cfg.Connection.MaxResponseHeaderBytes = 2222
	cfg.Connection.ProxyURL = "http://sentinel-proxy:8080"
	cfg.Connection.EnableSystemProxy = true
	cfg.Connection.EnableHTTP2 = false
	cfg.Connection.EnableCookies = true
	cfg.Connection.EnableDoH = true
	cfg.Connection.DoHCacheTTL = 77 * time.Second

	sentinelTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	cfg.Security.TLSConfig = sentinelTLS
	cfg.Security.MinTLSVersion = tls.VersionTLS12
	cfg.Security.MaxTLSVersion = tls.VersionTLS13
	cfg.Security.InsecureSkipVerify = true
	cfg.Security.MaxResponseBodySize = 9991
	cfg.Security.MaxRequestBodySize = 9992
	cfg.Security.MaxDecompressedBodySize = 9993
	cfg.Security.ValidateURL = false
	cfg.Security.ValidateHeaders = false
	cfg.Security.AllowPrivateIPs = true
	cfg.Security.StrictContentLength = false
	pinner, err := NewSPKIHashPinner(testSPKIHash)
	if err != nil {
		t.Fatalf("NewSPKIHashPinner: %v", err)
	}
	cfg.Security.CertificatePinner = pinner
	cfg.Security.SSRFExemptCIDRs = []string{"10.0.0.0/8"}
	cfg.Security.RedirectWhitelist = []string{"sentinel.example.com"}

	cfg.Retry.MaxRetries = 7
	cfg.Retry.Delay = 9 * time.Second
	cfg.Retry.MaxRetryDelay = 13 * time.Second
	cfg.Retry.BackoffFactor = 3.5
	cfg.Retry.EnableJitter = false
	cfg.Retry.CustomPolicy = driftTestRetryPolicy{}

	cfg.Defaults.UserAgent = "sentinel-ua/9.9"
	cfg.Defaults.Headers = map[string]string{"X-Sentinel": "v1", "X-Other": "v2"}
	cfg.Defaults.FollowRedirects = false
	cfg.Defaults.MaxRedirects = 4

	// SSRFExemptCIDRs must be parsed into parsedCIDRs before conversion.
	if err := cfg.parseSSRFExemptCIDRs(); err != nil {
		t.Fatalf("parseSSRFExemptCIDRs: %v", err)
	}

	engCfg, err := convertToEngineConfig(&cfg)
	if err != nil {
		t.Fatalf("convertToEngineConfig error: %v", err)
	}

	// --- Direct 1:1 mappings (the drift guard proper) ---
	assertions := []struct {
		name string
		got  any
		want any
	}{
		{"Timeouts.Request -> Timeout", engCfg.Timeout, cfg.Timeouts.Request},
		{"Timeouts.Dial -> DialTimeout", engCfg.DialTimeout, cfg.Timeouts.Dial},
		{"Timeouts.TLSHandshake", engCfg.TLSHandshakeTimeout, cfg.Timeouts.TLSHandshake},
		{"Timeouts.ResponseHeader", engCfg.ResponseHeaderTimeout, cfg.Timeouts.ResponseHeader},
		{"Timeouts.IdleConn", engCfg.IdleConnTimeout, cfg.Timeouts.IdleConn},

		{"Connection.MaxIdleConns", engCfg.MaxIdleConns, cfg.Connection.MaxIdleConns},
		{"Connection.MaxConnsPerHost", engCfg.MaxConnsPerHost, cfg.Connection.MaxConnsPerHost},
		{"Connection.MaxResponseHeaderBytes", engCfg.MaxResponseHeaderBytes, cfg.Connection.MaxResponseHeaderBytes},
		{"Connection.ProxyURL", engCfg.ProxyURL, cfg.Connection.ProxyURL},
		{"Connection.EnableSystemProxy", engCfg.EnableSystemProxy, cfg.Connection.EnableSystemProxy},
		{"Connection.EnableHTTP2", engCfg.EnableHTTP2, cfg.Connection.EnableHTTP2},
		{"Connection.EnableCookies", engCfg.EnableCookies, cfg.Connection.EnableCookies},
		{"Connection.EnableDoH", engCfg.EnableDoH, cfg.Connection.EnableDoH},
		{"Connection.DoHCacheTTL", engCfg.DoHCacheTTL, cfg.Connection.DoHCacheTTL},

		{"Security.InsecureSkipVerify", engCfg.InsecureSkipVerify, cfg.Security.InsecureSkipVerify},
		{"Security.MaxResponseBodySize", engCfg.MaxResponseBodySize, cfg.Security.MaxResponseBodySize},
		{"Security.MaxRequestBodySize", engCfg.MaxRequestBodySize, cfg.Security.MaxRequestBodySize},
		{"Security.MaxDecompressedBodySize", engCfg.MaxDecompressedBodySize, cfg.Security.MaxDecompressedBodySize},
		{"Security.ValidateURL", engCfg.ValidateURL, cfg.Security.ValidateURL},
		{"Security.ValidateHeaders", engCfg.ValidateHeaders, cfg.Security.ValidateHeaders},
		{"Security.AllowPrivateIPs", engCfg.AllowPrivateIPs, cfg.Security.AllowPrivateIPs},
		{"Security.StrictContentLength", engCfg.StrictContentLength, cfg.Security.StrictContentLength},
		{"Security.MinTLSVersion (explicit)", engCfg.MinTLSVersion, cfg.Security.MinTLSVersion},
		{"Security.MaxTLSVersion (explicit)", engCfg.MaxTLSVersion, cfg.Security.MaxTLSVersion},

		{"Retry.MaxRetries", engCfg.MaxRetries, cfg.Retry.MaxRetries},
		{"Retry.Delay -> RetryDelay", engCfg.RetryDelay, cfg.Retry.Delay},
		{"Retry.MaxRetryDelay (explicit)", engCfg.MaxRetryDelay, cfg.Retry.MaxRetryDelay},
		{"Retry.BackoffFactor", engCfg.BackoffFactor, cfg.Retry.BackoffFactor},
		{"Retry.EnableJitter -> Jitter", engCfg.Jitter, cfg.Retry.EnableJitter},

		{"Middleware.UserAgent", engCfg.UserAgent, cfg.Defaults.UserAgent},
		{"Middleware.FollowRedirects", engCfg.FollowRedirects, cfg.Defaults.FollowRedirects},
		{"Middleware.MaxRedirects", engCfg.MaxRedirects, cfg.Defaults.MaxRedirects},
	}
	for _, a := range assertions {
		if a.got != a.want {
			t.Errorf("%s: got %v, want %v", a.name, a.got, a.want)
		}
	}

	// --- Pointer / interface / map identity (not comparable via the table above) ---
	if engCfg.TLSConfig != sentinelTLS {
		t.Errorf("TLSConfig pointer not propagated: got %p, want %p", engCfg.TLSConfig, sentinelTLS)
	}
	if engCfg.CertificatePinner != pinner {
		t.Error("CertificatePinner not propagated (interface identity mismatch)")
	}
	if engCfg.CustomRetryPolicy != cfg.Retry.CustomPolicy {
		t.Error("CustomRetryPolicy not propagated (interface identity mismatch)")
	}
	if len(engCfg.Headers) != 2 || engCfg.Headers["X-Sentinel"] != "v1" {
		t.Errorf("Middleware.Headers not propagated: got %v", engCfg.Headers)
	}

	// --- Derived fields (documented derivation rules) ---
	if engCfg.KeepAlive != 30*time.Second {
		t.Errorf("KeepAlive (hard-coded default): got %v, want 30s", engCfg.KeepAlive)
	}
	if wantIdle := calculateIdleConnsPerHost(cfg.Connection.MaxConnsPerHost); engCfg.MaxIdleConnsPerHost != wantIdle {
		t.Errorf("MaxIdleConnsPerHost: got %d, want %d (derived from MaxConnsPerHost=%d)",
			engCfg.MaxIdleConnsPerHost, wantIdle, cfg.Connection.MaxConnsPerHost)
	}
	if engCfg.CookieJar == nil {
		t.Error("CookieJar should be non-nil when EnableCookies=true")
	}
	if len(engCfg.ExemptNets) != 1 || engCfg.ExemptNets[0].String() != "10.0.0.0/8" {
		t.Errorf("ExemptNets not parsed from SSRFExemptCIDRs: got %+v", engCfg.ExemptNets)
	}
	if engCfg.RedirectWhitelist == nil {
		t.Error("RedirectWhitelist should be built when Security.RedirectWhitelist is non-empty")
	}
}

// TestConvertToEngineConfig_DerivedDefaults covers the zero-value defaulting
// paths for TLS version, retry delay, and cookie jar.
func TestConvertToEngineConfig_DerivedDefaults(t *testing.T) {
	t.Run("TLS versions default to 1.2/1.3", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Security.MinTLSVersion = 0
		cfg.Security.MaxTLSVersion = 0
		engCfg, err := convertToEngineConfig(&cfg)
		if err != nil {
			t.Fatalf("convertToEngineConfig: %v", err)
		}
		if engCfg.MinTLSVersion != tls.VersionTLS12 || engCfg.MaxTLSVersion != tls.VersionTLS13 {
			t.Errorf("TLS defaults: got min=%d max=%d, want TLS1.2/TLS1.3", engCfg.MinTLSVersion, engCfg.MaxTLSVersion)
		}
	})

	t.Run("MaxRetryDelay defaults to 30s", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Retry.MaxRetryDelay = 0
		engCfg, err := convertToEngineConfig(&cfg)
		if err != nil {
			t.Fatalf("convertToEngineConfig: %v", err)
		}
		if engCfg.MaxRetryDelay != 30*time.Second {
			t.Errorf("MaxRetryDelay default: got %v, want 30s", engCfg.MaxRetryDelay)
		}
	})

	t.Run("CookieJar nil when cookies disabled", func(t *testing.T) {
		cfg := DefaultConfig()
		engCfg, err := convertToEngineConfig(&cfg)
		if err != nil {
			t.Fatalf("convertToEngineConfig: %v", err)
		}
		if engCfg.CookieJar != nil {
			t.Error("CookieJar should be nil when EnableCookies=false")
		}
	})
}
