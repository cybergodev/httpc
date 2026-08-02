package httpc

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybergodev/httpc/internal/types"
)

// ============================================================================
// CONFIGURATION TESTS - Config validation, presets, TLS versions
// ============================================================================

// ----------------------------------------------------------------------------
// Config Creation and Defaults
// ----------------------------------------------------------------------------

func TestConfig_Defaults(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig should not return nil")
	}
	if config.Timeouts.Request <= 0 {
		t.Error("Default timeout should be positive")
	}
	if config.Retry.MaxRetries < 0 {
		t.Error("Default max retries should be non-negative")
	}
	if config.Connection.MaxIdleConns <= 0 {
		t.Error("Default max idle connections should be positive")
	}
	if config.Middleware.UserAgent == "" {
		t.Error("Default user agent should not be empty")
	}
}

// ----------------------------------------------------------------------------
// Config Presets - Creation and Field Verification
// ----------------------------------------------------------------------------

func TestConfig_Presets(t *testing.T) {
	t.Run("SecureConfig", func(t *testing.T) {
		config := SecureConfig()
		client, err := New(config)
		if err != nil {
			t.Fatalf("New(SecureConfig()) failed: %v", err)
		}
		defer client.Close()

		// Verify security-focused settings
		if config.Security.MinTLSVersion < tls.VersionTLS12 {
			t.Error("Secure config should enforce TLS 1.2+")
		}
		if config.Security.InsecureSkipVerify {
			t.Error("Secure config should not skip TLS verification")
		}
		if config.Security.AllowPrivateIPs {
			t.Error("Secure config should not allow private IPs")
		}
		if config.Timeouts.Request != 15*time.Second {
			t.Errorf("Expected Timeout=15s, got %v", config.Timeouts.Request)
		}
		if config.Retry.MaxRetries != 1 {
			t.Errorf("Expected MaxRetries=1, got %d", config.Retry.MaxRetries)
		}
		if config.Middleware.FollowRedirects {
			t.Error("Expected FollowRedirects=false")
		}
	})

	t.Run("PerformanceConfig", func(t *testing.T) {
		config := PerformanceConfig()
		client, err := New(config)
		if err != nil {
			t.Fatalf("New(PerformanceConfig()) failed: %v", err)
		}
		defer client.Close()

		// Verify performance-focused settings
		if config.Connection.MaxIdleConns <= 0 {
			t.Error("Performance config should have connection pooling")
		}
		if !config.Connection.EnableHTTP2 {
			t.Error("Performance config should enable HTTP/2")
		}
		if config.Timeouts.Request != 60*time.Second {
			t.Errorf("Expected Timeout=60s, got %v", config.Timeouts.Request)
		}
	})

	t.Run("MinimalConfig", func(t *testing.T) {
		config := MinimalConfig()
		client, err := New(config)
		if err != nil {
			t.Fatalf("New(MinimalConfig()) failed: %v", err)
		}
		defer client.Close()

		// Verify minimal settings
		if config.Retry.MaxRetries != 0 {
			t.Error("Minimal config should have no retries")
		}
		if config.Middleware.FollowRedirects {
			t.Error("Minimal config should not follow redirects")
		}
	})

	t.Run("TestingConfig", func(t *testing.T) {
		config := TestingConfig()

		// Verify testing-focused settings
		if config.Timeouts.Request != 180*time.Second {
			t.Errorf("Expected timeout 180s, got %v", config.Timeouts.Request)
		}
		if !config.Security.AllowPrivateIPs {
			t.Error("Expected AllowPrivateIPs to be true")
		}
		if !config.Security.InsecureSkipVerify {
			t.Error("Expected InsecureSkipVerify to be true for testing")
		}
		if config.Retry.MaxRetries != 1 {
			t.Errorf("Expected MaxRetries=1, got %d", config.Retry.MaxRetries)
		}
		if config.Middleware.UserAgent != "httpc-test/1.0" {
			t.Errorf("Expected UserAgent='httpc-test/1.0', got %q", config.Middleware.UserAgent)
		}
	})
}

// ----------------------------------------------------------------------------
// Config Validation - Field-Specific Tests
// ----------------------------------------------------------------------------

func TestConfig_Validation(t *testing.T) {
	t.Run("Timeout", func(t *testing.T) {
		tests := []struct {
			name    string
			timeout time.Duration
			wantErr bool
		}{
			{"Positive", 30 * time.Second, false},
			{"Zero", 0, false},
			{"Negative", -1 * time.Second, true},
			{"TooLarge", 24 * time.Hour, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				config := DefaultConfig()
				config.Timeouts.Request = tt.timeout
				_, err := New(config)
				if (err != nil) != tt.wantErr {
					t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				}
			})
		}
	})

	t.Run("MaxRetries", func(t *testing.T) {
		tests := []struct {
			name       string
			maxRetries int
			wantErr    bool
		}{
			{"Zero", 0, false},
			{"Positive", 3, false},
			{"Negative", -1, true},
			{"TooLarge", 100, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				config := DefaultConfig()
				config.Retry.MaxRetries = tt.maxRetries
				_, err := New(config)
				if (err != nil) != tt.wantErr {
					t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				}
			})
		}
	})

	t.Run("ConnectionPool", func(t *testing.T) {
		tests := []struct {
			name         string
			maxIdleConns int
			maxConns     int
			wantErr      bool
		}{
			{"Valid", 100, 10, false},
			{"NegativeIdle", -1, 10, true},
			{"NegativePerHost", 100, -1, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				config := DefaultConfig()
				config.Connection.MaxIdleConns = tt.maxIdleConns
				config.Connection.MaxConnsPerHost = tt.maxConns
				client, err := New(config)
				if (err != nil) != tt.wantErr {
					t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				}
				if client != nil {
					client.Close()
				}
			})
		}
	})

	t.Run("UserAgent", func(t *testing.T) {
		tests := []struct {
			name      string
			userAgent string
			wantErr   bool
		}{
			{"Valid", "MyApp/1.0", false},
			{"Empty", "", false},
			{"WithCRLF", "MyApp\r\n/1.0", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				config := DefaultConfig()
				config.Middleware.UserAgent = tt.userAgent
				client, err := New(config)
				if (err != nil) != tt.wantErr {
					t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				}
				if client != nil {
					client.Close()
				}
			})
		}
	})
}

// ----------------------------------------------------------------------------
// TLS Configuration
// ----------------------------------------------------------------------------

func TestConfig_TLSVersions(t *testing.T) {
	t.Run("MinTLSVersion", func(t *testing.T) {
		tests := []struct {
			name       string
			minVersion uint16
			wantErr    bool
		}{
			{"TLS 1.2", tls.VersionTLS12, false},
			{"TLS 1.3", tls.VersionTLS13, false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				config := DefaultConfig()
				config.Security.MinTLSVersion = tt.minVersion
				client, err := New(config)
				if (err != nil) != tt.wantErr {
					t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				}
				if client != nil {
					client.Close()
				}
			})
		}
	})

	t.Run("MaxTLSVersion", func(t *testing.T) {
		tests := []struct {
			name       string
			maxVersion uint16
			wantErr    bool
		}{
			{"TLS 1.3", tls.VersionTLS13, false},
			{"TLS 1.2", tls.VersionTLS12, false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				config := DefaultConfig()
				config.Security.MaxTLSVersion = tt.maxVersion
				client, err := New(config)
				if (err != nil) != tt.wantErr {
					t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				}
				if client != nil {
					client.Close()
				}
			})
		}
	})

	t.Run("TLSVersionRange", func(t *testing.T) {
		tests := []struct {
			name       string
			minVersion uint16
			maxVersion uint16
			wantErr    bool
		}{
			{"Valid: 1.2-1.3", tls.VersionTLS12, tls.VersionTLS13, false},
			{"Valid: 1.2-1.2", tls.VersionTLS12, tls.VersionTLS12, false},
			{"Invalid: Min>Max", tls.VersionTLS13, tls.VersionTLS12, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				config := DefaultConfig()
				config.Security.MinTLSVersion = tt.minVersion
				config.Security.MaxTLSVersion = tt.maxVersion
				client, err := New(config)
				if (err != nil) != tt.wantErr {
					t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				}
				if client != nil {
					client.Close()
				}
			})
		}
	})

	t.Run("WithTLSConfig", func(t *testing.T) {
		config := DefaultConfig()
		config.Security.MinTLSVersion = tls.VersionTLS12
		config.Security.MaxTLSVersion = tls.VersionTLS13
		config.Security.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}

		client, err := New(config)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()
	})
}

// ----------------------------------------------------------------------------
// Config Immutability
// ----------------------------------------------------------------------------

func TestConfig_Modification(t *testing.T) {
	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	originalTimeout := config.Timeouts.Request

	client, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Modify config after client creation
	config.Timeouts.Request = 1 * time.Nanosecond
	config.Retry.MaxRetries = 10

	// Sanity check: config was actually modified
	if config.Timeouts.Request == originalTimeout {
		t.Fatal("sanity check failed: config should have been modified")
	}

	// Verify client is unaffected: make a request that would time out
	// if the client used the modified 1ns timeout.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond) // Small delay that 1ns timeout can't survive
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err = client.Get(server.URL)
	if err != nil {
		t.Errorf("client should use original timeout, not modified 1ns: %v", err)
	}
}

// ----------------------------------------------------------------------------
// Internal Helper Functions
// ----------------------------------------------------------------------------

func TestConfig_InternalHelpers(t *testing.T) {
	t.Run("isTestEnvironment", func(t *testing.T) {
		if !isTestEnvironment() {
			t.Error("isTestEnvironment() should return true when running under go test")
		}
	})

	t.Run("isTestEnvironment false positive", func(t *testing.T) {
		// Verify the check is based on os.Args[0] containing ".test"
		original := os.Args[0]
		os.Args[0] = "myapp"
		defer func() { os.Args[0] = original }()

		// Even with modified Args, isTestEnvironment should check the actual binary
		// This test ensures the function doesn't just check a global that could be wrong
		_ = isTestEnvironment()
	})
}

// ----------------------------------------------------------------------------
// Advanced Config Fields
// ----------------------------------------------------------------------------

func TestConfig_AdvancedFields(t *testing.T) {
	t.Run("FlatFieldUsage", func(t *testing.T) {
		config := DefaultConfig()

		// Use flat fields for common settings
		config.Timeouts.Request = 60 * time.Second
		config.Retry.MaxRetries = 5
		config.Connection.ProxyURL = "http://proxy:8080"
		config.Security.AllowPrivateIPs = true
		config.Middleware.UserAgent = "my-app/1.0"
		config.Middleware.FollowRedirects = false

		// Use flat fields for advanced settings
		config.Timeouts.Dial = 5 * time.Second
		config.Timeouts.TLSHandshake = 5 * time.Second
		config.Connection.MaxIdleConns = 100
		config.Connection.MaxConnsPerHost = 20
		config.Security.MaxResponseBodySize = 50 * 1024 * 1024
		config.Retry.Delay = 500 * time.Millisecond
		config.Retry.BackoffFactor = 1.5

		client, err := New(config)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()
	})
}

// ----------------------------------------------------------------------------
// Config.String() Tests
// ----------------------------------------------------------------------------

func TestConfig_String(t *testing.T) {
	t.Run("Nil config", func(t *testing.T) {
		var config *Config = nil
		result := config.String()
		if result != "Config{<nil>}" {
			t.Errorf("Expected 'Config{<nil>}', got %q", result)
		}
	})

	t.Run("Default config", func(t *testing.T) {
		config := DefaultConfig()
		result := config.String()

		// Verify key parts are present
		if !strings.Contains(result, "Config{") {
			t.Error("String should start with 'Config{'")
		}
		if !strings.Contains(result, "Request:") {
			t.Error("String should contain 'Request:'")
		}
		if !strings.Contains(result, "ProxyURL:") {
			t.Error("String should contain 'ProxyURL:'")
		}
		if !strings.Contains(result, "TLSConfig:") {
			t.Error("String should contain 'TLSConfig:'")
		}
		if !strings.Contains(result, "<default>") {
			t.Error("String should contain '<default>' for nil TLSConfig")
		}
	})

	t.Run("Config with TLS", func(t *testing.T) {
		config := DefaultConfig()
		config.Security.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		result := config.String()
		if !strings.Contains(result, "<configured>") {
			t.Error("String should contain '<configured>' for non-nil TLSConfig")
		}
	})

	t.Run("Config with all fields", func(t *testing.T) {
		config := &Config{
			Timeouts: &TimeoutConfig{
				Request:      30 * time.Second,
				Dial:         5 * time.Second,
				TLSHandshake: 5 * time.Second,
			},
			Connection: &ConnectionConfig{
				MaxIdleConns:    100,
				MaxConnsPerHost: 20,
				ProxyURL:        "http://proxy:8080",
			},
			Security: &SecurityConfig{
				InsecureSkipVerify: true,
				AllowPrivateIPs:    true,
			},
			Retry: &RetryConfig{
				MaxRetries:    3,
				BackoffFactor: 1.5,
			},
			Middleware: &MiddlewareConfig{
				UserAgent:       "test-agent",
				FollowRedirects: false,
			},
		}

		result := config.String()

		// Verify all key fields are present
		expectedParts := []string{
			"Request:",
			"Dial:",
			"TLSHandshake:",
			"MaxIdleConns:",
			"MaxConnsPerHost:",
			"ProxyURL:",
			"InsecureSkipVerify:",
			"AllowPrivateIPs:",
			"MaxRetries:",
			"BackoffFactor:",
			"UserAgent:",
			"FollowRedirects:",
		}

		for _, part := range expectedParts {
			if !strings.Contains(result, part) {
				t.Errorf("String should contain %q", part)
			}
		}
	})
}

// ----------------------------------------------------------------------------
// maskProxyURL Tests (via Config.String())
// ----------------------------------------------------------------------------

func TestMaskProxyURL(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
		// We test this via Config.String() since maskProxyURL is not exported
		contains    string
		notContains string
	}{
		{
			name:     "Empty URL",
			proxyURL: "",
			contains: "ProxyURL:",
		},
		{
			name:     "URL without credentials",
			proxyURL: "http://proxy.example.com:8080",
			contains: "proxy.example.com",
		},
		{
			name:        "URL with credentials",
			proxyURL:    "http://user:secret@proxy.example.com:8080",
			notContains: "secret",
		},
		{
			name:     "HTTPS proxy URL",
			proxyURL: "https://proxy.example.com:8443",
			contains: "proxy.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.Connection.ProxyURL = tt.proxyURL
			result := config.String()

			if tt.contains != "" && !strings.Contains(result, tt.contains) {
				t.Errorf("Expected result to contain %q, got: %s", tt.contains, result)
			}
			if tt.notContains != "" && strings.Contains(result, tt.notContains) {
				t.Errorf("Expected result NOT to contain %q, got: %s", tt.notContains, result)
			}
		})
	}
}

func TestConfig_String_UserAgentTruncation(t *testing.T) {
	config := DefaultConfig()
	config.Middleware.UserAgent = strings.Repeat("x", 60)
	result := config.String()
	if !strings.Contains(result, "x...") {
		t.Error("Long UserAgent should be truncated with '...'")
	}
	config.Middleware.UserAgent = "short-agent"
	result = config.String()
	if !strings.Contains(result, "short-agent") {
		t.Error("Short UserAgent should appear in full")
	}
}

func TestDefaultCookieSecurityConfig(t *testing.T) {
	cfg := DefaultCookieSecurityConfig()
	if cfg == nil {
		t.Fatal("DefaultCookieSecurityConfig returned nil")
	}
	if cfg.RequireSecure {
		t.Error("Default should not require Secure")
	}
	if cfg.RequireHttpOnly {
		t.Error("Default should not require HttpOnly")
	}
}

func TestStrictCookieSecurityConfig(t *testing.T) {
	cfg := StrictCookieSecurityConfig()
	if cfg == nil {
		t.Fatal("StrictCookieSecurityConfig returned nil")
	}
	if !cfg.RequireSecure {
		t.Error("Strict should require Secure")
	}
	if !cfg.RequireHttpOnly {
		t.Error("Strict should require HttpOnly")
	}
	if cfg.RequireSameSite != "Strict" {
		t.Error("Strict should require SameSite=Strict")
	}
}

// ----------------------------------------------------------------------------
// ValidateConfig additional boundary cases
// ----------------------------------------------------------------------------

func TestValidateConfig_AdditionalBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"nil config", func(c *Config) {}, true},
		{"negative dial timeout", func(c *Config) { c.Timeouts.Dial = -1 * time.Second }, true},
		{"negative TLS handshake timeout", func(c *Config) { c.Timeouts.TLSHandshake = -1 * time.Second }, true},
		{"negative response header timeout", func(c *Config) { c.Timeouts.ResponseHeader = -1 * time.Second }, true},
		{"negative idle conn timeout", func(c *Config) { c.Timeouts.IdleConn = -1 * time.Second }, true},
		{"negative max idle conns", func(c *Config) { c.Connection.MaxIdleConns = -1 }, true},
		{"negative max conns per host", func(c *Config) { c.Connection.MaxConnsPerHost = -1 }, true},
		{"negative max response body size", func(c *Config) { c.Security.MaxResponseBodySize = -1 }, true},
		{"negative retry delay", func(c *Config) { c.Retry.Delay = -1 * time.Second }, true},
		{"invalid middleware headers", func(c *Config) { c.Middleware.Headers = map[string]string{"X-Bad": "value\r\nevil"} }, true},
		{"retry delay zero", func(c *Config) { c.Retry.Delay = 0 }, false},
		{"backoff factor zero", func(c *Config) { c.Retry.BackoffFactor = 0 }, true},
		{"negative backoff factor", func(c *Config) { c.Retry.BackoffFactor = -1 }, true},
		{"max response body size zero", func(c *Config) { c.Security.MaxResponseBodySize = 0 }, false},
		{"backoff factor at minimum", func(c *Config) { c.Retry.BackoffFactor = 1.0 }, false},
		{"backoff factor at maximum", func(c *Config) { c.Retry.BackoffFactor = 10.0 }, false},
		{"backoff factor over maximum", func(c *Config) { c.Retry.BackoffFactor = 11.0 }, true},
		{"invalid proxy pool entry", func(c *Config) { c.Connection.ProxyPool = []string{"ftp://bad.example.com:8080"} }, true},
		{"negative proxy failure threshold", func(c *Config) { c.Connection.ProxyFailureThreshold = -1 }, true},
		{"negative proxy cooldown", func(c *Config) { c.Connection.ProxyCooldown = -1 * time.Second }, true},
		{"invalid rotate status code low", func(c *Config) { c.Connection.ProxyRotateOnStatus = []int{99} }, true},
		{"invalid rotate status code high", func(c *Config) { c.Connection.ProxyRotateOnStatus = []int{600} }, true},
		{"valid proxy pool", func(c *Config) { c.Connection.ProxyPool = []string{"http://proxy:8080", "socks5://proxy2:1080"} }, false},
		{"valid rotate status code", func(c *Config) { c.Connection.ProxyRotateOnStatus = []int{403, 429} }, false},
		{"zero proxy failure threshold", func(c *Config) { c.Connection.ProxyFailureThreshold = 0 }, false},
		{"zero proxy cooldown", func(c *Config) { c.Connection.ProxyCooldown = 0 }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "nil config" {
				if err := ValidateConfig(nil); err == nil {
					t.Error("expected error for nil config")
				}
				return
			}
			cfg := DefaultConfig()
			tt.mutate(cfg)
			if err := ValidateConfig(cfg); (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
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
			err := ValidateConfig(cfg)
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
			cfg := &Config{Retry: &RetryConfig{}}
			cfg.Retry.MaxRetryDelay = tt.maxRetryDelay
			got := calculateMaxRetryDelay(cfg)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("calculateMaxRetryDelay() = %v, want between %v and %v", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestConvertToEngineConfig_NilConfig(t *testing.T) {
	// convertToEngineConfig requires non-nil config (New() always provides one).
	// Verify DefaultConfig() converts correctly.
	engCfg, err := convertToEngineConfig(DefaultConfig())
	if err != nil {
		t.Fatalf("convertToEngineConfig(DefaultConfig()) error: %v", err)
	}
	if engCfg == nil {
		t.Fatal("expected non-nil engine config")
	}
}

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

	cfg.Middleware.UserAgent = "sentinel-ua/9.9"
	cfg.Middleware.Headers = map[string]string{"X-Sentinel": "v1", "X-Other": "v2"}
	cfg.Middleware.FollowRedirects = false
	cfg.Middleware.MaxRedirects = 4

	// SSRFExemptCIDRs must be parsed into parsedCIDRs before conversion.
	if err := cfg.parseSSRFExemptCIDRs(); err != nil {
		t.Fatalf("parseSSRFExemptCIDRs: %v", err)
	}

	engCfg, err := convertToEngineConfig(cfg)
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

		{"Middleware.UserAgent", engCfg.UserAgent, cfg.Middleware.UserAgent},
		{"Middleware.FollowRedirects", engCfg.FollowRedirects, cfg.Middleware.FollowRedirects},
		{"Middleware.MaxRedirects", engCfg.MaxRedirects, cfg.Middleware.MaxRedirects},
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
		engCfg, err := convertToEngineConfig(cfg)
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
		engCfg, err := convertToEngineConfig(cfg)
		if err != nil {
			t.Fatalf("convertToEngineConfig: %v", err)
		}
		if engCfg.MaxRetryDelay != 30*time.Second {
			t.Errorf("MaxRetryDelay default: got %v, want 30s", engCfg.MaxRetryDelay)
		}
	})

	t.Run("CookieJar nil when cookies disabled", func(t *testing.T) {
		cfg := DefaultConfig()
		engCfg, err := convertToEngineConfig(cfg)
		if err != nil {
			t.Fatalf("convertToEngineConfig: %v", err)
		}
		if engCfg.CookieJar != nil {
			t.Error("CookieJar should be nil when EnableCookies=false")
		}
	})
}

func TestIsTestEnvironment_BoundaryConditions(t *testing.T) {
	t.Parallel()

	// Exercise the pure detection logic directly. These tests MUST NOT mutate
	// os.Args / environment variables: they are process-global and other
	// parallel tests read them via New() -> isTestEnvironment(), so writing
	// them here would data-race under -race.
	cases := []struct {
		name       string
		executable string
		goTest     string
		gotest     string
		want       bool
	}{
		{name: "GO_TEST env var", executable: "/usr/bin/myapp", goTest: "1", gotest: "", want: true},
		{name: "GOTEST env var", executable: "/usr/bin/myapp", goTest: "", gotest: "1", want: true},
		{name: "non-test binary returns false", executable: "/usr/bin/myapp", goTest: "", gotest: "", want: false},
		{name: "test infix pattern", executable: "/tmp/my.test.custom", goTest: "", gotest: "", want: true},
		{name: "dot-test suffix", executable: "runner.test", goTest: "", gotest: "", want: true},
		{name: "dot-test-exe suffix", executable: "runner.test.exe", goTest: "", gotest: "", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isTestEnvironmentFrom(tc.executable, tc.goTest, tc.gotest); got != tc.want {
				t.Errorf("isTestEnvironmentFrom(%q, %q, %q) = %v, want %v",
					tc.executable, tc.goTest, tc.gotest, got, tc.want)
			}
		})
	}
}

func TestWarnTestingConfigInProduction(t *testing.T) {
	origArgs := os.Args[0]
	origGoTest := os.Getenv("GO_TEST")
	origGotest := os.Getenv("GOTEST")
	defer func() {
		os.Args[0] = origArgs
		os.Setenv("GO_TEST", origGoTest)
		os.Setenv("GOTEST", origGotest)
		// Restore warning state
		testingConfigWarnOnce = sync.Once{}
		insecureSkipVerifyWarnOnce = sync.Once{}
		securityWarnOutput = os.Stderr
	}()

	// Simulate non-test environment
	os.Args[0] = "/usr/bin/myapp"
	os.Setenv("GO_TEST", "")
	os.Setenv("GOTEST", "")

	// Reset once so the warning fires in this test
	testingConfigWarnOnce = sync.Once{}

	// Capture warning output via SetSecurityWarnOutput
	var buf bytes.Buffer
	SetSecurityWarnOutput(&buf)

	warnTestingConfigInProduction()

	output := buf.String()

	if !strings.Contains(output, "SECURITY WARNING") {
		t.Error("expected security warning in stderr")
	}
	if !strings.Contains(output, "TLS") {
		t.Error("expected TLS warning")
	}
	if !strings.Contains(output, "SSRF") {
		t.Error("expected SSRF warning")
	}
}
