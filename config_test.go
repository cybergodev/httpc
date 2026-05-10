package httpc

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
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
		if config.Timeouts.Request != 30*time.Second {
			t.Errorf("Expected timeout 30s, got %v", config.Timeouts.Request)
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
		// When running under go test, this should return true
		if !isTestEnvironment() {
			t.Error("isTestEnvironment() should return true when running under go test")
		}
	})

	t.Run("warnTestingConfigInProduction", func(t *testing.T) {
		// Verify the function completes without panic in test environment.
		// In production, this would log a warning; in tests it should be silent.
		warnTestingConfigInProduction()
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
			Timeouts: TimeoutConfig{
				Request:      30 * time.Second,
				Dial:         5 * time.Second,
				TLSHandshake: 5 * time.Second,
			},
			Connection: ConnectionConfig{
				MaxIdleConns:    100,
				MaxConnsPerHost: 20,
				ProxyURL:        "http://proxy:8080",
			},
			Security: SecurityConfig{
				InsecureSkipVerify: true,
				AllowPrivateIPs:    true,
			},
			Retry: RetryConfig{
				MaxRetries:    3,
				BackoffFactor: 1.5,
			},
			Middleware: MiddlewareConfig{
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
			name:     "SOCKS5 URL",
			proxyURL: "socks5://proxy.example.com:1080",
			contains: "socks5",
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
	t.Run("nil config", func(t *testing.T) {
		if err := ValidateConfig(nil); err == nil {
			t.Error("expected error for nil config")
		}
	})

	t.Run("negative dial timeout", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Timeouts.Dial = -1 * time.Second
		if err := ValidateConfig(cfg); err == nil {
			t.Error("expected error for negative dial timeout")
		}
	})

	t.Run("negative TLS handshake timeout", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Timeouts.TLSHandshake = -1 * time.Second
		if err := ValidateConfig(cfg); err == nil {
			t.Error("expected error for negative TLS handshake timeout")
		}
	})

	t.Run("negative response header timeout", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Timeouts.ResponseHeader = -1 * time.Second
		if err := ValidateConfig(cfg); err == nil {
			t.Error("expected error for negative response header timeout")
		}
	})

	t.Run("negative idle conn timeout", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Timeouts.IdleConn = -1 * time.Second
		if err := ValidateConfig(cfg); err == nil {
			t.Error("expected error for negative idle conn timeout")
		}
	})

	t.Run("negative max idle conns", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Connection.MaxIdleConns = -1
		if err := ValidateConfig(cfg); err == nil {
			t.Error("expected error for negative max idle conns")
		}
	})

	t.Run("negative max conns per host", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Connection.MaxConnsPerHost = -1
		if err := ValidateConfig(cfg); err == nil {
			t.Error("expected error for negative max conns per host")
		}
	})

	t.Run("negative max response body size", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Security.MaxResponseBodySize = -1
		if err := ValidateConfig(cfg); err == nil {
			t.Error("expected error for negative max response body size")
		}
	})

	t.Run("negative retry delay", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Retry.Delay = -1 * time.Second
		if err := ValidateConfig(cfg); err == nil {
			t.Error("expected error for negative retry delay")
		}
	})

	t.Run("invalid middleware headers", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Middleware.Headers = map[string]string{"X-Bad": "value\r\nevil"}
		if err := ValidateConfig(cfg); err == nil {
			t.Error("expected error for CRLF in middleware header value")
		}
	})
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
			nets, err := parseExemptCIDRs(tt.cidrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseExemptCIDRs(%v) error = %v, wantErr %v", tt.cidrs, err, tt.wantErr)
				return
			}
			if len(nets) != tt.wantLen {
				t.Errorf("parseExemptCIDRs(%v) returned %d nets, want %d", tt.cidrs, len(nets), tt.wantLen)
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
		{"very small rounds to min", 1, 2},
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
		name    string
		delay   time.Duration
		backoff float64
		wantMin time.Duration
		wantMax time.Duration
	}{
		{"zero delay uses default", 0, 2.0, 5 * time.Second, 5 * time.Second},
		{"zero backoff uses default", 100 * time.Millisecond, 0, 5 * time.Second, 5 * time.Second},
		{"small product uses default min", 100 * time.Millisecond, 1.0, 5 * time.Second, 5 * time.Second},
		{"medium product", 1 * time.Second, 2.0, 6 * time.Second, 7 * time.Second},
		{"large product capped at absolute max", 10 * time.Second, 5.0, 30 * time.Second, 30 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Retry.Delay = tt.delay
			cfg.Retry.BackoffFactor = tt.backoff
			got := calculateMaxRetryDelay(cfg)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("calculateMaxRetryDelay() = %v, want between %v and %v", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestConvertToEngineConfig_NilConfig(t *testing.T) {
	// nil config should use defaults
	engCfg, err := convertToEngineConfig(nil)
	if err != nil {
		t.Fatalf("convertToEngineConfig(nil) error: %v", err)
	}
	if engCfg == nil {
		t.Fatal("expected non-nil engine config")
	}
}

func TestIsTestEnvironment_BoundaryConditions(t *testing.T) {
	t.Parallel()

	origArgs := os.Args[0]
	origGoTest := os.Getenv("GO_TEST")
	origGotest := os.Getenv("GOTEST")
	defer func() {
		os.Args[0] = origArgs
		os.Setenv("GO_TEST", origGoTest)
		os.Setenv("GOTEST", origGotest)
	}()

	t.Run("GO_TEST env var", func(t *testing.T) {
		os.Args[0] = "/usr/bin/myapp"
		os.Setenv("GO_TEST", "1")
		os.Setenv("GOTEST", "")
		if !isTestEnvironment() {
			t.Error("GO_TEST=1 should return true")
		}
	})

	t.Run("non-test binary returns false", func(t *testing.T) {
		os.Args[0] = "/usr/bin/myapp"
		os.Setenv("GO_TEST", "")
		os.Setenv("GOTEST", "")
		if isTestEnvironment() {
			t.Error("non-test binary with no env vars should return false")
		}
	})

	t.Run("test infix pattern", func(t *testing.T) {
		os.Args[0] = "/tmp/my.test.custom"
		os.Setenv("GO_TEST", "")
		os.Setenv("GOTEST", "")
		if !isTestEnvironment() {
			t.Error("binary with .test. infix should return true")
		}
	})
}

func TestWarnTestingConfigInProduction(t *testing.T) {
	origArgs := os.Args[0]
	origGoTest := os.Getenv("GO_TEST")
	origGotest := os.Getenv("GOTEST")
	defer func() {
		os.Args[0] = origArgs
		os.Setenv("GO_TEST", origGoTest)
		os.Setenv("GOTEST", origGotest)
	}()

	// Simulate non-test environment
	os.Args[0] = "/usr/bin/myapp"
	os.Setenv("GO_TEST", "")
	os.Setenv("GOTEST", "")

	// Capture stderr
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = old }()

	warnTestingConfigInProduction()
	w.Close()

	var buf bytes.Buffer
	io.Copy(&buf, r)
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
