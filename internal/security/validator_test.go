package security

import (
	"net/url"
	"strings"
	"testing"

	"github.com/cybergodev/httpc/internal/types"
)

// ============================================================================
// SECURITY VALIDATOR UNIT TESTS
// ============================================================================

func TestValidator_NewValidator(t *testing.T) {
	validator := NewValidator()
	if validator == nil {
		t.Fatal("Expected validator to be created")
	}

	if validator.config == nil {
		t.Fatal("Expected config to be set")
	}

	if !validator.config.ValidateURL {
		t.Error("Expected ValidateURL to be true by default")
	}

	if !validator.config.ValidateHeaders {
		t.Error("Expected ValidateHeaders to be true by default")
	}
}

func TestNewValidatorWithConfig(t *testing.T) {
	t.Run("CustomConfig", func(t *testing.T) {
		cfg := &Config{
			AllowPrivateIPs:     true,
			MaxResponseBodySize: 10 * 1024 * 1024,
			ValidateURL:         true,
			ValidateHeaders:     true,
		}

		validator := NewValidatorWithConfig(cfg)
		if validator == nil {
			t.Fatal("Expected non-nil validator")
		}
	})

	t.Run("NilConfig", func(t *testing.T) {
		validator := NewValidatorWithConfig(nil)
		if validator == nil {
			t.Fatal("Expected non-nil validator even with nil config")
		}
	})
}

func TestValidator_ValidateURL(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name      string
		url       string
		shouldErr bool
		errMsg    string
	}{
		{
			name:      "Valid HTTP URL",
			url:       "http://example.com",
			shouldErr: false,
		},
		{
			name:      "Valid HTTPS URL",
			url:       "https://example.com/path",
			shouldErr: false,
		},
		{
			name:      "Valid URL with port",
			url:       "http://example.com:8080",
			shouldErr: false,
		},
		{
			name:      "Valid URL with query",
			url:       "https://example.com/path?key=value",
			shouldErr: false,
		},
		{
			name:      "Empty URL",
			url:       "",
			shouldErr: true,
			errMsg:    "URL cannot be empty",
		},
		{
			name:      "Missing scheme",
			url:       "example.com",
			shouldErr: true,
			errMsg:    "URL scheme is required",
		},
		{
			name:      "Invalid scheme - FTP",
			url:       "ftp://example.com",
			shouldErr: true,
			errMsg:    "unsupported URL scheme",
		},
		{
			name:      "Invalid scheme - JavaScript",
			url:       "javascript:alert(1)",
			shouldErr: true,
			errMsg:    "URL host is required", // Host is checked before scheme
		},
		{
			name:      "Invalid scheme - Data URL",
			url:       "data:text/html,<script>alert(1)</script>",
			shouldErr: true,
			errMsg:    "URL host is required", // Host is checked before scheme
		},
		{
			name:      "Invalid scheme - File",
			url:       "file:///etc/passwd",
			shouldErr: true,
			errMsg:    "URL host is required", // File URLs have empty host, so host check fails first
		},
		{
			name:      "Missing host",
			url:       "http://",
			shouldErr: true,
			errMsg:    "URL host is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{
				Method: "GET",
				URL:    tt.url,
			}

			err := validator.ValidateRequest(req)
			if tt.shouldErr {
				if err == nil {
					t.Errorf("Expected error for URL: %s", tt.url)
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error message to contain '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for valid URL %s: %v", tt.url, err)
				}
			}
		})
	}
}

func TestValidator_ValidateHeaders(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name      string
		headers   map[string]string
		shouldErr bool
		errMsg    string
	}{
		{
			name: "Valid headers",
			headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer token",
				"X-Custom":      "value",
			},
			shouldErr: false,
		},
		{
			name: "CRLF injection in key",
			headers: map[string]string{
				"X-Test\r\nX-Injected": "value",
			},
			shouldErr: true,
			errMsg:    "invalid characters",
		},
		{
			name: "CRLF injection in value",
			headers: map[string]string{
				"X-Test": "value\r\nX-Injected: bad",
			},
			shouldErr: true,
			errMsg:    "invalid characters",
		},
		{
			name: "Null byte in key",
			headers: map[string]string{
				"X-Test\x00": "value",
			},
			shouldErr: true,
			errMsg:    "invalid characters",
		},
		{
			name: "Null byte in value",
			headers: map[string]string{
				"X-Test": "value\x00",
			},
			shouldErr: true,
			errMsg:    "invalid characters",
		},
		{
			name: "Very long header value",
			headers: map[string]string{
				"X-Test": strings.Repeat("a", 10000),
			},
			shouldErr: true,
			errMsg:    "too long",
		},
		{
			name: "Empty header key",
			headers: map[string]string{
				"": "value",
			},
			shouldErr: true,
			errMsg:    "cannot be empty",
		},
		{
			name: "Whitespace-only header key",
			headers: map[string]string{
				"   ": "value",
			},
			shouldErr: true,
			errMsg:    "invalid character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{
				Method:  "GET",
				URL:     "http://example.com",
				Headers: tt.headers,
			}

			err := validator.ValidateRequest(req)
			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error for invalid headers")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error message to contain '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for valid headers: %v", err)
				}
			}
		})
	}
}

func TestValidator_ValidateRequestSize(t *testing.T) {
	validator := NewValidator()
	// Override max size for testing
	validator.config.MaxRequestBodySize = 1024 // 1KB limit

	tests := []struct {
		name      string
		body      interface{}
		shouldErr bool
	}{
		{
			name:      "Small string body",
			body:      "small content",
			shouldErr: false,
		},
		{
			name:      "Large string body",
			body:      strings.Repeat("a", 2000),
			shouldErr: true,
		},
		{
			name:      "Small byte array",
			body:      []byte("small content"),
			shouldErr: false,
		},
		{
			name:      "Large byte array",
			body:      make([]byte, 2000),
			shouldErr: true,
		},
		{
			name:      "Nil body",
			body:      nil,
			shouldErr: false,
		},
		{
			name:      "Struct body (not validated)",
			body:      struct{ Data string }{Data: strings.Repeat("a", 2000)},
			shouldErr: false, // Structs are not validated for size
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{
				Method: "POST",
				URL:    "http://example.com",
				Body:   tt.body,
			}

			err := validator.ValidateRequest(req)
			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error for large request body")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidator_ValidateRequestSize_BodyTypes tests the size validation for url.Values
// and *types.FormData body types, plus the MaxResponseBodySize<=0 early return path.
func TestValidator_ValidateRequestSize_BodyTypes(t *testing.T) {
	t.Run("url.Values small", func(t *testing.T) {
		validator := NewValidator()
		validator.config.MaxRequestBodySize = 1024

		values := url.Values{"key": {"value"}}
		req := &Request{Method: "POST", URL: "http://example.com", Body: values}

		err := validator.ValidateRequest(req)
		if err != nil {
			t.Errorf("unexpected error for small url.Values: %v", err)
		}
	})

	t.Run("url.Values too large", func(t *testing.T) {
		validator := NewValidator()
		validator.config.MaxRequestBodySize = 10

		values := url.Values{"key": {strings.Repeat("a", 50)}}
		req := &Request{Method: "POST", URL: "http://example.com", Body: values}

		err := validator.ValidateRequest(req)
		if err == nil {
			t.Error("expected error for oversized url.Values")
		}
	})

	t.Run("FormData small", func(t *testing.T) {
		validator := NewValidator()
		validator.config.MaxRequestBodySize = 1024

		form := &types.FormData{
			Fields: map[string]string{"username": "john"},
			Files:  map[string]*types.FileData{"avatar": {Filename: "a.txt", Content: []byte("hello")}},
		}
		req := &Request{Method: "POST", URL: "http://example.com", Body: form}

		err := validator.ValidateRequest(req)
		if err != nil {
			t.Errorf("unexpected error for small FormData: %v", err)
		}
	})

	t.Run("FormData too large", func(t *testing.T) {
		validator := NewValidator()
		validator.config.MaxRequestBodySize = 5

		form := &types.FormData{
			Fields: map[string]string{"data": strings.Repeat("x", 100)},
		}
		req := &Request{Method: "POST", URL: "http://example.com", Body: form}

		err := validator.ValidateRequest(req)
		if err == nil {
			t.Error("expected error for oversized FormData fields")
		}
	})

	t.Run("FormData files too large", func(t *testing.T) {
		validator := NewValidator()
		validator.config.MaxRequestBodySize = 10

		form := &types.FormData{
			Files: map[string]*types.FileData{"big": {Content: make([]byte, 100)}},
		}
		req := &Request{Method: "POST", URL: "http://example.com", Body: form}

		err := validator.ValidateRequest(req)
		if err == nil {
			t.Error("expected error for oversized FormData files")
		}
	})

	t.Run("MaxResponseBodySize zero skips validation", func(t *testing.T) {
		validator := NewValidator()
		validator.config.MaxResponseBodySize = 0

		req := &Request{
			Method: "POST",
			URL:    "http://example.com",
			Body:   strings.Repeat("a", 100000),
		}

		err := validator.ValidateRequest(req)
		if err != nil {
			t.Errorf("expected no error when MaxResponseBodySize is zero, got: %v", err)
		}
	})

	t.Run("MaxResponseBodySize negative skips validation", func(t *testing.T) {
		validator := NewValidator()
		validator.config.MaxResponseBodySize = -1

		req := &Request{
			Method: "POST",
			URL:    "http://example.com",
			Body:   strings.Repeat("a", 100000),
		}

		err := validator.ValidateRequest(req)
		if err != nil {
			t.Errorf("expected no error when MaxResponseBodySize is negative, got: %v", err)
		}
	})
}

func TestValidator_DisabledValidation(t *testing.T) {
	validator := NewValidator()
	// Disable validation for testing
	validator.config.ValidateURL = false
	validator.config.ValidateHeaders = false

	// Even with invalid data, validation should pass when disabled
	req := &Request{
		Method: "GET",
		URL:    "javascript:alert(1)", // Invalid scheme
		Headers: map[string]string{
			"X-Test\r\n": "value\r\n", // CRLF injection
		},
	}

	err := validator.ValidateRequest(req)
	if err != nil {
		t.Errorf("Expected no error when validation is disabled, got: %v", err)
	}
}

func TestValidator_ComplexScenarios(t *testing.T) {
	validator := NewValidator()

	t.Run("Valid complex request", func(t *testing.T) {
		req := &Request{
			Method: "POST",
			URL:    "https://api.example.com/v1/users?page=1&limit=10",
			Headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
				"X-Request-ID":  "123e4567-e89b-12d3-a456-426614174000",
				"User-Agent":    "Mozilla/5.0",
			},
			Body: `{"name":"John Doe","email":"john@example.com"}`,
		}

		err := validator.ValidateRequest(req)
		if err != nil {
			t.Errorf("Unexpected error for valid complex request: %v", err)
		}
	})

	t.Run("Multiple validation failures", func(t *testing.T) {
		req := &Request{
			Method: "POST",
			URL:    "", // Invalid: empty URL
			Headers: map[string]string{
				"X-Test\r\n": "value", // Invalid: CRLF in key
			},
			Body: strings.Repeat("a", 20000), // Invalid: too large
		}

		err := validator.ValidateRequest(req)
		if err == nil {
			t.Error("Expected error for request with multiple validation failures")
		}
	})
}

func TestValidator_SpecialCharacters(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "URL with Unicode",
			url:     "https://example.com/path/chinese-text",
			wantErr: false,
		},
		{
			name:    "URL with encoded characters",
			url:     "https://example.com/path?q=%E4%B8%AD%E6%96%87",
			wantErr: false,
		},
		{
			name:    "URL with special characters",
			url:     "https://example.com/path?q=hello+world&foo=bar",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{
				Method: "GET",
				URL:    tt.url,
			}

			err := validator.ValidateRequest(req)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateHost_EdgeCases(t *testing.T) {
	validator := NewValidatorWithConfig(&Config{
		ValidateURL:         true,
		ValidateHeaders:     true,
		MaxResponseBodySize: 50 * 1024 * 1024,
		AllowPrivateIPs:     false,
	})

	tests := []struct {
		name      string
		host      string
		shouldErr bool
	}{
		{"ValidDomain", "example.com", false},
		{"ValidSubdomain", "api.example.com", false},
		{"ValidIP", "8.8.8.8", false},
		{"Localhost", "localhost", true},
		{"PrivateIP", "192.168.1.1", true},
		{"MetadataService", "169.254.169.254", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateHost(tt.host, nil)
			if (err != nil) != tt.shouldErr {
				t.Errorf("validateHost(%s) error = %v, shouldErr = %v", tt.host, err, tt.shouldErr)
			}
		})
	}
}

// TestValidator_ValidateCommonHeaderValue tests the Connection and Transfer-Encoding
// header value validation logic for allowed and disallowed values.
func TestValidator_ValidateCommonHeaderValue(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		value       string
		expectError bool
	}{
		// Connection header - valid values
		{"Connection keep-alive", "Connection", "keep-alive", false},
		{"Connection close", "Connection", "close", false},
		{"Connection upgrade", "Connection", "upgrade", false},
		{"Connection Keep-Alive case insensitive", "connection", "Keep-Alive", false},
		{"Connection CLOSE case insensitive", "CONNECTION", "CLOSE", false},
		// Connection header - multi-token (RFC 9110)
		{"Connection multi keep-alive Upgrade", "Connection", "keep-alive, Upgrade", false},
		{"Connection multi with spaces", "Connection", "keep-alive, upgrade", false},
		// Connection header - invalid values
		{"Connection invalid", "Connection", "invalid-value", true},
		{"Connection empty", "Connection", "", true},
		{"Connection invalid in multi", "Connection", "keep-alive, invalid", true},
		// Transfer-Encoding header - valid values
		{"Transfer-Encoding chunked", "Transfer-Encoding", "chunked", false},
		{"Transfer-Encoding gzip", "Transfer-Encoding", "gzip", false},
		{"Transfer-Encoding deflate", "Transfer-Encoding", "deflate", false},
		{"Transfer-Encoding compress", "Transfer-Encoding", "compress", false},
		{"Transfer-Encoding identity", "Transfer-Encoding", "identity", false},
		{"Transfer-Encoding Chunked case insensitive", "transfer-encoding", "Chunked", false},
		// Transfer-Encoding - invalid
		{"Transfer-Encoding invalid", "Transfer-Encoding", "invalid", true},
		{"Transfer-Encoding empty", "Transfer-Encoding", "", true},
		// Other headers should pass through without error
		{"Content-Type passes through", "Content-Type", "application/json", false},
		{"X-Custom passes through", "X-Custom", "anything", false},
		{"Authorization passes through", "Authorization", "Bearer token", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCommonHeaderValue(tt.key, tt.value)
			if tt.expectError && err == nil {
				t.Errorf("validateCommonHeaderValue(%q, %q) expected error, got nil", tt.key, tt.value)
			}
			if !tt.expectError && err != nil {
				t.Errorf("validateCommonHeaderValue(%q, %q) unexpected error: %v", tt.key, tt.value, err)
			}
		})
	}
}

func TestValidateHeader_EdgeCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name      string
		key       string
		value     string
		shouldErr bool
	}{
		{"ValidHeader", "X-Custom", "value", false},
		{"EmptyKey", "", "value", true},
		{"EmptyValue", "X-Custom", "", false},
		{"CRLFInKey", "X-Custom\r\n", "value", true},
		{"CRLFInValue", "X-Custom", "value\r\nInjection", true},
		{"NullByteInKey", "X-Custom\x00", "value", true},
		{"NullByteInValue", "X-Custom", "value\x00", true},
		{"TabInValue", "X-Custom", "value\twith\ttabs", false},
		{"SpaceInValue", "X-Custom", "value with spaces", false},
		{"LongValue", "X-Custom", "very long value here", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateHeader(tt.key, tt.value)
			if (err != nil) != tt.shouldErr {
				t.Errorf("validateHeader(%q, %q) error = %v, shouldErr = %v", tt.key, tt.value, err, tt.shouldErr)
			}
		})
	}
}

func TestValidateURL_WithAllowPrivateIPs(t *testing.T) {
	cfg := &Config{
		AllowPrivateIPs: true,
	}
	validator := NewValidatorWithConfig(cfg)

	tests := []struct {
		name      string
		url       string
		shouldErr bool
	}{
		{"PrivateIP", "http://192.168.1.1", false},
		{"Localhost", "http://localhost", false},
		{"PublicIP", "http://8.8.8.8", false},
		{"InvalidURL", "://invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateURL(tt.url, nil)
			if (err != nil) != tt.shouldErr {
				t.Errorf("validateURL(%s) error = %v, shouldErr = %v", tt.url, err, tt.shouldErr)
			}
		})
	}
}

// TestValidateRequestBodySize_UrlValues verifies that url.Values body size
// is checked against MaxRequestBodySize when set.
func TestValidateRequestBodySize_UrlValues(t *testing.T) {
	validator := NewValidatorWithConfig(&Config{
		ValidateURL:         true,
		ValidateHeaders:     true,
		MaxRequestBodySize:  10,
		MaxResponseBodySize: 50 * 1024 * 1024,
		AllowPrivateIPs:     true,
	})

	values := url.Values{"key": []string{strings.Repeat("x", 200)}}
	req := &Request{
		Method: "POST",
		URL:    "http://example.com",
		Body:   values,
	}

	err := validator.ValidateRequest(req)
	if err == nil {
		t.Fatal("expected error for oversized url.Values body, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error should mention body size limit, got: %v", err)
	}
}

// TestValidateRequestBodySize_ZeroLimitNoValidation verifies that when
// MaxRequestBodySize is zero, no request-body size validation is performed
// (there is intentionally NO fallback to MaxResponseBodySize).
func TestValidateRequestBodySize_ZeroLimitNoValidation(t *testing.T) {
	validator := NewValidatorWithConfig(&Config{
		ValidateURL:         true,
		ValidateHeaders:     true,
		MaxRequestBodySize:  0,
		MaxResponseBodySize: 100,
		AllowPrivateIPs:     true,
	})

	req := &Request{
		Method: "POST",
		URL:    "http://example.com",
		Body:   strings.Repeat("a", 200),
	}

	err := validator.ValidateRequest(req)
	if err != nil {
		t.Fatalf("expected no error when MaxRequestBodySize is 0, got: %v", err)
	}
}

// TestValidateHost_AllowPrivateIPsFastReturn verifies that validateHost
// returns nil immediately for any host when AllowPrivateIPs is true.
func TestValidateHost_AllowPrivateIPsFastReturn(t *testing.T) {
	validator := NewValidatorWithConfig(&Config{
		ValidateURL:     true,
		ValidateHeaders: true,
		AllowPrivateIPs: true,
	})

	hosts := []string{
		"localhost",
		"127.0.0.1",
		"192.168.1.1",
		"10.0.0.1",
		"169.254.169.254",
		"example.com",
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			err := validator.validateHost(host, nil)
			if err != nil {
				t.Errorf("validateHost(%q) expected nil with AllowPrivateIPs=true, got: %v", host, err)
			}
		})
	}
}

// TestValidatorCacheConcurrency verifies that concurrent URL validation
// does not create duplicate entries in the urlKeys slice.
func TestValidatorCacheConcurrency(t *testing.T) {
	validator := NewValidatorWithConfig(&Config{
		ValidateURL:     true,
		AllowPrivateIPs: true,
	})

	const goroutines = 50
	errCh := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			req := &Request{
				Method:  "GET",
				URL:     "https://example.com/api/test",
				Headers: map[string]string{},
			}
			errCh <- validator.ValidateRequest(req)
		}()
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("ValidateRequest failed: %v", err)
		}
	}

	// Check that urlKeys has at most 1 entry for the URL
	validator.urlMu.Lock()
	keys := validator.urlKeys
	validator.urlMu.Unlock()

	if len(keys) > 1 {
		t.Errorf("expected at most 1 urlKey entry, got %d: %v", len(keys), keys)
	}
}

// boolPtr returns a pointer to b, used to build per-request AllowPrivateIPs overrides.
func boolPtr(b bool) *bool { return &b }

// TestValidateHost_PerRequestOverride verifies that a per-request AllowPrivateIPs
// override takes precedence over the validator's configured policy in both directions.
func TestValidateHost_PerRequestOverride(t *testing.T) {
	// Validator with SSRF protection enabled (AllowPrivateIPs=false).
	validator := NewValidatorWithConfig(&Config{
		ValidateURL:     true,
		AllowPrivateIPs: false,
	})

	// nil override → client policy (false) → localhost blocked.
	if err := validator.validateHost("localhost", nil); err == nil {
		t.Error("validateHost(localhost, nil) expected error with client policy=false")
	}
	// true override → localhost allowed.
	if err := validator.validateHost("localhost", boolPtr(true)); err != nil {
		t.Errorf("validateHost(localhost, true) expected nil, got: %v", err)
	}
	// false override (explicit) → localhost blocked, matching client policy.
	if err := validator.validateHost("localhost", boolPtr(false)); err == nil {
		t.Error("validateHost(localhost, false) expected error")
	}

	// Validator with SSRF protection disabled (AllowPrivateIPs=true): a false
	// override must RE-ENABLE protection for that request.
	permissive := NewValidatorWithConfig(&Config{
		ValidateURL:     true,
		AllowPrivateIPs: true,
	})
	if err := permissive.validateHost("localhost", nil); err != nil {
		t.Errorf("validateHost(localhost, nil) expected nil with client policy=true, got: %v", err)
	}
	if err := permissive.validateHost("localhost", boolPtr(false)); err == nil {
		t.Error("validateHost(localhost, false) expected error even when client policy=true")
	}
}

// TestValidateURL_OverrideDoesNotPoisonCache verifies the URL-validation cache is
// not poisoned by a per-request override. A URL allowed only via override must not
// be cached as generally-allowed, so a later request without the override is still
// blocked. This is the regression guard for the cache keyed by URL string alone.
func TestValidateURL_OverrideDoesNotPoisonCache(t *testing.T) {
	validator := NewValidatorWithConfig(&Config{
		ValidateURL:     true,
		AllowPrivateIPs: false,
	})

	localhost := "http://localhost:8080/"

	// 1. Validate with override=true → allowed (must NOT be cached).
	if err := validator.validateURL(localhost, boolPtr(true)); err != nil {
		t.Fatalf("validateURL with override=true expected nil, got: %v", err)
	}

	// 2. Validate the SAME url with no override → must still be blocked.
	//    If the override result had been cached, this would incorrectly return nil.
	if err := validator.validateURL(localhost, nil); err == nil {
		t.Error("SECURITY ISSUE: validateURL without override must still block localhost after an override-allowed validation (cache poisoned)")
	}
}
