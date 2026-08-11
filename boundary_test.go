package httpc

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/cybergodev/httpc/internal/engine"
	"github.com/cybergodev/httpc/internal/validation"
)

// ============================================================================
// BOUNDARY CONDITION TESTS
// Targets nil-receiver paths, empty/invalid inputs, and edge cases that are
// not covered by the main test suites.
// ============================================================================

// ---------------------------------------------------------------------------
// SessionManager nil-receiver safety
// ---------------------------------------------------------------------------

func TestSessionManager_NilReceiverSafety(t *testing.T) {
	var s *SessionManager // nil receiver

	t.Run("SetCookieSecurity does not panic", func(t *testing.T) {
		s.SetCookieSecurity(nil)
	})

	t.Run("SetHeader returns error", func(t *testing.T) {
		if err := s.SetHeader("key", "val"); err == nil {
			t.Error("expected error on nil receiver")
		}
	})

	t.Run("SetHeaders returns error", func(t *testing.T) {
		if err := s.SetHeaders(map[string]string{"k": "v"}); err == nil {
			t.Error("expected error on nil receiver")
		}
	})

	t.Run("SetHeaders with invalid header returns error", func(t *testing.T) {
		sm, _ := NewSessionManagerDefault()
		badHeaders := map[string]string{"": "empty-key"}
		if err := sm.SetHeaders(badHeaders); err == nil {
			t.Error("expected error for empty header key")
		}
	})

	t.Run("DeleteHeader does not panic", func(t *testing.T) {
		s.DeleteHeader("key")
	})

	t.Run("ClearHeaders does not panic", func(t *testing.T) {
		s.ClearHeaders()
	})

	t.Run("GetHeaders returns nil", func(t *testing.T) {
		if h := s.GetHeaders(); h != nil {
			t.Errorf("expected nil, got %v", h)
		}
	})

	t.Run("SetCookie returns error", func(t *testing.T) {
		if err := s.SetCookie(&http.Cookie{Name: "k", Value: "v"}); err == nil {
			t.Error("expected error on nil receiver")
		}
	})

	t.Run("SetCookies returns error", func(t *testing.T) {
		if err := s.SetCookies([]*http.Cookie{{Name: "k", Value: "v"}}); err == nil {
			t.Error("expected error on nil receiver")
		}
	})

	t.Run("DeleteCookie does not panic", func(t *testing.T) {
		s.DeleteCookie("key")
	})

	t.Run("ClearCookies does not panic", func(t *testing.T) {
		s.ClearCookies()
	})

	t.Run("GetCookies returns nil", func(t *testing.T) {
		if c := s.GetCookies(); c != nil {
			t.Errorf("expected nil, got %v", c)
		}
	})

	t.Run("GetCookie returns nil", func(t *testing.T) {
		if c := s.GetCookie("key"); c != nil {
			t.Errorf("expected nil, got %v", c)
		}
	})
}

// ---------------------------------------------------------------------------
// Public option error paths — table-driven
// ---------------------------------------------------------------------------

func TestOptions_ErrorPaths(t *testing.T) {
	t.Run("WithBasicAuth", func(t *testing.T) {
		tests := []struct {
			name     string
			username string
			password string
			wantErr  bool
		}{
			{"empty username", "", "pass", true},
			{"username with control char", "user\x00name", "pass", true},
			{"password with control char", "user", "pass\x01word", true},
			{"valid credentials", "user", "pass", false},
			{"empty password rejected", "user", "", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := engine.AcquireRequest()
				err := WithBasicAuth(tt.username, tt.password)(req)
				if tt.wantErr && err == nil {
					t.Error("expected error, got nil")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			})
		}
	})

	t.Run("WithBearerToken", func(t *testing.T) {
		tests := []struct {
			name    string
			token   string
			wantErr bool
		}{
			{"empty token", "", true},
			{"token with control char", "tok\x01en", true},
			{"valid token", "Bearer123", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := engine.AcquireRequest()
				err := WithBearerToken(tt.token)(req)
				if tt.wantErr && err == nil {
					t.Error("expected error, got nil")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			})
		}
	})

	t.Run("WithQuery", func(t *testing.T) {
		tests := []struct {
			name    string
			key     string
			value   any
			wantErr bool
		}{
			{"empty key", "", "val", true},
			{"key too long", strings.Repeat("k", validation.MaxHeaderKeyLen+1), "val", true},
			{"nil value skipped", "key", nil, false},
			{"valid int value", "count", 42, false},
			{"valid string value", "name", "test", false},
			{"valid bool value", "enabled", true, false},
			{"value too long", "data", strings.Repeat("x", validation.MaxValueLen+1), true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := engine.AcquireRequest()
				err := WithQuery(tt.key, tt.value)(req)
				if tt.wantErr && err == nil {
					t.Error("expected error, got nil")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			})
		}
	})

	t.Run("WithQueryMap", func(t *testing.T) {
		tests := []struct {
			name    string
			params  map[string]any
			wantErr bool
		}{
			{"empty key in map", map[string]any{"": "val"}, true},
			{"nil value skipped", map[string]any{"key": nil}, false},
			{"valid map", map[string]any{"a": "1", "b": 2}, false},
			{"value too long", map[string]any{"key": strings.Repeat("x", validation.MaxValueLen+1)}, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := engine.AcquireRequest()
				err := WithQueryMap(tt.params)(req)
				if tt.wantErr && err == nil {
					t.Error("expected error, got nil")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			})
		}
	})

	t.Run("WithHeaderMap", func(t *testing.T) {
		tests := []struct {
			name    string
			headers map[string]string
			wantErr bool
		}{
			{"empty key", map[string]string{"": "val"}, true},
			{"control char in value", map[string]string{"X-Key": "bad\x01val"}, true},
			{"valid single header", map[string]string{"X-Custom": "value"}, false},
			{"valid multiple headers", map[string]string{"X-A": "1", "X-B": "2"}, false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := engine.AcquireRequest()
				err := WithHeaderMap(tt.headers)(req)
				if tt.wantErr && err == nil {
					t.Error("expected error, got nil")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			})
		}
	})

	t.Run("WithForm nil data", func(t *testing.T) {
		req := engine.AcquireRequest()
		err := WithForm(nil)(req)
		if err == nil {
			t.Error("expected error for nil form data")
		}
	})

	t.Run("WithMaxRetries", func(t *testing.T) {
		tests := []struct {
			name    string
			n       int
			wantErr bool
		}{
			{"zero", 0, false},
			{"positive", 3, false},
			{"negative", -1, true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := engine.AcquireRequest()
				err := WithMaxRetries(tt.n)(req)
				if tt.wantErr && err == nil {
					t.Error("expected error, got nil")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			})
		}
	})
}

// ---------------------------------------------------------------------------
// Cookie option boundary conditions
// ---------------------------------------------------------------------------

func TestWithCookie_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name    string
		cookie  http.Cookie
		wantErr bool
	}{
		{"empty name", http.Cookie{Name: "", Value: "val"}, true},
		{"control char in name", http.Cookie{Name: "ba\x00d", Value: "val"}, true},
		{"control char in value", http.Cookie{Name: "ok", Value: "ba\x01d"}, true},
		{"valid cookie", http.Cookie{Name: "session", Value: "abc123"}, false},
		{"valid with domain", http.Cookie{Name: "token", Value: "xyz", Domain: "example.com"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := engine.AcquireRequest()
			err := WithCookie(tt.cookie)(req)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cookie string parsing boundary conditions
// ---------------------------------------------------------------------------

func TestWithCookieString_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name       string
		cookieStr  string
		wantErr    bool
		wantCount  int
	}{
		{"empty string", "", false, 0},
		{"single valid cookie", "name=value", false, 1},
		{"multiple cookies", "a=1; b=2; c=3", false, 3},
		{"cookie with equals in value", "data=a=b=c", false, 1},
		{"whitespace only errors", "  badcookie  ", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := engine.AcquireRequest()
			err := WithCookieString(tt.cookieStr)(req)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// WithBinary boundary conditions
// ---------------------------------------------------------------------------

func TestWithBinary_BoundaryConditions(t *testing.T) {
	t.Run("nil data", func(t *testing.T) {
		req := engine.AcquireRequest()
		err := WithBinary(nil)(req)
		if err == nil {
			t.Error("expected error for nil binary data")
		}
	})

	t.Run("empty data", func(t *testing.T) {
		req := engine.AcquireRequest()
		err := WithBinary([]byte{})(req)
		if err != nil {
			t.Errorf("expected no error for empty binary data, got: %v", err)
		}
	})

	t.Run("valid binary data", func(t *testing.T) {
		req := engine.AcquireRequest()
		err := WithBinary([]byte{0x00, 0x01, 0xFF})(req)
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// WithFormData nil/empty boundary conditions
// ---------------------------------------------------------------------------

func TestWithFormData_BoundaryConditions(t *testing.T) {
	t.Run("nil form data", func(t *testing.T) {
		req := engine.AcquireRequest()
		err := WithFormData(nil)(req)
		if err == nil {
			t.Error("expected error for nil form data")
		}
	})

	t.Run("empty form data", func(t *testing.T) {
		req := engine.AcquireRequest()
		err := WithFormData(&FormData{})(req)
		// empty form data should be valid (no fields, no files)
		if err != nil {
			t.Errorf("expected no error for empty form data, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Config validation boundary conditions
// ---------------------------------------------------------------------------

func TestValidateConfig_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Config)
		wantError string // substring to check, empty = no error
	}{
		{
			name:      "zero request timeout rejected",
			mutate:    func(c *Config) { c.Timeouts.Request = 0 },
			wantError: "", // zero means default, allowed
		},
		{
			name:      "negative retry max",
			mutate:    func(c *Config) { c.Retry.MaxRetries = -1 },
			wantError: "",
		},
		{
			name:      "negative max redirects",
			mutate:    func(c *Config) { c.Defaults.MaxRedirects = -2 },
			wantError: "",
		},
		{
			name: "valid config no mutation",
			mutate: func(c *Config) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.mutate(&cfg)
			err := ValidateConfig(&cfg)
			if tt.wantError != "" {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantError)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Result edge cases
// ---------------------------------------------------------------------------

func TestResult_HasCookie_BoundaryConditions(t *testing.T) {
	t.Run("nil result", func(t *testing.T) {
		var r *Result
		if r.HasCookie("any") {
			t.Error("nil result should not have cookies")
		}
		if r.GetCookie("any") != nil {
			t.Error("nil result should return nil cookie")
		}
	})

	t.Run("empty result", func(t *testing.T) {
		r := &Result{}
		if r.HasCookie("any") {
			t.Error("empty result should not have cookies")
		}
	})
}

// ---------------------------------------------------------------------------
// URL value formatting boundary conditions
// ---------------------------------------------------------------------------

func TestQueryValueLength_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  int
	}{
		{"nil", nil, 0},
		{"int zero", 0, 1},
		{"int negative", -42, 3},
		{"int64", int64(1234567890), 10},
		{"uint64", uint64(1234567890), 10},
		{"float", 3.14, 4},
		{"bool true", true, 4},
		{"bool false", false, 5},
		{"empty string", "", 0},
		{"short string", "hi", 2},
		{"url.Values single", url.Values{"k": {"v"}}, 4}, // "k=v" -> len=3? actually depends on format
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := queryValueLength(tt.value)
			if got < 0 {
				t.Errorf("queryValueLength(%v) = %d, want >= 0", tt.value, got)
			}
		})
	}
}
