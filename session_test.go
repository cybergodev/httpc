package httpc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cybergodev/httpc/internal/engine"
	"github.com/cybergodev/httpc/internal/validation"
)

// ============================================================================
// SESSION MANAGER TESTS
// ============================================================================

// TestNewSessionManager construction with defaults is covered by
// TestNewSessionManagerDefault (DefaultSessionConfig is its input), so no
// separate minimal-constructor test is kept here.

func TestNewSessionManagerWithConfig(t *testing.T) {
	securityConfig := validation.StrictCookieSecurityConfig()
	cfg := DefaultSessionConfig()
	cfg.CookieSecurity = securityConfig
	session, err := NewSessionManager(cfg)

	if err != nil {
		t.Fatalf("NewSessionManager error: %v", err)
	}
	if session == nil {
		t.Fatal("Expected non-nil SessionManager")
	}
	if session.cookieSecurity == nil {
		t.Error("Expected cookieSecurity to be set")
	}
}

func TestNewSessionManagerDefault(t *testing.T) {
	// NewSessionManagerDefault is a shortcut for NewSessionManager(DefaultSessionConfig()).
	session, err := NewSessionManagerDefault()
	if err != nil {
		t.Fatalf("NewSessionManagerDefault error: %v", err)
	}
	if session == nil {
		t.Fatal("Expected non-nil SessionManager")
	}
	if len(session.cookies) != 0 {
		t.Error("Expected empty cookies map")
	}
	if len(session.headers) != 0 {
		t.Error("Expected empty headers map")
	}
	if session.cookieSecurity != nil {
		t.Error("Expected nil cookieSecurity with default config")
	}
}

// TestSessionManagerZeroValue exercises the write methods on a zero-value
// SessionManager (&SessionManager{} instead of NewSessionManager): the maps
// are initialized lazily on first write, so a mis-constructed manager behaves
// as an empty session instead of panicking with "assignment to entry in nil
// map" (SEC-003 regression guard).
func TestSessionManagerZeroValue(t *testing.T) {
	s := &SessionManager{}

	if err := s.SetHeader("Accept", "application/json"); err != nil {
		t.Fatalf("SetHeader on zero value: %v", err)
	}
	if err := s.SetHeaders(map[string]string{"X-A": "b"}); err != nil {
		t.Fatalf("SetHeaders on zero value: %v", err)
	}
	if err := s.SetCookie(&http.Cookie{Name: "sid", Value: "1"}); err != nil {
		t.Fatalf("SetCookie on zero value: %v", err)
	}
	if err := s.SetCookies([]*http.Cookie{{Name: "c2", Value: "v"}}); err != nil {
		t.Fatalf("SetCookies on zero value: %v", err)
	}
	s.UpdateFromCookies([]*http.Cookie{{Name: "c3", Value: "v"}})
	s.UpdateFromResult(&Result{Response: &ResponseInfo{Cookies: []*http.Cookie{{Name: "c4", Value: "v"}}}})
	s.captureFromOptions([]RequestOption{
		WithHeader("X-Zero", "1"),
		WithCookies([]http.Cookie{{Name: "c5", Value: "v"}}),
	})

	if got := s.GetCookie("sid"); got == nil || got.Value != "1" {
		t.Errorf("GetCookie(sid) = %+v, want value %q", got, "1")
	}
	if v, ok := s.GetHeaders()["X-A"]; !ok || v != "b" {
		t.Errorf("GetHeaders()[X-A] = %q, %v", v, ok)
	}
	for _, name := range []string{"c2", "c3", "c4", "c5"} {
		if s.GetCookie(name) == nil {
			t.Errorf("cookie %s missing after write on zero value", name)
		}
	}

	// Reads on a never-written zero value must also work (nil-map reads).
	s2 := &SessionManager{}
	if h := s2.GetHeaders(); len(h) != 0 {
		t.Errorf("GetHeaders on untouched zero value = %v, want empty", h)
	}
	if c := s2.GetCookies(); c != nil {
		t.Errorf("GetCookies on untouched zero value = %v, want nil", c)
	}
	if c := s2.GetCookie("missing"); c != nil {
		t.Errorf("GetCookie on untouched zero value = %v, want nil", c)
	}
}

func TestSessionManager_SetCookieSecurity(t *testing.T) {
	session, err := NewSessionManagerDefault()
	if err != nil {
		t.Fatalf("NewSessionManager error: %v", err)
	}

	// Initially no security config
	if session.cookieSecurity != nil {
		t.Error("Expected no cookie security initially")
	}

	// Set security config
	securityConfig := validation.StrictCookieSecurityConfig()
	session.SetCookieSecurity(securityConfig)

	if session.cookieSecurity == nil {
		t.Error("Expected cookieSecurity to be set")
	}
}

func TestSessionManager_CookieSecurityValidation(t *testing.T) {
	// Create session with strict security
	securityConfig := validation.StrictCookieSecurityConfig()
	cfg := DefaultSessionConfig()
	cfg.CookieSecurity = securityConfig
	session, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("NewSessionManager error: %v", err)
	}

	// Try to set insecure cookie - should fail
	insecureCookie := &http.Cookie{
		Name:     "session",
		Value:    "test123",
		Secure:   false, // Should be true for strict config
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	err = session.SetCookie(insecureCookie)
	if err == nil {
		t.Error("Expected error for insecure cookie with strict security")
	}

	// Try to set secure cookie - should succeed
	secureCookie := &http.Cookie{
		Name:     "session",
		Value:    "test123",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}

	err = session.SetCookie(secureCookie)
	if err != nil {
		t.Errorf("Expected no error for secure cookie, got: %v", err)
	}
}

// newTestSession returns an initialized SessionManager, collapsing the repeated
// NewSessionManager + error-check boilerplate shared by the accessor tests.
// (Not used by TestNewSessionManager itself, which validates the constructor.)
func newTestSession(t *testing.T) *SessionManager {
	t.Helper()
	session, err := NewSessionManagerDefault()
	if err != nil {
		t.Fatalf("NewSessionManager error: %v", err)
	}
	return session
}

func TestSessionManager_SetCookie(t *testing.T) {
	session := newTestSession(t)

	// Test nil cookie
	if err := session.SetCookie(nil); err == nil {
		t.Error("Expected error for nil cookie")
	}

	// Test valid cookie
	cookie := &http.Cookie{
		Name:  "test",
		Value: "value",
	}
	if err := session.SetCookie(cookie); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Verify cookie was stored
	stored := session.GetCookie("test")
	if stored == nil {
		t.Fatal("Expected cookie to be stored")
	}
	if stored.Value != "value" {
		t.Errorf("Expected value 'value', got %s", stored.Value)
	}
}

func TestSessionManager_SetCookies(t *testing.T) {
	session := newTestSession(t)

	cookies := []*http.Cookie{
		{Name: "cookie1", Value: "value1"},
		{Name: "cookie2", Value: "value2"},
	}

	if err := session.SetCookies(cookies); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	allCookies := session.GetCookies()
	if len(allCookies) != 2 {
		t.Errorf("Expected 2 cookies, got %d", len(allCookies))
	}
}

func TestSessionManager_DeleteCookie(t *testing.T) {
	session := newTestSession(t)

	// Add cookie
	cookie := &http.Cookie{Name: "test", Value: "value"}
	_ = session.SetCookie(cookie)

	// Delete it
	session.DeleteCookie("test")

	// Verify it's gone
	stored := session.GetCookie("test")
	if stored != nil {
		t.Error("Expected cookie to be deleted")
	}
}

func TestSessionManager_ClearCookies(t *testing.T) {
	session := newTestSession(t)

	// Add multiple cookies
	_ = session.SetCookie(&http.Cookie{Name: "c1", Value: "v1"})
	_ = session.SetCookie(&http.Cookie{Name: "c2", Value: "v2"})

	// Clear all
	session.ClearCookies()

	// Verify empty
	allCookies := session.GetCookies()
	if len(allCookies) != 0 {
		t.Errorf("Expected 0 cookies after clear, got %d", len(allCookies))
	}
}

func TestSessionManager_SetHeader(t *testing.T) {
	session := newTestSession(t)

	// Valid header
	if err := session.SetHeader("X-Custom", "value"); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Invalid header (with CRLF)
	if err := session.SetHeader("X-Bad", "value\r\nX-Injected: malicious"); err == nil {
		t.Error("Expected error for header with CRLF")
	}

	// Oversize key / value are rejected by ValidateHeaderKeyValue limits.
	if err := session.SetHeader("X-"+strings.Repeat("k", validation.MaxHeaderKeyLen), "value"); err == nil {
		t.Error("Expected error for oversize header key")
	}
	if err := session.SetHeader("X-Key", strings.Repeat("v", validation.MaxValueLen+1)); err == nil {
		t.Error("Expected error for oversize header value")
	}
}

func TestSessionManager_SetHeaders(t *testing.T) {
	session := newTestSession(t)

	headers := map[string]string{
		"X-Header-1": "value1",
		"X-Header-2": "value2",
	}

	if err := session.SetHeaders(headers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	allHeaders := session.GetHeaders()
	if len(allHeaders) != 2 {
		t.Errorf("Expected 2 headers, got %d", len(allHeaders))
	}
}

func TestSessionManager_DeleteHeader(t *testing.T) {
	session := newTestSession(t)

	_ = session.SetHeader("X-Test", "value")
	session.DeleteHeader("X-Test")

	allHeaders := session.GetHeaders()
	if _, exists := allHeaders["X-Test"]; exists {
		t.Error("Expected header to be deleted")
	}
}

func TestSessionManager_ClearHeaders(t *testing.T) {
	session := newTestSession(t)

	_ = session.SetHeader("X-Header-1", "value1")
	_ = session.SetHeader("X-Header-2", "value2")

	session.ClearHeaders()

	allHeaders := session.GetHeaders()
	if len(allHeaders) != 0 {
		t.Errorf("Expected 0 headers after clear, got %d", len(allHeaders))
	}
}

func TestSessionManager_prepareOptions(t *testing.T) {
	session, err := NewSessionManagerDefault()
	if err != nil {
		t.Fatalf("NewSessionManager error: %v", err)
	}

	// Test empty session
	options := session.prepareOptions()
	if options != nil {
		t.Error("Expected nil options for empty session")
	}

	// Add cookies and headers
	_ = session.SetCookie(&http.Cookie{Name: "session", Value: "abc123"})
	_ = session.SetHeader("Authorization", "Bearer token")

	options = session.prepareOptions()
	if len(options) < 2 {
		t.Errorf("Expected at least 2 options, got %d", len(options))
	}

	// Verify options actually work when applied to a request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("Authorization header not applied")
		}
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value != "abc123" {
			t.Errorf("Session cookie not applied: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer func() { _ = client.Close() }()

	resp, err := client.Get(server.URL, options...)
	if err != nil {
		t.Fatalf("Request with session options failed: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode())
	}
}

func TestSessionManager_UpdateFromResult(t *testing.T) {
	session, err := NewSessionManagerDefault()
	if err != nil {
		t.Fatalf("NewSessionManager error: %v", err)
	}

	// Test nil result
	session.UpdateFromResult(nil)

	// Test result with cookies
	result := &Result{
		Response: &ResponseInfo{
			Cookies: []*http.Cookie{
				{Name: "server-cookie", Value: "server-value"},
			},
		},
	}

	session.UpdateFromResult(result)

	cookie := session.GetCookie("server-cookie")
	if cookie == nil {
		t.Fatal("Expected cookie from result")
	}
	if cookie.Value != "server-value" {
		t.Errorf("Expected value 'server-value', got %s", cookie.Value)
	}
}

func TestSessionManager_SecurityValidation_SetCookieSecurity(t *testing.T) {
	// Test that SetCookieSecurity affects subsequent SetCookie calls
	session, err := NewSessionManagerDefault()
	if err != nil {
		t.Fatalf("NewSessionManager error: %v", err)
	}

	// Set security config after creation
	securityConfig := validation.DefaultCookieSecurityConfig()
	securityConfig.RequireSecure = true
	session.SetCookieSecurity(securityConfig)

	// This should fail because cookie is not secure
	insecureCookie := &http.Cookie{
		Name:   "test",
		Value:  "value",
		Secure: false,
	}

	err = session.SetCookie(insecureCookie)
	if err == nil {
		t.Error("Expected error for insecure cookie with RequireSecure=true")
	}
}

// ----------------------------------------------------------------------------
// UpdateFromCookies / SetCookies edge cases
// ----------------------------------------------------------------------------

func TestSessionManager_UpdateFromCookies(t *testing.T) {
	session, err := NewSessionManagerDefault()
	if err != nil {
		t.Fatalf("NewSessionManager error: %v", err)
	}

	t.Run("empty slice", func(t *testing.T) {
		session.UpdateFromCookies([]*http.Cookie{})
	})

	t.Run("nil cookie skipped", func(t *testing.T) {
		session.UpdateFromCookies([]*http.Cookie{
			nil,
			{Name: "test", Value: "val"},
		})
		c := session.GetCookie("test")
		if c == nil || c.Value != "val" {
			t.Error("should have stored non-nil cookie")
		}
	})
}

func TestSessionManager_SetCookies_NilElement(t *testing.T) {
	session, err := NewSessionManagerDefault()
	if err != nil {
		t.Fatalf("NewSessionManager error: %v", err)
	}

	// Slice with nil element at index > 0 should return error
	err = session.SetCookies([]*http.Cookie{
		{Name: "a", Value: "1"},
		nil,
	})
	if err == nil {
		t.Error("expected error for nil cookie element")
	}
}

// ----------------------------------------------------------------------------
// Nil-receiver safety
// ----------------------------------------------------------------------------

// TestSessionManager_NilReceiverSafety verifies every SessionManager method
// either returns an error or is a safe no-op when called on a nil receiver.
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

// Moved from quality_regression_test.go (dissolved grab-bag file):
// TestCaptureFromOptionsSkipsInvalidCookies guards the ValidateCookie gate in
// captureFromOptions: cookies set by raw options that bypass WithCookies
// validation must not enter the session store.
func TestCaptureFromOptionsSkipsInvalidCookies(t *testing.T) {
	sm, err := NewSessionManagerDefault()
	if err != nil {
		t.Fatal(err)
	}
	raw := RequestOption(func(r *engine.Request) error {
		r.SetCookies([]http.Cookie{
			{Name: "good", Value: "fine"},
			{Name: "bad;name", Value: "invalid"}, // control/separator chars in name
		})
		return nil
	})
	sm.captureFromOptions([]RequestOption{raw})

	if got := sm.GetCookie("good"); got == nil {
		t.Error("valid cookie from option should be captured")
	}
	if got := sm.GetCookie("bad;name"); got != nil {
		t.Errorf("invalid cookie should be rejected, got %v", got)
	}
}
