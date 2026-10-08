package httpc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybergodev/httpc/internal/engine"
)

// ============================================================================
// SECURITY AUDIT TESTS - Verify security fixes from 2026-03-14 audit
// ============================================================================

// Test_SSRF_BlocksLocalhost verifies that localhost is blocked when SSRF protection is enabled
func Test_SSRF_BlocksLocalhost(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.AllowPrivateIPs = false // Enable SSRF protection

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Should fail because localhost is blocked when SSRF protection is enabled
	_, err = client.Get(server.URL, WithTimeout(5*time.Second))
	if err == nil {
		t.Error("SECURITY ISSUE: Expected error when accessing localhost with SSRF protection enabled")
	}
	if err != nil && !strings.Contains(err.Error(), "blocked") && !strings.Contains(err.Error(), "localhost") {
		t.Errorf("Expected SSRF blocking error, got: %v", err)
	}
}

// Test_SSRF_RedirectProtection verifies that redirects to private IPs are blocked
func Test_SSRF_RedirectProtection(t *testing.T) {
	// Create a new config that disallows private IPs for redirect testing
	cfg := DefaultConfig()
	cfg.Security.AllowPrivateIPs = false
	cfg.Defaults.FollowRedirects = true

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Create a server that redirects to localhost
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to localhost (should be blocked)
		http.Redirect(w, r, "http://127.0.0.1:12345/", http.StatusFound)
	}))
	defer redirectServer.Close()

	// Should fail because redirect target is blocked
	_, err = client.Get(redirectServer.URL, WithTimeout(5*time.Second))
	if err == nil {
		t.Error("SECURITY ISSUE: Expected error when redirecting to private IP")
	}
	if !strings.Contains(err.Error(), "blocked") && !strings.Contains(err.Error(), "redirect") {
		t.Errorf("Expected redirect blocking error, got: %v", err)
	}
}

// Test_SSRF_BlocksIPv6Localhost verifies that IPv6 localhost addresses are also blocked
func Test_SSRF_BlocksIPv6Localhost(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping IPv6 SSRF test in short mode")
	}

	cfg := DefaultConfig()
	cfg.Security.AllowPrivateIPs = false

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Get("http://[::1]:12345/", WithTimeout(2*time.Second))
	if err == nil {
		t.Error("SECURITY ISSUE: Expected error when requesting IPv6 localhost")
	}
}

// Test_DecompressionBombProtection verifies that decompression bombs are blocked
func Test_DecompressionBombProtection(t *testing.T) {
	cfg := testConfig()
	cfg.Security.MaxResponseBodySize = 1000 // Very small limit for testing

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Create a server that returns a response larger than the limit
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return more than 1000 bytes
		largeData := make([]byte, 2000)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(largeData) // best-effort test response
	}))
	defer server.Close()

	// Should fail because response exceeds limit
	_, err = client.Get(server.URL, WithTimeout(5*time.Second))
	if err == nil {
		t.Error("SECURITY ISSUE: Expected error when response exceeds size limit")
	}
	// Check for size-related error (could be "exceeds", "limit", or "failed to read")
	if !strings.Contains(err.Error(), "exceeds") &&
		!strings.Contains(err.Error(), "limit") &&
		!strings.Contains(err.Error(), "failed to read") {
		t.Errorf("Expected size limit error, got: %v", err)
	}
}

// Test_ResponseBodyLimitEnforcedWithDefaultDecompressedLimit pins the C-1
// regression end-to-end: DefaultConfig sets MaxDecompressedBodySize (100MB)
// alongside MaxResponseBodySize, and the buffered path must still enforce the
// body cap. (Test_DecompressionBombProtection above uses a Config with
// MaxDecompressedBodySize=0, which masks the bug this test guards against.)
func Test_ResponseBodyLimitEnforcedWithDefaultDecompressedLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.AllowPrivateIPs = true     // test against loopback
	cfg.Security.MaxResponseBodySize = 1000 // keep the fixture small; 100MB decompressed limit stays

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 2000)) // identity body over the 1000-byte cap
	}))
	defer server.Close()

	_, err = client.Get(server.URL, WithTimeout(5*time.Second))
	if err == nil {
		t.Fatal("SECURITY ISSUE: identity body over MaxResponseBodySize accepted while MaxDecompressedBodySize is set")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("Expected 'exceeds limit' error, got: %v", err)
	}
}

// ============================================================================
// PANIC SAFETY TESTS - Verify library never panics in production
// ============================================================================

// assertNoPanic runs fn and reports a test error if it panics.
func assertNoPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PANIC [%s]: %v", name, r)
		}
	}()
	fn()
}

func TestPanicSafety(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test")) // best-effort test response
	}))
	defer server.Close()

	tests := []struct {
		name string
		fn   func()
	}{
		{"NilConfig", func() {
			client, err := New(DefaultConfig())
			if err != nil {
				t.Errorf("New(DefaultConfig()) should succeed with defaults, got error: %v", err)
			}
			if client == nil {
				t.Error("New(DefaultConfig()) should return a valid client")
			}
			if client != nil {
				_ = client.Close()
			}
		}},
		{"NilBody", func() {
			cfg := testConfig()
			client, err := New(cfg)
			if err != nil {
				return
			}
			defer func() { _ = client.Close() }()
			// WithBody(nil) must be rejected with a clean validation error —
			// not silently sent, and not a panic.
			_, err = client.Post(server.URL, WithBody(nil))
			if err == nil {
				t.Error("Expected WithBody(nil) to be rejected with an error")
			}
		}},
		{"MiddlewarePanicRecovery", func() {
			cfg := testConfig()
			cfg.Middleware.Middlewares = []MiddlewareFunc{
				RecoveryMiddleware(),
				func(next Handler) Handler {
					return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
						panic("intentional test panic")
					}
				},
			}
			client, err := New(cfg)
			if err != nil {
				return
			}
			defer func() { _ = client.Close() }()
			_, err = client.Get(server.URL)
			if err == nil {
				t.Error("Expected error from recovered panic")
			}
		}},
		{"DomainClientInvalidURL", func() {
			_, err := NewDomain("not a url", DefaultConfig())
			if err == nil {
				t.Error("Expected error for invalid base URL")
			}
		}},
		{"SessionManagerNilInput", func() {
			session, err := NewSessionManagerDefault()
			if err != nil {
				return
			}
			if err := session.SetCookie(nil); err == nil {
				t.Error("SetCookie(nil) must be rejected, got nil error")
			}
			// Nil/empty batches must be tolerated as no-ops, not panic.
			_ = session.SetCookies(nil)
			_ = session.SetCookies([]*http.Cookie{})
		}},
		{"RequestOptionError", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			cfg := testConfig()
			client, err := New(cfg)
			if err != nil {
				return
			}
			defer func() { _ = client.Close() }()
			// Apply a failing RequestOption and verify the error propagates.
			_, err = client.Get(server.URL, func(r *engine.Request) error {
				return fmt.Errorf("test option error")
			})
			if err == nil {
				t.Error("Expected failing RequestOption to surface as a request error")
			}
		}},
		{"ConcurrentAccess", func() {
			cfg := testConfig()
			client, err := New(cfg)
			if err != nil {
				return
			}
			defer func() { _ = client.Close() }()
			done := make(chan bool, 10)
			for i := 0; i < 10; i++ {
				go func() {
					_, _ = client.Get(server.URL)
					done <- true
				}()
			}
			for i := 0; i < 10; i++ {
				<-done
			}
		}},
		// SEC-003: the default safety net must convert panics to errors even when
		// the user has NOT installed RecoveryMiddleware.
		{"MiddlewarePanicDefaultNet", func() {
			cfg := testConfig()
			cfg.Middleware.Middlewares = []MiddlewareFunc{
				func(next Handler) Handler {
					return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
						panic("internal panic without recovery middleware")
					}
				},
			}
			client, err := New(cfg)
			if err != nil {
				return
			}
			defer func() { _ = client.Close() }()
			_, err = client.Get(server.URL)
			if err == nil {
				t.Error("Expected error from panic caught by default safety net")
			}
		}},
		{"DownloadPanicDefaultNet", func() {
			cfg := testConfig()
			cfg.Middleware.Middlewares = []MiddlewareFunc{
				func(next Handler) Handler {
					return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
						panic("internal panic during download")
					}
				},
			}
			client, err := New(cfg)
			if err != nil {
				return
			}
			defer func() { _ = client.Close() }()
			dest := filepath.Join(t.TempDir(), "out.bin")
			_, err = client.Download(context.Background(), server.URL, &DownloadConfig{FilePath: dest})
			if err == nil {
				t.Error("Expected error from panic caught by download safety net")
			}
		}},
		// SEC-003: a panicking RequestOption must not crash DomainClient —
		// the session-capture pass applies user options before the
		// request-path safety net is installed, so it needs its own guard.
		{"DomainClientPanicOption", func() {
			dc, err := NewDomain(server.URL, testConfig())
			if err != nil {
				return
			}
			defer func() { _ = dc.Close() }()
			_, err = dc.Get("/",
				func(r *engine.Request) error { panic("option panic during session capture") },
			)
			if err == nil {
				t.Error("Expected error from panicking option in DomainClient")
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertNoPanic(t, tt.name, tt.fn)
		})
	}
}

// ============================================================================
// PER-REQUEST AllowPrivateIPs OVERRIDE TESTS
// ============================================================================

// Test_WithAllowPrivateIPs_OverridesClientPolicy verifies that the per-request
// WithAllowPrivateIPs(true) option lets a request reach a localhost server even
// when the client has SSRF protection enabled (AllowPrivateIPs=false). This
// exercises all three SSRF layers: pre-flight validator, connection dialer.
func Test_WithAllowPrivateIPs_OverridesClientPolicy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.AllowPrivateIPs = false // SSRF protection enabled at client level

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("local-ok")) // best-effort test response
	}))
	defer server.Close()

	t.Run("OverrideTrueReachesLocalhost", func(t *testing.T) {
		result, err := client.Get(server.URL, WithAllowPrivateIPs(true), WithTimeout(5*time.Second))
		if err != nil {
			t.Fatalf("Expected request to succeed with per-request override, got: %v", err)
		}
		if result.StatusCode() != http.StatusOK {
			t.Errorf("Expected status 200, got %d", result.StatusCode())
		}
	})

	t.Run("NoOverrideStillBlocked", func(t *testing.T) {
		// Regression guard: without the option, the secure default must still block localhost.
		_, err := client.Get(server.URL, WithTimeout(5*time.Second))
		if err == nil {
			t.Fatal("SECURITY ISSUE: Expected localhost to be blocked without per-request override")
		}
		if !strings.Contains(err.Error(), "blocked") && !strings.Contains(err.Error(), "localhost") {
			t.Errorf("Expected SSRF blocking error, got: %v", err)
		}
	})
}

// Test_WithAllowPrivateIPs_FalseReEnablesProtection verifies that passing false
// re-enables SSRF protection on a permissive client (AllowPrivateIPs=true) for
// that single request. This validates the *bool semantics (nil=client default,
// non-nil=override in either direction).
func Test_WithAllowPrivateIPs_FalseReEnablesProtection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.AllowPrivateIPs = true // Permissive client

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Permissive client would normally reach localhost; the per-request false override blocks it.
	_, err = client.Get(server.URL, WithAllowPrivateIPs(false), WithTimeout(5*time.Second))
	if err == nil {
		t.Fatal("SECURITY ISSUE: Expected localhost to be blocked by per-request WithAllowPrivateIPs(false)")
	}
	if !strings.Contains(err.Error(), "blocked") && !strings.Contains(err.Error(), "localhost") {
		t.Errorf("Expected SSRF blocking error, got: %v", err)
	}
}

// Test_WithAllowPrivateIPs_RedirectOverride verifies the per-request override
// also permits following a redirect to a localhost target, exercising the
// transport's redirect-target SSRF check in addition to the dialer.
func Test_WithAllowPrivateIPs_RedirectOverride(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.AllowPrivateIPs = false // SSRF protection enabled
	cfg.Defaults.FollowRedirects = true

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Final target: a real localhost server the redirect resolves to.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("redirected-ok")) // best-effort test response
	}))
	defer target.Close()

	// Redirector: 302 to the localhost target.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	t.Run("OverrideFollowsLocalRedirect", func(t *testing.T) {
		result, err := client.Get(redirector.URL, WithAllowPrivateIPs(true), WithTimeout(5*time.Second))
		if err != nil {
			t.Fatalf("Expected redirect to succeed with per-request override, got: %v", err)
		}
		if result.StatusCode() != http.StatusOK {
			t.Errorf("Expected status 200 after redirect, got %d", result.StatusCode())
		}
	})

	t.Run("NoOverrideBlocksLocalRedirect", func(t *testing.T) {
		_, err := client.Get(redirector.URL, WithTimeout(5*time.Second))
		if err == nil {
			t.Fatal("SECURITY ISSUE: Expected redirect to localhost to be blocked without override")
		}
		if !strings.Contains(err.Error(), "blocked") && !strings.Contains(err.Error(), "redirect") {
			t.Errorf("Expected redirect blocking error, got: %v", err)
		}
	})
}

// ============================================================================
// SSRF BYPASS BOUNDARY TESTS
// ============================================================================

func Test_SSRF_BypassAttempts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
	}{
		{"Decimal IP localhost", "http://2130706433/"},
		{"Hex IP localhost", "http://0x7f000001/"},
		{"Octal IP localhost", "http://017700000001/"},
		{"IPv6 compressed localhost", "http://[0:0:0:0:0:0:0:1]/"},
		{"IPv4-mapped IPv6 localhost", "http://[::ffff:127.0.0.1]/"},
		{"Zero IP", "http://0.0.0.0/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Security.AllowPrivateIPs = false

			client, err := New(cfg)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}
			defer func() { _ = client.Close() }()

			_, err = client.Get(tt.url, WithTimeout(2*time.Second))
			if err == nil {
				t.Errorf("SECURITY ISSUE: Expected SSRF block for %q", tt.url)
			}
		})
	}
}
