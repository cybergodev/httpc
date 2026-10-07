package connection

// ============================================================================
// Context-value helper tests (proxy_context.go + ssrf_context.go)
//
// Both production files are tiny context plumbing (store/restore a
// per-request value), so their tests are co-located here.
// ============================================================================

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"
)

// TestProxyAttempt_ContextRoundTrip verifies the context helper stores and
// retrieves the retry-attempt index correctly, including the absent-key case.
func TestProxyAttempt_ContextRoundTrip(t *testing.T) {
	t.Run("Absent", func(t *testing.T) {
		_, ok := proxyAttemptFromContext(context.Background())
		if ok {
			t.Error("expected ok=false when no attempt is present")
		}
	})

	tests := []struct {
		name    string
		attempt int
	}{
		{"zero", 0},
		{"first retry", 1},
		{"large attempt", 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithProxyAttempt(context.Background(), tt.attempt)
			got, ok := proxyAttemptFromContext(ctx)
			if !ok {
				t.Fatalf("expected ok=true, got false")
			}
			if got != tt.attempt {
				t.Errorf("attempt = %d, want %d", got, tt.attempt)
			}
		})
	}
}

// TestPoolManager_NextProxyIndex verifies the round-robin cursor advance used by
// the retry layer for deterministic proxy rotation.
func TestPoolManager_NextProxyIndex(t *testing.T) {
	t.Run("no proxy pool returns false", func(t *testing.T) {
		pm, err := NewPoolManager(nil)
		if err != nil {
			t.Fatalf("NewPoolManager() error: %v", err)
		}
		defer func() { _ = pm.Close() }()

		idx, ok := pm.NextProxyIndex()
		if ok {
			t.Error("expected ok=false when no proxy pool is configured")
		}
		if idx != 0 {
			t.Errorf("idx = %d, want 0", idx)
		}
	})

	t.Run("with proxy pool advances cursor", func(t *testing.T) {
		pm, err := NewPoolManager(&Config{
			ProxyPool: []string{
				"http://proxy1.example.com:8080",
				"http://proxy2.example.com:8080",
				"http://proxy3.example.com:8080",
			},
		})
		if err != nil {
			t.Fatalf("NewPoolManager() error: %v", err)
		}
		defer func() { _ = pm.Close() }()

		// NextProxyIndex should advance and wrap modulo pool size.
		for i := 0; i < 6; i++ {
			idx, ok := pm.NextProxyIndex()
			if !ok {
				t.Fatalf("call %d: expected ok=true", i)
			}
			want := i % 3
			if idx != want {
				t.Errorf("call %d: idx = %d, want %d", i, idx, want)
			}
		}
	})
}

// TestPoolManager_CloseIdleConnections verifies the method delegates to the
// underlying transport without panicking.
func TestPoolManager_CloseIdleConnections(t *testing.T) {
	pm, err := NewPoolManager(nil)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	// Should not panic on a normally-constructed PoolManager.
	pm.CloseIdleConnections()

	// After Close, transport is still non-nil — calling again must not panic.
	pm.CloseIdleConnections()
}

// TestProxyRecorder_ContextRoundTrip verifies the recorder context helper and
// the nil-safe record/Last semantics.
func TestProxyRecorder_ContextRoundTrip(t *testing.T) {
	t.Run("Absent", func(t *testing.T) {
		if rec := proxyRecorderFromContext(context.Background()); rec != nil {
			t.Errorf("expected nil recorder when none attached, got %v", rec)
		}
	})

	t.Run("Nil receiver is safe", func(t *testing.T) {
		var rec *ProxyRecorder
		if got := rec.Last(); got != "" {
			t.Errorf("nil receiver Last() = %q, want empty", got)
		}
		rec.record(mustParseURL(t, "http://proxy.example.com:8080")) // must not panic
	})

	t.Run("Record and overwrite", func(t *testing.T) {
		rec := &ProxyRecorder{}
		if got := rec.Last(); got != "" {
			t.Errorf("Last() = %q, want empty before any record", got)
		}

		ctx := WithProxyRecorder(context.Background(), rec)
		if proxyRecorderFromContext(ctx) != rec {
			t.Error("expected attached recorder to be returned from context")
		}

		rec.record(mustParseURL(t, "http://proxy1.example.com:8080"))
		if want := "http://proxy1.example.com:8080"; rec.Last() != want {
			t.Errorf("Last() = %q, want %q", rec.Last(), want)
		}

		// A retry attempt on a different proxy overwrites the earlier value.
		rec.record(mustParseURL(t, "http://proxy2.example.com:8080"))
		if want := "http://proxy2.example.com:8080"; rec.Last() != want {
			t.Errorf("Last() = %q, want %q", rec.Last(), want)
		}
	})

	t.Run("Nil URL is ignored", func(t *testing.T) {
		rec := &ProxyRecorder{}
		rec.record(mustParseURL(t, "http://proxy1.example.com:8080"))
		rec.record(nil)
		if want := "http://proxy1.example.com:8080"; rec.Last() != want {
			t.Errorf("Last() = %q, want %q (nil URL must not clear)", rec.Last(), want)
		}
	})
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// TestProxyRecorder_RedactsCredentials verifies the recorder never stores
// proxy userinfo in plain text: Last() feeds the public Response.ProxyURL
// field, so a raw u.String() would leak the proxy password to anyone
// printing or serializing the response.
func TestProxyRecorder_RedactsCredentials(t *testing.T) {
	rec := &ProxyRecorder{}
	rec.record(mustParseURL(t, "http://admin:s3cret@proxy.example.com:8080"))

	want := "http://admin:xxxxx@proxy.example.com:8080"
	if got := rec.Last(); got != want {
		t.Errorf("Last() = %q, want %q (password must be redacted, username kept for diagnostics)", got, want)
	}

	// URLs without credentials are stored unchanged.
	rec.record(mustParseURL(t, "http://proxy2.example.com:3128"))
	if got := rec.Last(); got != "http://proxy2.example.com:3128" {
		t.Errorf("Last() without credentials = %q, want plain URL", got)
	}
}

// ---------------------------------------------------------------------------
// SSRF context helpers (ssrf_context.go)
// ---------------------------------------------------------------------------

// TestAllowPrivateIPsOverride_ContextRoundTrip verifies the context helper
// stores and retrieves the per-request override correctly, including the
// absent-key and nil-context cases.
func TestAllowPrivateIPsOverride_ContextRoundTrip(t *testing.T) {
	t.Run("Absent", func(t *testing.T) {
		_, ok := AllowPrivateIPsOverrideFromContext(context.Background())
		if ok {
			t.Error("expected ok=false when no override is present")
		}
	})
	t.Run("True", func(t *testing.T) {
		ctx := WithAllowPrivateIPsOverride(context.Background(), true)
		allow, ok := AllowPrivateIPsOverrideFromContext(ctx)
		if !ok || !allow {
			t.Errorf("expected (true, true), got (%v, %v)", allow, ok)
		}
	})
	t.Run("False", func(t *testing.T) {
		ctx := WithAllowPrivateIPsOverride(context.Background(), false)
		allow, ok := AllowPrivateIPsOverrideFromContext(ctx)
		if !ok || allow {
			t.Errorf("expected (false, true), got (%v, %v)", allow, ok)
		}
	})
}

// TestCreateDialer_PerRequestOverride verifies that a per-request AllowPrivateIPs
// override carried on the dial context lets the dialer reach a localhost address
// even when the pool is configured with SSRF protection enabled (AllowPrivateIPs=false).
func TestCreateDialer_PerRequestOverride(t *testing.T) {
	// Real local listener to connect to.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	// SSRF protection ON at the pool level.
	config := &Config{
		AllowPrivateIPs: false,
		DialTimeout:     2 * time.Second,
		KeepAlive:       30 * time.Second,
	}
	pm, err := NewPoolManager(config)
	if err != nil {
		t.Fatalf("NewPoolManager() error: %v", err)
	}
	defer func() { _ = pm.Close() }()

	dialFn := pm.createDialer()

	t.Run("OverrideTrueConnects", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ctx = WithAllowPrivateIPsOverride(ctx, true)

		conn, err := dialFn(ctx, "tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("expected successful connection with override=true, got: %v", err)
		}
		_ = conn.Close()
	})

	t.Run("NoOverrideBlocked", func(t *testing.T) {
		// Regression guard: without the override, SSRF protection must still block localhost.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := dialFn(ctx, "tcp", listener.Addr().String())
		if err == nil {
			t.Fatal("SECURITY ISSUE: expected localhost dial to be blocked without override")
		}
	})

	t.Run("OverrideFalseBlocked", func(t *testing.T) {
		// Explicit false override matches the client policy → blocked.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ctx = WithAllowPrivateIPsOverride(ctx, false)

		_, err := dialFn(ctx, "tcp", listener.Addr().String())
		if err == nil {
			t.Fatal("SECURITY ISSUE: expected localhost dial to be blocked with override=false")
		}
	})
}
