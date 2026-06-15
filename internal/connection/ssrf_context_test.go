package connection

import (
	"context"
	"net"
	"testing"
	"time"
)

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
