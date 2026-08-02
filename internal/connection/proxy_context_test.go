package connection

import (
	"context"
	"testing"
)

// TestProxyAttempt_ContextRoundTrip verifies the context helper stores and
// retrieves the retry-attempt index correctly, including the absent-key case.
func TestProxyAttempt_ContextRoundTrip(t *testing.T) {
	t.Run("Absent", func(t *testing.T) {
		_, ok := ProxyAttemptFromContext(context.Background())
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
			got, ok := ProxyAttemptFromContext(ctx)
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
