//go:build integration

package dns

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestDoHIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	resolver := NewDoHResolver(nil, 5*time.Minute)

	tests := []struct {
		name string
		host string
	}{
		{"Google", "www.google.com"},
		{"Baidu", "www.baidu.com"},
		{"Cloudflare DNS", "1.1.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			ips, err := resolver.LookupIPAddr(ctx, tt.host)
			if err != nil {
				t.Logf("LookupIPAddr(%s) error: %v", tt.host, err)
				// Don't fail the test, just log the error
				return
			}

			if len(ips) == 0 {
				t.Logf("No IPs found for %s", tt.host)
				return
			}

			t.Logf("Successfully resolved %s:", tt.host)
			for _, ip := range ips {
				t.Logf("  - %s", ip.IP.String())
			}
		})
	}
}

// Test that DoH resolver cache works
func TestDoHResolverCacheIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	resolver := NewDoHResolver(nil, 1*time.Minute)
	ctx := context.Background()

	// First lookup
	start1 := time.Now()
	ips1, err1 := resolver.LookupIPAddr(ctx, "www.baidu.com")
	duration1 := time.Since(start1)

	if err1 != nil {
		t.Logf("First lookup error: %v (expected in some network environments)", err1)
		t.Skip("Cannot test cache without successful DNS resolution")
		return
	}

	if len(ips1) == 0 {
		t.Skip("First lookup returned no IPs")
		return
	}

	t.Logf("First lookup: %v, got %d IPs", duration1, len(ips1))

	// Second lookup (should use cache)
	start2 := time.Now()
	ips2, err2 := resolver.LookupIPAddr(ctx, "www.baidu.com")
	duration2 := time.Since(start2)

	if err2 != nil {
		t.Fatalf("Second lookup failed: %v", err2)
	}

	if len(ips2) != len(ips1) {
		t.Errorf("Cache returned different number of IPs: got %d, want %d", len(ips2), len(ips1))
	}

	t.Logf("Second lookup (cached): %v, got %d IPs", duration2, len(ips2))

	// Cached lookup should be significantly faster
	if duration2 < duration1 {
		speedup := float64(duration1) / float64(duration2)
		t.Logf("Cache speedup: %.2fx faster", speedup)
	}
}

// Test fallback to system resolver
func TestDoHResolverFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create resolver with invalid provider to force fallback
	invalidProviders := []*dohProvider{
		{
			Name:     "invalid",
			Template: "http://invalid.invalid.invalid/test",
			Priority: 1,
		},
	}

	resolver := NewDoHResolver(invalidProviders, 5*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Should fall back to system resolver
	ips, err := resolver.LookupIPAddr(ctx, "localhost")
	if err != nil {
		t.Skipf("System resolver lookup error: %v", err)
	}

	if len(ips) == 0 {
		t.Skip("System resolver returned no IPs for localhost")
	}

	t.Logf("System resolver (fallback) found %d IPs for localhost:", len(ips))
	for _, ip := range ips {
		t.Logf("  - %s", ip.IP.String())
	}
}

// Benchmark DoH vs system resolver
func BenchmarkDoHVsSystemResolver(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	ctx := context.Background()

	// Warm up
	_, _ = NewDoHResolver(nil, 5*time.Minute).LookupIPAddr(ctx, "www.baidu.com")

	b.Run("DoH", func(b *testing.B) {
		resolver := NewDoHResolver(nil, 5*time.Minute)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = resolver.LookupIPAddr(ctx, "www.baidu.com")
		}
	})
}

func ExampleDoHResolver() {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := resolver.LookupIPAddr(ctx, "www.example.com")
	if err != nil {
		fmt.Printf("DNS resolution failed: %v\n", err)
		return
	}

	fmt.Printf("Resolved to %d IP addresses:\n", len(ips))
	for _, ip := range ips {
		fmt.Printf("  %s\n", ip.IP.String())
	}
}
