//go:build integration

package dns

import (
	"context"
	"testing"
	"time"
)

func TestDoHResolver_LookupIPAddr(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantMin int // Minimum expected IP addresses
	}{
		{
			name:    "Google DNS",
			host:    "dns.google",
			wantMin: 1,
		},
		{
			name:    "Cloudflare DNS",
			host:    "1.1.1.1",
			wantMin: 1,
		},
		{
			name:    "Baidu",
			host:    "www.baidu.com",
			wantMin: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := NewDoHResolver(nil, 5*time.Minute)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ips, err := resolver.LookupIPAddr(ctx, tt.host)
			if err != nil {
				t.Fatalf("LookupIPAddr() error = %v", err)
			}

			if len(ips) < tt.wantMin {
				t.Errorf("LookupIPAddr() returned %d IPs, want at least %d", len(ips), tt.wantMin)
			}

			t.Logf("Resolved %s to %d IPs:", tt.host, len(ips))
			for _, ip := range ips {
				t.Logf("  - %s", ip.IP.String())
			}
		})
	}
}

func TestDoHResolver_Cache(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	ctx := context.Background()

	// First lookup
	ips1, err := resolver.LookupIPAddr(ctx, "www.google.com")
	if err != nil {
		t.Fatalf("First lookup failed: %v", err)
	}

	if len(ips1) == 0 {
		t.Fatal("First lookup returned no IPs")
	}

	// Second lookup should use cache
	ips2, err := resolver.LookupIPAddr(ctx, "www.google.com")
	if err != nil {
		t.Fatalf("Second lookup failed: %v", err)
	}

	if len(ips2) != len(ips1) {
		t.Errorf("Cache returned different number of IPs: got %d, want %d", len(ips2), len(ips1))
	}
}

func TestDoHResolver_ClearCache(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	ctx := context.Background()

	// Populate cache
	_, err := resolver.LookupIPAddr(ctx, "www.example.com")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	// Clear cache
	resolver.ClearCache()

	// Lookup again - should still work
	_, err = resolver.LookupIPAddr(ctx, "www.example.com")
	if err != nil {
		t.Fatalf("Lookup after cache clear failed: %v", err)
	}
}

func TestDoHResolver_Fallback(t *testing.T) {
	// Create resolver with invalid providers
	invalidProviders := []*DoHProvider{
		{
			Name:     "invalid",
			Template: "http://invalid.local/test",
			Priority: 1,
		},
	}

	resolver := NewDoHResolver(invalidProviders, 5*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Should fall back to system resolver
	_, err := resolver.LookupIPAddr(ctx, "www.google.com")
	if err != nil {
		t.Logf("Fallback lookup error (expected with invalid providers): %v", err)
	}
}

func TestDefaultDoHProviders(t *testing.T) {
	providers := DefaultDoHProviders()

	if len(providers) == 0 {
		t.Fatal("DefaultDoHProviders() returned empty list")
	}

	for _, p := range providers {
		if p.Name == "" {
			t.Error("Provider has empty Name")
		}
		if p.Template == "" {
			t.Error("Provider has empty Template")
		}
		t.Logf("Provider: %s - %s", p.Name, p.Template)
	}
}

// Benchmark test
func BenchmarkDoHResolver_LookupIPAddr(b *testing.B) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = resolver.LookupIPAddr(ctx, "www.google.com")
	}
}

func BenchmarkDoHResolver_CachedLookup(b *testing.B) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	ctx := context.Background()

	// Warm up cache
	_, _ = resolver.LookupIPAddr(ctx, "www.google.com")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = resolver.LookupIPAddr(ctx, "www.google.com")
	}
}

// The "CacheSize_MultipleLookups" and "ConcurrentCacheAccess" tests that lived
// here were retired: they required live network and duplicated cache-size /
// concurrent-access coverage already provided by doh_unit_test.go, which runs
// without the integration build tag.
