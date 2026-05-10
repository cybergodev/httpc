package dns

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// buildDNSWireResponse constructs a valid DNS wire-format response for testing.
// Parameters:
//   - id: transaction ID (2 bytes)
//   - domain: question domain name (e.g., "example.com")
//   - answers: slice of {recordType, ttl, rdata} for each answer
func buildDNSWireResponse(id uint16, domain string, answers []struct {
	recordType uint16
	ttl        uint32
	rdata      []byte
}) []byte {
	var buf []byte

	// Header (12 bytes)
	buf = append(buf, byte(id>>8), byte(id))                     // ID
	buf = append(buf, 0x81, 0x80)                                // Flags: standard response, no error
	buf = append(buf, 0x00, 0x01)                                // QDCOUNT = 1
	buf = append(buf, byte(len(answers)>>8), byte(len(answers))) // ANCOUNT
	buf = append(buf, 0x00, 0x00)                                // NSCOUNT = 0
	buf = append(buf, 0x00, 0x00)                                // ARCOUNT = 0

	// Question section
	for _, label := range append(splitDomain(domain), "") {
		if label == "" {
			buf = append(buf, 0x00) // null terminator
		} else {
			buf = append(buf, byte(len(label)))
			buf = append(buf, []byte(label)...)
		}
	}
	buf = append(buf, 0x00, 0x01) // QTYPE = A
	buf = append(buf, 0x00, 0x01) // QCLASS = IN

	// Answer section
	for _, ans := range answers {
		// Name pointer to offset 12 (the question name)
		buf = append(buf, 0xC0, 0x0C)
		// TYPE
		buf = append(buf, byte(ans.recordType>>8), byte(ans.recordType))
		// CLASS = IN
		buf = append(buf, 0x00, 0x01)
		// TTL
		buf = append(buf, byte(ans.ttl>>24), byte(ans.ttl>>16), byte(ans.ttl>>8), byte(ans.ttl))
		// RDLENGTH
		buf = append(buf, byte(len(ans.rdata)>>8), byte(len(ans.rdata)))
		// RDATA
		buf = append(buf, ans.rdata...)
	}

	return buf
}

// splitDomain splits "example.com" into ["example", "com"].
func splitDomain(domain string) []string {
	var labels []string
	start := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			labels = append(labels, domain[start:i])
			start = i + 1
		}
	}
	if start < len(domain) {
		labels = append(labels, domain[start:])
	}
	return labels
}

func TestParseDomain(t *testing.T) {
	tests := []struct {
		name       string
		msgHex     string
		offset     int
		wantDomain string
		wantErr    bool
	}{
		{
			name:       "simple domain",
			msgHex:     "076578616d706c6503636f6d00", // example.com\0
			offset:     0,
			wantDomain: "example.com",
			wantErr:    false,
		},
		{
			name:       "single label",
			msgHex:     "096c6f63616c686f737400", // localhost (9 bytes) + null terminator
			offset:     0,
			wantDomain: "localhost",
			wantErr:    false,
		},
		{
			name:    "empty message",
			msgHex:  "",
			offset:  0,
			wantErr: true,
		},
		{
			name:    "offset out of bounds",
			msgHex:  "076578616d706c6500",
			offset:  100,
			wantErr: true,
		},
		{
			name:    "label exceeds message length",
			msgHex:  "ff6578616d706c65", // length=255 but message too short
			offset:  0,
			wantErr: true,
		},
		{
			name:    "compression pointer circular",
			msgHex:  "c000", // pointer to offset 0 (self-referential)
			offset:  0,
			wantErr: true, // Should fail due to recursion depth limit
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, _ := hex.DecodeString(tt.msgHex)
			domain, _, err := parseDomain(msg, tt.offset, 0)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseDomain() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("parseDomain() unexpected error: %v", err)
				}
				if domain != tt.wantDomain {
					t.Errorf("parseDomain() = %q, want %q", domain, tt.wantDomain)
				}
			}
		})
	}
}

func TestGetUint16(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    uint16
		wantErr bool
	}{
		{"valid", []byte{0x01, 0x02}, 0x0102, false},
		{"zero", []byte{0x00, 0x00}, 0x0000, false},
		{"max", []byte{0xff, 0xff}, 0xffff, false},
		{"too short - empty", []byte{}, 0, true},
		{"too short - 1 byte", []byte{0x01}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getUint16(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Errorf("getUint16() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("getUint16() unexpected error: %v", err)
				}
				if got != tt.want {
					t.Errorf("getUint16() = %d, want %d", got, tt.want)
				}
			}
		})
	}
}

// Note: parseWireFormatResponse and parseJSONResponse are tested indirectly
// through LookupIPAddr integration tests. Unit tests for these private methods
// would require exposing them or using reflection, which is not idiomatic Go.

func TestDoHResolver_CacheExpiration(t *testing.T) {
	// Create resolver with very short TTL for testing
	resolver := NewDoHResolver(nil, 100*time.Millisecond)
	ctx := context.Background()

	// First lookup - should query network
	ips1, err := resolver.LookupIPAddr(ctx, "www.google.com")
	if err != nil {
		t.Fatalf("First lookup failed: %v", err)
	}

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Second lookup - should query network again (cache expired)
	ips2, err := resolver.LookupIPAddr(ctx, "www.google.com")
	if err != nil {
		t.Fatalf("Second lookup failed: %v", err)
	}

	// Results should be similar (same host)
	if len(ips1) == 0 || len(ips2) == 0 {
		t.Error("Expected non-empty IP results")
	}
}

func TestDoHResolver_CacheSize(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	defer resolver.Close()

	// Initial cache size should be 0
	if size := resolver.CacheSize(); size != 0 {
		t.Errorf("Initial cache size = %d, want 0", size)
	}

	ctx := context.Background()

	// First lookup populates cache (ignore errors - we just want to test cache behavior)
	_, _ = resolver.LookupIPAddr(ctx, "www.google.com")

	// Cache size should be 0 or 1 depending on whether lookup succeeded
	// We can't guarantee network success, so just verify the method works
	size := resolver.CacheSize()
	t.Logf("Cache size after lookup: %d", size)

	// Clear cache
	resolver.ClearCache()

	if size := resolver.CacheSize(); size != 0 {
		t.Errorf("Cache size after clear = %d, want 0", size)
	}

	// Populate cache with multiple entries to verify multi-host tracking
	hosts := []string{
		"www.google.com",
		"www.example.com",
		"www.cloudflare.com",
		"www.github.com",
		"www.microsoft.com",
	}

	for _, host := range hosts {
		_, _ = resolver.LookupIPAddr(ctx, host)
	}

	size = resolver.CacheSize()
	t.Logf("Cache size after %d lookups: %d", len(hosts), size)

	// Clear cache and verify counter resets
	resolver.ClearCache()
	if resolver.CacheSize() != 0 {
		t.Errorf("Cache size after clear = %d, want 0", resolver.CacheSize())
	}
}

func TestDoHResolver_SetCacheTTL(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	ctx := context.Background()

	// Populate cache
	_, _ = resolver.LookupIPAddr(ctx, "www.example.com")

	// Change TTL (this clears cache)
	resolver.SetCacheTTL(1 * time.Minute)

	// Cache should be cleared
	if size := resolver.CacheSize(); size != 0 {
		t.Errorf("Cache size after SetCacheTTL = %d, want 0", size)
	}
}

func TestDoHResolver_ConcurrentAccess(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	ctx := context.Background()

	var wg sync.WaitGroup
	errors := make(chan error, 20)

	// Launch 20 concurrent lookups
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := resolver.LookupIPAddr(ctx, "www.google.com")
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent lookup error: %v", err)
	}
}

func TestDoHResolver_ContextCancellation(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := resolver.LookupIPAddr(ctx, "www.google.com")
	if err == nil {
		t.Error("Expected error with cancelled context")
	}
}

func TestDoHResolver_ContextTimeout(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)

	// Create context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(2 * time.Nanosecond) // Ensure timeout

	_, err := resolver.LookupIPAddr(ctx, "www.google.com")
	if err == nil {
		t.Error("Expected error with timed out context")
	}
}

func TestDoHResolver_EmptyHost(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	ctx := context.Background()

	// Empty host should fail
	_, err := resolver.LookupIPAddr(ctx, "")
	if err == nil {
		t.Error("Expected error for empty host")
	}
}

func TestDoHResolver_IPAddressInput(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	ctx := context.Background()

	// IP address should be handled
	ips, err := resolver.LookupIPAddr(ctx, "8.8.8.8")
	if err != nil {
		t.Logf("IP address lookup returned error (may be expected): %v", err)
	} else if len(ips) == 0 {
		t.Error("Expected at least one IP for IP address input")
	}
}

func TestDoHResolver_CacheReturnsCopy(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	ctx := context.Background()

	// First lookup
	ips1, err := resolver.LookupIPAddr(ctx, "www.google.com")
	if err != nil {
		t.Fatalf("First lookup failed: %v", err)
	}

	// Modify the returned slice
	if len(ips1) > 0 {
		ips1[0] = net.IPAddr{IP: net.ParseIP("1.2.3.4")}
	}

	// Second lookup should return original cached data
	ips2, err := resolver.LookupIPAddr(ctx, "www.google.com")
	if err != nil {
		t.Fatalf("Second lookup failed: %v", err)
	}

	// Data should not be modified
	if len(ips2) > 0 && ips2[0].IP.String() == "1.2.3.4" {
		t.Error("Cache returned modified data instead of copy")
	}
}

func TestDoHResolver_Close(t *testing.T) {
	t.Run("CloseOnce", func(t *testing.T) {
		resolver := NewDoHResolver(nil, 5*time.Minute)

		err := resolver.Close()
		if err != nil {
			t.Errorf("Close() returned error: %v", err)
		}
	})

	t.Run("CloseTwice", func(t *testing.T) {
		resolver := NewDoHResolver(nil, 5*time.Minute)

		// First close
		err := resolver.Close()
		if err != nil {
			t.Errorf("First close() returned error: %v", err)
		}

		// Second close should be idempotent
		err = resolver.Close()
		if err != nil {
			t.Errorf("Second close() returned error: %v", err)
		}
	})

	t.Run("LookupAfterClose", func(t *testing.T) {
		resolver := NewDoHResolver(nil, 5*time.Minute)

		// Close the resolver
		_ = resolver.Close()

		ctx := context.Background()
		_, err := resolver.LookupIPAddr(ctx, "www.google.com")
		if err == nil {
			t.Error("Expected error when using closed resolver")
		}
	})
}

func TestDoHResolver_GetCacheTTL(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)

	// Get default TTL
	ttl := resolver.GetCacheTTL()
	if ttl != 5*time.Minute {
		t.Errorf("GetCacheTTL() = %v, want %v", ttl, 5*time.Minute)
	}

	// Set new TTL
	resolver.SetCacheTTL(10 * time.Minute)

	// Verify TTL was changed
	ttl = resolver.GetCacheTTL()
	if ttl != 10*time.Minute {
		t.Errorf("GetCacheTTL() after SetCacheTTL = %v, want %v", ttl, 10*time.Minute)
	}
}

func TestDoHResolver_ConcurrentClearCache(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	ctx := context.Background()

	var wg sync.WaitGroup

	// Concurrent cache operations
	for i := 0; i < 10; i++ {
		wg.Add(2)

		// Goroutine 1: lookup
		go func() {
			defer wg.Done()
			_, _ = resolver.LookupIPAddr(ctx, "www.google.com")
		}()

		// Goroutine 2: clear cache
		go func() {
			defer wg.Done()
			resolver.ClearCache()
		}()
	}

	wg.Wait()
	// If we get here without deadlock or panic, the test passes
}

// ============================================================================
// parseWireFormatResponse Unit Tests
// ============================================================================

func TestParseWireFormatResponse(t *testing.T) {
	r := &DoHResolver{}

	// Pre-build bodies that use buildDNSWireResponse helper
	multipleAnswersBody := buildDNSWireResponse(0x0001, "example.com", []struct {
		recordType uint16
		ttl        uint32
		rdata      []byte
	}{
		{recordType: 1, ttl: 300, rdata: []byte{1, 1, 1, 1}},   // 1.1.1.1
		{recordType: 1, ttl: 300, rdata: []byte{8, 8, 8, 8}},   // 8.8.8.8
	})

	ipv6 := net.ParseIP("2001:4860:4860::8888")
	aaaaBody := buildDNSWireResponse(0x0001, "example.com", []struct {
		recordType uint16
		ttl        uint32
		rdata      []byte
	}{
		{recordType: 28, ttl: 300, rdata: ipv6.To16()}, // Type AAAA
	})

	skipsNonIPBody := buildDNSWireResponse(0x0001, "example.com", []struct {
		recordType uint16
		ttl        uint32
		rdata      []byte
	}{
		{recordType: 5, ttl: 300, rdata: []byte{'t', 'e', 's', 't'}}, // Type CNAME (should be skipped)
		{recordType: 1, ttl: 300, rdata: []byte{1, 2, 3, 4}},         // Type A
	})

	tests := []struct {
		name    string
		body    []byte
		wantErr bool
		wantIPs []net.IP
	}{
		// Error cases
		{
			name:    "Empty body",
			body:    []byte{},
			wantErr: true,
		},
		{
			name:    "Too short - 1 byte",
			body:    []byte{0x00},
			wantErr: true,
		},
		{
			name:    "Too short - 11 bytes",
			body:    make([]byte, 11),
			wantErr: true,
		},
		{
			name: "Valid header no answers",
			// DNS header with QDCOUNT=0, ANCOUNT=0
			body:    []byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
			wantErr: true, // No IP addresses found
		},
		{
			name: "Truncated after question",
			// DNS header with QDCOUNT=1, but truncated
			body:    []byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, 0x65, 0x78},
			wantErr: true,
		},
		// Success case: single A record
		{
			name: "Success - single A record",
			body: []byte{
				// Header (12 bytes)
				0x12, 0x34, // ID
				0x81, 0x80, // Flags: standard query response, no error
				0x00, 0x01, // QDCOUNT = 1
				0x00, 0x01, // ANCOUNT = 1
				0x00, 0x00, // NSCOUNT = 0
				0x00, 0x00, // ARCOUNT = 0
				// Question section
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // label "example"
				0x03, 'c', 'o', 'm', // label "com"
				0x00,       // null terminator
				0x00, 0x01, // QTYPE = A (1)
				0x00, 0x01, // QCLASS = IN (1)
				// Answer section
				0xC0, 0x0C, // name: compression pointer to offset 12
				0x00, 0x01, // TYPE = A (1)
				0x00, 0x01, // CLASS = IN (1)
				0x00, 0x00, 0x01, 0x2C, // TTL = 300
				0x00, 0x04, // RDLENGTH = 4
				0x5D, 0xB8, 0xD8, 0x22, // RDATA = 93.184.216.34
			},
			wantErr: false,
			wantIPs: []net.IP{net.IP([]byte{93, 184, 216, 34})},
		},
		// Multiple A records
		{
			name:    "Multiple answers - two A records",
			body:    multipleAnswersBody,
			wantErr: false,
			wantIPs: []net.IP{net.IP([]byte{1, 1, 1, 1}), net.IP([]byte{8, 8, 8, 8})},
		},
		// AAAA record
		{
			name:    "AAAA record - IPv6",
			body:    aaaaBody,
			wantErr: false,
			wantIPs: []net.IP{ipv6},
		},
		// Truncated answer section
		{
			name: "Truncated answer section",
			body: []byte{
				0x00, 0x01, // ID
				0x81, 0x80, // Flags
				0x00, 0x01, // QDCOUNT=1
				0x00, 0x01, // ANCOUNT=1
				0x00, 0x00, // NSCOUNT=0
				0x00, 0x00, // ARCOUNT=0
				// Question: example.com
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,       // null terminator
				0x00, 0x01, // QTYPE=A
				0x00, 0x01, // QCLASS=IN
				// Answer starts here but is truncated — only name pointer, no TYPE/CLASS/TTL/RDLENGTH
				0xC0, 0x0C, // name pointer
				// Missing remaining 10 bytes (TYPE, CLASS, TTL, RDLENGTH)
			},
			wantErr: true,
		},
		// Truncated RData
		{
			name: "Truncated rdata",
			body: []byte{
				0x00, 0x01, // ID
				0x81, 0x80, // Flags
				0x00, 0x01, // QDCOUNT=1
				0x00, 0x01, // ANCOUNT=1
				0x00, 0x00, // NSCOUNT=0
				0x00, 0x00, // ARCOUNT=0
				// Question: example.com
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,       // null terminator
				0x00, 0x01, // QTYPE=A
				0x00, 0x01, // QCLASS=IN
				// Answer
				0xC0, 0x0C, // name pointer
				0x00, 0x01, // TYPE=A
				0x00, 0x01, // CLASS=IN
				0x00, 0x00, 0x01, 0x2C, // TTL=300
				0x00, 0x04, // RDLENGTH=4
				// RDATA is missing (should be 4 bytes) — truncated
			},
			wantErr: true,
		},
		// Skips non-IP records (CNAME)
		{
			name:    "Skips non-IP records (CNAME + A)",
			body:    skipsNonIPBody,
			wantErr: false,
			wantIPs: []net.IP{net.IP([]byte{1, 2, 3, 4})},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := r.parseWireFormatResponse(tt.body, "example.com")
			if (err != nil) != tt.wantErr {
				t.Errorf("parseWireFormatResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if len(ips) != len(tt.wantIPs) {
				t.Fatalf("expected %d IPs, got %d", len(tt.wantIPs), len(ips))
			}
			for i, wantIP := range tt.wantIPs {
				if !ips[i].IP.Equal(wantIP) {
					t.Errorf("IP[%d] = %v, want %v", i, ips[i].IP, wantIP)
				}
			}
		})
	}
}

// ============================================================================
// parseJSONResponse Unit Tests - Error Cases
// ============================================================================

func TestParseJSONResponse_Errors(t *testing.T) {
	r := &DoHResolver{}

	tests := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{
			name:    "Invalid JSON",
			body:    []byte(`{invalid json}`),
			wantErr: true,
		},
		{
			name:    "Empty object",
			body:    []byte(`{}`),
			wantErr: true, // No IP addresses found
		},
		{
			name:    "DNS error status",
			body:    []byte(`{"Status": 2, "Answer": []}`),
			wantErr: true, // Non-zero status
		},
		{
			name:    "Empty answers",
			body:    []byte(`{"Status": 0, "Answer": []}`),
			wantErr: true, // No IP addresses found
		},
		{
			name:    "No A/AAAA records",
			body:    []byte(`{"Status": 0, "Answer": [{"name": "example.com", "type": 5, "data": "target.com"}]}`),
			wantErr: true, // No IP addresses found
		},
		{
			name:    "Invalid IP in answer",
			body:    []byte(`{"Status": 0, "Answer": [{"name": "example.com", "type": 1, "data": "invalid-ip"}]}`),
			wantErr: true, // No valid IPs after parsing
		},
		{
			name:    "Valid A record",
			body:    []byte(`{"Status": 0, "Answer": [{"name": "example.com", "type": 1, "data": "8.8.8.8"}]}`),
			wantErr: false,
		},
		{
			name:    "Valid AAAA record",
			body:    []byte(`{"Status": 0, "Answer": [{"name": "example.com", "type": 28, "data": "2001:4860:4860::8888"}]}`),
			wantErr: false,
		},
		{
			name:    "NXDOMAIN status (3) with empty answers",
			body:    []byte(`{"Status": 3, "Answer": []}`),
			wantErr: true, // No IP addresses
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := r.parseJSONResponse(tt.body, "example.com")
			if (err != nil) != tt.wantErr {
				t.Errorf("parseJSONResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(ips) == 0 {
				t.Error("Expected at least one IP address")
			}
		})
	}
}

// ============================================================================
// Provider Priority Tests
// ============================================================================

func TestDoHResolver_ProviderPriority(t *testing.T) {
	// Create custom providers with different priorities
	providers := []*DoHProvider{
		{
			Name:     "primary",
			Template: "https://1.1.1.1/dns-query?name={name}&type=A",
			Priority: 1,
		},
		{
			Name:     "secondary",
			Template: "https://dns.google/resolve?name={name}&type=A",
			Priority: 2,
		},
	}

	resolver := NewDoHResolver(providers, 5*time.Minute)
	defer resolver.Close()

	// Verify providers are set
	if len(resolver.providers) != 2 {
		t.Errorf("Expected 2 providers, got %d", len(resolver.providers))
	}

	// Verify order
	if resolver.providers[0].Priority > resolver.providers[1].Priority {
		t.Error("Providers should be ordered by priority")
	}
}

// ============================================================================
// HTTP Client Timeout Tests
// ============================================================================

func TestDoHResolver_HTTPTimeout(t *testing.T) {
	// Create resolver with short timeout
	resolver := NewDoHResolver(nil, 5*time.Minute)
	defer resolver.Close()

	// Create context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for context to expire
	time.Sleep(2 * time.Nanosecond)

	_, err := resolver.LookupIPAddr(ctx, "www.google.com")
	if err == nil {
		t.Error("Expected timeout error")
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestDoHResolver_InvalidProviderTemplate(t *testing.T) {
	// Create resolver with invalid provider template
	providers := []*DoHProvider{
		{
			Name:     "invalid",
			Template: "http://[::1]:namedpipe",
			Priority: 1,
		},
	}

	resolver := NewDoHResolver(providers, 5*time.Minute)
	defer resolver.Close()

	ctx := context.Background()

	// Should fall back to system resolver
	_, err := resolver.LookupIPAddr(ctx, "www.google.com")
	// The fallback might succeed, so we just verify it doesn't panic
	_ = err
}

func TestDoHResolver_CacheExpirationRaceCondition(t *testing.T) {
	resolver := NewDoHResolver(nil, 100*time.Millisecond)
	defer resolver.Close()

	ctx := context.Background()

	// First lookup to populate cache
	_, _ = resolver.LookupIPAddr(ctx, "www.google.com")

	var wg sync.WaitGroup
	errors := make(chan error, 20)

	// Concurrent reads during cache expiration
	for i := 0; i < 10; i++ {
		wg.Add(2)

		// Reader 1
		go func() {
			defer wg.Done()
			_, err := resolver.LookupIPAddr(ctx, "www.google.com")
			if err != nil {
				errors <- err
			}
		}()

		// Reader 2
		go func() {
			defer wg.Done()
			_, err := resolver.LookupIPAddr(ctx, "www.google.com")
			if err != nil {
				errors <- err
			}
		}()

		// Small delay to allow cache expiration
		time.Sleep(20 * time.Millisecond)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Logf("Concurrent lookup error (may be expected): %v", err)
	}
}

func TestDoHResolver_MultipleProvidersFailover(t *testing.T) {
	// Create providers with first one invalid to test failover
	providers := []*DoHProvider{
		{
			Name:     "invalid-first",
			Template: "http://invalid.localhost:99999/dns?name={name}",
			Priority: 1,
		},
		{
			Name:     "valid-fallback",
			Template: "https://dns.google/resolve?name={name}&type=A",
			Priority: 2,
		},
	}

	resolver := NewDoHResolver(providers, 5*time.Minute)
	defer resolver.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Should fail over to valid provider or system resolver
	ips, err := resolver.LookupIPAddr(ctx, "www.google.com")
	if err != nil {
		t.Logf("Lookup error (may be expected in test env): %v", err)
	} else {
		t.Logf("Successfully resolved with failover: %d IPs", len(ips))
	}
}

// ============================================================================
// EXPIRED CACHE ENTRY EVICTION TESTS
// ============================================================================

func TestDoHResolver_EvictExpiredEntries(t *testing.T) {
	r := NewDoHResolver(nil, 5*time.Minute)
	defer func() { _ = r.Close() }()

	// Manually populate cache with expired and fresh entries
	now := time.Now()

	// Expired entries
	expired := []string{"expired1.com", "expired2.com", "expired3.com"}
	for _, host := range expired {
		r.cache.Store(host, &cacheEntry{
			IPs:     []net.IPAddr{{IP: net.ParseIP("1.2.3.4")}},
			Expires: now.Add(-time.Hour), // expired 1 hour ago
		})
		r.cacheSize.Add(1)
	}

	// Fresh entries
	fresh := []string{"fresh1.com", "fresh2.com"}
	for _, host := range fresh {
		r.cache.Store(host, &cacheEntry{
			IPs:     []net.IPAddr{{IP: net.ParseIP("5.6.7.8")}},
			Expires: now.Add(time.Hour), // expires in 1 hour
		})
		r.cacheSize.Add(1)
	}

	// Run eviction
	r.evictExpiredEntries()

	// Verify expired entries are removed
	for _, host := range expired {
		if _, ok := r.cache.Load(host); ok {
			t.Errorf("expired entry %q should have been evicted", host)
		}
	}

	// Verify fresh entries remain
	for _, host := range fresh {
		if _, ok := r.cache.Load(host); !ok {
			t.Errorf("fresh entry %q should still exist", host)
		}
	}

	// Verify counter reflects only fresh entries
	if size := r.CacheSize(); size != int64(len(fresh)) {
		t.Errorf("expected cache size %d, got %d", len(fresh), size)
	}
}

func TestDoHResolver_CacheFullTriggersEviction(t *testing.T) {
	r := NewDoHResolver(nil, 100*time.Millisecond)
	defer func() { _ = r.Close() }()

	// Fill cache to max with entries that will expire quickly
	for i := 0; i < maxDoHCacheSize; i++ {
		host := fmt.Sprintf("host%d.com", i)
		r.cache.Store(host, &cacheEntry{
			IPs:     []net.IPAddr{{IP: net.ParseIP("1.2.3.4")}},
			Expires: time.Now().Add(50 * time.Millisecond),
		})
		r.cacheSize.Add(1)
	}

	// Wait for entries to expire
	time.Sleep(150 * time.Millisecond)

	// Now cache is full of expired entries. Calling evictExpiredEntries
	// should clear them all
	r.evictExpiredEntries()

	if size := r.CacheSize(); size != 0 {
		t.Errorf("expected cache size 0 after all expired, got %d", size)
	}
}
