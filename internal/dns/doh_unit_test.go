package dns

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

// parseWireFormatResponse and parseJSONResponse have direct unit tests in this
// file (see the wire-format and parseResponse sections below).

func TestDoHResolver_CacheExpiration(t *testing.T) {
	// Local DoH provider (httptest) keeps this test hermetic; the hit counter
	// proves the second lookup re-queries after the TTL expires.
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"name":"expiry.test","type":1,"data":"9.9.9.9"}]}`))
	}))
	defer server.Close()

	resolver := NewDoHResolver([]*dohProvider{
		{Name: "local", Template: server.URL + "/dns-query?name={name}&type=A", Priority: 1},
	}, 100*time.Millisecond)
	defer func() { _ = resolver.Close() }()
	ctx := context.Background()

	// One LookupIPAddr round may issue several provider queries (A + AAAA),
	// so the assertions compare hit counts between rounds, not absolute values.
	ips1, err := resolver.LookupIPAddr(ctx, "expiry.test")
	if err != nil {
		t.Fatalf("First lookup failed: %v", err)
	}
	if len(ips1) == 0 || ips1[0].IP.String() != "9.9.9.9" {
		t.Fatalf("First lookup = %v, want 9.9.9.9", ips1)
	}
	firstRound := atomic.LoadInt32(&hits)
	if firstRound == 0 {
		t.Fatal("provider was not queried on first lookup")
	}

	// Cached hit must not re-query the provider.
	if _, err := resolver.LookupIPAddr(ctx, "expiry.test"); err != nil {
		t.Fatalf("Cached lookup failed: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != firstRound {
		t.Errorf("provider hits = %d on cache hit, want %d (cache not used)", got, firstRound)
	}

	// Wait for the TTL to expire, then look up again.
	time.Sleep(150 * time.Millisecond)

	ips2, err := resolver.LookupIPAddr(ctx, "expiry.test")
	if err != nil {
		t.Fatalf("Second lookup failed: %v", err)
	}
	if len(ips2) == 0 {
		t.Fatal("Expected non-empty IP results after expiry")
	}
	if got := atomic.LoadInt32(&hits); got <= firstRound {
		t.Errorf("provider hits = %d after TTL expiry, want > %d (entry should have been re-queried)", got, firstRound)
	}
}

func TestDoHResolver_CacheSize(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	defer func() { _ = resolver.Close() }()

	// Initial cache size should be 0
	if size := resolver.CacheSize(); size != 0 {
		t.Errorf("Initial cache size = %d, want 0", size)
	}

	// Seed multiple entries directly (no network) to verify multi-host tracking.
	hosts := []string{
		"size-a.test",
		"size-b.test",
		"size-c.test",
		"size-d.test",
		"size-e.test",
	}
	for _, host := range hosts {
		resolver.cache.Store(host, &cacheEntry{
			IPs:     []net.IPAddr{{IP: net.ParseIP("1.2.3.4")}},
			Expires: time.Now().Add(time.Hour),
		})
		resolver.cacheSize.Add(1)
	}

	if size := resolver.CacheSize(); size != int64(len(hosts)) {
		t.Errorf("Cache size after seeding %d hosts = %d", len(hosts), size)
	}

	// Clear cache and verify counter resets
	resolver.ClearCache()
	if resolver.CacheSize() != 0 {
		t.Errorf("Cache size after clear = %d, want 0", resolver.CacheSize())
	}
}

func TestDoHResolver_SetCacheTTL(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)

	// Seed one entry directly (no network).
	resolver.cache.Store("ttl.test", &cacheEntry{
		IPs:     []net.IPAddr{{IP: net.ParseIP("1.2.3.4")}},
		Expires: time.Now().Add(time.Hour),
	})
	resolver.cacheSize.Add(1)

	// Change TTL (this clears cache)
	resolver.SetCacheTTL(1 * time.Minute)

	// Cache should be cleared
	if size := resolver.CacheSize(); size != 0 {
		t.Errorf("Cache size after SetCacheTTL = %d, want 0", size)
	}
}

func TestDoHResolver_ConcurrentAccess(t *testing.T) {
	// Local provider keeps this hermetic; the in-flight dedup may coalesce
	// the 20 lookups into one provider hit, but every caller must receive
	// the resolved address.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"name":"concurrent.test","type":1,"data":"4.4.4.4"}]}`))
	}))
	defer server.Close()

	resolver := NewDoHResolver([]*dohProvider{
		{Name: "local", Template: server.URL + "/dns-query?name={name}&type=A", Priority: 1},
	}, 5*time.Minute)
	defer func() { _ = resolver.Close() }()
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ips, err := resolver.LookupIPAddr(ctx, "concurrent.test")
			if err != nil {
				errs <- err
				return
			}
			if len(ips) == 0 || ips[0].IP.String() != "4.4.4.4" {
				errs <- fmt.Errorf("lookup returned %v, want 4.4.4.4", ips)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("Concurrent lookup error: %v", err)
	}
}

// TestDoHResolver_BrokenContext covers context cancellation and expiry before
// any provider is contacted (formerly two separate tests with identical
// assertions, differing only in how the context was broken).
func TestDoHResolver_BrokenContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
	}{
		{"cancelled context", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // Cancel immediately
			return ctx, cancel
		}},
		{"expired context", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
			time.Sleep(2 * time.Nanosecond) // Ensure the deadline has passed
			return ctx, cancel
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := NewDoHResolver(nil, 5*time.Minute)
			ctx, cancel := tt.ctx()
			defer cancel()

			_, err := resolver.LookupIPAddr(ctx, "www.google.com")
			if err == nil {
				t.Error("Expected error with broken context")
			}
		})
	}
}

func TestDoHResolver_EmptyHost(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	defer func() { _ = resolver.Close() }()

	// Short deadline: providers are unreachable on offline machines, and the
	// assertion only needs the error — not a 10s provider timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Empty host should fail
	_, err := resolver.LookupIPAddr(ctx, "")
	if err == nil {
		t.Error("Expected error for empty host")
	}
}

// TestDoHResolver_IPAddressInput is retired: its stale comment predated the
// IP-literal fast path, and its accept-success-or-deadline assertion could not
// fail. TestLookupIPAddr_IPLiteralFastPath pins the actual behavior.

func TestDoHResolver_CacheReturnsCopy(t *testing.T) {
	resolver := NewDoHResolver(nil, 5*time.Minute)
	defer func() { _ = resolver.Close() }()

	// Seed the cache directly (no network); both lookups below are cache hits.
	resolver.cache.Store("copy.test", &cacheEntry{
		IPs:     []net.IPAddr{{IP: net.ParseIP("203.0.113.7")}},
		Expires: time.Now().Add(time.Hour),
	})
	resolver.cacheSize.Add(1)
	ctx := context.Background()

	ips1, err := resolver.LookupIPAddr(ctx, "copy.test")
	if err != nil {
		t.Fatalf("First lookup failed: %v", err)
	}
	if len(ips1) != 1 || ips1[0].IP.String() != "203.0.113.7" {
		t.Fatalf("First lookup = %v, want 203.0.113.7", ips1)
	}

	// Mutate the returned slice.
	ips1[0] = net.IPAddr{IP: net.ParseIP("1.2.3.4")}

	// Second lookup must return the original cached data, not the mutation.
	ips2, err := resolver.LookupIPAddr(ctx, "copy.test")
	if err != nil {
		t.Fatalf("Second lookup failed: %v", err)
	}
	if len(ips2) == 0 {
		t.Fatal("Expected non-empty cached result")
	}
	if ips2[0].IP.String() == "1.2.3.4" {
		t.Error("Cache returned modified data instead of copy")
	}
	if ips2[0].IP.String() != "203.0.113.7" {
		t.Errorf("Cached entry corrupted: got %s, want 203.0.113.7", ips2[0].IP.String())
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
	// A local provider keeps even the race-loser lookups (cache cleared before
	// the read) off the network.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"name":"clear.test","type":1,"data":"4.4.4.4"}]}`))
	}))
	defer server.Close()

	resolver := NewDoHResolver([]*dohProvider{
		{Name: "local", Template: server.URL + "/dns-query?name={name}&type=A", Priority: 1},
	}, 5*time.Minute)
	defer func() { _ = resolver.Close() }()
	ctx := context.Background()

	var wg sync.WaitGroup

	// Concurrent cache operations
	for i := 0; i < 10; i++ {
		wg.Add(2)

		// Goroutine 1: lookup
		go func() {
			defer wg.Done()
			_, _ = resolver.LookupIPAddr(ctx, "clear.test")
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
		{recordType: 1, ttl: 300, rdata: []byte{1, 1, 1, 1}}, // 1.1.1.1
		{recordType: 1, ttl: 300, rdata: []byte{8, 8, 8, 8}}, // 8.8.8.8
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
	providers := []*dohProvider{
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
	defer func() { _ = resolver.Close() }()

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
// Provider Failover
// ============================================================================

// TestDoHResolver_HTTPTimeout was removed: identical to
// TestDoHResolver_ContextTimeout (same 1ns-ctx + expired-context assertion).
// TestDoHResolver_InvalidProviderTemplate and
// TestDoHResolver_CacheExpirationRaceCondition were removed: neither asserted
// anything (results discarded or demoted to t.Logf).

// TestDoHResolver_MultipleProvidersFailover verifies a failing first provider
// falls through to the next-priority provider. Replaces the former log-only
// version: both providers are local/deterministic, so the result is asserted.
func TestDoHResolver_MultipleProvidersFailover(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"name":"failover.test","type":1,"data":"5.6.7.8"}]}`))
	}))
	defer server.Close()

	providers := []*dohProvider{
		{
			Name:     "invalid-first",
			Template: "http://[::1]:namedpipe", // unparseable - always fails
			Priority: 1,
		},
		{
			Name:     "valid-fallback",
			Template: server.URL + "/dns-query?name={name}&type=A",
			Priority: 2,
		},
	}

	resolver := NewDoHResolver(providers, 5*time.Minute)
	defer func() { _ = resolver.Close() }()

	ips, err := resolver.LookupIPAddr(context.Background(), "failover.test")
	if err != nil {
		t.Fatalf("failover lookup failed: %v", err)
	}
	if len(ips) == 0 || ips[0].IP.String() != "5.6.7.8" {
		t.Errorf("failover lookup = %v, want 5.6.7.8 from second provider", ips)
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

// TestDoHResolver_EvictOldestEntry verifies that when the cache is full of fresh
// (unexpired) entries, evictOldestEntry removes the one closest to expiry — the
// admission path that prevents freshly resolved hosts from being silently dropped.
func TestDoHResolver_EvictOldestEntry(t *testing.T) {
	r := NewDoHResolver(nil, 5*time.Minute)
	defer func() { _ = r.Close() }()

	now := time.Now()

	// Populate cache with fresh entries at varying TTLs.
	entries := []struct {
		host   string
		offset time.Duration // expiry offset from now
	}{
		{"long1.com", 1 * time.Hour},
		{"mid.com", 30 * time.Minute},
		{"short.com", 5 * time.Minute}, // nearest expiry — should be evicted
		{"long2.com", 2 * time.Hour},
	}
	for _, e := range entries {
		r.cache.Store(e.host, &cacheEntry{
			IPs:     []net.IPAddr{{IP: net.ParseIP("1.2.3.4")}},
			Expires: now.Add(e.offset),
		})
		r.cacheSize.Add(1)
	}

	r.evictOldestEntry()

	// The entry nearest to expiry (short.com) should be gone.
	if _, ok := r.cache.Load("short.com"); ok {
		t.Error("short.com (nearest expiry) should have been evicted")
	}

	// All other entries should remain.
	for _, e := range entries {
		if e.host == "short.com" {
			continue
		}
		if _, ok := r.cache.Load(e.host); !ok {
			t.Errorf("%s should still be cached", e.host)
		}
	}

	if size := r.CacheSize(); size != int64(len(entries)-1) {
		t.Errorf("cache size = %d, want %d", size, len(entries)-1)
	}
}

// TestDoHResolver_EvictOldestEntry_EmptyCache verifies evictOldestEntry is a
// safe no-op when the cache holds no entries.
func TestDoHResolver_EvictOldestEntry_EmptyCache(t *testing.T) {
	r := NewDoHResolver(nil, 5*time.Minute)
	defer func() { _ = r.Close() }()

	r.evictOldestEntry() // must not panic

	if size := r.CacheSize(); size != 0 {
		t.Errorf("expected cache size 0, got %d", size)
	}
}

// TestDoHResolver_LookupGoroutinePanicRecovered (SEC-003) verifies that a panic
// inside the concurrent A/AAAA lookup goroutines is recovered and converted into
// a lookup error instead of crashing the process. recover() does not cross
// goroutine boundaries, so without the per-goroutine safety net the nil-client
// dereference triggered here would terminate the whole test binary.
func TestDoHResolver_LookupGoroutinePanicRecovered(t *testing.T) {
	// Construct a resolver with a nil HTTP client. lookupRecordType builds a
	// valid request URL from the template, then dereferences r.client on Do(),
	// panicking inside the lookup goroutine.
	r := &DoHResolver{}
	provider := &dohProvider{
		Name:     "test",
		Template: "https://dns.example.test/resolve?name={name}&type={type}",
	}

	ips, err := r.lookupWithProvider(context.Background(), provider, "example.com")

	if err == nil {
		t.Fatal("expected panic-recovered error from lookupWithProvider, got nil")
	}
	if !strings.Contains(err.Error(), "panic recovered") {
		t.Errorf("expected error to mention 'panic recovered', got: %v", err)
	}
	if len(ips) != 0 {
		t.Errorf("expected no IPs on panic, got %d", len(ips))
	}
}

// TestDoH_dohMediaType verifies Content-Type media-type extraction strips
// parameters, trims whitespace, and lowercases.
func TestDoH_dohMediaType(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"application/dns-json", "application/dns-json"},
		{"application/json; charset=utf-8", "application/json"},
		{"  Application/dns-message ", "application/dns-message"},
		{"", ""},
		{"text/plain; charset=ascii", "text/plain"},
	}
	for _, tt := range tests {
		if got := dohMediaType(tt.in); got != tt.want {
			t.Errorf("dohMediaType(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestDoH_parseResponse_DispatchByContentType verifies the parser is selected by
// the response Content-Type (not provider name) and that a missing/unknown
// Content-Type falls back to a JSON-then-wire sniff.
func TestDoH_parseResponse_DispatchByContentType(t *testing.T) {
	jsonBody := []byte(`{"Status":0,"Answer":[{"name":"example.com","type":1,"data":"1.2.3.4"}]}`)
	wireBody := buildDNSWireResponse(0x1234, "example.com", []struct {
		recordType uint16
		ttl        uint32
		rdata      []byte
	}{{recordType: 1, ttl: 60, rdata: []byte{1, 2, 3, 4}}})

	r := &DoHResolver{}

	tests := []struct {
		name        string
		contentType string
		body        []byte
		wantIP      string
	}{
		{"json via application/dns-json", "application/dns-json", jsonBody, "1.2.3.4"},
		{"json via application/json", "application/json", jsonBody, "1.2.3.4"},
		{"json with charset param", "application/json; charset=utf-8", jsonBody, "1.2.3.4"},
		{"wire via application/dns-message", "application/dns-message", wireBody, "1.2.3.4"},
		{"wire via application/dns-wire", "application/dns-wire", wireBody, "1.2.3.4"},
		{"missing content-type sniffs json", "", jsonBody, "1.2.3.4"},
		{"unknown content-type sniffs json", "text/plain", jsonBody, "1.2.3.4"},
		{"missing content-type falls back to wire", "", wireBody, "1.2.3.4"},
		{"unknown content-type falls back to wire", "text/plain", wireBody, "1.2.3.4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: http.Header{},
				Body:   io.NopCloser(bytes.NewReader(tt.body)),
			}
			resp.Header.Set("Content-Type", tt.contentType)
			ips, err := r.parseResponse(resp, "example.com")
			if err != nil {
				t.Fatalf("parseResponse error: %v", err)
			}
			if len(ips) != 1 || ips[0].IP.String() != tt.wantIP {
				t.Errorf("got %v, want single IP %s", ips, tt.wantIP)
			}
		})
	}
}

// TestDoH_parseResponse_Boundaries covers the hardening branches of
// parseResponse: the response-size ceiling, mid-read transport errors, and the
// combined parser-failure error for an unknown Content-Type.
func TestDoH_parseResponse_Boundaries(t *testing.T) {
	r := &DoHResolver{}

	t.Run("body exceeding size limit is rejected", func(t *testing.T) {
		oversize := bytes.Repeat([]byte{0}, maxDoHResponseSize+1)
		resp := &http.Response{
			Header: http.Header{},
			Body:   io.NopCloser(bytes.NewReader(oversize)),
		}
		_, err := r.parseResponse(resp, "example.com")
		if err == nil {
			t.Fatal("expected size-limit error, got nil")
		}
		if !strings.Contains(err.Error(), "maximum size") {
			t.Errorf("error should mention the size limit, got: %v", err)
		}
	})

	t.Run("body read error is surfaced", func(t *testing.T) {
		resp := &http.Response{
			Header: http.Header{},
			Body:   io.NopCloser(errReader{errors.New("connection reset")}),
		}
		resp.Header.Set("Content-Type", "application/dns-json")
		_, err := r.parseResponse(resp, "example.com")
		if err == nil {
			t.Fatal("expected read error, got nil")
		}
		if !strings.Contains(err.Error(), "read response body") {
			t.Errorf("error should mention body read failure, got: %v", err)
		}
	})

	t.Run("unknown content-type with both parsers failing reports both", func(t *testing.T) {
		// Valid neither as JSON nor as DNS wire format.
		resp := &http.Response{
			Header: http.Header{},
			Body:   io.NopCloser(bytes.NewReader([]byte("not-a-dns-response"))),
		}
		resp.Header.Set("Content-Type", "application/octet-stream")
		_, err := r.parseResponse(resp, "example.com")
		if err == nil {
			t.Fatal("expected combined parser error, got nil")
		}
		if !strings.Contains(err.Error(), "unknown DoH response format") ||
			!strings.Contains(err.Error(), "json:") || !strings.Contains(err.Error(), "wire:") {
			t.Errorf("error should report both parser failures, got: %v", err)
		}
	})
}

// errReader fails every Read with err, for exercising body-read error paths.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// TestDoH_parseResponse_CloudflareJSONNotForcedToWire is a regression guard: a
// provider literally named "cloudflare" returning JSON (Content-Type
// application/dns-json) must be parsed as JSON. The old name-based switch forced
// cloudflare to wire format regardless of Content-Type, which would mis-parse a
// JSON response and break DoH.
func TestDoH_parseResponse_CloudflareJSONNotForcedToWire(t *testing.T) {
	jsonBody := []byte(`{"Status":0,"Answer":[{"name":"example.com","type":1,"data":"5.6.7.8"}]}`)
	r := &DoHResolver{}
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(bytes.NewReader(jsonBody)),
	}
	resp.Header.Set("Content-Type", "application/dns-json")
	ips, err := r.parseResponse(resp, "example.com")
	if err != nil {
		t.Fatalf("parseResponse error: %v", err)
	}
	if len(ips) != 1 || ips[0].IP.String() != "5.6.7.8" {
		t.Errorf("cloudflare-named JSON response mis-dispatched: got %v, want 5.6.7.8", ips)
	}
}

// ============================================================================
// Response Binding & RCODE Tests
// ============================================================================

// TestParseWireFormatResponse_NameBinding verifies a wire response answering
// a different name than the one queried is rejected, while case differences
// and the trailing root dot are tolerated.
func TestParseWireFormatResponse_NameBinding(t *testing.T) {
	r := &DoHResolver{}

	foreignBody := buildDNSWireResponse(0x0001, "other.example.net", []struct {
		recordType uint16
		ttl        uint32
		rdata      []byte
	}{
		{recordType: 1, ttl: 300, rdata: []byte{10, 0, 0, 1}},
	})
	if _, err := r.parseWireFormatResponse(foreignBody, "example.com"); err == nil {
		t.Error("expected error when wire response answers a different host")
	}

	matchingBody := buildDNSWireResponse(0x0001, "example.com", []struct {
		recordType uint16
		ttl        uint32
		rdata      []byte
	}{
		{recordType: 1, ttl: 300, rdata: []byte{1, 2, 3, 4}},
	})
	if _, err := r.parseWireFormatResponse(matchingBody, "EXAMPLE.com."); err != nil {
		t.Errorf("case-insensitive/trailing-dot host match should pass: %v", err)
	}
}

// TestParseWireFormatResponse_RCODE verifies non-zero RCODEs surface as
// errors instead of masquerading as empty answers; NXDOMAIN (3) is tolerated
// to match the JSON parser semantics.
func TestParseWireFormatResponse_RCODE(t *testing.T) {
	r := &DoHResolver{}

	servfail := buildDNSWireResponse(0x0001, "example.com", []struct {
		recordType uint16
		ttl        uint32
		rdata      []byte
	}{
		{recordType: 1, ttl: 300, rdata: []byte{1, 2, 3, 4}},
	})
	servfail[3] |= 0x02 // SERVFAIL
	_, err := r.parseWireFormatResponse(servfail, "example.com")
	if err == nil || !strings.Contains(err.Error(), "SERVFAIL") {
		t.Errorf("expected SERVFAIL error, got %v", err)
	}

	nxdomain := buildDNSWireResponse(0x0001, "example.com", nil)
	nxdomain[3] |= 0x03 // NXDOMAIN — tolerated, surfaces as "no IP addresses"
	_, err = r.parseWireFormatResponse(nxdomain, "example.com")
	if err == nil || !strings.Contains(err.Error(), "no IP addresses") {
		t.Errorf("NXDOMAIN should fall through to no-IP error, got %v", err)
	}
}

// TestParseJSONResponse_NameBinding verifies a JSON response answering a
// different name than the one queried is rejected (cache-poisoning guard).
func TestParseJSONResponse_NameBinding(t *testing.T) {
	r := &DoHResolver{}

	foreign := []byte(`{"Status":0,"Answer":[{"name":"evil.example.net","type":1,"data":"8.8.8.8"}]}`)
	if _, err := r.parseJSONResponse(foreign, "example.com"); err == nil {
		t.Error("expected error when JSON response answers a different host")
	}

	matching := []byte(`{"Status":0,"Answer":[{"name":"Example.COM.","type":1,"data":"8.8.8.8"}]}`)
	if _, err := r.parseJSONResponse(matching, "example.com"); err != nil {
		t.Errorf("case-insensitive/trailing-dot host match should pass: %v", err)
	}
}

// TestLookupDedup_WaiterHonorsContext verifies a waiter whose context is
// canceled while a lookup is in flight returns promptly instead of blocking
// behind the leader's provider queries.
func TestLookupDedup_WaiterHonorsContext(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // block the leader's provider query
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"name":"test.local","type":1,"data":"1.2.3.4"}]}`))
	}))
	defer server.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	provider := &dohProvider{
		Name:     "slow",
		Template: server.URL + "/dns-query?name={name}&type=A",
		Priority: 1,
	}
	resolver := NewDoHResolver([]*dohProvider{provider}, 5*time.Minute)
	defer func() { _ = resolver.Close() }()

	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, _ = resolver.LookupIPAddr(context.Background(), "test.local")
	}()

	// Give the leader time to register the in-flight call.
	time.Sleep(50 * time.Millisecond)

	waiterCtx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := resolver.LookupIPAddr(waiterCtx, "test.local")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("waiter blocked %v behind leader; cancellation should be prompt", elapsed)
	}

	// Unblock the leader's provider query before joining it — otherwise the
	// leader stalls until its HTTP timeout (~10s offline) and slows the suite.
	close(release)
	<-leaderDone
}

// TestDefaultDoHProviders verifies the built-in provider list is well-formed.
// (Moved from doh_test.go when that integration-tagged file was retired.)
func TestDefaultDoHProviders(t *testing.T) {
	providers := defaultDoHProviders()

	if len(providers) == 0 {
		t.Fatal("defaultDoHProviders() returned empty list")
	}

	for _, p := range providers {
		if p.Name == "" {
			t.Error("Provider has empty Name")
		}
		if p.Template == "" {
			t.Error("Provider has empty Template")
		}
	}
}

// TestRcodeName pins the RCODE-to-mnemonic table used in resolution error
// messages (RFC 1035 / RFC 8914 names; everything else reads UNKNOWN).
func TestRcodeName(t *testing.T) {
	tests := []struct {
		rcode byte
		want  string
	}{
		{0, "UNKNOWN"}, // NOERROR is never rendered as an error
		{1, "FORMERR"},
		{2, "SERVFAIL"},
		{3, "UNKNOWN"}, // NXDOMAIN handled elsewhere
		{4, "NOTIMP"},
		{5, "REFUSED"},
		{9, "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := rcodeName(tt.rcode); got != tt.want {
			t.Errorf("rcodeName(%d) = %q, want %q", tt.rcode, got, tt.want)
		}
	}
}

// TestLookupIPAddr_IPLiteralFastPath pins the IP-literal fast path: an IP
// address host must resolve locally without touching any DoH provider. The
// cancelled context proves zero network involvement — the provider path would
// fail immediately on ctx.Err(), and without the fast path it would be the
// only outcome. Matches net.DefaultResolver semantics for IP literals.
func TestLookupIPAddr_IPLiteralFastPath(t *testing.T) {
	resolver := NewDoHResolver(nil, time.Minute)
	t.Cleanup(func() { _ = resolver.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // any provider round-trip must fail; only the fast path can succeed

	tests := []struct {
		host string
		want string
	}{
		{"127.0.0.1", "127.0.0.1"},
		{"192.0.2.1", "192.0.2.1"},
		{"::1", "::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"::ffff:192.0.2.1", "192.0.2.1"}, // IPv4-mapped collapses via String()
	}
	for _, tt := range tests {
		ips, err := resolver.LookupIPAddr(ctx, tt.host)
		if err != nil {
			t.Errorf("LookupIPAddr(%q) error: %v", tt.host, err)
			continue
		}
		if len(ips) != 1 {
			t.Errorf("LookupIPAddr(%q) returned %d IPs, want 1", tt.host, len(ips))
			continue
		}
		if got := ips[0].IP.String(); got != tt.want {
			t.Errorf("LookupIPAddr(%q) = %s, want %s", tt.host, got, tt.want)
		}
	}

	// A non-IP host on the cancelled context must NOT take the fast path.
	if _, err := resolver.LookupIPAddr(ctx, "example.com"); err == nil {
		t.Error("LookupIPAddr(example.com) with cancelled ctx unexpectedly succeeded")
	}
}
