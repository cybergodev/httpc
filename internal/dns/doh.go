// Package dns provides DNS-over-HTTPS resolution with caching support
// for the httpc library.
package dns

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Compile-time interface check for io.Closer
var _ io.Closer = (*DoHResolver)(nil)

// DoHResolver provides DNS-over-HTTPS resolution
type DoHResolver struct {
	client    *http.Client
	providers []*dohProvider
	cache     sync.Map
	cacheTTL  atomic.Int64 // Thread-safe cache TTL (stored as nanoseconds)
	cacheSize atomic.Int64 // O(1) cache size tracking
	closed    atomic.Bool  // Prevents double-close and operations after close

	// inflight coalesces concurrent network lookups for the same host into a
	// single provider round-trip, preventing a cache-stampede (thundering herd).
	inflight inflightMap
}

// dohProvider represents a DNS-over-HTTPS service provider with a URL template and priority.
type dohProvider struct {
	Name     string
	Template string // URL template with {name} placeholder
	// Priority controls query order: lower values are tried first.
	// NewDoHResolver sorts providers by this field.
	Priority int

	// Pre-computed template parts for fast URL building (set by NewDoHResolver)
	urlPrefix string // portion before {name}
	urlMiddle string // portion between {name} and {type}
	urlSuffix string // portion after {type}
	hasTypePH bool   // template contains {type} placeholder
}

// cacheEntry holds cached DNS resolution results
type cacheEntry struct {
	IPs     []net.IPAddr
	Expires time.Time
}

// call represents a single in-flight DoH lookup shared by concurrent waiters.
type call struct {
	ips  []net.IPAddr
	err  error
	done chan struct{} // closed once ips/err are published
}

// inflightMap deduplicates concurrent lookups for the same host
// (singleflight-style), so a stampede of cache misses collapses into one
// network round-trip. Implemented with the standard library — no x/sync dep.
type inflightMap struct {
	mu sync.Mutex
	m  map[string]*call
}

// Security constants for DoH
const (
	// maxDoHResponseSize limits the maximum size of a DoH response to prevent
	// memory exhaustion attacks from malicious DNS servers
	maxDoHResponseSize = 64 * 1024 // 64KB - DNS responses should never be this large

	// maxDoHCacheSize limits the number of cached DNS entries to prevent
	// unbounded memory growth
	maxDoHCacheSize = 1000
)

// defaultDoHProviders returns common DoH providers.
// Templates use {name} for hostname and {type} for record type (A/AAAA).
func defaultDoHProviders() []*dohProvider {
	return []*dohProvider{
		{
			Name:     "cloudflare",
			Template: "https://1.1.1.1/dns-query?name={name}&type={type}",
			Priority: 1,
		},
		{
			Name:     "google",
			Template: "https://dns.google/resolve?name={name}&type={type}",
			Priority: 2,
		},
		{
			Name:     "ali",
			Template: "https://dns.alidns.com/resolve?name={name}&type={type}",
			Priority: 3,
		},
	}
}

// NewDoHResolver creates a new DoH resolver. Passing nil or an empty
// providers slice selects defaultDoHProviders(); custom providers can only
// be supplied within this package (the dohProvider type is unexported).
func NewDoHResolver(providers []*dohProvider, cacheTTL time.Duration) *DoHResolver {
	if len(providers) == 0 {
		providers = defaultDoHProviders()
	}
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	// Defensive copy: callers may reuse or share the provided dohProvider
	// structs. The template pre-split below writes resolver-internal fields
	// (urlPrefix/urlMiddle/urlSuffix) onto each provider, so operate on owned
	// copies to avoid mutating the caller's input or aliasing across resolvers.
	owned := make([]*dohProvider, len(providers))
	for i := range providers {
		cp := *providers[i]
		owned[i] = &cp
	}

	// Query in Priority order (lower value = tried first) regardless of the
	// order providers were passed in — previously the field was silently
	// ignored and lookupViaProviders used slice order.
	slices.SortStableFunc(owned, func(a, b *dohProvider) int {
		return cmp.Compare(a.Priority, b.Priority)
	})

	r := &DoHResolver{
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: true,
				DisableKeepAlives:  false,
				ForceAttemptHTTP2:  true,
			},
		},
		providers: owned,
	}
	r.cacheTTL.Store(int64(cacheTTL))

	// Pre-split URL templates for fast URL building
	for i := range r.providers {
		p := r.providers[i]
		parts := strings.SplitN(p.Template, "{name}", 2)
		p.urlPrefix = parts[0]
		if len(parts) > 1 {
			rest := parts[1]
			typeParts := strings.SplitN(rest, "{type}", 2)
			p.urlMiddle = typeParts[0]
			if len(typeParts) > 1 {
				p.urlSuffix = typeParts[1]
				p.hasTypePH = true
			}
		}
	}

	return r
}

// LookupIPAddr resolves a host name to IP addresses using DoH
func (r *DoHResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	// Check if resolver is closed
	if r.closed.Load() {
		return nil, fmt.Errorf("DoH resolver is closed")
	}

	// Fast path: an IP-literal host needs no resolution. Without this, every
	// connection to an IP address (e.g. http://127.0.0.1) would pay a full DoH
	// provider round-trip — stalling until the provider timeout when offline.
	// Matches net.DefaultResolver semantics, which returns IP literals as-is.
	// SSRF filtering happens in the caller (connection pool) on the returned
	// IPs, so private-address blocking is unaffected.
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}

	// DNS names are case-insensitive (RFC 1035 §3.1). Normalize the key so
	// Example.com and example.com share one cache entry and one singleflight
	// round-trip instead of duplicating provider queries and cache slots.
	// strings.ToLower returns s unchanged (no allocation) when already lower.
	host = strings.ToLower(host)

	// Check cache — Load is safe since cacheEntry is read-only after creation.
	if cached, ok := r.cache.Load(host); ok {
		if entry, typeOk := cached.(*cacheEntry); typeOk && entry != nil {
			if time.Now().Before(entry.Expires) {
				// Shallow copy the slice header. net.IP values from DNS are
				// treated as read-only by all callers, so sharing the underlying
				// byte data is safe and avoids per-IP allocations.
				ips := make([]net.IPAddr, len(entry.IPs))
				copy(ips, entry.IPs)
				return ips, nil
			}
			// Expired — atomically delete and decrement counter only if we win the race
			if _, deleted := r.cache.LoadAndDelete(host); deleted {
				r.cacheSize.Add(-1)
			}
		}
	}

	// Resolve via providers, coalescing concurrent lookups for the same host
	// into a single network round-trip (prevents cache-stampede). The returned
	// slice may be shared across concurrent waiters and must be treated read-only.
	ips, err := r.lookupDedup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		// Unreachable in practice — every provider path and the system
		// fallback return an error rather than an empty success — but if it
		// ever fired, the caller (connection/pool.go) would misreport it as
		// "resolves only to blocked addresses". Surface the real condition.
		return nil, fmt.Errorf("DoH lookup for %s returned no addresses", host)
	}

	// SECURITY: Use CAS to atomically reserve cache slot before storing.
	// Bounded retry prevents theoretical livelock under extreme contention
	// where concurrent goroutines continuously fill and evict the cache.
	const maxCacheRetryAttempts = 3
	for range maxCacheRetryAttempts {
		current := r.cacheSize.Load()
		if current >= maxDoHCacheSize {
			// Cache full — evict expired entries first, then the oldest fresh
			// entry, so a new admission never silently drops the result.
			r.evictExpiredEntries()
			if r.cacheSize.Load() >= maxDoHCacheSize {
				r.evictOldestEntry()
			}
			continue
		}
		if r.cacheSize.CompareAndSwap(current, current+1) {
			cacheTTL := time.Duration(r.cacheTTL.Load())
			// IPs from lookupWithProvider are fresh allocations.
			// Shallow copy for cache isolation: the slice header is independent
			// while the underlying net.IP data is shared (read-only per contract).
			cachedIPs := make([]net.IPAddr, len(ips))
			copy(cachedIPs, ips)
			newEntry := &cacheEntry{
				IPs:     cachedIPs,
				Expires: time.Now().Add(cacheTTL),
			}
			// Use LoadOrStore to detect concurrent stores and prevent counter drift.
			// If another goroutine already stored an entry for this host,
			// revert our counter increment since no new slot was consumed.
			if _, exists := r.cache.LoadOrStore(host, newEntry); exists {
				r.cacheSize.Add(-1)
			}
			break
		}
	}
	return ips, nil
}

// lookupDedup coalesces concurrent lookups for the same host into a single
// network round-trip. When several goroutines miss the cache for a host at
// once, only the first performs the provider queries; the others wait and
// share the result. This is a minimal singleflight using the standard library.
func (r *DoHResolver) lookupDedup(ctx context.Context, host string) ([]net.IPAddr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.inflight.mu.Lock()
	if r.inflight.m == nil {
		r.inflight.m = make(map[string]*call)
	}
	if c, ok := r.inflight.m[host]; ok {
		// Another goroutine is already resolving this host. Wait for its
		// result, but honor the caller's context: cancellation must not
		// block behind a slow leader.
		r.inflight.mu.Unlock()
		select {
		case <-c.done:
			return c.ips, c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &call{done: make(chan struct{})}
	r.inflight.m[host] = c
	r.inflight.mu.Unlock()

	// Guard the leader's provider round-trip the same way the per-record-type
	// goroutines in lookupWithProvider are guarded. A panic escaping
	// lookupViaProviders would skip both close(c.done) and the inflight cleanup
	// below: the orphaned call would never complete, and every later lookup for
	// this host would attach to it and block until its own context deadline.
	// Converting the panic into an error keeps waiters (and the fallback path)
	// moving.
	ips, err := func() (ips []net.IPAddr, err error) {
		defer func() {
			if rec := recover(); rec != nil {
				ips, err = nil, fmt.Errorf("doh lookup panic recovered: %v", rec)
			}
		}()
		return r.lookupViaProviders(ctx, host)
	}()

	// Publish the result before closing done so waiters observe it.
	c.ips, c.err = ips, err
	close(c.done)

	r.inflight.mu.Lock()
	delete(r.inflight.m, host)
	r.inflight.mu.Unlock()

	return ips, err
}

// lookupViaProviders queries each configured DoH provider in priority order
// until one returns addresses, falling back to the system resolver on failure.
func (r *DoHResolver) lookupViaProviders(ctx context.Context, host string) ([]net.IPAddr, error) {
	var lastErr error
	for _, provider := range r.providers {
		ips, err := r.lookupWithProvider(ctx, provider, host)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		lastErr = err
	}
	return r.fallbackLookup(ctx, host, lastErr)
}

// CacheSize returns the current number of entries in the cache (O(1) via atomic counter)
func (r *DoHResolver) CacheSize() int64 {
	return r.cacheSize.Load()
}

// lookupWithProvider performs DNS lookup using a specific DoH provider.
// It queries both A (IPv4) and AAAA (IPv6) records concurrently.
func (r *DoHResolver) lookupWithProvider(ctx context.Context, provider *dohProvider, host string) ([]net.IPAddr, error) {
	escapedHost := url.PathEscape(host)

	type lookupResult struct {
		ips []net.IPAddr
		err error
	}

	chA := make(chan lookupResult, 1)
	chAAAA := make(chan lookupResult, 1)

	// lookup runs a single record-type query in a panic-guarded goroutine.
	// recover does not cross goroutine boundaries: an unguarded panic inside
	// lookupRecordType would terminate the whole process, bypassing the
	// request-path safety nets. Convert any panic into a lookup error so the
	// caller's fallback path (r.fallbackLookup) still runs. Each goroutine
	// sends exactly once on a capacity-1 channel, so the recover's send cannot
	// block or race with the normal send.
	lookup := func(recordType string, ch chan<- lookupResult) {
		defer func() {
			if rec := recover(); rec != nil {
				ch <- lookupResult{err: fmt.Errorf("doh %s lookup panic recovered: %v", recordType, rec)}
			}
		}()
		ips, err := r.lookupRecordType(ctx, provider, escapedHost, recordType)
		ch <- lookupResult{ips: ips, err: err}
	}

	// Query A and AAAA records concurrently
	go lookup("A", chA)
	go lookup("AAAA", chAAAA)

	resA := <-chA
	resAAAA := <-chAAAA

	// Merge results: return any IPs found
	ips := make([]net.IPAddr, 0, len(resA.ips)+len(resAAAA.ips))
	if resA.err == nil {
		ips = append(ips, resA.ips...)
	}
	if resAAAA.err == nil {
		ips = append(ips, resAAAA.ips...)
	}
	if len(ips) > 0 {
		return ips, nil
	}

	// Both failed — return the first non-nil error, preferring A record error
	if resA.err != nil {
		return nil, resA.err
	}
	return nil, resAAAA.err
}

// lookupRecordType queries a specific DNS record type (A or AAAA) via DoH.
func (r *DoHResolver) lookupRecordType(ctx context.Context, provider *dohProvider, escapedHost, recordType string) ([]net.IPAddr, error) {
	// Build request URL using pre-split template parts (avoids strings.Replace allocations)
	var requestURL string
	if provider.urlPrefix != "" || provider.urlMiddle != "" {
		requestURL = provider.urlPrefix + escapedHost + provider.urlMiddle
		if provider.hasTypePH {
			requestURL += recordType + provider.urlSuffix
		} else {
			sep := "&"
			if !strings.Contains(requestURL, "?") {
				sep = "?"
			}
			requestURL += sep + "type=" + recordType
		}
	} else {
		// Fallback for providers without pre-split templates
		requestURL = strings.Replace(provider.Template, "{name}", escapedHost, 1)
		requestURL = strings.Replace(requestURL, "{type}", recordType, 1)
		if !strings.Contains(provider.Template, "{type}") {
			sep := "&"
			if !strings.Contains(requestURL, "?") {
				sep = "?"
			}
			requestURL += sep + "type=" + recordType
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	req.Header.Set("Accept", "application/dns-json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDoHResponseSize))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request returned status %d", resp.StatusCode)
	}

	return r.parseResponse(resp, escapedHost)
}

// parseResponse parses DoH response with size limits to prevent memory exhaustion.
//
// The parser is selected by the response Content-Type, not by provider name. Every
// request sends "Accept: application/dns-json", but a provider may answer with
// JSON (application/dns-json / application/json) or DNS wire format
// (application/dns-message / application/dns-wire). Name-based dispatch was
// fragile: a custom provider named like a built-in, or a built-in serving an
// unexpected content type, would hit the wrong parser (e.g. Cloudflare forced to
// wire format even when it served JSON for the requested Accept header). When the
// Content-Type is missing or unrecognized we try JSON (matching the Accept header)
// and fall back to wire format, so a misconfigured server still resolves.
func (r *DoHResolver) parseResponse(resp *http.Response, host string) ([]net.IPAddr, error) {
	// SECURITY: Limit response body size to prevent memory exhaustion attacks
	limitedReader := io.LimitReader(resp.Body, maxDoHResponseSize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("read response body failed: %w", err)
	}

	// SECURITY: Check if response exceeded size limit
	if len(body) > maxDoHResponseSize {
		return nil, fmt.Errorf("DoH response exceeds maximum size limit (%d bytes)", maxDoHResponseSize)
	}

	switch dohMediaType(resp.Header.Get("Content-Type")) {
	case "application/dns-json", "application/json":
		return r.parseJSONResponse(body, host)
	case "application/dns-message", "application/dns-wire":
		return r.parseWireFormatResponse(body, host)
	}

	// Unknown or missing Content-Type: try JSON (matches the Accept header we
	// sent) and fall back to wire format so a misconfigured server still
	// resolves. When both fail, report both clues instead of silently
	// discarding the JSON parse error.
	jsonIPs, jsonErr := r.parseJSONResponse(body, host)
	if jsonErr == nil {
		return jsonIPs, nil
	}
	wireIPs, wireErr := r.parseWireFormatResponse(body, host)
	if wireErr == nil {
		return wireIPs, nil
	}
	return nil, fmt.Errorf("unknown DoH response format (json: %w; wire: %w)", jsonErr, wireErr)
}

// dohMediaType extracts the media type from a Content-Type header value,
// lowercased and stripped of parameters (e.g. "application/json; charset=utf-8"
// becomes "application/json"). Returns "" for an empty/blank value.
func dohMediaType(contentType string) string {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

// parseJSONResponse parses JSON DoH response (Google and AliDNS format)
func (r *DoHResolver) parseJSONResponse(body []byte, host string) ([]net.IPAddr, error) {
	type DNSResponse struct {
		Status int `json:"Status"`
		Answer []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}

	var resp DNSResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse JSON failed: %w", err)
	}

	if resp.Status != 0 && resp.Status != 3 { // 0 = NOERROR, 3 = NXDOMAIN
		return nil, fmt.Errorf("DNS query returned status %d", resp.Status)
	}

	// BINDING: the first answer must answer the queried name. Without this
	// check a faulty or malicious endpoint could return another domain's
	// records and have them cached under this host.
	if len(resp.Answer) > 0 && !dnsNameEqual(resp.Answer[0].Name, host) {
		return nil, fmt.Errorf("response answers %q, not the queried host %q", resp.Answer[0].Name, host)
	}

	ips := make([]net.IPAddr, 0, 4)
	for _, answer := range resp.Answer {
		// Type 1 = A record (IPv4), Type 28 = AAAA record (IPv6)
		if answer.Type == 1 || answer.Type == 28 {
			ip := net.ParseIP(answer.Data)
			if ip != nil {
				ips = append(ips, net.IPAddr{
					IP:   ip,
					Zone: "",
				})
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found in response")
	}

	return ips, nil
}

// parseWireFormatResponse parses DNS wire format response (RFC 1035)
func (r *DoHResolver) parseWireFormatResponse(body []byte, host string) ([]net.IPAddr, error) {
	if len(body) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	// RCODE lives in the low nibble of byte 3. Non-zero codes (SERVFAIL,
	// REFUSED, ...) must surface as errors — otherwise they parse as empty
	// answers and mask the real failure. NXDOMAIN (3) is tolerated to match
	// the JSON parser, which maps it to "no IP addresses found".
	if rcode := body[3] & 0x0F; rcode != 0 && rcode != 3 {
		return nil, fmt.Errorf("DNS response RCODE %d (%s)", rcode, rcodeName(rcode))
	}

	// Skip header (12 bytes)
	offset := 12

	// Parse question section
	qdCount, err := getUint16(body[4:6])
	if err != nil {
		return nil, fmt.Errorf("invalid question count: %w", err)
	}
	for i := 0; i < int(qdCount); i++ {
		var err error
		_, offset, err = parseDomain(body, offset, 0)
		if err != nil {
			return nil, err
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Parse answer section
	anCount, err := getUint16(body[6:8])
	if err != nil {
		return nil, fmt.Errorf("invalid answer count: %w", err)
	}
	ips := make([]net.IPAddr, 0, 4)

	for i := 0; i < int(anCount); i++ {
		name, newOffset, err := parseDomain(body, offset, 0)
		if err != nil {
			// Surface the parse error instead of breaking out to the generic
			// "no IP addresses found in response" below: a truncated or
			// corrupt wire response deserves its actual diagnosis, and the
			// caller's fallback path logs it.
			return nil, fmt.Errorf("malformed answer name at %d: %w", offset, err)
		}
		offset = newOffset

		// BINDING: the first answer must answer the queried name (later
		// answers may legitimately belong to a CNAME chain). Without this
		// check a faulty or malicious endpoint could return another domain's
		// records and have them cached under this host.
		if i == 0 && !dnsNameEqual(name, host) {
			return nil, fmt.Errorf("response answers %q, not the queried host %q", name, host)
		}

		if offset+10 > len(body) {
			return nil, fmt.Errorf("truncated DNS answer record at offset %d", offset)
		}

		// TYPE, CLASS, TTL, RDLENGTH
		recordType := int(body[offset])<<8 | int(body[offset+1])
		rdLength := int(body[offset+8])<<8 | int(body[offset+9])
		offset += 10

		if offset+rdLength > len(body) {
			return nil, fmt.Errorf("DNS RDATA overruns response (offset %d, length %d, body %d)", offset, rdLength, len(body))
		}

		// Type 1 = A record (IPv4), Type 28 = AAAA record (IPv6)
		// Copy IP bytes to avoid aliasing the response body slice,
		// which would corrupt IP data if the body is GC'd or reused.
		if recordType == 1 && rdLength == 4 {
			ip := make(net.IP, 4)
			copy(ip, body[offset:offset+4])
			ips = append(ips, net.IPAddr{IP: ip, Zone: ""})
		} else if recordType == 28 && rdLength == 16 {
			ip := make(net.IP, 16)
			copy(ip, body[offset:offset+16])
			ips = append(ips, net.IPAddr{IP: ip, Zone: ""})
		}

		offset += rdLength
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found in response")
	}

	return ips, nil
}

// dnsNameEqual compares DNS names case-insensitively (RFC 1035 §2.3.3),
// tolerating the optional trailing root dot.
func dnsNameEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// rcodeName maps common DNS RCODEs (RFC 1035 §4.1.1, RFC 8914) to their
// mnemonic for clearer error messages.
func rcodeName(rcode byte) string {
	switch rcode {
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return "UNKNOWN"
	}
}

// maxDomainRecursion limits the depth of DNS compression pointer recursion
// to prevent stack overflow from malicious responses with circular pointers.
// RFC 1035 allows compression, but malformed responses could exploit this.
// 16 handles legitimate deeply nested compression while preventing stack overflow.
const maxDomainRecursion = 16

// parseDomain parses a DNS domain name (RFC 1035) with recursion depth limit.
// The depth parameter tracks the current recursion depth to prevent stack overflow
// from malicious DNS responses with circular or deeply nested compression pointers.
func parseDomain(msg []byte, offset int, depth int) (string, int, error) {
	// SECURITY: Check recursion depth to prevent stack overflow from circular pointers
	if depth > maxDomainRecursion {
		return "", offset, fmt.Errorf("compression pointer depth exceeded (max %d)", maxDomainRecursion)
	}

	if offset >= len(msg) {
		return "", offset, fmt.Errorf("offset out of bounds")
	}

	var labels []string
	originalOffset := offset

	for {
		if offset >= len(msg) {
			return "", originalOffset, fmt.Errorf("invalid domain name")
		}

		length := int(msg[offset])
		offset++

		if length == 0 {
			break
		}

		// Check for compression pointer
		if length >= 192 {
			if offset >= len(msg) {
				return "", originalOffset, fmt.Errorf("invalid compression pointer")
			}
			pointer := int(length&0x3F)<<8 | int(msg[offset])
			offset++

			// SECURITY: Pass incremented depth to recursive call
			compressedName, _, err := parseDomain(msg, pointer, depth+1)
			if err != nil {
				return "", originalOffset, err
			}
			labels = append(labels, compressedName)
			break
		}

		if offset+length > len(msg) {
			return "", originalOffset, fmt.Errorf("label exceeds message length")
		}

		labels = append(labels, string(msg[offset:offset+length]))
		offset += length
	}

	// Use strings.Join for O(n) allocation instead of O(n²) iterative concatenation
	return strings.Join(labels, "."), offset, nil
}

// getUint16 parses a big-endian 16-bit unsigned integer
func getUint16(b []byte) (uint16, error) {
	if len(b) < 2 {
		return 0, fmt.Errorf("buffer too short")
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

// fallbackLookupTimeout bounds the system-resolver fallback when the caller's
// context carries no deadline. The DoH providers have already spent up to
// ~10s (5s HTTP timeout × sequential providers × 2 record types); handing a
// deadline-less context to the system resolver can stall the dial far beyond
// DialTimeout. Mirrors the 10s cap the non-DoH dialer path applies to DNS
// (connection/pool.go resolveAndValidateAddress) so both resolution paths
// have consistent worst-case behavior.
const fallbackLookupTimeout = 10 * time.Second

// fallbackLookup falls back to system DNS resolver
func (r *DoHResolver) fallbackLookup(ctx context.Context, host string, lastErr error) ([]net.IPAddr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, fallbackLookupTimeout)
		defer cancel()
	}
	// Use system resolver as fallback
	systemResolver := net.DefaultResolver
	ips, err := systemResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DoH and system lookup both failed: %w", errors.Join(err, lastErr))
	}
	return ips, nil
}

// ClearCache clears the DNS cache.
// Deletes all entries and atomically resets the counter to zero.
//
// The final recount is approximate under concurrency: an entry admitted
// between the counting Range and the Store can leave the counter slightly
// below the true size, so the cache may transiently exceed maxDoHCacheSize by
// the number of concurrent admissions. The overshoot is bounded by caller
// concurrency (never unbounded) and self-corrects at the next admission check,
// which re-reads and evicts.
func (r *DoHResolver) ClearCache() {
	r.cache.Range(func(key, value any) bool {
		if _, ok := r.cache.LoadAndDelete(key); ok {
			r.cacheSize.Add(-1)
		}
		return true
	})
	// Reconcile counter: concurrent eviction may have decremented entries
	// we already deleted, or new entries may have been inserted during the scan.
	// Loading the actual count ensures the counter never goes negative.
	// (See the doc comment above for the bounded under-count race this leaves.)
	count := int64(0)
	r.cache.Range(func(_, _ any) bool {
		count++
		return true
	})
	r.cacheSize.Store(count)
}

// evictExpiredEntries removes expired cache entries to free space.
// Called proactively when the cache is full to avoid discarding fresh results.
func (r *DoHResolver) evictExpiredEntries() {
	now := time.Now()
	r.cache.Range(func(key, value any) bool {
		if entry, ok := value.(*cacheEntry); ok && entry != nil {
			if now.After(entry.Expires) {
				if _, deleted := r.cache.LoadAndDelete(key); deleted {
					r.cacheSize.Add(-1)
				}
			}
		}
		return true
	})
}

// evictOldestEntry removes the cache entry with the nearest expiry time.
// Used when the cache is full of fresh (unexpired) entries and a new entry
// must be admitted; without it, freshly resolved hosts are silently dropped
// once the cache fills with long-TTL entries. O(n), but only runs on admission
// when the working set exceeds maxDoHCacheSize.
func (r *DoHResolver) evictOldestEntry() {
	var oldestKey any
	var oldestExpiry time.Time
	found := false
	r.cache.Range(func(key, value any) bool {
		entry, ok := value.(*cacheEntry)
		if !ok || entry == nil {
			return true
		}
		if !found || entry.Expires.Before(oldestExpiry) {
			found = true
			oldestKey = key
			oldestExpiry = entry.Expires
		}
		return true
	})
	if found {
		if _, deleted := r.cache.LoadAndDelete(oldestKey); deleted {
			r.cacheSize.Add(-1)
		}
	}
}

// SetCacheTTL sets the cache TTL duration.
// Thread-safe: can be called concurrently with other operations.
func (r *DoHResolver) SetCacheTTL(ttl time.Duration) {
	r.cacheTTL.Store(int64(ttl))
	r.ClearCache()
}

// GetCacheTTL returns the current cache TTL duration.
// Thread-safe: can be called concurrently with other operations.
func (r *DoHResolver) GetCacheTTL() time.Duration {
	return time.Duration(r.cacheTTL.Load())
}

// Close releases resources held by the DoHResolver.
// It closes idle connections in the internal HTTP client's transport.
// Safe to call multiple times - subsequent calls are no-ops.
// Implements io.Closer for consistent resource management.
func (r *DoHResolver) Close() error {
	// Use CompareAndSwap to ensure we only close once
	if !r.closed.CompareAndSwap(false, true) {
		return nil // Already closed
	}

	// Close idle connections in the transport
	if r.client != nil {
		if transport, ok := r.client.Transport.(*http.Transport); ok && transport != nil {
			transport.CloseIdleConnections()
		}
	}

	// Clear the cache to release memory
	r.ClearCache()

	return nil
}
