package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		request *Request
		wantErr bool
	}{
		{
			name: "Valid request",
			request: testRequestBuilder().
				Method("GET").
				URL("https://example.com").
				Headers(make(map[string]string)).
				QueryParams(make(map[string]any)).
				Context(context.Background()).
				Build(),
			wantErr: false,
		},
		{
			name: "Empty method",
			request: testRequestBuilder().
				Method("").
				URL("https://example.com").
				Context(context.Background()).
				Build(),
			wantErr: false, // Should default to GET
		},
		{
			name: "Empty URL",
			request: testRequestBuilder().
				Method("GET").
				URL("").
				Context(context.Background()).
				Build(),
			wantErr: true,
		},
		{
			name: "Nil context",
			request: testRequestBuilder().
				Method("GET").
				URL("https://example.com").
				Build(),
			wantErr: false, // Should use background context
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.request.Method() == "" {
				tt.request.SetMethod("GET")
			}
			if tt.request.Context() == nil {
				tt.request.SetContext(context.Background())
			}

			hasURL := tt.request.URL() != ""
			if tt.wantErr && hasURL {
				t.Errorf("expected error case %q should have empty URL", tt.name)
			}
			if !tt.wantErr && !hasURL {
				t.Errorf("non-error case %q should have a URL", tt.name)
			}
		})
	}
}

func TestRequest_WithTimeout(t *testing.T) {
	req := testRequestBuilder().
		Method("GET").
		URL("https://example.com").
		Timeout(5 * time.Second).
		Context(context.Background()).
		Build()

	if req.Timeout() != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", req.Timeout())
	}
}

func TestRequest_WithHeaders(t *testing.T) {
	req := testRequestBuilder().
		Method("GET").
		URL("https://example.com").
		Headers(map[string]string{
			"Authorization": "Bearer token",
			"Content-Type":  "application/json",
		}).
		Context(context.Background()).
		Build()

	if req.Headers()["Authorization"] != "Bearer token" {
		t.Error("Authorization header not set correctly")
	}

	if req.Headers()["Content-Type"] != "application/json" {
		t.Error("Content-Type header not set correctly")
	}
}

func TestRequest_WithQueryParams(t *testing.T) {
	req := testRequestBuilder().
		Method("GET").
		URL("https://example.com").
		QueryParams(map[string]any{
			"page":  1,
			"limit": 10,
			"sort":  "name",
		}).
		Context(context.Background()).
		Build()

	if req.QueryParams()["page"] != 1 {
		t.Error("Page query param not set correctly")
	}

	if req.QueryParams()["limit"] != 10 {
		t.Error("Limit query param not set correctly")
	}

	if req.QueryParams()["sort"] != "name" {
		t.Error("Sort query param not set correctly")
	}
}

func TestRequest_WithCookies(t *testing.T) {
	cookies := []http.Cookie{
		{Name: "session", Value: "abc123"},
		{Name: "theme", Value: "dark"},
	}

	req := testRequestBuilder().
		Method("GET").
		URL("https://example.com").
		Cookies(cookies).
		Context(context.Background()).
		Build()

	if len(req.Cookies()) != 2 {
		t.Errorf("Expected 2 cookies, got %d", len(req.Cookies()))
	}

	reqCookies := req.Cookies()
	if reqCookies[0].Name != "session" || reqCookies[0].Value != "abc123" {
		t.Error("Session cookie not set correctly")
	}
}

func TestRequest_WithBody(t *testing.T) {
	testBody := map[string]string{"key": "value"}

	req := testRequestBuilder().
		Method("POST").
		URL("https://example.com").
		Body(testBody).
		Context(context.Background()).
		Build()

	if req.Body() == nil {
		t.Error("Request body should not be nil")
	}

	bodyMap, ok := req.Body().(map[string]string)
	if !ok {
		t.Error("Request body should be map[string]string")
	}

	if bodyMap["key"] != "value" {
		t.Error("Request body not set correctly")
	}
}

func TestRequest_WithMaxRetries(t *testing.T) {
	req := testRequestBuilder().
		Method("GET").
		URL("https://example.com").
		MaxRetries(3).
		Context(context.Background()).
		Build()

	if req.MaxRetries() != 3 {
		t.Errorf("Expected MaxRetries 3, got %d", req.MaxRetries())
	}
}

func TestRequest_Clone(t *testing.T) {
	original := testRequestBuilder().
		Method("POST").
		URL("https://example.com").
		Headers(map[string]string{
			"Content-Type": "application/json",
		}).
		QueryParams(map[string]any{
			"test": "value",
		}).
		Body(map[string]string{"key": "value"}).
		Timeout(10 * time.Second).
		MaxRetries(2).
		Context(context.Background()).
		Cookies([]http.Cookie{
			{Name: "test", Value: "cookie"},
		}).
		Build()

	// Test that modifying headers doesn't affect original
	headers := original.Headers()
	if headers == nil {
		headers = make(map[string]string)
		original.SetHeaders(headers)
	}
	headers["New-Header"] = "new-value"

	if original.Headers()["New-Header"] != "new-value" {
		t.Error("Header modification failed")
	}

	if original.Headers()["Content-Type"] != "application/json" {
		t.Error("Original header was modified")
	}
}

// TestURLCache_EvictRawIfNeeded covers the raw-cache eviction logic
// (request.go:278): when the raw map reaches rawCacheMaxSize, entries whose
// parsed URL no longer appears in the sanitized entries map are removed until
// the size drops below rawCacheMaxSize/2. A local urlCache is used so the
// process-wide globalURLCache is untouched.
func TestURLCache_EvictRawIfNeeded(t *testing.T) {
	c := &urlCache{
		raw:     make(map[string]*url.URL, rawCacheMaxSize+1),
		entries: make(map[string]*url.URL, 1),
		maxSize: 1024,
	}

	// One "live" entry: present in both raw and entries (same pointer).
	liveURL := &url.URL{Path: "/live"}
	c.entries["sanitized-live"] = liveURL
	c.raw["http://example.com/0"] = liveURL

	// Fill the rest with "stale" entries whose pointers are NOT in entries,
	// pushing len(raw) past rawCacheMaxSize so eviction triggers.
	for i := 1; i <= rawCacheMaxSize; i++ {
		key := fmt.Sprintf("http://example.com/%d", i)
		c.raw[key] = &url.URL{Path: fmt.Sprintf("/stale-%d", i)}
	}
	if len(c.raw) < rawCacheMaxSize {
		t.Fatalf("setup error: raw cache not over threshold, len=%d", len(c.raw))
	}

	c.evictRawIfNeeded()

	// The live entry is always retained (its pointer is found in entries).
	if _, ok := c.raw["http://example.com/0"]; !ok {
		t.Error("live entry should be retained after eviction")
	}
	// Eviction must have reduced the raw cache below the threshold.
	if len(c.raw) >= rawCacheMaxSize {
		t.Errorf("eviction did not reduce raw cache: len=%d (threshold %d)",
			len(c.raw), rawCacheMaxSize)
	}
}

// TestURLCache_EvictRaw_NoopBelowThreshold confirms eviction is a no-op when
// the raw cache is under rawCacheMaxSize.
func TestURLCache_EvictRaw_NoopBelowThreshold(t *testing.T) {
	c := &urlCache{
		raw:     map[string]*url.URL{"http://example.com/a": {Path: "/a"}},
		entries: map[string]*url.URL{},
		maxSize: 1024,
	}
	c.evictRawIfNeeded()
	if len(c.raw) != 1 {
		t.Errorf("eviction should be a no-op below threshold, got len=%d", len(c.raw))
	}
}

// TestURLCache_PopulateRawCache covers the lazy-init (nil raw) branch and the
// existing-key no-op of populateRawCache (request.go:393).
func TestURLCache_PopulateRawCache(t *testing.T) {
	c := &urlCache{
		entries: make(map[string]*url.URL),
		keys:    []string{},
		maxSize: 1024,
		// raw intentionally nil → exercises the lazy-init branch.
	}
	parsed := &url.URL{Path: "/x"}
	c.populateRawCache("http://example.com/x", parsed)
	if c.raw == nil || c.raw["http://example.com/x"] != parsed {
		t.Error("populateRawCache did not lazily init raw and store the entry")
	}
	// Re-populating an existing key is a no-op (no duplicate, no eviction).
	c.populateRawCache("http://example.com/x", parsed)
	if len(c.raw) != 1 {
		t.Errorf("duplicate populate should be a no-op, got len=%d", len(c.raw))
	}
}

// TestURLCache_EvictOldest covers the entries-LRU eviction (request.go:419):
// when entries exceed maxSize the oldest key is dropped, its raw entry is
// cleaned up, and the keys slice is advanced.
func TestURLCache_EvictOldest(t *testing.T) {
	oldest := &url.URL{Path: "/oldest"}
	newest := &url.URL{Path: "/newest"}
	c := &urlCache{
		entries: map[string]*url.URL{"k1": oldest, "k2": newest},
		raw: map[string]*url.URL{
			"http://example.com/oldest": oldest,
			"http://example.com/newest": newest,
		},
		keys:    []string{"k1", "k2"},
		maxSize: 1, // tiny so eviction triggers with two entries
	}

	c.evictOldest()

	if _, ok := c.entries["k1"]; ok {
		t.Error("oldest entry (k1) should be evicted")
	}
	if _, ok := c.entries["k2"]; !ok {
		t.Error("newest entry (k2) should be retained")
	}
	if _, ok := c.raw["http://example.com/oldest"]; ok {
		t.Error("raw entry for the evicted URL should be removed")
	}
	if _, ok := c.raw["http://example.com/newest"]; !ok {
		t.Error("raw entry for the retained URL should remain")
	}
	if len(c.keys) != 1 || c.keys[0] != "k2" {
		t.Errorf("keys slice should advance to [k2], got %v", c.keys)
	}
}

// TestRequest_AccessorRoundTrip locks the round-trip contract of the small
// Request accessors/mutators that are not exercised elsewhere
// (SanitizedURL/SetSanitizedURL, EnsureQueryParams lazy-init + identity,
// SetAllowPrivateIPs). Consolidated into one test to avoid accessor sprawl.
func TestRequest_AccessorRoundTrip(t *testing.T) {
	r := &Request{maxRetries: maxRetriesUnset}

	r.SetSanitizedURL("https://sanitized.example.com/x")
	if r.SanitizedURL() != "https://sanitized.example.com/x" {
		t.Errorf("SanitizedURL round-trip failed: %q", r.SanitizedURL())
	}

	// EnsureQueryParams lazily allocates a pooled map and returns the SAME
	// map on subsequent calls.
	qp := r.EnsureQueryParams()
	if qp == nil {
		t.Fatal("EnsureQueryParams returned nil")
	}
	qp["page"] = 1
	if r.EnsureQueryParams()["page"] != 1 {
		t.Error("EnsureQueryParams should return the same map instance")
	}

	// AllowPrivateIPs override round-trips through the *bool pointer.
	allow := true
	r.SetAllowPrivateIPs(&allow)
	if r.AllowPrivateIPs() == nil || *r.AllowPrivateIPs() != true {
		t.Error("SetAllowPrivateIPs round-trip failed")
	}
}
