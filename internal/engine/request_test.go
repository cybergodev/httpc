package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestRequest_Validation was removed: it never invoked any validation —
// it compared builder-set values back against the table that supplied
// them (wantErr was decorative). Real validation paths are exercised in
// request_processor_test.go and the client option tests.

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
	// evictOldest no longer scans the raw map: an orphaned raw entry is a
	// still-correct parse of its key and is reclaimed by evictRawIfNeeded
	// once the raw map exceeds its cap. Verify both raw entries survive here.
	if _, ok := c.raw["http://example.com/oldest"]; !ok {
		t.Error("orphaned raw entry for the evicted URL may remain until evictRawIfNeeded runs")
	}
	if _, ok := c.raw["http://example.com/newest"]; !ok {
		t.Error("raw entry for the retained URL should remain")
	}
	if len(c.keys) != 1 || c.keys[0] != "k2" {
		t.Errorf("keys slice should advance to [k2], got %v", c.keys)
	}

	// populateRawCacheLocked must lazily initialize a nil raw map, and an
	// existing key must be a no-op (no overwrite). Covers the branches that
	// formerly relied on the removed TestURLCache_Eviction.
	u := &url.URL{Path: "/x"}
	c2 := &urlCache{
		entries: map[string]*url.URL{"k": u},
		keys:    []string{"k"},
		maxSize: 4,
		// raw intentionally nil
	}
	c2.populateRawCacheLocked("http://example.com/x", u)
	if c2.raw == nil || c2.raw["http://example.com/x"] != u {
		t.Error("populateRawCacheLocked should lazily create the raw map and insert")
	}
	c2.populateRawCacheLocked("http://example.com/x", &url.URL{Path: "/other"})
	if c2.raw["http://example.com/x"] != u {
		t.Error("populateRawCacheLocked must not overwrite an existing raw entry")
	}

	// The keys-slice compaction branch: after eviction leaves a slice whose
	// capacity is more than double its length, the backing array is shrunk.
	big := &url.URL{Path: "/big"}
	c3 := &urlCache{
		entries: map[string]*url.URL{"k": big},
		keys:    append(make([]string, 0, 16), "k"), // cap 16 >> len 1
		maxSize: 1,
	}
	c3.evictOldest()
	if _, ok := c3.entries["k"]; ok {
		t.Error("entry should be evicted at maxSize")
	}
	if cap(c3.keys) > 2*len(c3.keys) {
		t.Errorf("keys backing array should be shrunk, cap=%d len=%d", cap(c3.keys), len(c3.keys))
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

// ---------------------------------------------------------------------------
// Cookie header sanitization (request.go)
// ---------------------------------------------------------------------------

// TestSanitizeCookieNameValue pins the Cookie header-injection defenses:
// CR/LF stripped from names, and invalid value bytes (quote, semicolon,
// backslash, control, non-ASCII) octal-escaped exactly like net/http.
func TestSanitizeCookieNameValue(t *testing.T) {
	t.Run("sanitizeCookieName", func(t *testing.T) {
		tests := []struct {
			name, in, want string
		}{
			{"clean name passthrough", "session", "session"},
			{"strip LF", "bad\nname", "badname"},
			{"strip CR", "bad\rname", "badname"},
			{"strip both", "a\r\nb", "ab"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := sanitizeCookieName(tt.in); got != tt.want {
					t.Errorf("sanitizeCookieName(%q) = %q, want %q", tt.in, got, tt.want)
				}
			})
		}
	})

	t.Run("sanitizeCookieValue", func(t *testing.T) {
		tests := []struct {
			name, in, want string
		}{
			{"clean value passthrough (fast path)", "abc123", "abc123"},
			{"printable specials excepted stay clean", "a:b/c?d#e", "a:b/c?d#e"},
			{"quote escaped", "a\"b", "a\\042b"},
			{"semicolon escaped", "a;b", "a\\073b"},
			{"backslash escaped", "a\\b", "a\\134b"},
			{"control byte escaped", "a\x01b", "a\\001b"},
			{"non-ASCII escaped as UTF-8 byte pair (slow path)", "a\u00e4b", "a\\303\\244b"},
			{"invalid at start", "\x00x", "\\000x"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := sanitizeCookieValue(tt.in); got != tt.want {
					t.Errorf("sanitizeCookieValue(%q) = %q, want %q", tt.in, got, tt.want)
				}
			})
		}
	})
}

// TestPooledStringsReader_NoReleaseOnEOF pins the release discipline of the
// request-body reader wrappers: the pool return must happen ONLY in Close,
// never at EOF in Read. net/http reads the body to EOF and closes it later
// (on HTTP/2, from the writeLoop goroutine); releasing at EOF would put the
// wrapper back in the pool while a delayed Close can still arrive, and after
// another request recycles the wrapper that stale Close would release the
// new request's live reader.
func TestPooledStringsReader_NoReleaseOnEOF(t *testing.T) {
	r := getPooledStringsReader("hello world")
	pr := r.(*pooledStringsReader)

	if _, err := io.ReadAll(pr); err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if pr.released {
		t.Fatal("reader released at EOF: release must happen only in Close")
	}

	_ = pr.Close()
	if !pr.released {
		t.Fatal("Close did not release the reader back to the pool")
	}
}

// TestBuild_MultipartCRLFInjectionRejected verifies that control characters
// in multipart field names, filenames, and per-file Content-Types are
// rejected at the encoding sink. *FormData is a public struct constructible
// without going through WithFile's validation, and mime/multipart.Writer
// writes Content-Disposition values verbatim — CRLF in a token would inject
// arbitrary MIME headers/parts into the outgoing body.
func TestBuild_MultipartCRLFInjectionRejected(t *testing.T) {
	tests := []struct {
		name    string
		fields  map[string]string
		files   map[string]*fileDataHelper
		wantErr bool
	}{
		{
			name:    "CRLF in field name",
			fields:  map[string]string{"field\r\nX-Injected: 1": "v"},
			wantErr: true,
		},
		{
			name:   "CRLF in field value is legal (part body, not a header)",
			fields: map[string]string{"note": "line1\r\nline2"},
			files:  map[string]*fileDataHelper{},
		},
		{
			name:    "CRLF in filename",
			files:   map[string]*fileDataHelper{"f": {Filename: "a\"\r\nX-Injected: 1\r\n.txt", Content: []byte("x")}},
			wantErr: true,
		},
		{
			name:    "CRLF in file field name",
			files:   map[string]*fileDataHelper{"f\r\nX-Injected: 1": {Filename: "a.txt", Content: []byte("x")}},
			wantErr: true,
		},
		{
			name:    "CRLF in file Content-Type",
			files:   map[string]*fileDataHelper{"f": {Filename: "a.txt", Content: []byte("x"), ContentType: "text/plain\r\nX-Injected: 1"}},
			wantErr: true,
		},
		{
			name:    "NUL in filename",
			files:   map[string]*fileDataHelper{"f": {Filename: "a\x00.txt", Content: []byte("x")}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fields map[string]string
			if tt.fields != nil {
				fields = tt.fields
			}
			formData := formDataHelper(fields, tt.files)
			req := testRequestBuilder().
				Method("POST").
				URL("https://api.example.com/upload").
				Context(context.Background()).
				Body(formData).
				Build()

			httpReq, err := newRequestProcessor(&Config{Timeout: 30 * time.Second}).Build(req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Build() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				bodyBytes, readErr := io.ReadAll(httpReq.Body)
				if readErr != nil {
					t.Fatalf("read body: %v", readErr)
				}
				if strings.Contains(string(bodyBytes), "X-Injected") {
					t.Fatalf("injection leaked into multipart body:\n%s", bodyBytes)
				}
			}
		})
	}
}
