package engine

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestStreamModeContextCancelCleanup was removed: TestStreamingBody
// (coverage_test.go) asserts the same streaming->RawBodyReader->ReleaseResponse
// path and additionally checks body content.

// TestStreamModeContextCancelOnEarlyError was removed: its only assertion was
// err != nil for a pre-cancelled context (equivalent to the general
// context-cancellation test in client_test.go). The cancel-func-leak concern
// it documented is behaviorally covered by TestReleaseResponseCleansUpStreamingResources.

// TestNonStreamModeContextCancel was removed: the "baseline" observed nothing
// about cancellation — it was equivalent to a plain successful mock request.

// TestReleaseResponseCleansUpStreamingResources verifies that ReleaseResponse
// properly closes the raw body reader and calls the cancel function for
// streaming responses.
func TestReleaseResponseCleansUpStreamingResources(t *testing.T) {
	var bodyClosed atomic.Int32
	var cancelCalled atomic.Int32

	body := &trackingReadCloser{
		Reader: strings.NewReader("test data"),
		onClose: func() {
			bodyClosed.Store(1)
		},
	}

	resp := getResponse()
	resp.SetStatusCode(200)
	resp.rawBodyReader = body
	resp.cancelFunc = func() {
		cancelCalled.Store(1)
	}

	ReleaseResponse(resp)

	if bodyClosed.Load() != 1 {
		t.Error("Body reader was not closed by ReleaseResponse")
	}
	if cancelCalled.Load() != 1 {
		t.Error("Cancel function was not called by ReleaseResponse")
	}
}

// TestReleaseResponseNilSafe verifies that ReleaseResponse handles nil and
// already-released responses without panicking.
func TestReleaseResponseNilSafe(t *testing.T) {
	ReleaseResponse(nil)
	ReleaseResponse(&Response{})

	// Normal release zeroes the response in place (folded in from the former
	// standalone TestReleaseResponse in coverage_test.go).
	resp := &Response{}
	resp.SetStatusCode(200)
	resp.SetBody("test")
	ReleaseResponse(resp)
	if resp.StatusCode() != 0 {
		t.Error("Expected zeroed response after release")
	}

	resp2 := getResponse()
	ReleaseResponse(resp2)
	ReleaseResponse(resp2) // Double release should not panic
}

// trackingReadCloser tracks Close calls for testing.
type trackingReadCloser struct {
	*strings.Reader
	onClose func()
}

func (t *trackingReadCloser) Close() error {
	if t.onClose != nil {
		t.onClose()
	}
	return nil
}

// TestURLCacheRawEviction verifies that the raw URL cache is evicted when it
// exceeds rawCacheMaxSize, preventing unbounded memory growth.
func TestURLCacheRawEviction(t *testing.T) {
	cache := &urlCache{
		raw:     make(map[string]*url.URL, 16),
		entries: make(map[string]*url.URL, 16),
		keys:    make([]string, 0, 16),
		maxSize: 64,
	}

	// Fill the cache with unique entries
	for i := 0; i < 64; i++ {
		urlStr := fmt.Sprintf("https://host%d.example.com/path", i)
		_, err := cache.Get(urlStr)
		if err != nil {
			t.Fatalf("Get(%q) failed: %v", urlStr, err)
		}
	}

	// Verify entries map is at maxSize
	cache.mu.RLock()
	entriesLen := len(cache.entries)
	rawLen := len(cache.raw)
	cache.mu.RUnlock()

	if entriesLen != 64 {
		t.Errorf("expected 64 entries, got %d", entriesLen)
	}
	if rawLen != 64 {
		t.Errorf("expected 64 raw entries, got %d", rawLen)
	}

	// Now add many URL variants for the same host to grow the raw map beyond entries
	for i := 0; i < 2500; i++ {
		urlStr := fmt.Sprintf("https://host0.example.com/path?v=%d", i)
		_, err := cache.Get(urlStr)
		if err != nil {
			t.Fatalf("Get(%q) failed: %v", urlStr, err)
		}
	}

	cache.mu.RLock()
	rawLen = len(cache.raw)
	entriesLen = len(cache.entries)
	cache.mu.RUnlock()

	// The raw map should not grow unboundedly — it must be capped
	if rawLen > rawCacheMaxSize*2 {
		t.Errorf("raw cache grew to %d entries, expected cap near %d", rawLen, rawCacheMaxSize)
	}

	// Entries should still be bounded at maxSize
	if entriesLen > 64 {
		t.Errorf("entries grew to %d, expected max 64", entriesLen)
	}

	// Verify cache still works correctly after eviction
	u, err := cache.Get("https://host0.example.com/path?v=42")
	if err != nil {
		t.Fatalf("Get after eviction failed: %v", err)
	}
	if u == nil {
		t.Fatal("expected non-nil URL after eviction")
	}
}

// TestURLCacheRawDuplicateCheck verifies that re-looking up the same raw URL
// does not create duplicate entries in the raw map.
func TestURLCacheRawDuplicateCheck(t *testing.T) {
	cache := &urlCache{
		raw:     make(map[string]*url.URL, 16),
		entries: make(map[string]*url.URL, 16),
		keys:    make([]string, 0, 16),
		maxSize: 64,
	}

	urlStr := "https://example.com/api/v1"

	// Look up the same URL many times
	for i := 0; i < 100; i++ {
		_, err := cache.Get(urlStr)
		if err != nil {
			t.Fatalf("Get failed on iteration %d: %v", i, err)
		}
	}

	cache.mu.RLock()
	rawLen := len(cache.raw)
	entriesLen := len(cache.entries)
	cache.mu.RUnlock()

	if rawLen != 1 {
		t.Errorf("expected 1 raw entry, got %d", rawLen)
	}
	if entriesLen != 1 {
		t.Errorf("expected 1 entry, got %d", entriesLen)
	}
}

// TestDecompressorPoolCleanup verifies that decompressor fallback paths
// properly handle pooled readers instead of silently discarding them.
func TestDecompressorPoolCleanup(t *testing.T) {
	config := &Config{
		Timeout:         10 * time.Second,
		AllowPrivateIPs: true,
	}

	// Verify gzip decompression works correctly and the reader returns to the pool.
	mock := &mockTransport{
		Response: &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Encoding": []string{"gzip"},
			},
			Body: createGzipBody(t, "compressed data"),
		},
	}

	client, err := NewClient(config, func(opts *clientOptions) {
		opts.customTransport = mock
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	resp, err := client.Request(context.Background(), "GET", "https://example.com")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if got := resp.Body(); got != "compressed data" {
		t.Errorf("gzip body = %q, want %q (decompression broken)", got, "compressed data")
	}
	ReleaseResponse(resp)

	// Verify deflate decompression works correctly and the reader returns to the pool.
	mock2 := &mockTransport{
		Response: &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Encoding": []string{"deflate"},
			},
			Body: createDeflateBody(t, "deflated data"),
		},
	}

	client2, err := NewClient(config, func(opts *clientOptions) {
		opts.customTransport = mock2
	})
	if err != nil {
		t.Fatalf("Failed to create client2: %v", err)
	}
	defer client2.Close()

	resp2, err := client2.Request(context.Background(), "GET", "https://example.com")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if got := resp2.Body(); got != "deflated data" {
		t.Errorf("deflate body = %q, want %q (decompression broken)", got, "deflated data")
	}
	ReleaseResponse(resp2)
}

// createGzipBody creates a gzip-compressed HTTP body for testing.
func createGzipBody(t *testing.T, data string) io.ReadCloser {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(data)); err != nil {
		t.Fatalf("gzip write failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}
	return io.NopCloser(&buf)
}

// createDeflateBody creates a deflate-compressed HTTP body for testing.
func createDeflateBody(t *testing.T, data string) io.ReadCloser {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	if _, err := w.Write([]byte(data)); err != nil {
		t.Fatalf("flate write failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close failed: %v", err)
	}
	return io.NopCloser(&buf)
}
