package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestReadBody_TruncatedBodyIsError is a regression test for the fast-path
// readBody bug: a server that declares Content-Length but closes the
// connection after sending fewer bytes used to produce a "successful"
// response with the partial body when StrictContentLength was disabled
// (e.g. PerformanceConfig). The slow path already surfaced this as an error;
// the fast path must behave the same.
func TestReadBody_TruncatedBodyIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short")) // 5 of 100 declared bytes, then close
	}))
	defer srv.Close()

	cfg := &Config{
		Timeout:             5 * 1e9,
		ValidateURL:         true,
		AllowPrivateIPs:     true,
		StrictContentLength: false, // must not matter — truncation is an error per se
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// Small declared length exercises the pre-sized fast path in readBody.
	if _, err := client.Request(backgroundCtx, "GET", srv.URL); err == nil {
		t.Fatal("expected error for truncated response body, got nil")
	}

	// A declared length above maxBufferSize (512KB) exercises the buffered
	// slow path and must keep failing as before.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1048576")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
	}))
	defer srv2.Close()
	if _, err := client.Request(backgroundCtx, "GET", srv2.URL); err == nil {
		t.Fatal("expected error for truncated large response body, got nil")
	}
}

// TestReadBody_HeadRequestKeepsEmptyBody guards the one legitimate case the
// truncation fix must preserve: HEAD responses carry a declared
// Content-Length but no body, which reads as (0, io.EOF).
func TestReadBody_HeadRequestKeepsEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &Config{Timeout: 5 * 1e9, ValidateURL: true, AllowPrivateIPs: true}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	resp, err := client.Request(backgroundCtx, "HEAD", srv.URL)
	if err != nil {
		t.Fatalf("HEAD request failed: %v", err)
	}
	if got := len(resp.RawBody()); got != 0 {
		t.Fatalf("HEAD body should be empty, got %d bytes", got)
	}
}

// TestAppendQueryParams_DeterministicOrder guards the sorted-key contract of
// appendQueryParams: identical maps must encode to identical strings.
func TestAppendQueryParams_DeterministicOrder(t *testing.T) {
	a := map[string]any{"z": 1, "a": 2, "m": "x", "0": true}
	b := map[string]any{"0": true, "m": "x", "a": 2, "z": 1}
	s1 := appendQueryParams("", a)
	s2 := appendQueryParams("", b)
	if s1 != s2 {
		t.Fatalf("same params encoded differently: %q vs %q", s1, s2)
	}
	// Merging into an existing query must also be sorted after the existing part.
	merged := appendQueryParams("keep=1", a)
	want := "keep=1&0=true&a=2&m=x&z=1"
	if merged != want {
		t.Fatalf("merged query = %q, want %q", merged, want)
	}
}
