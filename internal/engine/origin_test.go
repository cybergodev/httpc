package engine

import (
	"net/http"
	"net/url"
	"testing"
)

// TestSameOrigin covers the RFC 6454 origin comparison used by checkRedirect
// to decide when sensitive headers are stripped: scheme, host, and effective
// port, with scheme-default ports normalized.
func TestSameOrigin(t *testing.T) {
	t.Parallel()

	parse := func(raw string) *url.URL {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		return u
	}

	cases := []struct {
		name         string
		from, to     string
		sameOriginOK bool
	}{
		{"identical", "http://example.com/a", "http://example.com/b", true},
		{"default port explicit", "http://example.com", "http://example.com:80", true},
		{"https default port explicit", "https://example.com", "https://example.com:443", true},
		{"port change", "http://example.com", "http://example.com:8080", false},
		{"port change explicit to default", "https://example.com:443", "https://example.com:8443", false},
		{"https to http same host", "https://example.com", "http://example.com", false},
		{"http to https same host", "http://example.com", "https://example.com", false},
		{"hostname change", "http://example.com", "http://evil.example", false},
		{"case-insensitive host and scheme", "HTTP://EXAMPLE.com", "http://example.com", true},
		{"different host same port", "http://a.example:9000", "http://b.example:9000", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := sameOrigin(parse(tc.from), parse(tc.to)); got != tc.sameOriginOK {
				t.Errorf("sameOrigin(%q, %q) = %v, want %v", tc.from, tc.to, got, tc.sameOriginOK)
			}
		})
	}
}

// TestIsIdempotentMethod covers the retry idempotency classification:
// RFC 9110 §9.2.1 idempotent methods plus the fail-safe default for anything
// else (POST, PATCH, custom methods).
func TestIsIdempotentMethod(t *testing.T) {
	t.Parallel()

	idempotent := []string{
		http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace,
		http.MethodPut, http.MethodDelete,
	}
	for _, m := range idempotent {
		if !isIdempotentMethod(m) {
			t.Errorf("isIdempotentMethod(%q) = false, want true", m)
		}
	}

	nonIdempotent := []string{http.MethodPost, http.MethodPatch, http.MethodConnect, "PURGE", ""}
	for _, m := range nonIdempotent {
		if isIdempotentMethod(m) {
			t.Errorf("isIdempotentMethod(%q) = true, want false", m)
		}
	}
}
