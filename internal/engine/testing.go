package engine

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
)

// errForcedFailure is returned by mockTransport for the first failFirst calls,
// enabling deterministic retry tests without goroutine timing. The message uses
// "connection reset by peer" so the error classifier marks it as retryable.
var errForcedFailure = errors.New("connection reset by peer")

// mockTransport is a mock implementation of transportManager for testing.
// It allows controlling the response and error returned by RoundTrip.
type mockTransport struct {
	mu        sync.Mutex
	Response  *http.Response
	Error     error
	Called    bool
	CallCount int
	Requests  []*http.Request

	// failFirst forces the first N RoundTrip calls to return errForcedFailure,
	// then falls through to the normal Error/Response path. Useful for
	// deterministic retry tests (fail-then-succeed scenarios).
	failFirst int

	// Redirect behavior
	RedirectChain []string
}

// newMockTransport creates a new mockTransport with a predefined response.
func newMockTransport(statusCode int, body string) *mockTransport {
	return &mockTransport{
		Response: &http.Response{
			StatusCode: statusCode,
			Status:     http.StatusText(statusCode),
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
		},
	}
}

// RoundTrip implements transportManager.
func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Called = true
	m.CallCount++
	m.Requests = append(m.Requests, req)

	if m.failFirst > 0 {
		m.failFirst--
		return nil, errForcedFailure
	}

	if m.Error != nil {
		return nil, m.Error
	}

	return m.Response, nil
}

// SetRedirectPolicy implements transportManager.
func (m *mockTransport) SetRedirectPolicy(ctx context.Context, followRedirects bool, maxRedirects int) (context.Context, *redirectSettings) {
	return ctx, nil
}

// GetRedirectChain implements transportManager.
func (m *mockTransport) GetRedirectChain(ctx context.Context) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	chain := make([]string, len(m.RedirectChain))
	copy(chain, m.RedirectChain)
	return chain
}

// Close implements transportManager.
func (m *mockTransport) Close() error {
	return nil
}

// SetError sets the error to return for subsequent requests.
func (m *mockTransport) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Error = err
}

// GetCallCount returns the number of times RoundTrip was called.
func (m *mockTransport) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.CallCount
}

// withMockTransport returns a clientOption that injects a mock transport.
func withMockTransport(mt *mockTransport) clientOption {
	return func(opts *clientOptions) {
		opts.customTransport = mt
	}
}

// clearResponsePools resets all sync.Pool instances used for response processing.
// For use in tests only — ensures a clean state between test cases.
func clearResponsePools() {
	gzipReaderPool = sync.Pool{
		New: func() any {
			reader, _ := gzip.NewReader(bytes.NewReader(nil))
			return reader
		},
	}
	flateReaderPool = sync.Pool{
		New: func() any {
			return flate.NewReader(bytes.NewReader(nil))
		},
	}
	bufferPool = sync.Pool{
		New: func() any {
			return bytes.NewBuffer(make([]byte, 0, defaultBufferSize))
		},
	}
	responsePool = sync.Pool{
		New: func() any {
			return &Response{}
		},
	}
	limitReaderPool = sync.Pool{
		New: func() any {
			return &pooledLimitReader{}
		},
	}
}

// clearTransportPools resets all sync.Pool instances used by the transport package.
// For use in tests only.
func clearTransportPools() {
	redirectSettingsPool = sync.Pool{
		New: func() any {
			return &redirectSettings{}
		},
	}
	cookieMapPool = sync.Pool{
		New: func() any {
			m := make(map[string]*http.Cookie, 8)
			return &m
		},
	}
	cookieSlicePool = sync.Pool{
		New: func() any {
			s := make([]*http.Cookie, 0, 8)
			return &s
		},
	}
}

// clearURLCache clears the global URL cache to release memory.
// For use in tests only.
func clearURLCache() {
	globalURLCache.clear()
}

// getURLCacheSize returns the current number of entries in the URL cache.
// For use in tests only.
func getURLCacheSize() int {
	return globalURLCache.size()
}
