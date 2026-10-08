package connection

import (
	"context"
	"net/url"
	"sync"
)

// proxyAttemptKey is a typed context key for the retry-attempt index used by
// deterministic proxy selection. The engine sets this in the retry loop; the
// proxy selector in NewPoolManager reads it to choose a different proxy per
// attempt via Pool.SelectIndex. It follows the same pattern as ssrfOverrideKey.
type proxyAttemptKey struct{}

// WithProxyAttempt returns a copy of ctx that carries the retry-attempt index.
// When present, the proxy selector uses Pool.SelectIndex(attempt) instead of
// the round-robin Pool.Select, ensuring each retry attempt deterministically
// lands on a different proxy even when redirect-following within a single
// attempt consumes extra Select calls.
//
// ctx must be non-nil; callers (the engine) always supply the request context.
func WithProxyAttempt(ctx context.Context, attempt int) context.Context {
	return context.WithValue(ctx, proxyAttemptKey{}, attempt)
}

// proxyAttemptFromContext reports the retry-attempt index carried on ctx.
// The ok result is false when no attempt is present (non-retry path or when
// proxy rotation is not configured), in which case the selector falls back to
// normal round-robin via Pool.Select.
func proxyAttemptFromContext(ctx context.Context) (attempt int, ok bool) {
	attempt, ok = ctx.Value(proxyAttemptKey{}).(int)
	return attempt, ok
}

// proxyRecorderKey is a typed context key for the per-request proxy recorder.
// The engine attaches a *ProxyRecorder to the request context before
// execution; the transport's Proxy callback records the selected proxy into
// it during RoundTrip; the engine reads it after the attempt completes to
// populate Response.ProxyURL. It follows the same pattern as proxyAttemptKey.
type proxyRecorderKey struct{}

// ProxyRecorder captures the proxy URL chosen by the transport's Proxy
// callback for a single logical request. net/http invokes the Proxy callback
// on every request — including redirects and idle-connection reuse — so the
// value recorded after an attempt completes is the proxy that actually
// carried it. A zero value is ready to use and safe for concurrent access.
type ProxyRecorder struct {
	mu  sync.Mutex
	url string
}

// record stores the selected proxy URL. It is safe to call on a nil receiver
// or with a nil URL (direct connection reported by system-proxy detection) —
// both are ignored so call sites need no nil guard.
func (p *ProxyRecorder) record(u *url.URL) {
	if p == nil || u == nil {
		return
	}
	p.mu.Lock()
	// Redacted replaces any userinfo password with "xxxxx". ProxyRecorder feeds
	// the public Response.ProxyURL field; storing the raw string would leak
	// proxy credentials to anyone printing or serializing the response.
	p.url = u.Redacted()
	p.mu.Unlock()
}

// Last returns the most recently recorded proxy URL, or "" when no proxy was
// selected for the request (direct connection, or no recorder attached).
func (p *ProxyRecorder) Last() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.url
}

// WithProxyRecorder returns a copy of ctx that carries the proxy recorder.
// The engine calls this once per request before execution; the transport's
// Proxy callback then writes into rec for every attempt of that request.
func WithProxyRecorder(ctx context.Context, rec *ProxyRecorder) context.Context {
	return context.WithValue(ctx, proxyRecorderKey{}, rec)
}

// proxyRecorderFromContext reports the proxy recorder carried on ctx, or nil
// when none is present (no proxy configured, or the caller is outside the
// engine's execution path). Returning nil is safe: record and Last accept a
// nil receiver.
func proxyRecorderFromContext(ctx context.Context) *ProxyRecorder {
	rec, _ := ctx.Value(proxyRecorderKey{}).(*ProxyRecorder)
	return rec
}
