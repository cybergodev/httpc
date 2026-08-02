package connection

import "context"

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

// ProxyAttemptFromContext reports the retry-attempt index carried on ctx.
// The ok result is false when no attempt is present (non-retry path or when
// proxy rotation is not configured), in which case the selector falls back to
// normal round-robin via Pool.Select.
func ProxyAttemptFromContext(ctx context.Context) (attempt int, ok bool) {
	attempt, ok = ctx.Value(proxyAttemptKey{}).(int)
	return attempt, ok
}
