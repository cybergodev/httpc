package connection

import "context"

// ssrfOverrideKey is a typed context key carrying a per-request override of the
// dialer's SSRF AllowPrivateIPs policy. It is set by the engine when a request
// carries the WithAllowPrivateIPs option, so the override reaches the
// connection pool's dialer (which validates dialed IPs at connect time) and the
// engine's redirect-target validator.
//
// Defined here rather than in the engine package to avoid an import cycle:
// the connection package is the lowest layer that must read it, and the engine
// already imports connection. The helpers below are exported only because the
// engine must set and read the value across the package boundary; they are not
// part of the public httpc API.
type ssrfOverrideKey struct{}

// WithAllowPrivateIPsOverride returns a copy of ctx that carries a per-request
// AllowPrivateIPs override. When present, the dialer and redirect validator use
// this value in place of the client-level config. It is intended for internal
// use by the engine to honor the per-request WithAllowPrivateIPs option.
//
// ctx must be non-nil; callers (the engine) always supply the request context.
func WithAllowPrivateIPsOverride(ctx context.Context, allow bool) context.Context {
	return context.WithValue(ctx, ssrfOverrideKey{}, allow)
}

// AllowPrivateIPsOverrideFromContext reports the per-request AllowPrivateIPs
// override carried on ctx. The ok result is false when no override is present,
// in which case callers fall back to the client-level policy.
func AllowPrivateIPsOverrideFromContext(ctx context.Context) (allow bool, ok bool) {
	allow, ok = ctx.Value(ssrfOverrideKey{}).(bool)
	return allow, ok
}
