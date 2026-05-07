package engine

import (
	"context"
	"net/http"
)

// transportManager extends http.RoundTripper with redirect and lifecycle management.
type transportManager interface {
	http.RoundTripper

	// SetRedirectPolicy configures redirect behavior for a specific request.
	// Returns a new context with the redirect settings and the settings pointer.
	// The caller MUST call putRedirectSettings(settings) (typically via defer) after
	// the request completes to prevent memory leaks from pool exhaustion.
	SetRedirectPolicy(ctx context.Context, followRedirects bool, maxRedirects int) (context.Context, *redirectSettings)

	// GetRedirectChain returns the list of URLs followed during redirects.
	GetRedirectChain(ctx context.Context) []string

	// Close releases resources held by the transport.
	Close() error
}
