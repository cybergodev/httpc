//go:build !windows && !darwin && !linux

package proxy

import (
	"net/http"
	"net/url"
)

// detectPlatform handles proxy detection for unsupported platforms.
// detect() has already probed environment variables before falling through
// here, so there is nothing platform-specific to consult: report no proxy.
func (d *Detector) detectPlatform() func(*http.Request) (*url.URL, error) {
	return nil
}
