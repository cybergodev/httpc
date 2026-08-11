// Package proxy detects system proxy configuration for the httpc library.
package proxy

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

// Detector provides automatic system proxy detection
type Detector struct {
	cache   *proxyConfig
	cacheMu sync.RWMutex
}

type proxyConfig struct {
	proxyFunc func(*http.Request) (*url.URL, error)
	enabled   bool
}

// NewDetector creates a new system proxy detector
func NewDetector() *Detector {
	return &Detector{}
}

// GetProxyFunc returns a proxy function that automatically detects system proxy settings.
// It returns nil if no proxy is configured, which means direct connection.
func (d *Detector) GetProxyFunc() func(*http.Request) (*url.URL, error) {
	// Fast path: check cache with read lock
	d.cacheMu.RLock()
	if d.cache != nil {
		proxyFunc := d.cache.proxyFunc
		d.cacheMu.RUnlock()
		return proxyFunc
	}
	d.cacheMu.RUnlock()

	// Slow path: detect and cache with write lock
	d.cacheMu.Lock()
	// Double-check after acquiring write lock (another goroutine may have cached)
	if d.cache != nil {
		proxyFunc := d.cache.proxyFunc
		d.cacheMu.Unlock()
		return proxyFunc
	}

	// Detect and cache proxy configuration
	proxyFunc := d.detect()
	d.cache = &proxyConfig{
		proxyFunc: proxyFunc,
		enabled:   proxyFunc != nil,
	}
	d.cacheMu.Unlock()

	return proxyFunc
}

// detect performs platform-specific proxy detection
func (d *Detector) detect() func(*http.Request) (*url.URL, error) {
	// First try environment variables (works on all platforms)
	if envProxy := d.detectFromEnvironment(); envProxy != nil {
		return envProxy
	}

	// Platform-specific detection
	return d.detectPlatform()
}

// detectFromEnvironment checks environment variables for proxy settings.
// It reads the environment directly rather than calling http.ProxyFromEnvironment,
// which caches values process-wide via sync.Once and cannot reflect later changes.
func (d *Detector) detectFromEnvironment() func(*http.Request) (*url.URL, error) {
	httpProxy := getEnvAny("HTTP_PROXY", "http_proxy")
	httpsProxy := getEnvAny("HTTPS_PROXY", "https_proxy")
	noProxy := getEnvAny("NO_PROXY", "no_proxy")

	if httpProxy == "" && httpsProxy == "" {
		return nil
	}

	// Pre-parse and normalize proxy URLs at detection time.
	httpURL, httpErr := parseProxyURL(httpProxy)
	httpsURL, httpsErr := parseProxyURL(httpsProxy)

	return func(req *http.Request) (*url.URL, error) {
		// Don't use proxies in a CGI environment, matching net/http behavior.
		if os.Getenv("REQUEST_METHOD") != "" {
			return nil, nil
		}

		host := req.URL.Hostname()

		// localhost is always direct, matching net/http behavior.
		if host == "localhost" {
			return nil, nil
		}

		// Check NO_PROXY exclusions.
		if noProxy != "" && !shouldUseProxy(host, req.URL.Port(), noProxy) {
			return nil, nil
		}

		// Select proxy URL, matching net/http's resolution order:
		// HTTPS requests prefer HTTPS_PROXY, falling back to HTTP_PROXY.
		// Other requests use HTTP_PROXY only.
		if req.URL.Scheme == "https" && httpsURL != nil {
			if httpsErr != nil {
				return nil, httpsErr
			}
			return httpsURL, nil
		}
		if httpURL != nil {
			if httpErr != nil {
				return nil, httpErr
			}
			return httpURL, nil
		}
		// Fall back to HTTPS proxy for non-HTTPS requests.
		if httpsURL != nil {
			if httpsErr != nil {
				return nil, httpsErr
			}
			return httpsURL, nil
		}

		return nil, nil
	}
}

// getEnvAny returns the first non-empty value from the given env var names.
func getEnvAny(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// parseProxyURL parses a proxy URL string, normalizing bare host:port values
// by prepending "http://" when no recognizable scheme is present.
func parseProxyURL(proxy string) (*url.URL, error) {
	if proxy == "" {
		return nil, nil
	}
	u, err := url.Parse(proxy)
	if err == nil && u != nil {
		if strings.HasPrefix(u.Scheme, "http") || strings.HasPrefix(u.Scheme, "socks") {
			return u, nil
		}
	}
	// Fall back to prepending "http://" for bare host:port values.
	return url.Parse("http://" + proxy)
}

// shouldUseProxy reports whether requests to the given host should use a proxy,
// according to the NO_PROXY environment variable. It supports hostname suffix
// matching, IP addresses, CIDR notation, and the "*" wildcard, following the
// same conventions as net/http's httpproxy package.
func shouldUseProxy(host, port, noProxy string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return true
	}

	ip := net.ParseIP(host)

	for _, pattern := range strings.Split(noProxy, ",") {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}

		if pattern == "*" {
			return false // bypass all hosts
		}

		// CIDR match (e.g., 10.0.0.0/8).
		if _, pnet, err := net.ParseCIDR(pattern); err == nil {
			if ip != nil && pnet.Contains(ip) {
				return false
			}
			continue
		}

		// Split optional host:port in pattern.
		phost, pport := pattern, ""
		if h, p, err := net.SplitHostPort(pattern); err == nil {
			phost, pport = h, p
		}

		// IP literal match.
		if net.ParseIP(phost) != nil {
			if host == phost && (pport == "" || pport == port) {
				return false
			}
			continue
		}

		if phost == "" {
			continue
		}

		// Domain suffix match (e.g., ".example.com" or "example.com").
		if strings.HasPrefix(phost, "*.") {
			phost = phost[1:] // "*.example.com" -> ".example.com"
		}
		matchHost := false
		if !strings.HasPrefix(phost, ".") {
			matchHost = true
			phost = "." + phost
		}

		if ip == nil {
			if strings.HasSuffix(host, phost) {
				if pport == "" || pport == port {
					return false
				}
			}
			if matchHost && host == phost[1:] {
				if pport == "" || pport == port {
					return false
				}
			}
		}
	}

	return true
}
