// Package proxy detects system proxy configuration for the httpc library.
package proxy

import (
	"fmt"
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
	// Capture the CGI indicator once: REQUEST_METHOD is fixed for the process
	// lifetime, and reading os.Getenv per request both costs a syscall and
	// races with any concurrent os.Setenv by the host application.
	inCGI := os.Getenv("REQUEST_METHOD") != ""

	if httpProxy == "" && httpsProxy == "" {
		return nil
	}

	// Pre-parse and normalize proxy URLs at detection time.
	httpURL, httpErr := parseProxyURL(httpProxy)
	httpsURL, httpsErr := parseProxyURL(httpsProxy)

	return func(req *http.Request) (*url.URL, error) {
		// Don't use proxies in a CGI environment, matching net/http behavior.
		if inCGI {
			return nil, nil
		}

		host := req.URL.Hostname()

		// localhost and loopback IPs are always direct, matching net/http
		// behavior (x/net httpproxy exempts net.IP.IsLoopback in addition to
		// the literal hostname).
		if host == "localhost" {
			return nil, nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil, nil
		}

		// Check NO_PROXY exclusions.
		if noProxy != "" && !shouldUseProxy(host, req.URL.Port(), noProxy) {
			return nil, nil
		}

		// Select proxy URL, matching net/http's resolution order:
		// HTTPS requests prefer HTTPS_PROXY, falling back to HTTP_PROXY.
		// Other requests use HTTP_PROXY only (an invalid HTTPS_PROXY does not
		// affect plain-HTTP requests — same as ProxyFromEnvironment).
		//
		// A proxy env var that is SET but INVALID must surface its parse
		// error for the schemes it governs rather than silently
		// direct-connecting — net/http's ProxyFromEnvironment does the same.
		// (The previous error checks sat inside the `!= nil` branches where
		// they were unreachable, so an invalid HTTPS_PROXY silently disabled
		// proxying for HTTPS traffic.)
		if req.URL.Scheme == "https" {
			if httpsURL != nil {
				return httpsURL, nil
			}
			if httpsErr != nil {
				return nil, httpsErr
			}
		}
		if httpURL != nil {
			return httpURL, nil
		}
		if httpErr != nil {
			return nil, httpErr
		}
		// Fall back to HTTPS proxy for non-HTTPS requests.
		if httpsURL != nil {
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

// isLoopbackRequest reports whether the request targets localhost or a
// loopback IP. Platform-detected proxies (Windows registry, macOS
// networksetup) bypass such requests, matching net/http behavior and the
// environment-variable path above — without this, an enterprise system proxy
// would route http://127.0.0.1/health calls through the corporate proxy,
// breaking local calls and disclosing internal URLs to the proxy.
func isLoopbackRequest(req *http.Request) bool {
	host := req.URL.Hostname()
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// parseProxyURL parses a proxy URL string, normalizing bare host:port values
// by prepending "http://" when no recognizable scheme is present.
func parseProxyURL(proxy string) (*url.URL, error) {
	if proxy == "" {
		return nil, nil
	}
	// Normalize the bare "socks" scheme to "socks5" (same as the Windows
	// registry path): net/http recognizes socks5/socks5h but not "socks://".
	if after, ok := strings.CutPrefix(proxy, "socks://"); ok {
		proxy = "socks5://" + after
	}
	// Scheme allow-list matches validation.ValidateProxyURL exactly (the
	// previous prefix check accepted "httpx://"/"socks4://", deferring failure
	// to a per-request transport error instead of a clear detection-time one).
	// Only values carrying an explicit "://" are treated as schemed — a bare
	// "host:port" like "proxy:3128" parses with the hostname in the scheme
	// position and must keep the http fallback below.
	if i := strings.Index(proxy, "://"); i > 0 {
		scheme := strings.ToLower(proxy[:i])
		switch scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q", scheme)
		}
	}
	u, err := url.Parse(proxy)
	if err == nil && u != nil {
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
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
