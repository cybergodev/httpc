// Package connection manages HTTP connection pooling, TLS configuration,
// and proxy detection for the httpc library.
package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybergodev/httpc/internal/dns"
	"github.com/cybergodev/httpc/internal/proxy"
	"github.com/cybergodev/httpc/internal/proxypool"
	"github.com/cybergodev/httpc/internal/validation"
)

// ErrPoolExhausted is returned when the connection pool has reached its
// maximum capacity and cannot accept new connections. Callers can detect
// this condition with errors.Is(err, connection.ErrPoolExhausted).
var ErrPoolExhausted = errors.New("connection pool exhausted")

// ErrProxyConnectionFailed wraps errors that occur while connecting to a
// proxy server (dial failure, invalid address, refused connection, etc.).
// The retry engine checks for this sentinel when proxy rotation is active
// to decide whether to retry with the next proxy in the pool.
var ErrProxyConnectionFailed = errors.New("proxy connection failed")

// httpcDebug caches the HTTPC_DEBUG environment-variable check to avoid a
// syscall per proxy selection. Evaluated once at first use via sync.OnceValue.
var httpcDebug = sync.OnceValue(func() bool {
	return os.Getenv("HTTPC_DEBUG") != ""
})

// PoolManager provides intelligent connection pool management with monitoring
type PoolManager struct {
	config *Config

	transport   *http.Transport
	dohResolver *dns.DoHResolver
	proxyAddrs  []string
	proxyPool   *proxypool.Pool

	// atomic.Int64 (not plain int64 + atomic funcs) guarantees 8-byte
	// alignment on 32-bit platforms, where interior struct fields are only
	// 4-aligned and atomic 64-bit ops would panic.
	activeConns   atomic.Int64
	totalConns    atomic.Int64
	rejectedConns atomic.Int64
	// acceptedConns is a monotonically increasing count of successfully
	// established connections (unlike totalConns, which is a gauge that
	// decreases as connections close). Used by GetMetrics for a meaningful
	// admission-hit rate.
	acceptedConns atomic.Int64

	closed int32

	// NOTE: a per-host stats map (hostStats/hostConns/evictStaleHosts) was
	// removed — it was write-only (GetMetrics reports aggregate counters
	// only), cost a sync.Map load + atomics on every dial, and keyed entries
	// by resolved IP on the standard path (one logical host with N A/AAAA
	// records created N entries). Aggregate counters cover everything any
	// consumer reads.
}

// certPinner defines the interface for certificate pinning
type certPinner interface {
	VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

// Config defines connection pool configuration.
// Treated as immutable once passed to NewPoolManager: scalar fields are frozen
// via a shallow copy at construction; reference fields (ProxyPool, ExemptNets,
// TLSConfig, CookieJar) are shared and must not be mutated afterwards.
type Config struct {
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int
	MaxTotalConns       int

	DialTimeout            time.Duration
	KeepAlive              time.Duration
	TLSHandshakeTimeout    time.Duration
	ResponseHeaderTimeout  time.Duration
	IdleConnTimeout        time.Duration
	ExpectContinueTimeout  time.Duration
	MaxResponseHeaderBytes int64

	TLSConfig          *tls.Config
	MinTLSVersion      uint16
	MaxTLSVersion      uint16
	InsecureSkipVerify bool

	EnableHTTP2 bool
	ProxyURL    string

	// System proxy configuration
	EnableSystemProxy bool // Automatically detect and use system proxy settings

	// Proxy pool configuration. When set, requests are distributed across the
	// listed proxies with passive circuit breaking. Lower priority than
	// ProxyURL, higher than EnableSystemProxy.
	ProxyPool             []string
	ProxyPoolStrategy     proxypool.Strategy
	ProxyFailureThreshold int
	ProxyCooldown         time.Duration

	AllowPrivateIPs bool

	ExemptNets []*net.IPNet

	// Note: there is deliberately no DisableCompression field — the transport
	// always disables automatic decompression (the engine handles it manually,
	// including the decompression-bomb limit), so a config knob for it was
	// dead API surface and has been removed.

	DisableKeepAlives bool
	ForceAttemptHTTP2 bool

	CookieJar http.CookieJar

	// DNS configuration
	EnableDoH   bool          // Enable DNS-over-HTTPS
	DoHCacheTTL time.Duration // DoH cache TTL

	// Certificate pinning
	certPinner certPinner
}

// SetCertPinner sets the certificate pinner for TLS certificate verification.
func (c *Config) SetCertPinner(p certPinner) { c.certPinner = p }

// metrics provides connection pool performance metrics.
//
// TotalConnections is the cumulative count of successfully established
// connections (monotonic); the current number of open connections is
// ActiveConnections. ConnectionHitRate = Total/(Total+Rejected), i.e. the
// share of dial attempts the pool admitted (the old implementation mixed the
// live-connection gauge with the monotonic rejection counter, making the rate
// drift and jitter).
type metrics struct {
	ActiveConnections   int64
	TotalConnections    int64
	RejectedConnections int64
	ConnectionHitRate   float64
	LastUpdate          int64
}

// DefaultConfig returns optimized default configuration.
func DefaultConfig() *Config {
	return &Config{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 20,
		MaxConnsPerHost:     50,
		MaxTotalConns:       1000,

		DialTimeout:           10 * time.Second,
		KeepAlive:             30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,

		MinTLSVersion:      tls.VersionTLS12,
		MaxTLSVersion:      tls.VersionTLS13,
		InsecureSkipVerify: false,

		EnableHTTP2: true,

		DisableKeepAlives: false,
		ForceAttemptHTTP2: true,

		AllowPrivateIPs: false,
	}
}

// NewPoolManager creates a new connection pool manager with the given configuration.
func NewPoolManager(config *Config) (*PoolManager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Freeze scalar fields with a shallow copy: the dialer and TLS callback
	// read config fields on every connection, so a caller mutating them after
	// construction would race with concurrent dialing. Reference fields
	// (ProxyPool, ExemptNets, TLSConfig, CookieJar) remain shared and must be
	// treated as immutable once passed in.
	frozen := *config
	config = &frozen

	pm := &PoolManager{
		config: config,
	}

	// Initialize DoH resolver if enabled
	if config.EnableDoH {
		pm.dohResolver = dns.NewDoHResolver(nil, config.DoHCacheTTL)
	}

	// EnableHTTP2=false must override ForceAttemptHTTP2 regardless of its
	// default value. Compute the effective value without mutating the input config.
	forceAttemptHTTP2 := config.ForceAttemptHTTP2
	if !config.EnableHTTP2 {
		forceAttemptHTTP2 = false
	}

	transport := &http.Transport{
		DialContext:            pm.createDialer(),
		TLSHandshakeTimeout:    config.TLSHandshakeTimeout,
		ResponseHeaderTimeout:  config.ResponseHeaderTimeout,
		IdleConnTimeout:        config.IdleConnTimeout,
		ExpectContinueTimeout:  config.ExpectContinueTimeout,
		MaxResponseHeaderBytes: config.MaxResponseHeaderBytes,
		MaxIdleConns:           config.MaxIdleConns,
		MaxIdleConnsPerHost:    config.MaxIdleConnsPerHost,
		MaxConnsPerHost:        config.MaxConnsPerHost,
		ForceAttemptHTTP2:      forceAttemptHTTP2,
		DisableCompression:     true, // Always disable automatic decompression - we handle it manually
		DisableKeepAlives:      config.DisableKeepAlives,
	}

	// Always set TLSClientConfig — it is required for HTTPS connections
	// through HTTP proxies (CONNECT tunnels).
	transport.TLSClientConfig = pm.createTLSConfig()

	// Configure proxy settings with priority:
	// 1. Manual proxy URL (highest priority)
	// 2. Proxy pool (rotating, with circuit breaking)
	// 3. System proxy detection (if enabled)
	// 4. Direct connection (no proxy)
	if config.ProxyURL != "" {
		// Shared validator (same one ValidateConfig uses): accepts http/https and
		// socks5/socks5h, and checks the host. Routing through it here — instead of
		// a local http/https-only check — keeps the pool from rejecting socks5
		// proxies that the public Config layer already accepted.
		proxyURL, err := validation.ValidateProxyURL(config.ProxyURL)
		if err != nil {
			return nil, err
		}
		// Proxy URL is explicitly configured by the developer, not user-supplied input.
		// SSRF validation targets request URLs (attacker-controlled), not developer-chosen
		// infrastructure. A developer who can set ProxyURL can already bypass SSRF by
		// connecting directly, so blocking proxy hosts adds no meaningful security.
		// Canonicalize to the address net/http actually dials (default port
		// appended for portless URLs) — isProxyAddr compares against exactly
		// that, and the raw url.Host would never match for portless entries.
		pm.proxyAddrs = append(pm.proxyAddrs, validation.CanonicalProxyAddr(proxyURL))
		// Equivalent to http.ProxyURL(proxyURL), but records the selection
		// into the per-request ProxyRecorder (see WithProxyRecorder) so the
		// engine can surface which proxy served the request.
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			proxyRecorderFromContext(req.Context()).record(proxyURL)
			return proxyURL, nil
		}
	} else if len(config.ProxyPool) > 0 {
		// Proxy pool: distribute requests across multiple proxies with passive
		// circuit breaking. transport.Proxy delegates to pool.Select, which
		// skips circuit-open proxies; the dialer reports connection failures
		// and successes back to the pool so dead proxies are temporarily
		// removed from rotation.
		pool, err := proxypool.New(proxypool.Config{
			Proxies:          config.ProxyPool,
			Strategy:         config.ProxyPoolStrategy,
			FailureThreshold: config.ProxyFailureThreshold,
			Cooldown:         config.ProxyCooldown,
		})
		if err != nil {
			return nil, fmt.Errorf("proxy pool: %w", err)
		}
		pm.proxyPool = pool
		// Seed all proxy hosts so isProxyAddr recognizes them and the dialer
		// bypasses SSRF validation for developer-configured proxy infrastructure.
		pm.proxyAddrs = append(pm.proxyAddrs, pool.Hosts()...)
		// Wrap pool.Select so that when the retry engine sets a proxy-attempt
		// index on the request context (WithProxyAttempt), we use deterministic
		// SelectIndex instead of advancing the round-robin counter. This ensures
		// each retry attempt lands on a different proxy even when redirect-
		// following within a single attempt consumes extra Proxy calls.
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			rec := proxyRecorderFromContext(req.Context())
			if attempt, ok := proxyAttemptFromContext(req.Context()); ok {
				u := pool.SelectIndex(attempt)
				rec.record(u)
				if httpcDebug() {
					fmt.Fprintf(os.Stderr, "[httpc] proxy SelectIndex(%d) → %s\n", attempt, u.Host)
				}
				return u, nil
			}
			u, err := pool.Select(req)
			if err == nil {
				rec.record(u)
				if httpcDebug() {
					fmt.Fprintf(os.Stderr, "[httpc] proxy Select(round-robin) → %s\n", u.Host)
				}
			}
			return u, err
		}
	} else if config.EnableSystemProxy {
		// No manual proxy, but system proxy detection is enabled.
		// Automatically detect system proxy settings (reads from Windows registry,
		// macOS system settings, environment variables, etc.).
		detector := proxy.NewDetector()
		proxyFunc := detector.GetProxyFunc()
		if proxyFunc != nil {
			// The transport consults proxyFunc on every request, but the proxy host
			// is seeded into proxyAddrs (used to bypass SSRF validation for the proxy
			// connection itself) only from a one-shot probe at construction time.
			// Probe both http and https because ProxyFromEnvironment may return a
			// different proxy per scheme (HTTP_PROXY vs HTTPS_PROXY).
			//
			// LIMITATION: if the environment later resolves to a proxy on a
			// private/loopback address (e.g. 127.0.0.1) that was absent at
			// construction, SSRF protection may block it because that host is not in
			// proxyAddrs. For dynamically-changing localhost proxies, set
			// Connection.ProxyURL explicitly (always exempted) or AllowPrivateIPs.
			transport.Proxy = proxyFunc
			for _, scheme := range []string{"http", "https"} {
				testURL, _ := url.Parse(scheme + "://example.com") // literal URL; Parse cannot fail
				if pu, err := proxyFunc(&http.Request{URL: testURL}); err == nil && pu != nil {
					// Canonical dial address (see the ProxyURL branch above):
					// the dial callback compares against what net/http dials,
					// not the raw url.Host.
					canonical := validation.CanonicalProxyAddr(pu)
					if !slices.Contains(pm.proxyAddrs, canonical) {
						pm.proxyAddrs = append(pm.proxyAddrs, canonical)
					}
				}
			}
		}
		// If proxyFunc is nil, transport.Proxy remains nil (direct connection).
	}
	// If neither condition is met, transport.Proxy remains nil (direct connection).

	pm.transport = transport
	return pm, nil
}

// createDialer creates an optimized dialer with SSRF protection and connection tracking.
func (pm *PoolManager) createDialer() func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   pm.config.DialTimeout,
		KeepAlive: pm.config.KeepAlive,
		// Note: Control is not used here due to cross-platform compatibility issues.
		// SSRF protection is implemented directly in the dialer function instead.
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if atomic.LoadInt32(&pm.closed) == 1 {
			return nil, errors.New("connection pool is closed")
		}

		// Atomically reserve a connection slot to prevent TOCTOU race
		if pm.config.MaxTotalConns > 0 {
			newCount := pm.totalConns.Add(1)
			if newCount > int64(pm.config.MaxTotalConns) {
				pm.totalConns.Add(-1)
				pm.rejectedConns.Add(1)
				return nil, fmt.Errorf("%w (max %d)", ErrPoolExhausted, pm.config.MaxTotalConns)
			}
		}
		// Proxy connections bypass SSRF validation and DoH resolution —
		// the proxy address is explicitly configured by the user.
		if pm.isProxyAddr(address) {
			conn, err := dialer.DialContext(ctx, network, address)

			if err != nil {
				if pm.proxyPool != nil {
					pm.proxyPool.ReportFailure(address)
				}
				pm.rejectedConns.Add(1)
				if pm.config.MaxTotalConns > 0 {
					pm.totalConns.Add(-1)
				}
				return nil, fmt.Errorf("%w: %w", ErrProxyConnectionFailed, err)
			}

			if pm.proxyPool != nil {
				pm.proxyPool.ReportSuccess(address)
			}
			pm.acceptedConns.Add(1)
			pm.activeConns.Add(1)
			return &trackedConn{
				Conn: conn,
				pm:   pm,
			}, nil
		}

		// Per-request AllowPrivateIPs override (set by the WithAllowPrivateIPs
		// request option) takes precedence over the client-level policy. When no
		// override is present on the request context, fall back to the client config.
		allowPrivateIPs := pm.config.AllowPrivateIPs
		if override, ok := AllowPrivateIPsOverrideFromContext(ctx); ok {
			allowPrivateIPs = override
		}

		// If DoH is enabled, resolve the address using DoH and dial the IP directly
		if pm.dohResolver != nil {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				host = address
				port = "443"
			}

			// Use DoH resolver for DNS lookup
			ips, err := pm.dohResolver.LookupIPAddr(ctx, host)
			if err != nil {
				pm.rejectedConns.Add(1)
				if pm.config.MaxTotalConns > 0 {
					pm.totalConns.Add(-1)
				}
				return nil, fmt.Errorf("DoH DNS resolution failed: %w", err)
			}

			// SSRF protection: filter to allowed IPs (supports Split-Horizon DNS)
			resolvedIPs := make([]net.IP, len(ips))
			for i, addr := range ips {
				resolvedIPs[i] = addr.IP
			}
			if !allowPrivateIPs {
				allowedIPs := validation.FilterAllowedIPs(resolvedIPs, pm.config.ExemptNets)
				if len(allowedIPs) == 0 {
					pm.rejectedConns.Add(1)
					if pm.config.MaxTotalConns > 0 {
						pm.totalConns.Add(-1)
					}
					return nil, fmt.Errorf("SSRF protection: domain resolves only to blocked addresses")
				}
				resolvedIPs = allowedIPs
			}

			// Try to connect to each allowed IP until one succeeds. lastErr is
			// seeded so an empty candidate list cannot render as %!w(<nil>).
			lastErr := errors.New("no resolved addresses")
			for _, ip := range resolvedIPs {
				ipAddress := net.JoinHostPort(ip.String(), port)
				conn, err := dialer.DialContext(ctx, network, ipAddress)

				if err == nil {
					pm.acceptedConns.Add(1)
					pm.activeConns.Add(1)
					return &trackedConn{
						Conn: conn,
						pm:   pm,
					}, nil
				}
				lastErr = err
			}

			pm.rejectedConns.Add(1)
			if pm.config.MaxTotalConns > 0 {
				pm.totalConns.Add(-1)
			}
			return nil, fmt.Errorf("connection failed after trying %d IPs: %w", len(resolvedIPs), lastErr)
		}

		// Standard path without DoH
		// SECURITY: Resolve DNS, validate all IPs, then dial a validated IP
		// directly to prevent DNS rebinding TOCTOU attacks where an
		// attacker-controlled DNS server returns a different IP between
		// validation and actual connection.
		var candidates []string
		if !allowPrivateIPs {
			validatedAddrs, err := pm.resolveAndValidateAddress(ctx, address)
			if err != nil {
				pm.rejectedConns.Add(1)
				if pm.config.MaxTotalConns > 0 {
					pm.totalConns.Add(-1)
				}
				return nil, fmt.Errorf("SSRF protection: %w", err)
			}
			candidates = validatedAddrs
		} else {
			candidates = []string{address}
		}

		// Try every validated IP in turn (e.g. IPv6 unreachable → IPv4
		// fallback), mirroring the DoH path above. All candidates passed SSRF
		// validation, so dialing any of them is rebinding-safe.
		var conn net.Conn
		// Seeded so an empty candidate list cannot render as %!w(<nil>).
		lastErr := errors.New("no validated addresses to dial")
		for _, addr := range candidates {
			conn, lastErr = dialer.DialContext(ctx, network, addr)
			if conn != nil {
				break
			}
		}

		if conn == nil {
			pm.rejectedConns.Add(1)
			if pm.config.MaxTotalConns > 0 {
				pm.totalConns.Add(-1)
			}
			return nil, fmt.Errorf("connection failed after trying %d address(es): %w", len(candidates), lastErr)
		}

		pm.acceptedConns.Add(1)
		pm.activeConns.Add(1)

		return &trackedConn{
			Conn: conn,
			pm:   pm,
		}, nil
	}
}

// resolveAndValidateAddress resolves the given address and validates all resulting IPs
// against SSRF protection rules. It returns validated "ip:port" candidates that should
// be dialed directly to prevent DNS rebinding TOCTOU attacks; callers may try each
// candidate in turn (IPv6 → IPv4 failover) since all of them passed validation.
//
// SECURITY: By resolving DNS once and dialing a validated IP directly (instead of
// the original hostname), we eliminate the window where an attacker-controlled DNS
// server could return a different (private) IP on the second resolution.
func (pm *PoolManager) resolveAndValidateAddress(ctx context.Context, address string) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		port = "443"
	}

	// If the address is already an IP, validate it directly
	if ip := net.ParseIP(host); ip != nil {
		if err := validation.ValidateIPWithExemptions(ip, pm.config.ExemptNets); err != nil {
			return nil, err
		}
		return []string{address}, nil
	}

	// For domain names, resolve and filter to allowed IPs.
	// Derive the resolution timeout from the caller's context so request
	// cancellation aborts the lookup promptly (the DoH path already honors ctx).
	// Cap at 10s to avoid unbounded waits; derive from DialTimeout when smaller.
	dnsTimeout := 10 * time.Second
	if pm.config.DialTimeout > 0 && pm.config.DialTimeout < dnsTimeout {
		dnsTimeout = pm.config.DialTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dnsCtx, dnsCancel := context.WithTimeout(ctx, dnsTimeout)
	defer dnsCancel()
	ipAddrs, err := net.DefaultResolver.LookupIPAddr(dnsCtx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for SSRF validation of %s: %w", host, err)
	}
	ips := make([]net.IP, len(ipAddrs))
	for i, addr := range ipAddrs {
		ips[i] = addr.IP
	}

	// Filter to public/exempted IPs — supports Split-Horizon DNS environments
	// where a domain may resolve to both public and private IPs.
	allowedIPs := validation.FilterAllowedIPs(ips, pm.config.ExemptNets)
	if len(allowedIPs) == 0 {
		return nil, fmt.Errorf("domain %s resolves only to blocked addresses", host)
	}

	// Return every allowed IP for direct dialing to prevent DNS rebinding:
	// callers dial the validated IP literals (never the hostname).
	addrs := make([]string, 0, len(allowedIPs))
	for _, ip := range allowedIPs {
		addrs = append(addrs, net.JoinHostPort(ip.String(), port))
	}
	return addrs, nil
}

func (pm *PoolManager) isProxyAddr(address string) bool {
	return slices.Contains(pm.proxyAddrs, address)
}

func (pm *PoolManager) createTLSConfig() *tls.Config {
	// If a custom TLS config is provided, use it (but add cert pinning if configured)
	if pm.config.TLSConfig != nil {
		tlsConfig := pm.config.TLSConfig.Clone()
		// Add certificate pinning verification if configured. Chain onto any
		// user-supplied VerifyPeerCertificate callback instead of replacing
		// it: custom CA validation or mTLS hooks must keep working.
		if pm.config.certPinner != nil {
			orig := tlsConfig.VerifyPeerCertificate
			pinVerify := pm.createVerifyPeerCertificate()
			tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if orig != nil {
					if err := orig(rawCerts, verifiedChains); err != nil {
						return err
					}
				}
				return pinVerify(rawCerts, verifiedChains)
			}
		}
		return tlsConfig
	}

	tlsConfig := &tls.Config{
		MinVersion:         pm.config.MinTLSVersion,
		MaxVersion:         pm.config.MaxTLSVersion,
		InsecureSkipVerify: pm.config.InsecureSkipVerify,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		SessionTicketsDisabled: false,
		ClientSessionCache:     tls.NewLRUClientSessionCache(256),
		Renegotiation:          tls.RenegotiateNever,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}

	// Add certificate pinning verification if configured
	if pm.config.certPinner != nil {
		tlsConfig.VerifyPeerCertificate = pm.createVerifyPeerCertificate()
	}

	return tlsConfig
}

// createVerifyPeerCertificate creates a certificate verification callback that
// enforces certificate pinning on top of Go's standard verification.
//
// When InsecureSkipVerify is true, Go skips all chain/hostname validation and
// invokes this callback with verifiedChains=nil; pinning is then the sole
// verification gate (rawCerts still carries the server's certificates, so
// SPKI/hash pinners work). When InsecureSkipVerify is false, Go performs full
// validation first and this callback adds the pinning check on top. Either way
// the only failure mode is the pin check, so the callback returns nil after a
// successful pin.
func (pm *PoolManager) createVerifyPeerCertificate() func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if err := pm.config.certPinner.VerifyPeerCertificate(rawCerts, verifiedChains); err != nil {
			return fmt.Errorf("certificate pinning failed: %w", err)
		}
		return nil
	}
}

type trackedConn struct {
	net.Conn
	pm        *PoolManager
	closeOnce sync.Once
	closed    int32 // Atomic flag for fast double-close detection
}

func (tc *trackedConn) Close() error {
	// Fast path: check if already closed (atomic check before sync.Once overhead)
	if atomic.LoadInt32(&tc.closed) == 1 {
		return nil
	}

	var closeErr error
	tc.closeOnce.Do(func() {
		atomic.StoreInt32(&tc.closed, 1)
		// Counter decrements are unconditional. closeOnce guarantees they run
		// exactly once per connection, and every dial-time increment has this
		// matching decrement even when the pool is closed in between — keeping
		// the accounting balanced. (The previous "skip if pool closed" guard
		// was a TOCTOU: a Close that raced past the closed load, followed by
		// PoolManager.Close's counter reset, drove the counters negative.)
		tc.pm.activeConns.Add(-1)
		if tc.pm.config.MaxTotalConns > 0 {
			tc.pm.totalConns.Add(-1)
		}
		closeErr = tc.Conn.Close()
	})
	return closeErr
}

// GetTransport returns the shared *http.Transport used for pooled connections.
func (pm *PoolManager) GetTransport() *http.Transport {
	return pm.transport
}

// CloseIdleConnections closes all idle connections in the underlying transport.
// Used by the retry layer to force the transport to re-evaluate transport.Proxy
// on the next request — without this, HTTP/2 connection reuse through a CONNECT
// tunnel can bypass Proxy() and reuse the connection from a previous attempt,
// defeating proxy rotation.
func (pm *PoolManager) CloseIdleConnections() {
	if pm.transport != nil {
		pm.transport.CloseIdleConnections()
	}
}

// NextProxyIndex advances the proxy pool's round-robin cursor once and returns
// the resulting base index. The caller (retry engine) combines this with the
// attempt number (base + attempt) to deterministically select a different proxy
// per retry, while still rotating across sequential requests.
// Returns (0, false) when no proxy pool is configured.
func (pm *PoolManager) NextProxyIndex() (int, bool) {
	if pm.proxyPool == nil {
		return 0, false
	}
	return pm.proxyPool.NextIndex(), true
}

// HasProxy reports whether requests are routed through an explicitly
// configured proxy — a manual ProxyURL or a proxy pool. System-proxy detection
// is not covered because its selection is resolved dynamically per request.
// The engine uses this to attach a ProxyRecorder only when a proxy may be
// selected, keeping the direct-connection path allocation-free.
func (pm *PoolManager) HasProxy() bool {
	return pm.proxyPool != nil || pm.config.ProxyURL != ""
}

// GetMetrics returns a snapshot of current connection pool statistics,
// including active, total, and rejected connection counts and the connection
// hit rate.
func (pm *PoolManager) GetMetrics() metrics {
	accepted := pm.acceptedConns.Load()
	rejected := pm.rejectedConns.Load()
	active := pm.activeConns.Load()
	hitRate := 0.0
	if accepted+rejected > 0 {
		hitRate = float64(accepted) / float64(accepted+rejected)
	}

	return metrics{
		ActiveConnections:   active,
		TotalConnections:    accepted,
		RejectedConnections: rejected,
		ConnectionHitRate:   hitRate,
		LastUpdate:          time.Now().Unix(),
	}
}

// Close releases the PoolManager's resources, including the DoH resolver and
// the shared transport. It is safe to call multiple times; subsequent calls
// are no-ops. Returns any error encountered while closing sub-components.
func (pm *PoolManager) Close() error {
	if !atomic.CompareAndSwapInt32(&pm.closed, 0, 1) {
		return nil
	}

	var closeErr error

	// Close DoH resolver first to release its HTTP client resources
	if pm.dohResolver != nil {
		if err := pm.dohResolver.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("failed to close DoH resolver: %w", err))
		}
	}

	if pm.transport != nil {
		pm.transport.CloseIdleConnections()
	}

	// Aggregate counters are intentionally NOT reset here: trackedConn.Close()
	// decrements unconditionally (closeOnce guards the single run), so gauges
	// converge to zero on their own as connections close — including ones that
	// outlive this call. A reset here could interleave with a decrement that
	// already passed its guard, driving counters negative.

	return closeErr
}
