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
var ErrPoolExhausted = fmt.Errorf("connection pool exhausted")

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

// hostConnMaxAge is the maximum age for a hostStats entry before it is
// eligible for eviction. Stale entries (no recent connections) are removed
// during periodic cleanup to prevent unbounded map growth.
const hostConnMaxAge = 30 * time.Minute

// maxHostEntries is the maximum number of per-host tracking entries.
// When exceeded, aggressive eviction runs regardless of the normal interval.
const maxHostEntries = 10000

// PoolManager provides intelligent connection pool management with monitoring
type PoolManager struct {
	config *Config

	transport   *http.Transport
	dohResolver *dns.DoHResolver
	proxyAddrs  []string
	proxyPool   *proxypool.Pool

	activeConns   int64
	totalConns    int64
	rejectedConns int64

	hostConns sync.Map

	// hostCount tracks the approximate number of entries in hostConns.
	// Used for O(1) maxHostEntries enforcement instead of expensive sync.Map.Range counting.
	// May drift slightly under high concurrency — acceptable for a memory-limit heuristic.
	hostCount atomic.Int64

	closed int32

	lastEviction int64 // Unix timestamp of last eviction run (atomic)
}

// certPinner defines the interface for certificate pinning
type certPinner interface {
	VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

// Config defines connection pool configuration.
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

	DisableCompression bool
	DisableKeepAlives  bool
	ForceAttemptHTTP2  bool

	CookieJar http.CookieJar

	// DNS configuration
	EnableDoH   bool          // Enable DNS-over-HTTPS
	DoHCacheTTL time.Duration // DoH cache TTL

	// Certificate pinning
	certPinner certPinner
}

// SetCertPinner sets the certificate pinner for TLS certificate verification.
func (c *Config) SetCertPinner(p certPinner) { c.certPinner = p }

// hostStats tracks per-host connection statistics.
//
// Only fields that are actually consumed are maintained here. Per-host dial
// latency and failed-connection counts were previously tracked but never
// surfaced — GetMetrics reports aggregate pool counters (total/active/
// rejected), not per-host figures — so they were removed to avoid a
// per-connection mutex Lock/Unlock and atomic op in the dial hot path.
type hostStats struct {
	Host        string
	ActiveConns int64
	TotalConns  int64
	LastUsed    int64 // Unix timestamp
}

// metrics provides connection pool performance metrics
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

		DisableCompression: false,
		DisableKeepAlives:  false,
		ForceAttemptHTTP2:  true,

		AllowPrivateIPs: false,
	}
}

// NewPoolManager creates a new connection pool manager with the given configuration.
func NewPoolManager(config *Config) (*PoolManager, error) {
	if config == nil {
		config = DefaultConfig()
	}

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
		pm.proxyAddrs = append(pm.proxyAddrs, proxyURL.Host)
		transport.Proxy = http.ProxyURL(proxyURL)
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
			if attempt, ok := ProxyAttemptFromContext(req.Context()); ok {
				u := pool.SelectIndex(attempt)
				if httpcDebug() {
					fmt.Fprintf(os.Stderr, "[httpc] proxy SelectIndex(%d) → %s\n", attempt, u.Host)
				}
				return u, nil
			}
			u, err := pool.Select(req)
			if httpcDebug() && err == nil {
				fmt.Fprintf(os.Stderr, "[httpc] proxy Select(round-robin) → %s\n", u.Host)
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
				testURL, _ := url.Parse(scheme + "://example.com")
				if pu, err := proxyFunc(&http.Request{URL: testURL}); err == nil && pu != nil {
					if !slices.Contains(pm.proxyAddrs, pu.Host) {
						pm.proxyAddrs = append(pm.proxyAddrs, pu.Host)
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
			newCount := atomic.AddInt64(&pm.totalConns, 1)
			if newCount > int64(pm.config.MaxTotalConns) {
				atomic.AddInt64(&pm.totalConns, -1)
				atomic.AddInt64(&pm.rejectedConns, 1)
				return nil, fmt.Errorf("%w (max %d)", ErrPoolExhausted, pm.config.MaxTotalConns)
			}
		}
		// Proxy connections bypass SSRF validation and DoH resolution —
		// the proxy address is explicitly configured by the user.
		if pm.isProxyAddr(address) {
			conn, err := dialer.DialContext(ctx, network, address)
			stats := pm.updateConnectionMetrics(address, err == nil)

			if err != nil {
				if pm.proxyPool != nil {
					pm.proxyPool.ReportFailure(address)
				}
				atomic.AddInt64(&pm.rejectedConns, 1)
				if pm.config.MaxTotalConns > 0 {
					atomic.AddInt64(&pm.totalConns, -1)
				}
				return nil, fmt.Errorf("%w: %w", ErrProxyConnectionFailed, err)
			}

			if pm.proxyPool != nil {
				pm.proxyPool.ReportSuccess(address)
			}
			atomic.AddInt64(&pm.activeConns, 1)
			return &trackedConn{
				Conn:  conn,
				pm:    pm,
				host:  address,
				stats: stats,
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
				atomic.AddInt64(&pm.rejectedConns, 1)
				if pm.config.MaxTotalConns > 0 {
					atomic.AddInt64(&pm.totalConns, -1)
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
					atomic.AddInt64(&pm.rejectedConns, 1)
					if pm.config.MaxTotalConns > 0 {
						atomic.AddInt64(&pm.totalConns, -1)
					}
					return nil, fmt.Errorf("SSRF protection: domain resolves only to blocked addresses")
				}
				resolvedIPs = allowedIPs
			}

			// Try to connect to each allowed IP until one succeeds
			var lastErr error
			for _, ip := range resolvedIPs {
				ipAddress := net.JoinHostPort(ip.String(), port)
				conn, err := dialer.DialContext(ctx, network, ipAddress)
				stats := pm.updateConnectionMetrics(address, err == nil)

				if err == nil {
					atomic.AddInt64(&pm.activeConns, 1)
					return &trackedConn{
						Conn:  conn,
						pm:    pm,
						host:  address,
						stats: stats,
					}, nil
				}
				lastErr = err
			}

			atomic.AddInt64(&pm.rejectedConns, 1)
			if pm.config.MaxTotalConns > 0 {
				atomic.AddInt64(&pm.totalConns, -1)
			}
			return nil, fmt.Errorf("connection failed after trying %d IPs: %w", len(resolvedIPs), lastErr)
		}

		// Standard path without DoH
		// SECURITY: Resolve DNS, validate all IPs, then dial the validated IP directly
		// to prevent DNS rebinding TOCTOU attacks where an attacker-controlled DNS
		// server returns a different IP between validation and actual connection.
		if !allowPrivateIPs {
			validatedAddr, err := pm.resolveAndValidateAddress(ctx, address)
			if err != nil {
				atomic.AddInt64(&pm.rejectedConns, 1)
				if pm.config.MaxTotalConns > 0 {
					atomic.AddInt64(&pm.totalConns, -1)
				}
				return nil, fmt.Errorf("SSRF protection: %w", err)
			}
			address = validatedAddr
		}

		conn, err := dialer.DialContext(ctx, network, address)
		stats := pm.updateConnectionMetrics(address, err == nil)

		if err != nil {
			atomic.AddInt64(&pm.rejectedConns, 1)
			if pm.config.MaxTotalConns > 0 {
				atomic.AddInt64(&pm.totalConns, -1)
			}
			return nil, fmt.Errorf("connection failed: %w", err)
		}

		atomic.AddInt64(&pm.activeConns, 1)

		return &trackedConn{
			Conn:  conn,
			pm:    pm,
			host:  address,
			stats: stats,
		}, nil
	}
}

// resolveAndValidateAddress resolves the given address and validates all resulting IPs
// against SSRF protection rules. It returns a validated "ip:port" string that should be
// dialed directly to prevent DNS rebinding TOCTOU attacks.
//
// SECURITY: By resolving DNS once and dialing the validated IP directly (instead of
// the original hostname), we eliminate the window where an attacker-controlled DNS
// server could return a different (private) IP on the second resolution.
func (pm *PoolManager) resolveAndValidateAddress(ctx context.Context, address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		port = "443"
	}

	// If the address is already an IP, validate it directly
	if ip := net.ParseIP(host); ip != nil {
		if err := validation.ValidateIPWithExemptions(ip, pm.config.ExemptNets); err != nil {
			return "", err
		}
		return address, nil
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
		return "", fmt.Errorf("DNS resolution failed for SSRF validation of %s: %w", host, err)
	}
	ips := make([]net.IP, len(ipAddrs))
	for i, addr := range ipAddrs {
		ips[i] = addr.IP
	}

	// Filter to public/exempted IPs — supports Split-Horizon DNS environments
	// where a domain may resolve to both public and private IPs.
	allowedIPs := validation.FilterAllowedIPs(ips, pm.config.ExemptNets)
	if len(allowedIPs) == 0 {
		return "", fmt.Errorf("domain %s resolves only to blocked addresses", host)
	}

	// Return the first allowed IP for direct dialing to prevent DNS rebinding
	return net.JoinHostPort(allowedIPs[0].String(), port), nil
}

func (pm *PoolManager) isProxyAddr(address string) bool {
	return slices.Contains(pm.proxyAddrs, address)
}

func (pm *PoolManager) createTLSConfig() *tls.Config {
	// If a custom TLS config is provided, use it (but add cert pinning if configured)
	if pm.config.TLSConfig != nil {
		tlsConfig := pm.config.TLSConfig.Clone()
		// Add certificate pinning verification if configured
		if pm.config.certPinner != nil {
			tlsConfig.VerifyPeerCertificate = pm.createVerifyPeerCertificate()
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
	host      string
	stats     *hostStats // captured at creation for direct Close() updates
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
		// Skip counter decrements if the pool is already closed — the pool's
		// own Close() has already cleared hostConns and reset counters.
		if atomic.LoadInt32(&tc.pm.closed) == 0 {
			atomic.AddInt64(&tc.pm.activeConns, -1)
			if tc.pm.config.MaxTotalConns > 0 {
				atomic.AddInt64(&tc.pm.totalConns, -1)
			}
			if tc.stats != nil {
				atomic.AddInt64(&tc.stats.ActiveConns, -1)
			}
		}
		closeErr = tc.Conn.Close()
	})
	return closeErr
}

// updateConnectionMetrics efficiently updates per-host connection statistics.
// Returns the hostStats pointer so callers can capture it for trackedConn.
func (pm *PoolManager) updateConnectionMetrics(host string, success bool) *hostStats {
	// Trigger lazy eviction of stale host entries to prevent unbounded map growth.
	pm.evictStaleHosts()

	// Fast path: check if host already tracked before allocating.
	if existing, ok := pm.hostConns.Load(host); ok {
		stats, ok := existing.(*hostStats)
		if !ok || stats == nil {
			return nil // Defensive: skip update if type assertion fails
		}
		pm.updateHostStats(stats, success)
		return stats
	}

	// Slow path: new host — allocate and store
	value, loaded := pm.hostConns.LoadOrStore(host, &hostStats{
		Host:     host,
		LastUsed: time.Now().Unix(),
	})

	// Track new entries via atomic counter for O(1) enforcement of maxHostEntries.
	if !loaded {
		if pm.hostCount.Add(1) > int64(maxHostEntries) {
			pm.evictStaleHosts()
		}
	}

	// Safe type assertion with defensive check
	stats, ok := value.(*hostStats)
	if !ok || stats == nil {
		return nil // Defensive: skip update if type assertion fails
	}

	pm.updateHostStats(stats, success)
	return stats
}

// updateHostStats applies connection metrics to an existing hostStats entry.
func (pm *PoolManager) updateHostStats(stats *hostStats, success bool) {
	if success {
		atomic.AddInt64(&stats.TotalConns, 1)
		atomic.AddInt64(&stats.ActiveConns, 1)
	}
	atomic.StoreInt64(&stats.LastUsed, time.Now().Unix())
}

// evictStaleHosts removes hostStats entries that haven't been used recently.
// Uses atomic CAS to ensure only one goroutine performs eviction at a time,
// avoiding contention in the hot path. Eviction runs at most once per minute.
func (pm *PoolManager) evictStaleHosts() {
	const evictionInterval int64 = 60 // seconds between eviction runs
	now := time.Now().Unix()

	last := atomic.LoadInt64(&pm.lastEviction)
	if now-last < evictionInterval {
		return
	}

	if !atomic.CompareAndSwapInt64(&pm.lastEviction, last, now) {
		return // Another goroutine is already evicting
	}

	cutoff := now - int64(hostConnMaxAge/time.Second)
	pm.hostConns.Range(func(key, value any) bool {
		if stats, ok := value.(*hostStats); ok && stats != nil {
			if atomic.LoadInt64(&stats.LastUsed) < cutoff && atomic.LoadInt64(&stats.ActiveConns) == 0 {
				// Use LoadAndDelete to atomically remove the entry. If a concurrent
				// connection incremented ActiveConns between the check above and here,
				// re-insert the entry to avoid orphaning in-use stats.
				if oldStats, loaded := pm.hostConns.LoadAndDelete(key); loaded {
					pm.hostCount.Add(-1)
					if s, ok := oldStats.(*hostStats); ok && atomic.LoadInt64(&s.ActiveConns) > 0 {
						// Re-insert with LoadOrStore so we never clobber a fresher
						// entry a concurrent connection stored after our delete, and
						// never double-count hostCount: only bump if our oldStats won.
						// LoadOrStore's second return is `loaded` (true = a different
						// entry already existed, ours was NOT stored), so we bump only
						// when ours was actually stored: !alreadyPresent.
						if _, alreadyPresent := pm.hostConns.LoadOrStore(key, oldStats); !alreadyPresent {
							pm.hostCount.Add(1) // oldStats was re-inserted: undo the decrement above
						}
					}
				}
			}
		}
		return true
	})
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

// GetMetrics returns a snapshot of current connection pool statistics,
// including active, total, and rejected connection counts and the connection
// hit rate.
func (pm *PoolManager) GetMetrics() metrics {
	total := atomic.LoadInt64(&pm.totalConns)
	rejected := atomic.LoadInt64(&pm.rejectedConns)
	active := atomic.LoadInt64(&pm.activeConns)
	hitRate := 0.0
	if total+rejected > 0 {
		hitRate = float64(total) / float64(total+rejected)
	}

	return metrics{
		ActiveConnections:   active,
		TotalConnections:    total,
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

	// Clean up per-host connection tracking map to prevent memory leak
	pm.hostConns.Range(func(key, _ any) bool {
		pm.hostConns.Delete(key)
		return true
	})
	pm.hostCount.Store(0)
	// Reset aggregate connection counters. trackedConn.Close() skips its
	// activeConns/totalConns decrement once closed==1, so connections established
	// concurrently with Close would otherwise leave phantom counts in
	// GetMetrics(). No subsequent decrement can run (the dialer rejects new
	// dials once closed), so resetting here cannot drive the counters negative.
	atomic.StoreInt64(&pm.activeConns, 0)
	atomic.StoreInt64(&pm.totalConns, 0)

	return closeErr
}
