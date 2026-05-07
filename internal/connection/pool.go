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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybergodev/httpc/internal/dns"
	"github.com/cybergodev/httpc/internal/proxy"
	"github.com/cybergodev/httpc/internal/validation"
)

// ErrPoolExhausted is returned when the connection pool has reached its
// maximum capacity and cannot accept new connections. Callers can detect
// this condition with errors.Is(err, connection.ErrPoolExhausted).
var ErrPoolExhausted = fmt.Errorf("connection pool exhausted")

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

	activeConns   int64
	totalConns    int64
	rejectedConns int64

	hostConns sync.Map

	metrics *metrics

	closed int32
	mu     sync.RWMutex

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

// hostStats tracks per-host connection statistics
type hostStats struct {
	Host           string
	ActiveConns    int64
	TotalConns     int64
	FailedConns    int64
	LastUsed       int64      // Unix timestamp
	AverageLatency int64      // Nanoseconds
	mu             sync.Mutex // Protects AverageLatency updates
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
		config:  config,
		metrics: &metrics{},
	}

	// Initialize DoH resolver if enabled
	if config.EnableDoH {
		pm.dohResolver = dns.NewDoHResolver(nil, config.DoHCacheTTL)
	}

	transport := &http.Transport{
		DialContext:            pm.createDialer(),
		TLSHandshakeTimeout:    config.TLSHandshakeTimeout,
		TLSClientConfig:        pm.createTLSConfig(),
		ResponseHeaderTimeout:  config.ResponseHeaderTimeout,
		IdleConnTimeout:        config.IdleConnTimeout,
		ExpectContinueTimeout:  config.ExpectContinueTimeout,
		MaxResponseHeaderBytes: config.MaxResponseHeaderBytes,
		MaxIdleConns:           config.MaxIdleConns,
		MaxIdleConnsPerHost:    config.MaxIdleConnsPerHost,
		MaxConnsPerHost:        config.MaxConnsPerHost,
		ForceAttemptHTTP2:      config.ForceAttemptHTTP2,
		DisableCompression:     true, // Always disable automatic decompression - we handle it manually
		DisableKeepAlives:      config.DisableKeepAlives,
	}
	// Configure proxy settings with priority:
	// 1. Manual proxy URL (highest priority)
	// 2. System proxy detection (if enabled)
	// 3. Direct connection (no proxy)
	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		if proxyURL.Host == "" {
			return nil, fmt.Errorf("invalid proxy URL: empty host")
		}
		if scheme := proxyURL.Scheme; scheme != "http" && scheme != "https" {
			return nil, fmt.Errorf("invalid proxy URL scheme %q: must be http or https", scheme)
		}
		// SECURITY: Validate that the proxy host does not resolve to a private/reserved IP
		// unless AllowPrivateIPs is explicitly set. This prevents SSRF attacks where a
		// library consumer in a multi-tenant environment configures a proxy URL pointing
		// to internal services (e.g., cloud metadata at 169.254.169.254).
		if !config.AllowPrivateIPs {
			proxyHost := proxyURL.Hostname()
			if ip := net.ParseIP(proxyHost); ip != nil {
				if err := validation.ValidateIPWithExemptions(ip, config.ExemptNets); err != nil {
					return nil, fmt.Errorf("proxy URL host fails SSRF validation: %w", err)
				}
			} else {
				ips, err := net.LookupIP(proxyHost)
				if err != nil {
					return nil, fmt.Errorf("failed to resolve proxy host %q: %w", proxyHost, err)
				}
				for _, ip := range ips {
					if err := validation.ValidateIPWithExemptions(ip, config.ExemptNets); err != nil {
						return nil, fmt.Errorf("proxy host %q resolves to blocked IP %s: %w", proxyHost, ip, err)
					}
				}
			}
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		pm.proxyAddrs = append(pm.proxyAddrs, proxyURL.Host)
	} else if config.EnableSystemProxy {
		// No manual proxy, but system proxy detection is enabled
		// Automatically detect system proxy settings (reads from Windows registry,
		// macOS system settings, environment variables, etc.)
		detector := proxy.NewDetector()
		if proxyFunc := detector.GetProxyFunc(); proxyFunc != nil {
			transport.Proxy = proxyFunc
			testURL, _ := url.Parse("https://example.com")
			testReq := &http.Request{URL: testURL}
			if pu, err := proxyFunc(testReq); err == nil && pu != nil {
				pm.proxyAddrs = append(pm.proxyAddrs, pu.Host)
			}
		}
		// If proxyFunc is nil, transport.Proxy remains nil (direct connection)
	}
	// If neither condition is met, transport.Proxy remains nil (direct connection)

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
		startTime := time.Now()

		// Proxy connections bypass SSRF validation and DoH resolution —
		// the proxy address is explicitly configured by the user.
		if pm.isProxyAddr(address) {
			conn, err := dialer.DialContext(ctx, network, address)
			connTime := time.Since(startTime).Nanoseconds()
			stats := pm.updateConnectionMetrics(address, connTime, err == nil)

			if err != nil {
				atomic.AddInt64(&pm.rejectedConns, 1)
				if pm.config.MaxTotalConns > 0 {
					atomic.AddInt64(&pm.totalConns, -1)
				}
				return nil, fmt.Errorf("proxy connection failed: %w", err)
			}

			atomic.AddInt64(&pm.activeConns, 1)
			return &trackedConn{
				Conn:  conn,
				pm:    pm,
				host:  address,
				stats: stats,
			}, nil
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
			if !pm.config.AllowPrivateIPs {
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
				attemptStart := time.Now()
				conn, err := dialer.DialContext(ctx, network, ipAddress)
				connTime := time.Since(attemptStart).Nanoseconds()
				stats := pm.updateConnectionMetrics(address, connTime, err == nil)

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
		if !pm.config.AllowPrivateIPs {
			validatedAddr, err := pm.resolveAndValidateAddress(address)
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
		connTime := time.Since(startTime).Nanoseconds()
		stats := pm.updateConnectionMetrics(address, connTime, err == nil)

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
func (pm *PoolManager) resolveAndValidateAddress(address string) (string, error) {
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

	// For domain names, resolve and filter to allowed IPs
	ipAddrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
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
			tlsConfig.VerifyPeerCertificate = pm.createVerifyPeerCertificate(tlsConfig)
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
		tlsConfig.VerifyPeerCertificate = pm.createVerifyPeerCertificate(tlsConfig)
	}

	return tlsConfig
}

// createVerifyPeerCertificate creates a certificate verification function
// that combines standard verification with certificate pinning
func (pm *PoolManager) createVerifyPeerCertificate(tlsConfig *tls.Config) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// First, run the pinner verification
		if err := pm.config.certPinner.VerifyPeerCertificate(rawCerts, verifiedChains); err != nil {
			return fmt.Errorf("certificate pinning failed: %w", err)
		}

		// If InsecureSkipVerify is true, we skip standard verification
		if tlsConfig.InsecureSkipVerify {
			return nil
		}

		// Otherwise, standard TLS verification is performed by Go's TLS implementation
		// This function only adds the pinning check on top of standard verification
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
		atomic.AddInt64(&tc.pm.activeConns, -1)
		if tc.pm.config.MaxTotalConns > 0 {
			atomic.AddInt64(&tc.pm.totalConns, -1)
		}
		if tc.stats != nil {
			atomic.AddInt64(&tc.stats.ActiveConns, -1)
		}
		closeErr = tc.Conn.Close()
	})
	return closeErr
}

// updateConnectionMetrics efficiently updates per-host connection statistics.
// Returns the hostStats pointer so callers can capture it for trackedConn.
func (pm *PoolManager) updateConnectionMetrics(host string, connTime int64, success bool) *hostStats {
	// Trigger lazy eviction of stale host entries to prevent unbounded map growth.
	pm.evictStaleHosts()

	// Use a pre-allocated stats pointer to avoid allocation in the hot path
	value, loaded := pm.hostConns.LoadOrStore(host, &hostStats{
		Host:     host,
		LastUsed: time.Now().Unix(),
	})

	// Enforce max host entries to prevent unbounded map growth from unique hosts
	if !loaded {
		var count int
		pm.hostConns.Range(func(_, _ any) bool {
			count++
			return count < maxHostEntries+1
		})
		if count > maxHostEntries {
			pm.evictStaleHosts()
		}
	}

	// Safe type assertion with defensive check
	stats, ok := value.(*hostStats)
	if !ok || stats == nil {
		return nil // Defensive: skip update if type assertion fails
	}

	if success {
		atomic.AddInt64(&stats.TotalConns, 1)
		atomic.AddInt64(&stats.ActiveConns, 1)

		// Use mutex for latency update to ensure consistency under high contention
		// This is acceptable since latency tracking is not on the critical path
		stats.mu.Lock()
		current := stats.AverageLatency
		if current == 0 {
			stats.AverageLatency = connTime
		} else {
			stats.AverageLatency = (current*9 + connTime) / 10
		}
		stats.mu.Unlock()
	} else {
		atomic.AddInt64(&stats.FailedConns, 1)
	}

	atomic.StoreInt64(&stats.LastUsed, time.Now().Unix())
	return stats
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
					if s, ok := oldStats.(*hostStats); ok && atomic.LoadInt64(&s.ActiveConns) > 0 {
						pm.hostConns.Store(key, oldStats)
					}
				}
			}
		}
		return true
	})
}

func (pm *PoolManager) GetTransport() *http.Transport {
	return pm.transport
}

func (pm *PoolManager) GetMetrics() metrics {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

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

func (pm *PoolManager) Close() error {
	if !atomic.CompareAndSwapInt32(&pm.closed, 0, 1) {
		return nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

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

	return closeErr
}
