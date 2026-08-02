// Package proxypool provides a rotating proxy pool with passive health checking
// and circuit breaking for the httpc library.
//
// A Pool holds a list of proxy URLs and selects one per request according to a
// strategy (round-robin or random). Connection-level failures are tracked
// passively: after a configurable number of consecutive failures a proxy's
// circuit opens and it is temporarily skipped, then automatically retried
// (half-open probe) after a cooldown.
//
// HTTP status codes (e.g. 403) are NOT treated as proxy failures here — they
// are target-specific. Status-based rotation is handled at the retry layer by
// re-invoking Select, which naturally returns a different proxy under
// round-robin/random.
package proxypool

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/cybergodev/httpc/internal/validation"
)

// Strategy selects the algorithm for choosing a proxy from the pool.
type Strategy int

const (
	// StrategyRoundRobin cycles through proxies in order. Each selection
	// advances the cursor, so a retry that re-invokes Select naturally lands
	// on a different proxy without any extra wiring.
	StrategyRoundRobin Strategy = iota
	// StrategyRandom picks a healthy proxy uniformly at random.
	StrategyRandom
)

// Defaults applied when the corresponding Config field is zero.
const (
	defaultFailureThreshold = 3
	defaultCooldown         = 30 * time.Second
)

// ErrNoProxies is returned when the pool is created with no proxy URLs.
var ErrNoProxies = errors.New("proxy pool is empty")

// Config configures a proxy pool. Zero-value fields receive defaults.
type Config struct {
	// Proxies is the list of proxy URLs (http, https, socks5, socks5h).
	// Entries sharing the same host:port are collapsed to the first occurrence.
	Proxies []string

	// Strategy selects how proxies are chosen. The zero value defaults to
	// StrategyRoundRobin.
	Strategy Strategy

	// FailureThreshold is the number of consecutive connection failures to a
	// proxy before its circuit opens. Zero defaults to 3.
	FailureThreshold int

	// Cooldown is how long a circuit stays open before the proxy is eligible
	// again (half-open probe). Zero defaults to 30s.
	Cooldown time.Duration
}

// entry tracks the live state of a single proxy.
type entry struct {
	url  *url.URL // parsed proxy URL returned by Select
	host string   // url.Host (host:port); the key for ReportFailure/ReportSuccess

	failures  atomic.Int64 // consecutive failure count; reset to 0 on success
	openUntil atomic.Int64 // unix-nano timestamp until which the circuit is open; 0 = closed
}

// Pool is a concurrency-safe, rotating proxy pool with passive circuit breaking.
// It is safe for concurrent use by multiple goroutines. Create one with New.
type Pool struct {
	entries []*entry
	byHost  map[string]*entry // host:port -> entry; built once, read-only after

	counter atomic.Uint64 // round-robin cursor

	failureThreshold int
	cooldown         time.Duration
	strategy         Strategy
}

// New creates a proxy pool from the given configuration. All proxy URLs are
// validated with the same validator the public Config layer uses, so scheme
// and host rules cannot drift. Entries sharing a host:port are collapsed to
// the first occurrence.
func New(cfg Config) (*Pool, error) {
	if len(cfg.Proxies) == 0 {
		return nil, ErrNoProxies
	}

	threshold := cfg.FailureThreshold
	if threshold <= 0 {
		threshold = defaultFailureThreshold
	}
	cooldown := cfg.Cooldown
	if cooldown <= 0 {
		cooldown = defaultCooldown
	}

	entries := make([]*entry, 0, len(cfg.Proxies))
	byHost := make(map[string]*entry, len(cfg.Proxies))

	for _, raw := range cfg.Proxies {
		u, err := validation.ValidateProxyURL(raw)
		if err != nil {
			return nil, fmt.Errorf("proxy pool entry %q: %w", raw, err)
		}
		// Collapse duplicates by host:port — the same proxy listed twice would
		// skew round-robin distribution and double-count failures.
		if _, exists := byHost[u.Host]; exists {
			continue
		}
		e := &entry{url: u, host: u.Host}
		entries = append(entries, e)
		byHost[u.Host] = e
	}

	if len(entries) == 0 {
		return nil, ErrNoProxies
	}

	return &Pool{
		entries:          entries,
		byHost:           byHost,
		failureThreshold: threshold,
		cooldown:         cooldown,
		strategy:         cfg.Strategy,
	}, nil
}

// Select returns a proxy URL for the given request, skipping any proxy whose
// circuit is currently open. If every circuit is open it returns the proxy
// closest to recovery (earliest open-unil timestamp) as a best-effort fallback
// rather than failing outright.
//
// The request parameter is accepted to satisfy the http.Transport.Proxy
// signature; it is not used in the current implementation.
func (p *Pool) Select(_ *http.Request) (*url.URL, error) {
	now := time.Now().UnixNano()

	if p.strategy == StrategyRandom {
		return p.selectRandom(now), nil
	}
	return p.selectRoundRobin(now), nil
}

// selectRoundRobin advances the global cursor and scans forward, returning the
// first healthy entry. The cursor advances on every call, so a retry that
// re-invokes Select naturally lands on a different proxy.
func (p *Pool) selectRoundRobin(now int64) *url.URL {
	n := len(p.entries)
	start := int(p.counter.Add(1)-1) % n
	if start < 0 {
		start += n
	}

	var fallback *entry
	var fallbackOpenUntil int64

	for i := 0; i < n; i++ {
		e := p.entries[(start+i)%n]
		ou := e.openUntil.Load()
		if ou <= now {
			return e.url
		}
		if fallback == nil || ou < fallbackOpenUntil {
			fallback = e
			fallbackOpenUntil = ou
		}
	}
	return fallback.url
}

// selectRandom probes random entries, returning the first healthy one. If all
// random probes hit open circuits it falls back to the entry closest to
// recovery.
func (p *Pool) selectRandom(now int64) *url.URL {
	n := len(p.entries)

	for i := 0; i < n; i++ {
		e := p.entries[rand.IntN(n)]
		if e.openUntil.Load() <= now {
			return e.url
		}
	}

	var fallback *entry
	var fallbackOpenUntil int64
	for _, e := range p.entries {
		ou := e.openUntil.Load()
		if fallback == nil || ou < fallbackOpenUntil {
			fallback = e
			fallbackOpenUntil = ou
		}
	}
	return fallback.url
}

// NextIndex atomically advances the round-robin cursor once and returns the
// resulting entry index (modulo pool size). Unlike Select, it does not check
// circuit-open proxies or return a URL — it simply reserves a starting
// position. Used by the retry layer to reserve a unique base proxy per
// request, ensuring inter-request rotation; each retry attempt then uses
// base + attempt as the SelectIndex argument for intra-request rotation.
func (p *Pool) NextIndex() int {
	n := len(p.entries)
	idx := int(p.counter.Add(1)-1) % n
	if idx < 0 {
		idx += n
	}
	return idx
}

// SelectIndex returns a proxy URL deterministically indexed by attempt,
// skipping any proxy whose circuit is currently open. Unlike Select it does
// NOT advance the round-robin counter, so the same attempt always lands on the
// same proxy regardless of how many times the transport calls Proxy within a
// single logical request (e.g. redirect-following).
//
// This is used by the retry layer to guarantee that retry attempt N selects a
// DIFFERENT proxy than attempt N-1, even when redirect chains consume extra
// Select calls and would otherwise desynchronize the round-robin cursor.
func (p *Pool) SelectIndex(attempt int) *url.URL {
	now := time.Now().UnixNano()

	n := len(p.entries)
	start := attempt % n
	if start < 0 {
		start += n
	}

	var fallback *entry
	var fallbackOpenUntil int64

	for i := 0; i < n; i++ {
		e := p.entries[(start+i)%n]
		ou := e.openUntil.Load()
		if ou <= now {
			return e.url
		}
		if fallback == nil || ou < fallbackOpenUntil {
			fallback = e
			fallbackOpenUntil = ou
		}
	}
	return fallback.url
}

// ReportFailure records a connection-level failure (dial/TLS) for the proxy at
// the given host:port. After FailureThreshold consecutive failures the proxy's
// circuit opens and it is temporarily skipped by Select for Cooldown.
//
// Only connection-level failures should be reported here. HTTP status codes
// (e.g. 403) are target-specific and must NOT circuit-break a proxy; they are
// handled by retrying with a fresh Select (see Connection.ProxyRotateOnStatus).
func (p *Pool) ReportFailure(host string) {
	e, ok := p.byHost[host]
	if !ok {
		return
	}
	if e.failures.Add(1) >= int64(p.failureThreshold) {
		e.openUntil.Store(time.Now().Add(p.cooldown).UnixNano())
	}
}

// ReportSuccess resets a proxy's failure count and closes its circuit, marking
// it healthy for immediate reuse.
func (p *Pool) ReportSuccess(host string) {
	e, ok := p.byHost[host]
	if !ok {
		return
	}
	e.failures.Store(0)
	e.openUntil.Store(0)
}

// Hosts returns the host:port of every proxy in the pool, including those
// whose circuit is currently open. Used to seed SSRF exemptions so that proxy
// connections are never blocked by private-IP validation.
func (p *Pool) Hosts() []string {
	hosts := make([]string, len(p.entries))
	for i, e := range p.entries {
		hosts[i] = e.host
	}
	return hosts
}

// Len returns the number of proxies in the pool.
func (p *Pool) Len() int {
	return len(p.entries)
}
