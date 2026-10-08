package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cybergodev/httpc/internal/types"
	"github.com/cybergodev/httpc/internal/validation"
)

// maxRetriesUnset is the sentinel value for "not configured — use default".
// Request.maxRetries is initialized to this value in pool New functions.
const maxRetriesUnset = -1

// headersMapPool reduces allocations for the per-request headers map (map[string]string).
// Pooled maps are cleared before reuse and must not exceed 32 entries to prevent bloat.
// Stores the map value directly: boxing a map into any is allocation-free, whereas
// storing &m would force the parameter to escape (see httpHeaderPool for details).
var headersMapPool = sync.Pool{
	New: func() any {
		return make(map[string]string, 4)
	},
}

// queryParamsPool reduces allocations for the per-request query params map (map[string]any).
// Pooled maps are cleared before reuse and must not exceed 32 entries to prevent bloat.
var queryParamsPool = sync.Pool{
	New: func() any {
		return make(map[string]any, 4)
	},
}

func getHeadersMap() map[string]string {
	m, ok := headersMapPool.Get().(map[string]string)
	if !ok || m == nil {
		return make(map[string]string, 4)
	}
	return m
}

func putHeadersMap(m map[string]string) {
	if m == nil || len(m) > 32 {
		return
	}
	for k := range m {
		delete(m, k)
	}
	headersMapPool.Put(m)
}

func getQueryParamsMap() map[string]any {
	m, ok := queryParamsPool.Get().(map[string]any)
	if !ok || m == nil {
		return make(map[string]any, 4)
	}
	return m
}

func putQueryParamsMap(m map[string]any) {
	if m == nil || len(m) > 32 {
		return
	}
	for k := range m {
		delete(m, k)
	}
	queryParamsPool.Put(m)
}

// requestPool is a typed pool for Request objects that eliminates
// repetitive get/put/zeroing boilerplate.
type requestPool struct {
	pool sync.Pool
}

func newRequestPool() requestPool {
	return requestPool{
		pool: sync.Pool{
			New: func() any {
				return &Request{maxRetries: maxRetriesUnset}
			},
		},
	}
}

func (p *requestPool) get() *Request {
	req, ok := p.pool.Get().(*Request)
	if !ok || req == nil {
		return &Request{maxRetries: maxRetriesUnset}
	}
	return req
}

// resetRequest clears every field of a pooled Request and returns its pooled
// maps. Both requestPool.put and ReleaseRequest must go through here so a
// future Request field is reset in exactly one place.
func resetRequest(req *Request) {
	putHeadersMap(req.headers)
	putQueryParamsMap(req.queryParams)
	*req = Request{maxRetries: maxRetriesUnset}
}

func (p *requestPool) put(req *Request) {
	resetRequest(req)
	p.pool.Put(req)
}

// sharedRequestPool is a global pool for Request objects used by external packages
// (httpc middleware path, session capture). Consolidating into a single pool improves
// hit rates under concurrency compared to multiple separate pools.
// maxRetries defaults to maxRetriesUnset so middleware-path requests use config defaults.
var sharedRequestPool = sync.Pool{
	New: func() any { return &Request{maxRetries: maxRetriesUnset} },
}

// AcquireRequest retrieves a Request from the shared pool.
// The caller must call ReleaseRequest when done.
func AcquireRequest() *Request {
	req, ok := sharedRequestPool.Get().(*Request)
	if !ok || req == nil {
		return &Request{maxRetries: maxRetriesUnset}
	}
	return req
}

// ReleaseRequest returns a Request to the shared pool after clearing all fields.
// Resets maxRetries to maxRetriesUnset so recycled requests inherit the client's retry config.
func ReleaseRequest(req *Request) {
	if req == nil {
		return
	}
	resetRequest(req)
	sharedRequestPool.Put(req)
}

// requestCallback is a callback function invoked before a request is sent.
type requestCallback func(req *Request) error

// responseCallback is a callback function invoked after a response is received.
type responseCallback func(resp *Response) error

// Request represents an HTTP request with method, URL, headers, body, and options.
//
// The exported accessor and mutator methods below implement the
// types.RequestMutator interface (which embeds both read and write methods).
// They are trivial field pass-throughs and intentionally lack per-method godoc;
// refer to the interface definition for their contract.
type Request struct {
	method      string
	url         string
	headers     map[string]string
	queryParams map[string]any
	body        any
	timeout     time.Duration
	maxRetries  int
	// context carries the request's cancellation/deadline. Storing it here is an
	// intentional, narrow exception to the "do not store context in a struct"
	// guideline: Request is a short-lived, pooled, request-scoped object whose
	// lifetime is bounded by a single request — mirroring net/http.Request. It is
	// reset to its zero value when returned to the pool (see requestPool.put /
	// ReleaseRequest) and is never retained beyond the request. Long-lived structs
	// that outlive a request must continue to take context.Context as the first
	// parameter instead.
	context         context.Context
	cookies         []http.Cookie
	followRedirects *bool
	maxRedirects    *int
	onRequest       requestCallback
	onResponse      responseCallback
	streamBody      bool   // When true, skip buffering response body; caller reads via RawBodyReader
	sanitizedURL    string // Cached per-request sanitized URL, set by middleware on first access
	allowPrivateIPs *bool  // Per-request override of client-level AllowPrivateIPs (nil = use client policy)
	// retryNonIdempotent overrides client-level RetryNonIdempotent for this
	// request (nil = use client config).
	retryNonIdempotent *bool
	// noTimeout suppresses the client-level request timeout for this request.
	// An explicit per-request timeout (WithTimeout) still applies; a deadline
	// on the caller's context is always respected.
	noTimeout bool
}

// Compile-time interface check
var _ types.RequestMutator = (*Request)(nil)

// Accessors (implement RequestMutator)
func (r *Request) Method() string { return r.method }
func (r *Request) URL() string    { return r.url }

// Headers returns the internal pooled headers map. The reference is valid
// only for the lifetime of this request: after the request is released the
// map is cleared and recycled for other requests. Callers that need to
// retain the data (async logging, audit) must copy it.
func (r *Request) Headers() map[string]string { return r.headers }

// QueryParams returns the internal pooled query-parameter map, subject to
// the same lifetime contract as Headers — copy before retaining.
func (r *Request) QueryParams() map[string]any { return r.queryParams }
func (r *Request) Body() any                   { return r.body }
func (r *Request) Timeout() time.Duration      { return r.timeout }
func (r *Request) MaxRetries() int             { return r.maxRetries }
func (r *Request) Context() context.Context    { return r.context }
func (r *Request) Cookies() []http.Cookie      { return r.cookies }
func (r *Request) FollowRedirects() *bool      { return r.followRedirects }
func (r *Request) MaxRedirects() *int          { return r.maxRedirects }
func (r *Request) AllowPrivateIPs() *bool      { return r.allowPrivateIPs }
func (r *Request) RetryNonIdempotent() *bool   { return r.retryNonIdempotent }
func (r *Request) NoTimeout() bool             { return r.noTimeout }
func (r *Request) SanitizedURL() string        { return r.sanitizedURL }
func (r *Request) SetSanitizedURL(v string)    { r.sanitizedURL = v }

// Mutators
func (r *Request) SetMethod(v string) { r.method = v }
func (r *Request) SetURL(v string)    { r.url = v }

// SetHeaders replaces all headers with a COPY of v held in a pooled map.
//
// SECURITY (pool poisoning): Request objects are pooled, and resetRequest
// returns whatever map is stored here to the shared headersMapPool (after
// clearing it). Storing a caller-owned map by reference would hand that map
// to an unrelated future request — concurrent map writes, or request A's
// headers appearing in request B. User middleware reaches this method via the
// RequestMutator interface, so the setter must copy. Internal zero-copy
// moves of engine-owned pooled maps use moveHeaders (see Apply).
func (r *Request) SetHeaders(v map[string]string) {
	if v == nil {
		r.headers = nil
		return
	}
	h := getHeadersMap()
	maps.Copy(h, v)
	r.headers = h
}

// moveHeaders transfers ownership of an engine-pooled headers map without
// copying. The caller MUST guarantee the map was produced by getHeadersMap
// (engine-owned) and that no other reference retains it. Used by Apply.
func (r *Request) moveHeaders(v map[string]string) { r.headers = v }

func (r *Request) SetHeader(key, value string) {
	if r.headers == nil {
		r.headers = getHeadersMap()
	}
	r.headers[key] = value
}

// SetQueryParams replaces all query parameters with a COPY of v held in a
// pooled map. See SetHeaders for why copying is mandatory (pool poisoning).
func (r *Request) SetQueryParams(v map[string]any) {
	if v == nil {
		r.queryParams = nil
		return
	}
	q := getQueryParamsMap()
	maps.Copy(q, v)
	r.queryParams = q
}

// moveQueryParams transfers ownership of an engine-pooled query-params map.
// See moveHeaders for the ownership contract. Used by Apply.
func (r *Request) moveQueryParams(v map[string]any) { r.queryParams = v }

func (r *Request) EnsureQueryParams() map[string]any {
	if r.queryParams == nil {
		r.queryParams = getQueryParamsMap()
	}
	return r.queryParams
}
func (r *Request) SetBody(v any)                 { r.body = v }
func (r *Request) SetTimeout(v time.Duration)    { r.timeout = v }
func (r *Request) SetMaxRetries(v int)           { r.maxRetries = v }
func (r *Request) SetContext(v context.Context)  { r.context = v }
func (r *Request) SetCookies(v []http.Cookie)    { r.cookies = v }
func (r *Request) SetFollowRedirects(v *bool)    { r.followRedirects = v }
func (r *Request) SetMaxRedirects(v *int)        { r.maxRedirects = v }
func (r *Request) SetAllowPrivateIPs(v *bool)    { r.allowPrivateIPs = v }
func (r *Request) SetRetryNonIdempotent(v *bool) { r.retryNonIdempotent = v }
func (r *Request) SetNoTimeout(v bool)           { r.noTimeout = v }
func (r *Request) StreamBody() bool              { return r.streamBody }
func (r *Request) SetStreamBody(v bool)          { r.streamBody = v }

// Apply transfers all per-request mutable state from src onto r. It exists so
// callers that forward a request through a fresh engine.Request call — e.g.
// the facade middleware chain's terminal handler — stay in sync with the
// Request type by construction instead of enumerating fields by hand.
//
// Ownership: the pooled headers and query-parameter maps are MOVED, not
// copied — src's references are cleared so a later release of src cannot
// return the same maps to the pool twice. The context is not transferred:
// it is owned by the engine.Client.Request call that created r. Optional
// fields (followRedirects, maxRedirects, allowPrivateIPs, callbacks) are
// copied only when set on src, preserving r's defaults otherwise.
func (r *Request) Apply(src *Request) {
	r.SetMethod(src.method)
	r.SetURL(src.url)
	// Zero-copy MOVE of engine-owned pooled maps (see moveHeaders for the
	// ownership contract). The public SetHeaders/SetQueryParams copy because
	// middleware can call them with caller-owned maps.
	r.moveHeaders(src.headers)
	r.moveQueryParams(src.queryParams)
	r.SetBody(src.body)
	r.SetTimeout(src.timeout)
	r.SetMaxRetries(src.maxRetries)
	r.SetCookies(src.cookies)
	if src.followRedirects != nil {
		r.SetFollowRedirects(src.followRedirects)
	}
	if src.maxRedirects != nil {
		r.SetMaxRedirects(src.maxRedirects)
	}
	if src.allowPrivateIPs != nil {
		r.SetAllowPrivateIPs(src.allowPrivateIPs)
	}
	if src.retryNonIdempotent != nil {
		r.SetRetryNonIdempotent(src.retryNonIdempotent)
	}
	r.SetNoTimeout(src.noTimeout)
	r.SetStreamBody(src.streamBody)
	if src.onRequest != nil {
		r.SetOnRequest(src.onRequest)
	}
	if src.onResponse != nil {
		r.SetOnResponse(src.onResponse)
	}
	// Ownership transfer of pooled maps (see doc comment).
	src.headers = nil
	src.queryParams = nil
}

// Callback accessors
func (r *Request) OnRequest() requestCallback        { return r.onRequest }
func (r *Request) OnResponse() responseCallback      { return r.onResponse }
func (r *Request) SetOnRequest(cb requestCallback)   { r.onRequest = cb }
func (r *Request) SetOnResponse(cb responseCallback) { r.onResponse = cb }

// stringsReaderPool reduces allocations for strings.Reader used in request bodies
var stringsReaderPool = sync.Pool{
	New: func() any { return &strings.Reader{} },
}

// bytesReaderPool reduces allocations for bytes.Reader used in request bodies
var bytesReaderPool = sync.Pool{
	New: func() any { return &bytes.Reader{} },
}

// stringBuilderPool reduces allocations for strings.Builder used in escapeQuotes
var stringBuilderPool = sync.Pool{
	New: func() any {
		sb := &strings.Builder{}
		return sb
	},
}

// maxMultipartBufferSize limits the maximum buffer size returned to the pool
// to prevent memory bloat from large file uploads (256KB)
const maxMultipartBufferSize = 256 * 1024

// maxJSONBufferSize limits the maximum buffer size for JSON encoding (1MB)
const maxJSONBufferSize = 1024 * 1024

// newMultipartBoundary generates a random multipart boundary: 30 random
// bytes, hex-encoded — the same construction as mime/multipart.randomBoundary
// (60 chars, well under the 70-char RFC 2046 limit). The hex alphabet contains
// no RFC 2045 tspecials, so the boundary never needs quoting in the
// Content-Type header (see the FormDataContentType note in Build).
// Unlike the stdlib, which panics when crypto/rand fails, the error is
// returned to the caller.
func newMultipartBoundary() (string, error) {
	var b [30]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate multipart boundary: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// writeMultipartPartHeader writes one multipart part's delimiter and MIME
// headers directly into buf. The bytes are identical to what
// mime/multipart.Writer.CreatePart produces for the two headers this engine
// emits: the first part's delimiter is "--<boundary>\r\n", later parts repeat
// "\r\n--<boundary>\r\n", headers appear as "%s: %s\r\n" lines in sorted key
// order (Content-Disposition sorts before Content-Type), and the header block
// ends with a blank line. Writing directly into the pooled buffer avoids
// CreatePart's per-part allocations (an escaping bytes.Buffer, several
// fmt.Fprintf calls, and a sorted-keys slice). TestMultipartWireParity pins
// this byte-for-byte against the stdlib.
// first tracks whether this is the first part of the body.
func writeMultipartPartHeader(buf *bytes.Buffer, first *bool, boundary, disposition, contentType string) {
	if *first {
		buf.WriteString("--")
		*first = false
	} else {
		buf.WriteString("\r\n--")
	}
	buf.WriteString(boundary)
	buf.WriteString("\r\nContent-Disposition: ")
	buf.WriteString(disposition)
	if contentType != "" {
		buf.WriteString("\r\nContent-Type: ")
		buf.WriteString(contentType)
	}
	buf.WriteString("\r\n\r\n")
}

// multipartBufferPool reduces allocations for multipart form data buffers
var multipartBufferPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 8*1024))
	},
}

// jsonBufferPool reduces allocations for JSON encoding buffers
var jsonBufferPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 512))
	},
}

// pooledStringsReader wraps a strings.Reader and returns it to the pool on
// Close. Release happens ONLY in Close — never on EOF in Read: net/http reads
// the body to EOF and closes it later (on HTTP/2, from the writeLoop
// goroutine). Releasing at EOF would return the wrapper to the pool while a
// delayed Close can still arrive; another request could then acquire the
// wrapper, and the stale Close would release the new request's live reader.
type pooledStringsReader struct {
	reader   *strings.Reader
	released bool
}

func (r *pooledStringsReader) Read(p []byte) (n int, err error) {
	if r.reader == nil {
		return 0, io.EOF
	}
	return r.reader.Read(p)
}

func (r *pooledStringsReader) Close() error {
	r.release()
	return nil
}

func (r *pooledStringsReader) release() {
	if r.released {
		return
	}
	r.released = true
	if r.reader != nil {
		r.reader.Reset("")
		stringsReaderPool.Put(r.reader)
		r.reader = nil
	}
	stringsReaderWrapperPool.Put(r)
}

// pooledBytesReader wraps a bytes.Reader and returns it to the pool on Close
// only — see pooledStringsReader for why release-on-EOF is unsafe.
type pooledBytesReader struct {
	reader   *bytes.Reader
	released bool
}

func (r *pooledBytesReader) Read(p []byte) (n int, err error) {
	if r.reader == nil {
		return 0, io.EOF
	}
	return r.reader.Read(p)
}

func (r *pooledBytesReader) Close() error {
	r.release()
	return nil
}

func (r *pooledBytesReader) release() {
	if r.released {
		return
	}
	r.released = true
	if r.reader != nil {
		r.reader.Reset(nil)
		bytesReaderPool.Put(r.reader)
		r.reader = nil
	}
	bytesReaderWrapperPool.Put(r)
}

// stringsReaderWrapperPool reduces allocations for pooledStringsReader wrapper structs.
var stringsReaderWrapperPool = sync.Pool{
	New: func() any { return &pooledStringsReader{} },
}

// bytesReaderWrapperPool reduces allocations for pooledBytesReader wrapper structs.
var bytesReaderWrapperPool = sync.Pool{
	New: func() any { return &pooledBytesReader{} },
}

// getPooledStringsReader gets a strings.Reader from the pool and wraps it
func getPooledStringsReader(s string) io.Reader {
	reader, ok := stringsReaderPool.Get().(*strings.Reader)
	if !ok || reader == nil {
		reader = &strings.Reader{}
	}
	reader.Reset(s)
	wrapper, _ := stringsReaderWrapperPool.Get().(*pooledStringsReader)
	if wrapper == nil {
		wrapper = &pooledStringsReader{}
	}
	wrapper.reader = reader
	wrapper.released = false
	return wrapper
}

// getPooledBytesReader gets a bytes.Reader from the pool and wraps it
func getPooledBytesReader(b []byte) io.Reader {
	reader, ok := bytesReaderPool.Get().(*bytes.Reader)
	if !ok || reader == nil {
		reader = &bytes.Reader{}
	}
	reader.Reset(b)
	wrapper, _ := bytesReaderWrapperPool.Get().(*pooledBytesReader)
	if wrapper == nil {
		wrapper = &pooledBytesReader{}
	}
	wrapper.reader = reader
	wrapper.released = false
	return wrapper
}

// rawCacheMaxSize limits the raw-string URL cache to prevent unbounded growth
// from URL variants (e.g., different query parameter orderings for the same endpoint).
const rawCacheMaxSize = 2048

// urlCache provides a thread-safe cache for parsed URLs to avoid expensive
// url.Parse() calls for repeated URLs. Eviction is insertion-order (FIFO):
// when the entries map reaches maxSize the oldest inserted key is dropped
// (see evictOldest). This is simpler than true LRU and sufficient here —
// hot URLs are typically re-inserted soon after eviction anyway.
//
// SECURITY: The cache uses a sanitized URL as the key (sensitive query parameter
// values redacted) to prevent credentials from persisting in memory.
// Callers always receive a clone of the cached entry to prevent mutation.
type urlCache struct {
	mu      sync.RWMutex
	raw     map[string]*url.URL // Fast path: raw URL string -> parsed URL
	entries map[string]*url.URL // Sanitized key -> parsed URL (for sensitive URLs)
	keys    []string            // Insertion order for FIFO eviction (hits do not refresh position)
	maxSize int
}

// globalURLCache is the shared URL cache for all engine.Client instances.
// All clients share a single cache (max 1024 entries), so one client's
// URLs may evict another's. This is an intentional trade-off: URL parsing
// is expensive and most workloads benefit from cross-client reuse.
var globalURLCache = &urlCache{
	raw:     make(map[string]*url.URL, 256),
	entries: make(map[string]*url.URL, 256),
	keys:    make([]string, 0, 256),
	maxSize: 1024,
}

// sanitizeURLKey produces a cache-safe URL string by redacting sensitive
// query parameter values (token, api_key, password, etc.).
// This prevents sensitive data from persisting in cache keys.
func sanitizeURLKey(u *url.URL) string {
	if u.RawQuery == "" {
		return u.String()
	}
	q := u.Query()
	redacted := false
	for key := range q {
		if validation.IsSensitiveQueryParam(key) {
			q.Set(key, "[REDACTED]")
			redacted = true
		}
	}
	clone := *u
	clone.User = nil
	if redacted {
		clone.RawQuery = q.Encode()
	}
	return clone.String()
}

// hasSensitiveContent returns true if the raw URL string contains credentials
// or sensitive query parameters that should not be stored in the raw string cache.
func hasSensitiveContent(rawURL string) bool {
	// '@' in the URL indicates user:pass credentials before the host
	if strings.IndexByte(rawURL, '@') >= 0 {
		return true
	}
	// Only check query parameters if present
	if _, query, ok := strings.Cut(rawURL, "?"); ok {
		return validation.HasSensitiveQueryParams(query)
	}
	return false
}

// evictRawIfNeeded removes stale raw cache entries when the map exceeds
// rawCacheMaxSize. Must be called with c.mu held for writing.
//
// A "live" raw entry is one whose *url.URL pointer also appears in the entries
// map — keeping it avoids a re-parse on the next access. Stale entries (pointer
// no longer in entries) are discarded. The previous implementation scanned the
// entries map for each raw entry — O(N×M), up to ~2M pointer comparisons under
// a write lock. Building a pointer set once reduces this to O(N+M).
func (c *urlCache) evictRawIfNeeded() {
	if len(c.raw) < rawCacheMaxSize {
		return
	}
	live := make(map[*url.URL]bool, len(c.entries))
	for _, u := range c.entries {
		live[u] = true
	}
	for k, v := range c.raw {
		if !live[v] {
			delete(c.raw, k)
		}
		if len(c.raw) < rawCacheMaxSize/2 {
			return
		}
	}
}

// Get retrieves a parsed URL from cache or parses and caches it.
// SECURITY: Uses sanitized URL as cache key to prevent sensitive data persistence.
// Raw string cache is skipped for URLs containing credentials.
// Returns a cloned URL to ensure cached entries remain immutable.
func (c *urlCache) Get(rawURL string) (*url.URL, error) {
	return c.getInternal(rawURL, true)
}

// GetReadOnly retrieves a parsed URL from cache without cloning.
// The caller MUST NOT modify the returned URL — it is shared across goroutines.
// Returns a reference to the cached entry on cache hit; on cache miss, the
// newly parsed URL is stored and the same reference is returned (no clone needed
// since the caller is the first and only holder at that point).
func (c *urlCache) GetReadOnly(rawURL string) (*url.URL, error) {
	return c.getInternal(rawURL, false)
}

// getInternal is the shared implementation for Get and GetReadOnly.
// When clone is true, the returned URL is deep-copied to prevent mutation
// of cached entries. When false, the cached pointer is returned directly
// (read-only contract enforced at call site).
//
// The raw cache is consulted before the sensitive-content scan: raw entries
// are only inserted after passing hasSensitiveContent, so a hit implies a
// non-sensitive URL and the scan (an 8–80ns per-request cost) is skipped
// entirely on the hot repeated-URL path.
func (c *urlCache) getInternal(rawURL string, clone bool) (*url.URL, error) {
	// Fast path: check raw string cache first (avoids url.Parse for repeated URLs)
	c.mu.RLock()
	if c.raw != nil {
		if cached, ok := c.raw[rawURL]; ok {
			c.mu.RUnlock()
			if clone {
				return cloneURL(cached), nil
			}
			return cached, nil
		}
	}
	c.mu.RUnlock()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	parsed.User = nil

	// Only URLs that failed the sensitive-content scan need the expensive
	// redacting key (u.Query + Encode, ~5 allocations). Non-sensitive URLs
	// are keyed by the raw string itself — an injective key that identifies
	// the entry exactly as well as the sanitized form.
	sensitive := hasSensitiveContent(rawURL)
	cacheKey := rawURL
	if sensitive {
		cacheKey = sanitizeURLKey(parsed)
	}

	// Second fast path: check sanitized cache
	c.mu.RLock()
	if cached, ok := c.entries[cacheKey]; ok {
		c.mu.RUnlock()
		if !sensitive {
			c.populateRawCache(rawURL, cached)
		}
		if clone {
			return cloneURL(cached), nil
		}
		return cached, nil
	}
	c.mu.RUnlock()

	// Slow path: cache the parsed URL
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if cached, ok := c.entries[cacheKey]; ok {
		if !sensitive {
			c.populateRawCacheLocked(rawURL, cached)
		}
		if clone {
			return cloneURL(cached), nil
		}
		return cached, nil
	}

	// SECURITY: Evict oldest entry if cache is full
	c.evictOldest()

	c.entries[cacheKey] = parsed
	if !sensitive {
		c.populateRawCacheLocked(rawURL, parsed)
	}
	c.keys = append(c.keys, cacheKey)

	if clone {
		return cloneURL(parsed), nil
	}
	return parsed, nil
}

// populateRawCache adds a raw→parsed mapping under a separate write lock.
// Used when the caller only holds a read lock on c.mu.
func (c *urlCache) populateRawCache(rawURL string, cached *url.URL) {
	c.mu.Lock()
	if c.raw == nil {
		c.raw = make(map[string]*url.URL, 16)
	}
	if _, exists := c.raw[rawURL]; !exists {
		c.evictRawIfNeeded()
		c.raw[rawURL] = cached
	}
	c.mu.Unlock()
}

// populateRawCacheLocked adds a raw→parsed mapping when the caller already
// holds c.mu for writing. Must be called with c.mu held.
func (c *urlCache) populateRawCacheLocked(rawURL string, cached *url.URL) {
	if c.raw == nil {
		c.raw = make(map[string]*url.URL, 16)
	}
	if _, exists := c.raw[rawURL]; !exists {
		c.evictRawIfNeeded()
		c.raw[rawURL] = cached
	}
}

// evictOldest removes the oldest entry when the cache is full.
// Must be called with c.mu held for writing.
//
// It deliberately does NOT scan the raw map for entries pointing at the
// evicted *url.URL: an orphaned raw entry is still a correct parse of its
// own key, so serving it is harmless, and evictRawIfNeeded reclaims raw
// entries once the raw map exceeds its own cap. The previous per-eviction
// O(|raw|) scan under the write lock was a contention hotspot once the
// entries map reached maxSize.
func (c *urlCache) evictOldest() {
	if len(c.entries) < c.maxSize || len(c.keys) == 0 {
		return
	}
	oldestKey := c.keys[0]
	delete(c.entries, oldestKey)
	c.keys = c.keys[1:]
	if cap(c.keys) > len(c.keys)*2 {
		newKeys := make([]string, len(c.keys), len(c.keys)*2)
		copy(newKeys, c.keys)
		c.keys = newKeys
	}
}

// cloneURL creates a deep copy of a URL
// to ensure cached entries remain immutable.
// Allocates directly rather than using sync.Pool — pooled objects
// were never returned, causing unbounded memory growth.
func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	return &url.URL{
		Scheme:      u.Scheme,
		Opaque:      u.Opaque,
		Host:        u.Host,
		Path:        u.Path,
		RawPath:     u.RawPath,
		OmitHost:    u.OmitHost,
		ForceQuery:  u.ForceQuery,
		RawQuery:    u.RawQuery,
		Fragment:    u.Fragment,
		RawFragment: u.RawFragment,
	}
}

// clear removes all entries from the cache
func (c *urlCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.raw = make(map[string]*url.URL, 256)
	c.entries = make(map[string]*url.URL, 256)
	c.keys = make([]string, 0, 256)
}

// size returns the current number of cached entries
func (c *urlCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// getMultipartBuffer gets a bytes.Buffer from the pool for multipart form data
func getMultipartBuffer() *bytes.Buffer {
	buf, ok := multipartBufferPool.Get().(*bytes.Buffer)
	if !ok || buf == nil {
		return bytes.NewBuffer(make([]byte, 0, 8*1024))
	}
	buf.Reset()
	return buf
}

// putMultipartBuffer returns a bytes.Buffer to the pool.
// SECURITY: Resets the buffer before returning to prevent data leakage.
// Buffers larger than maxMultipartBufferSize are discarded to prevent memory bloat.
func putMultipartBuffer(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxMultipartBufferSize {
		return // Discard large buffers
	}
	// SECURITY: Reset clears the buffer and allows GC to collect old data
	buf.Reset()
	multipartBufferPool.Put(buf)
}

// pooledMultipartBuffer wraps a bytes.Buffer and returns it to the pool when fully read.
// This enables buffer reuse for multipart form data without premature recycling.
type pooledMultipartBuffer struct {
	buf   *bytes.Buffer
	owned bool // Tracks if buffer still needs to be returned to pool
}

// multipartBufferWrapperPool reduces allocations for pooledMultipartBuffer wrapper structs.
var multipartBufferWrapperPool = sync.Pool{
	New: func() any { return &pooledMultipartBuffer{} },
}

// getPooledMultipartBufferWrapper creates a pooledMultipartBuffer from the pool.
func getPooledMultipartBufferWrapper(buf *bytes.Buffer) *pooledMultipartBuffer {
	wrapper, _ := multipartBufferWrapperPool.Get().(*pooledMultipartBuffer)
	if wrapper == nil {
		wrapper = &pooledMultipartBuffer{}
	}
	wrapper.buf = buf
	wrapper.owned = true
	return wrapper
}

func (r *pooledMultipartBuffer) Read(p []byte) (n int, err error) {
	if r.buf == nil {
		return 0, io.EOF
	}
	return r.buf.Read(p)
}

func (r *pooledMultipartBuffer) Close() error {
	r.release()
	return nil
}

func (r *pooledMultipartBuffer) release() {
	if !r.owned {
		return
	}
	r.owned = false
	if r.buf != nil {
		putMultipartBuffer(r.buf)
		r.buf = nil
	}
	multipartBufferWrapperPool.Put(r)
}

// getJSONBuffer retrieves a bytes.Buffer from the pool for JSON encoding.
func getJSONBuffer() *bytes.Buffer {
	buf, ok := jsonBufferPool.Get().(*bytes.Buffer)
	if !ok || buf == nil {
		return bytes.NewBuffer(make([]byte, 0, 512))
	}
	buf.Reset()
	return buf
}

// putJSONBuffer returns a bytes.Buffer to the JSON pool.
// SECURITY: Resets the buffer before returning to prevent data leakage.
// Buffers larger than maxJSONBufferSize are discarded to prevent memory bloat.
func putJSONBuffer(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxJSONBufferSize {
		return
	}
	buf.Reset()
	jsonBufferPool.Put(buf)
}

// pooledJSONBuffer wraps a bytes.Buffer for JSON data and returns it to the pool when fully read.
type pooledJSONBuffer struct {
	buf   *bytes.Buffer
	owned bool
}

// jsonBufferWrapperPool reduces allocations for pooledJSONBuffer wrapper structs.
var jsonBufferWrapperPool = sync.Pool{
	New: func() any { return &pooledJSONBuffer{} },
}

// getPooledJSONBufferWrapper creates a pooledJSONBuffer from the pool.
func getPooledJSONBufferWrapper(buf *bytes.Buffer) *pooledJSONBuffer {
	wrapper, _ := jsonBufferWrapperPool.Get().(*pooledJSONBuffer)
	if wrapper == nil {
		wrapper = &pooledJSONBuffer{}
	}
	wrapper.buf = buf
	wrapper.owned = true
	return wrapper
}

func (r *pooledJSONBuffer) Read(p []byte) (n int, err error) {
	if r.buf == nil {
		return 0, io.EOF
	}
	return r.buf.Read(p)
}

func (r *pooledJSONBuffer) Close() error {
	r.release()
	return nil
}

func (r *pooledJSONBuffer) release() {
	if !r.owned {
		return
	}
	r.owned = false
	if r.buf != nil {
		putJSONBuffer(r.buf)
		r.buf = nil
	}
	jsonBufferWrapperPool.Put(r)
}

// httpRequestPool reduces allocations for the per-request *http.Request used
// as a template before WithContext. The template is returned to the pool
// immediately after WithContext creates the actual request.
var httpRequestPool = sync.Pool{
	New: func() any { return &http.Request{} },
}

// Pre-canonicalized forms of the header keys set on every request. Computing
// these once at init time avoids a per-request http.CanonicalHeaderKey
// allocation (which allocates even for already-canonical input) on the hot
// path. Keys are stored exactly as http.CanonicalHeaderKey would produce them.
var (
	hdrContentType    = http.CanonicalHeaderKey("Content-Type")
	hdrAcceptEncoding = http.CanonicalHeaderKey("Accept-Encoding")
	hdrUserAgent      = http.CanonicalHeaderKey("User-Agent")
	hdrAuthorization  = http.CanonicalHeaderKey("Authorization")
	hdrCookie         = http.CanonicalHeaderKey("Cookie")
	hdrContentLength  = http.CanonicalHeaderKey("Content-Length")
	hdrHost           = http.CanonicalHeaderKey("Host")

	// hdrContentEncoding is used by responseProcessor — defined here alongside
	// the other pre-canonicalized keys to keep them in one place.
	hdrContentEncoding = http.CanonicalHeaderKey("Content-Encoding")
)

type requestProcessor struct {
	config           *Config
	canonicalHeaders map[string]string // config.Headers with pre-canonicalized keys
}

func newRequestProcessor(config *Config) *requestProcessor {
	rp := &requestProcessor{config: config}
	// Pre-canonicalize config header keys once at construction time.
	// This eliminates per-request http.CanonicalHeaderKey calls for every
	// config header, plus the http.Header.Get overhead (which internally
	// re-canonicalizes on every lookup).
	if len(config.Headers) > 0 {
		rp.canonicalHeaders = make(map[string]string, len(config.Headers))
		for k, v := range config.Headers {
			rp.canonicalHeaders[http.CanonicalHeaderKey(k)] = v
		}
	}
	return rp
}

// headerValueIsEmpty reports whether key is absent from h or its first value
// is the empty string. It replaces http.Header.Get(key) == "" on the hot path:
// Get always calls textproto.CanonicalMIMEHeaderKey internally, even when the
// key is already canonical. A direct map read skips that entirely. The key
// MUST already be in canonical (http.CanonicalHeaderKey) form.
func headerValueIsEmpty(h http.Header, key string) bool {
	vals := h[key]
	return len(vals) == 0 || vals[0] == ""
}

func (p *requestProcessor) Build(req *Request) (*http.Request, error) {
	if req.Method() == "" {
		req.SetMethod("GET")
	}

	if req.Context() == nil {
		req.SetContext(backgroundCtx)
	}

	// Use cached URL parsing to avoid expensive url.Parse() calls.
	// Optimization: use read-only cache path when URL won't be modified,
	// avoiding a cloneURL allocation per request.
	var parsedURL *url.URL
	var urlErr error
	if len(req.QueryParams()) == 0 {
		parsedURL, urlErr = globalURLCache.GetReadOnly(req.URL())
	} else {
		parsedURL, urlErr = globalURLCache.Get(req.URL())
	}
	if urlErr != nil {
		return nil, fmt.Errorf("invalid URL: %w", urlErr)
	}

	if len(req.QueryParams()) > 0 {
		// parsedURL is already a clone from the cache, safe to modify directly.
		parsedURL.RawQuery = appendQueryParams(parsedURL.RawQuery, req.QueryParams())
	}

	// Redirect following decides whether a replayable body is worth capturing:
	// net/http only calls Request.GetBody to re-send a body when following a
	// 307/308 redirect. Mirrors the effective-policy resolution at the
	// SetRedirectPolicy call site in Client.executeRequest.
	followRedirects := p.config.FollowRedirects
	if req.FollowRedirects() != nil {
		followRedirects = *req.FollowRedirects()
	}

	var body io.Reader
	var contentType string
	// replaySrc holds the body from a stable (non-pooled) source so GetBody can
	// produce a fresh reader per 307/308 hop: string/[]byte sources are closed
	// over as-is (immutable or caller-owned, same exposure as net/http's own
	// NewRequest); JSON/multipart bytes live in pooled buffers that are
	// recycled on body Close — which happens before any redirect hop needs
	// GetBody — so they are cloned once, and only when redirects are enabled.
	// Generic io.Reader bodies are left nil (not replayable), matching
	// net/http's rules; the retry path has already buffered those to []byte.
	var replaySrc any

	if req.Body() != nil {
		switch v := req.Body().(type) {
		case string:
			body = getPooledStringsReader(v)
			contentType = "text/plain"
			replaySrc = v
		case []byte:
			body = getPooledBytesReader(v)
			contentType = "application/octet-stream"
			replaySrc = v
		case io.Reader:
			body = v
		default:
			// Headers keep the caller's original key casing, so a lowercase
			// "content-type" must still be detected — otherwise a struct body
			// would be serialized as JSON under an XML Content-Type.
			existingContentType := ""
			for k, v := range req.Headers() {
				if http.CanonicalHeaderKey(k) == "Content-Type" {
					existingContentType = v
					break
				}
			}

			if isXMLContentType(existingContentType) {
				xmlData, err := xml.Marshal(v)
				if err != nil {
					return nil, fmt.Errorf("marshal XML failed: %w", err)
				}
				body = getPooledBytesReader(xmlData)
				contentType = "application/xml"
				replaySrc = xmlData
			} else if fd, ok := v.(*types.FormData); ok {
				// Use pooled buffer for multipart form data
				buf := getMultipartBuffer()
				boundary, err := newMultipartBoundary()
				if err != nil {
					putMultipartBuffer(buf)
					return nil, err
				}

				// SECURITY (sink validation): *FormData is a public struct that
				// callers can construct directly (types.go example) or via
				// WithFormData/WithBody(BodyMultipart), bypassing the stricter
				// option-layer checks in WithFile. Field names, filenames, and
				// per-file Content-Types land verbatim in Content-Disposition /
				// Content-Type header values, and hand-rolled MIME serialization
				// does not reject CR/LF — so control characters here would inject
				// arbitrary MIME headers/parts into the body. Validate every
				// token at this, the single encoding sink, so no entry path can
				// bypass it.
				//
				// Parts are written directly into the pooled buffer (see
				// writeMultipartPartHeader) instead of through
				// mime/multipart.Writer, whose CreatePart allocates per part.
				// Fields always precede files; within each group the map
				// iteration order applies (part order in multipart bodies is
				// not significant).
				first := true
				for key, value := range fd.Fields {
					if err := validation.ValidateMultipartToken(key, "multipart field name"); err != nil {
						putMultipartBuffer(buf)
						return nil, err
					}
					// Byte-identical to multipart.Writer.WriteField
					// (`form-data; name="%s"` with escapeQuotes).
					disposition := `form-data; name="` + escapeQuotes(key) + `"`
					writeMultipartPartHeader(buf, &first, boundary, disposition, "")
					buf.WriteString(value)
				}

				for key, fileData := range fd.Files {
					if fileData == nil {
						// A nil *FileData means the caller's map holds a nil
						// entry where a file was expected. Silently dropping it
						// would lose data without notice — fail the request
						// instead so the bug surfaces.
						putMultipartBuffer(buf)
						return nil, fmt.Errorf("multipart file %q has nil FileData", key)
					}
					if err := validation.ValidateMultipartToken(key, "multipart file field name"); err != nil {
						putMultipartBuffer(buf)
						return nil, err
					}
					if err := validation.ValidateMultipartToken(fileData.Filename, "multipart filename"); err != nil {
						putMultipartBuffer(buf)
						return nil, err
					}

					// Byte-identical to multipart.Writer.CreateFormFile for the
					// no-ContentType case (which implies application/octet-stream).
					fileContentType := fileData.ContentType
					if fileContentType == "" {
						fileContentType = "application/octet-stream"
					}
					if !validation.IsValidHeaderString(fileContentType) {
						putMultipartBuffer(buf)
						return nil, fmt.Errorf("multipart file %q: invalid Content-Type", key)
					}
					disposition := `form-data; name="` + escapeQuotes(key) +
						`"; filename="` + escapeQuotes(fileData.Filename) + `"`

					writeMultipartPartHeader(buf, &first, boundary, disposition, fileContentType)
					buf.Write(fileData.Content)
				}

				// Closing delimiter — byte-identical to multipart.Writer.Close,
				// including the leading CRLF it emits even for an empty form.
				buf.WriteString("\r\n--")
				buf.WriteString(boundary)
				buf.WriteString("--\r\n")

				body = getPooledMultipartBufferWrapper(buf)
				// The boundary is hex (no RFC 2045 tspecials), so it never needs
				// the quoting multipart.Writer.FormDataContentType applies —
				// this plain concatenation matches its output byte for byte.
				contentType = "multipart/form-data; boundary=" + boundary
				if followRedirects {
					replaySrc = bytes.Clone(buf.Bytes())
				}
			} else {
				// Use pooled buffer for JSON encoding to reduce allocations
				buf := getJSONBuffer()
				encoder := json.NewEncoder(buf)
				if err := encoder.Encode(v); err != nil {
					putJSONBuffer(buf)
					return nil, fmt.Errorf("marshal JSON failed: %w", err)
				}
				// Trim trailing newline added by json.Encoder.Encode
				// to maintain compatibility with json.Marshal behavior
				if b := buf.Bytes(); len(b) > 0 && b[len(b)-1] == '\n' {
					buf.Truncate(len(b) - 1)
				}
				body = getPooledJSONBufferWrapper(buf)
				contentType = "application/json"
				if followRedirects {
					replaySrc = bytes.Clone(buf.Bytes())
				}
			}
		}
	}

	// Construct http.Request directly to avoid:
	//   1. parsedURL.String() allocation (URL to string)
	//   2. url.Parse re-parsing that string back to *url.URL
	//   3. io.NopCloser wrapper for body readers that implement io.ReadCloser
	var bodyRC io.ReadCloser
	if body != nil {
		if rc, ok := body.(io.ReadCloser); ok {
			bodyRC = rc
		} else {
			bodyRC = io.NopCloser(body)
		}
	}

	method := req.Method()
	ctx := req.Context()

	// Use a pooled template for the initial http.Request to avoid one heap
	// allocation. WithContext creates a shallow copy (new *http.Request) and
	// sets the unexported ctx field — the only public API to set context.
	// After WithContext returns, the template's fields are stale but harmless:
	// the copy owns its own field values (shallow-copied pointers), and the
	// template is zeroed on next use (*tmpl = http.Request{...}). The template
	// is returned to the pool immediately, keeping it warm for the next call.
	// Safe pool assertion (v, ok := ...) matching every other accessor in the
	// package — a poisoned pool must degrade to an allocation, not a panic.
	tmpl, ok := httpRequestPool.Get().(*http.Request)
	if !ok || tmpl == nil {
		tmpl = &http.Request{}
	}
	*tmpl = http.Request{
		Method:     method,
		URL:        parsedURL,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     getHTTPHeader(),
		Body:       bodyRC,
		Host:       parsedURL.Host,
	}
	httpReq := tmpl.WithContext(ctx)
	httpRequestPool.Put(tmpl)

	// Set Content-Length from known body types
	p.setContentLength(httpReq, body)

	// GetBody lets net/http replay the body on 307/308 redirects (method and
	// body are preserved for these codes). Without it, a bodied request that
	// receives 307/308 is returned the 3xx response unfollowed. Each call
	// returns a fresh reader over the stable replay source; length always
	// matches ContentLength because both derive from the same bytes.
	if followRedirects && replaySrc != nil {
		switch src := replaySrc.(type) {
		case string:
			httpReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(src)), nil
			}
		case []byte:
			httpReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(src)), nil
			}
		}
	}

	// Header values are stored in http.Header as []string. http.Header.Set
	// allocates a fresh []string{value} on every call; assigning len-1 windows
	// into one shared backing slice (headerVals) instead collapses N per-request
	// allocations down to one. Each entry is a cap-1 slice (headerVals[i:i+1:i+1])
	// so entries never alias each other, matching Set's single-value semantics.
	// The backing array is retained with the header map (transferred to the
	// Result via captureRequestHeaders), exactly as individual slices would be.
	headerVals := make([]string, 0, 8)
	// setHeader stores a single-value header. canonKey must already be in
	// http.CanonicalHeaderKey form. The fixed keys set on every request
	// (Content-Type / Accept-Encoding / User-Agent) use the pre-canonicalized
	// package vars above, and config headers are pre-canonicalized at processor
	// construction time (canonicalHeaders), so neither pays the per-call
	// http.CanonicalHeaderKey allocation on the hot path. Only per-request user
	// headers (req.Headers) still canonicalize, since their keys are
	// caller-supplied and unbounded.
	setHeader := func(canonKey, value string) {
		idx := len(headerVals)
		headerVals = append(headerVals, value)
		httpReq.Header[canonKey] = headerVals[idx : idx+1 : idx+1]
	}

	if contentType != "" && headerValueIsEmpty(httpReq.Header, hdrContentType) {
		setHeader(hdrContentType, contentType)
	}

	for canonKey, value := range p.canonicalHeaders {
		if headerValueIsEmpty(httpReq.Header, canonKey) {
			setHeader(canonKey, value)
		}
	}

	for key, value := range req.Headers() {
		setHeader(http.CanonicalHeaderKey(key), value)
	}

	// URL userinfo → Basic auth, matching net/http behavior. The URL cache
	// strips credentials when keying/parsing (request.go parseAndCacheURL),
	// so without this the credentials would be silently dropped. An explicit
	// Authorization header (WithHeader/WithBasicAuth) always wins. The "@"
	// pre-filter keeps the common path at one string scan.
	if strings.Contains(req.URL(), "@") {
		if u, parseErr := url.Parse(req.URL()); parseErr == nil && u.User != nil {
			if headerValueIsEmpty(httpReq.Header, hdrAuthorization) {
				password, _ := u.User.Password()
				creds := u.User.Username() + ":" + password
				setHeader(hdrAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
			}
		}
	}

	// Add Accept-Encoding automatically since DisableCompression is true
	// and we handle decompression manually. Allows user override via WithHeader.
	// Streaming responses bypass the buffered decompression pipeline, so they
	// must request uncompressed bytes — otherwise servers honoring gzip would
	// deliver compressed bytes straight to the caller (e.g. Download writing
	// a gzip stream to disk).
	if headerValueIsEmpty(httpReq.Header, hdrAcceptEncoding) {
		if req.StreamBody() {
			setHeader(hdrAcceptEncoding, "identity")
		} else {
			setHeader(hdrAcceptEncoding, "gzip, deflate")
		}
	}

	if p.config.UserAgent != "" && headerValueIsEmpty(httpReq.Header, hdrUserAgent) {
		setHeader(hdrUserAgent, p.config.UserAgent)
	}

	// Add cookies to the request by building a single Cookie header string.
	// This replaces per-cookie http.Request.AddCookie calls, which each
	// allocate via fmt.Sprintf + Header.Get + Header.Set. For N cookies the
	// old path allocated ~3N objects; this path allocates 1 (the header string).
	// Note: If EnableCookies is true and a CookieJar is configured,
	// the cookies will be managed by the jar automatically.
	// We still add them here for immediate use in this request.
	cookies := req.Cookies()
	if len(cookies) > 0 {
		setHeader(hdrCookie, buildCookieHeader(cookies))
	}

	return httpReq, nil
}

// buildCookieHeader constructs a "name=value; name2=value2" string from cookies,
// applying the same sanitization rules as net/http.AddCookie. It uses a pooled
// strings.Builder and a fast-path scan so that already-valid values (the common
// case after ValidateCookie) incur zero intermediate allocations.
func buildCookieHeader(cookies []http.Cookie) string {
	sb := getQueryBuilder()
	// Pre-grow to the estimated size so the builder's backing array is allocated
	// once instead of growing incrementally. strings.Builder.Reset() nils the
	// internal buffer, so pooled builders always start empty.
	sb.Grow(len(cookies) * 32)
	for i := range cookies {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(sanitizeCookieName(cookies[i].Name))
		sb.WriteByte('=')
		sb.WriteString(sanitizeCookieValue(cookies[i].Value))
	}
	result := sb.String()
	putQueryBuilder(sb)
	return result
}

// sanitizeCookieName removes CR and LF from a cookie name, matching the
// behavior of net/http.sanitizeCookieName to prevent header injection.
// Fast path: returns the original string when no escaping is needed.
func sanitizeCookieName(name string) string {
	for i := 0; i < len(name); i++ {
		if name[i] == '\n' || name[i] == '\r' {
			return strings.NewReplacer("\n", "", "\r", "").Replace(name)
		}
	}
	return name
}

// sanitizeCookieValue escapes bytes that are invalid in a Cookie request-header
// value, matching net/http.sanitizeCookieValue. Valid bytes (printable ASCII
// except '"', ';', '\\') are passed through; invalid bytes are octal-escaped.
// Fast path: returns the original string when no escaping is needed.
func sanitizeCookieValue(v string) string {
	for i := 0; i < len(v); i++ {
		if !validCookieValueByte(v[i]) {
			return sanitizeCookieValueSlow(v, i)
		}
	}
	return v
}

func sanitizeCookieValueSlow(v string, start int) string {
	var b strings.Builder
	b.Grow(len(v))
	b.WriteString(v[:start])
	const octalDigits = "01234567"
	for i := start; i < len(v); i++ {
		c := v[i]
		if validCookieValueByte(c) {
			b.WriteByte(c)
		} else {
			// Octal escape: \ooo (3 digits), matching net/http behavior.
			b.WriteByte('\\')
			b.WriteByte(octalDigits[c>>6])
			b.WriteByte(octalDigits[(c>>3)&7])
			b.WriteByte(octalDigits[c&7])
		}
	}
	return b.String()
}

// validCookieValueByte reports whether b is a valid byte in a Cookie
// request-header value, matching net/http.validCookieValueByte.
func validCookieValueByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != '"' && b != ';' && b != '\\'
}

// setContentLength sets Content-Length on the http.Request for known body types.
// This avoids the stdlib's reflection-based detection when constructing requests directly.
func (p *requestProcessor) setContentLength(req *http.Request, body io.Reader) {
	switch v := body.(type) {
	case *pooledStringsReader:
		if v.reader != nil {
			req.ContentLength = int64(v.reader.Len())
		}
	case *pooledBytesReader:
		if v.reader != nil {
			req.ContentLength = int64(v.reader.Len())
		}
	case *pooledJSONBuffer:
		if v.buf != nil {
			req.ContentLength = int64(v.buf.Len())
		}
	case *pooledMultipartBuffer:
		if v.buf != nil {
			req.ContentLength = int64(v.buf.Len())
		}
	}
}

// escapeQuotes escapes backslashes and double quotes in filenames per RFC 7578.
// Optimized to use pooled strings.Builder for better performance.
func escapeQuotes(s string) string {
	// Fast path: no escapes needed - use direct byte scanning
	var hasEscape bool
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' || s[i] == '"' {
			hasEscape = true
			break
		}
	}
	if !hasEscape {
		return s
	}

	// Slow path: build escaped string using pooled builder
	sb, ok := stringBuilderPool.Get().(*strings.Builder)
	if !ok || sb == nil {
		sb = &strings.Builder{}
	}
	sb.Reset()
	sb.Grow(len(s) + len(s)/10) // Pre-allocate ~10% extra for escapes

	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			sb.WriteString("\\\\")
		case '"':
			sb.WriteString("\\\"")
		default:
			sb.WriteByte(s[i])
		}
	}

	result := sb.String()
	// Discard oversized builders so a malicious multipart filename (user-controlled,
	// full of escape chars) can't grow the pooled backing array and bloat memory.
	// Mirrors putQueryBuilder's cap guard.
	if sb.Cap() <= 4096 {
		stringBuilderPool.Put(sb)
	}
	return result
}

// FormatQueryParam converts a value to string for query parameters.
// Optimized to avoid fmt.Sprintf allocations for common types.
//
// MAINTENANCE: this type switch has two siblings that MUST stay in sync —
// writeQueryParamValue (pools.go, writes the wire format) and the facade's
// queryValueLength (public_options.go, measures length without allocating).
// query_param_parity_test.go guards the drift; when adding a type, add it to
// all three.
func FormatQueryParam(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case int32:
		return strconv.FormatInt(int64(val), 10)
	case uint:
		return strconv.FormatUint(uint64(val), 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	case uint32:
		return strconv.FormatUint(uint64(val), 10)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(val), 'f', -1, 32)
	case bool:
		return strconv.FormatBool(val)
	case fmt.Stringer:
		return val.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}

// isXMLContentType reports whether a Content-Type header value designates XML.
// Comparison ignores parameters ("; charset=...") and case, matching
// mime.ParseMediaType semantics without its allocation. Without this, a body
// declared as "application/xml; charset=utf-8" fell through to JSON encoding
// while the header still advertised XML.
func isXMLContentType(contentType string) bool {
	if contentType == "" {
		return false
	}
	if mediaType, _, ok := strings.Cut(contentType, ";"); ok {
		contentType = mediaType
	}
	contentType = strings.TrimSpace(contentType)
	return strings.EqualFold(contentType, "application/xml") ||
		strings.EqualFold(contentType, "text/xml")
}
