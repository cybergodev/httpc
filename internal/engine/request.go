package engine

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/cybergodev/httpc/internal/types"
	"github.com/cybergodev/httpc/internal/validation"
)

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

// mimeHeaderPool reduces allocations for textproto.MIMEHeader in multipart uploads
var mimeHeaderPool = sync.Pool{
	New: func() any {
		h := make(textproto.MIMEHeader, 4) // Pre-allocate for typical multipart headers
		return &h
	},
}

// getMIMEHeader retrieves a textproto.MIMEHeader from the pool
func getMIMEHeader() *textproto.MIMEHeader {
	h, ok := mimeHeaderPool.Get().(*textproto.MIMEHeader)
	if !ok || h == nil {
		tmp := make(textproto.MIMEHeader, 4)
		return &tmp
	}
	// Clear for reuse
	for k := range *h {
		delete(*h, k)
	}
	return h
}

// putMIMEHeader returns a textproto.MIMEHeader to the pool.
// Keys are deleted to clear the map for reuse, matching the pattern used by
// putHeadersMap / putQueryParamsMap / putHTTPHeader.
func putMIMEHeader(h *textproto.MIMEHeader) {
	if h == nil || len(*h) > 16 {
		return // Don't pool large headers
	}
	for k := range *h {
		delete(*h, k)
	}
	mimeHeaderPool.Put(h)
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

// pooledStringsReader wraps a strings.Reader and returns it to the pool on EOF or Close.
type pooledStringsReader struct {
	reader   *strings.Reader
	released bool
}

func (r *pooledStringsReader) Read(p []byte) (n int, err error) {
	if r.reader == nil {
		return 0, io.EOF
	}
	n, err = r.reader.Read(p)
	if err == io.EOF {
		r.release()
	}
	return n, err
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

// pooledBytesReader wraps a bytes.Reader and returns it to the pool on EOF or Close.
type pooledBytesReader struct {
	reader   *bytes.Reader
	released bool
}

func (r *pooledBytesReader) Read(p []byte) (n int, err error) {
	if r.reader == nil {
		return 0, io.EOF
	}
	n, err = r.reader.Read(p)
	if err == io.EOF {
		r.release()
	}
	return n, err
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

// urlCache provides a thread-safe LRU-like cache for parsed URLs
// to avoid expensive url.Parse() calls for repeated URLs.
//
// SECURITY: The cache uses a sanitized URL as the key (sensitive query parameter
// values redacted) to prevent credentials from persisting in memory.
// Callers always receive a clone of the cached entry to prevent mutation.
type urlCache struct {
	mu      sync.RWMutex
	raw     map[string]*url.URL // Fast path: raw URL string -> parsed URL
	entries map[string]*url.URL // Sanitized key -> parsed URL (for sensitive URLs)
	keys    []string            // Track insertion order for LRU eviction
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
	qIdx := strings.IndexByte(rawURL, '?')
	if qIdx < 0 {
		return false
	}
	return validation.HasSensitiveQueryParams(rawURL[qIdx+1:])
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
func (c *urlCache) getInternal(rawURL string, clone bool) (*url.URL, error) {
	sensitive := hasSensitiveContent(rawURL)

	// Fast path: check raw string cache first (avoids url.Parse for repeated URLs)
	if !sensitive {
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
	}

	// Parse URL to produce sanitized cache key
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	parsed.User = nil
	cacheKey := sanitizeURLKey(parsed)

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
func (c *urlCache) evictOldest() {
	if len(c.entries) < c.maxSize || len(c.keys) == 0 {
		return
	}
	oldestKey := c.keys[0]
	if old, ok := c.entries[oldestKey]; ok && c.raw != nil {
		for k, v := range c.raw {
			if v == old {
				delete(c.raw, k)
			}
		}
	}
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
	n, err = r.buf.Read(p)
	if err == io.EOF {
		r.release()
	}
	return n, err
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
	n, err = r.buf.Read(p)
	if err == io.EOF {
		r.release()
	}
	return n, err
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

// Pre-canonicalized forms of the header keys set on every request. Computing
// these once at init time avoids a per-request http.CanonicalHeaderKey
// allocation (which allocates even for already-canonical input) on the hot
// path. Keys are stored exactly as http.CanonicalHeaderKey would produce them.
var (
	hdrContentType    = http.CanonicalHeaderKey("Content-Type")
	hdrAcceptEncoding = http.CanonicalHeaderKey("Accept-Encoding")
	hdrUserAgent      = http.CanonicalHeaderKey("User-Agent")
	hdrCookie         = http.CanonicalHeaderKey("Cookie")
	hdrContentLength  = http.CanonicalHeaderKey("Content-Length")
	hdrHost           = http.CanonicalHeaderKey("Host")
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

	var body io.Reader
	var contentType string

	if req.Body() != nil {
		switch v := req.Body().(type) {
		case string:
			body = getPooledStringsReader(v)
			contentType = "text/plain"
		case []byte:
			body = getPooledBytesReader(v)
			contentType = "application/octet-stream"
		case io.Reader:
			body = v
		default:
			existingContentType := ""
			if req.Headers() != nil {
				existingContentType = req.Headers()["Content-Type"]
			}

			if existingContentType == "application/xml" {
				xmlData, err := xml.Marshal(v)
				if err != nil {
					return nil, fmt.Errorf("marshal XML failed: %w", err)
				}
				body = getPooledBytesReader(xmlData)
				contentType = "application/xml"
			} else if fd, ok := v.(*types.FormData); ok {
				// Use pooled buffer for multipart form data
				buf := getMultipartBuffer()
				writer := multipart.NewWriter(buf)

				for key, value := range fd.Fields {
					if err := writer.WriteField(key, value); err != nil {
						putMultipartBuffer(buf)
						return nil, fmt.Errorf("write form field failed: %w", err)
					}
				}

				for key, fileData := range fd.Files {
					if fileData == nil {
						continue
					}

					var part io.Writer
					var err error

					if fileData.ContentType != "" {
						h := getMIMEHeader()
						escapedKey := escapeQuotes(key)
						escapedFilename := escapeQuotes(fileData.Filename)
						contentDisposition := `form-data; name="` + escapedKey + `"; filename="` + escapedFilename + `"`

						h.Set("Content-Disposition", contentDisposition)
						h.Set("Content-Type", fileData.ContentType)
						part, err = writer.CreatePart(*h)
						putMIMEHeader(h)
					} else {
						part, err = writer.CreateFormFile(key, fileData.Filename)
					}

					if err != nil {
						putMultipartBuffer(buf)
						return nil, fmt.Errorf("create form file failed: %w", err)
					}

					if _, err := part.Write(fileData.Content); err != nil {
						putMultipartBuffer(buf)
						return nil, fmt.Errorf("write file content failed: %w", err)
					}
				}

				if err := writer.Close(); err != nil {
					putMultipartBuffer(buf)
					return nil, fmt.Errorf("close multipart writer failed: %w", err)
				}

				body = getPooledMultipartBufferWrapper(buf)
				contentType = writer.FormDataContentType()
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
	httpReq := &http.Request{
		Method:     method,
		URL:        parsedURL,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     getHTTPHeader(),
		Body:       bodyRC,
		Host:       parsedURL.Host,
	}
	httpReq = httpReq.WithContext(ctx)

	// Set Content-Length from known body types
	p.setContentLength(httpReq, body)

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

	// Add Accept-Encoding automatically since DisableCompression is true
	// and we handle decompression manually. Allows user override via WithHeader.
	if headerValueIsEmpty(httpReq.Header, hdrAcceptEncoding) {
		setHeader(hdrAcceptEncoding, "gzip, deflate")
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
