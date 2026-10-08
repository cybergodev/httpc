package engine

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybergodev/httpc/internal/types"
)

// gzipReaderPool pools gzip.Reader objects to reduce allocations during decompression.
// Each gzip.NewReader allocates a reader struct, a flate decompressor, and a
// 32KB sliding-window dictionary; Reset on a pooled reader reuses all of them.
var gzipReaderPool = sync.Pool{
	New: func() any {
		// A zero-value Reader is fully (re)initialized by Reset. Do NOT build
		// this via gzip.NewReader(bytes.NewReader(nil)): parsing the empty
		// stream fails header validation, so that call returns (nil, io.EOF),
		// and discarding the error silently yields a nil New result — which
		// disabled the entire pool (every Get missed, every compressed
		// response allocated a fresh decompressor stack).
		return new(gzip.Reader)
	},
}

// flateReaderPool pools flate.Reader objects (flate.Resetter interface).
// flate.NewReader returns an io.ReadCloser that can be reset.
var flateReaderPool = sync.Pool{
	New: func() any {
		// Create a dummy reader to initialize the pool
		return flate.NewReader(bytes.NewReader(nil))
	},
}

const (
	// defaultBufferSize is the initial size for buffer pool buffers
	defaultBufferSize = 4 * 1024 // 4KB - good balance for most responses
	// maxBufferSize caps the buffer size to prevent memory bloat
	maxBufferSize = 512 * 1024 // 512KB

	// SECURITY: maxCompressedSize limits the size of compressed response data
	// to prevent decompression bomb (zip bomb) attacks. A highly compressed
	// malicious payload could exhaust memory during decompression.
	maxCompressedSize = 100 * 1024 * 1024 // 100MB compressed data limit

	// SECURITY: defaultMaxDecompressedSize is the default limit for decompressed
	// response body size when MaxResponseBodySize is not explicitly configured.
	// This provides a safety net against compression bombs where 100MB of
	// highly compressible data (e.g., zeros) could decompress to many gigabytes.
	// Matches the public validation ceiling (httpc.maxDecompressedBodySize in
	// types.go) — keep the two in sync when changing either.
	defaultMaxDecompressedSize = 100 * 1024 * 1024 // 100MB decompressed data limit
)

// bufferPool reuses byte buffers for response body reading
var bufferPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, defaultBufferSize))
	},
}

// responsePool reuses Response objects to reduce allocations in the hot path
var responsePool = sync.Pool{
	New: func() any {
		return &Response{}
	},
}

// limitReaderPool reduces allocations for limit readers
var limitReaderPool = sync.Pool{
	New: func() any {
		return &pooledLimitReader{}
	},
}

// bufioReaderPool reuses the 4KB *bufio.Reader that gzip.Reader.Reset and
// flate's decompressor.Reset would otherwise allocate per compressed
// response: both reuse an input that already implements flate.Reader
// (*bufio.Reader does) instead of wrapping a plain io.Reader in a fresh
// buffered reader.
var bufioReaderPool = sync.Pool{
	New: func() any {
		return bufio.NewReader(bytes.NewReader(nil))
	},
}

// emptyReader is a shared zero-length input for re-pointing pooled readers
// before they are returned to their pools. See the pooledGzipReader.Close note.
var emptyReader = bytes.NewReader(nil)

// getBufioReader wraps r in a pooled *bufio.Reader.
func getBufioReader(r io.Reader) *bufio.Reader {
	br, ok := bufioReaderPool.Get().(*bufio.Reader)
	if !ok || br == nil {
		return bufio.NewReader(r)
	}
	br.Reset(r)
	return br
}

// putBufioReader returns a *bufio.Reader to the pool. Resetting with an
// empty source drops the reference to the previous response body. Stale
// bytes in the retained buffer array are unreachable after Reset (read
// positions are zeroed) and overwritten by the next response's data — the
// same retention policy as bufferPool below.
func putBufioReader(br *bufio.Reader) {
	if br == nil {
		return
	}
	br.Reset(emptyReader)
	bufioReaderPool.Put(br)
}

// pooledLimitReader is a reusable io.Reader that limits the number of bytes read
type pooledLimitReader struct {
	r io.Reader
	n int64
}

func (l *pooledLimitReader) Read(p []byte) (n int, err error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[0:l.n]
	}
	n, err = l.r.Read(p)
	l.n -= int64(n)
	return
}

func (l *pooledLimitReader) Reset(r io.Reader, n int64) {
	l.r = r
	l.n = n
}

// getLimitReader retrieves a pooledLimitReader from the pool
func getLimitReader(r io.Reader, n int64) *pooledLimitReader {
	lr, ok := limitReaderPool.Get().(*pooledLimitReader)
	if !ok || lr == nil {
		lr = &pooledLimitReader{}
	}
	lr.Reset(r, n)
	return lr
}

// putLimitReader returns a pooledLimitReader to the pool
func putLimitReader(lr *pooledLimitReader) {
	if lr == nil {
		return
	}
	lr.r = nil
	lr.n = 0
	limitReaderPool.Put(lr)
}

// streamBodyReader wraps a pooledLimitReader to enforce MaxResponseBodySize
// in streaming mode. It also holds a reference to the underlying source body
// so Close() properly closes the original http.Response.Body and returns the
// pooledLimitReader to the pool.
//
// The underlying reader is allocated with a limit+1 byte budget (see
// executeRequest), which lets Read distinguish an oversize body from one that
// ends exactly at the limit: after more than limit bytes have been read, Read
// reports an error instead of a synthetic EOF. Without this, io.Copy-based
// consumers (e.g. Download) would silently truncate the body to the limit and
// report success, writing a corrupted file with no error.
type streamBodyReader struct {
	reader *pooledLimitReader
	source io.ReadCloser
	// limit is the configured maximum body size in bytes; <= 0 means unlimited.
	limit int64
	// read counts bytes returned so far. Guarded by the caller's serial Read
	// contract (io.Reader is not safe for concurrent use).
	read int64
	// closed guards against double Close: the caller may close the body and
	// ReleaseResponse will close it again via rawBodyReader — possibly from a
	// different goroutine, so the flag must be set atomically. A second pool
	// put would return the same *pooledLimitReader to two future requests.
	closed atomic.Bool
}

func (s *streamBodyReader) Read(p []byte) (int, error) {
	// Use-after-Close guard: Close returns the pooled limit reader to the pool
	// (where its underlying reader is nil'd), so a Read racing through would
	// nil-deref. Report an error like net/http's read-on-closed-body instead.
	if s.closed.Load() {
		return 0, fmt.Errorf("read on closed stream body")
	}
	// Oversize check BEFORE reading: the limit+1 budget guarantees the byte
	// just past the limit was already delivered by a previous Read, so any
	// entry with read > limit proves the body exceeds the configured cap.
	// This catches bodies larger than limit+1, whose next pooled read would
	// return the limit reader's own synthetic EOF.
	if s.limit > 0 && s.read > s.limit {
		return 0, fmt.Errorf("streamed response body exceeds size limit of %d bytes", s.limit)
	}
	n, err := s.reader.Read(p)
	s.read += int64(n)
	// An io.Reader may legally return its final bytes together with io.EOF. If
	// that final chunk crosses the limit (body of exactly limit+1 bytes), an
	// EOF here would let io.Copy report a clean — truncated — success. Report
	// the oversize error instead; io.Copy writes the n bytes and fails.
	if err == io.EOF && s.limit > 0 && s.read > s.limit {
		return n, fmt.Errorf("streamed response body exceeds size limit of %d bytes", s.limit)
	}
	return n, err
}

func (s *streamBodyReader) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	putLimitReader(s.reader)
	return s.source.Close()
}

// getBuffer retrieves a buffer from the pool with safe type assertion.
// Returns a new buffer if the pool contains an unexpected type (defensive).
func getBuffer() *bytes.Buffer {
	pooled := bufferPool.Get()
	buf, ok := pooled.(*bytes.Buffer)
	if !ok || buf == nil {
		// Defensive: create new buffer if pool returns wrong type
		return bytes.NewBuffer(make([]byte, 0, defaultBufferSize))
	}
	buf.Reset()
	return buf
}

// putBuffer returns a buffer to the pool if it's not too large
func putBuffer(buf *bytes.Buffer) {
	if buf.Cap() <= maxBufferSize {
		bufferPool.Put(buf)
	}
	// Let large buffers be garbage collected to prevent memory bloat
}

// getResponse retrieves a Response object from the pool.
// SECURITY: Resets all fields to zero values to prevent data leakage from previous requests.
func getResponse() *Response {
	resp, ok := responsePool.Get().(*Response)
	if !ok || resp == nil {
		return &Response{}
	}
	// SECURITY: Clear all fields to prevent sensitive data leakage
	*resp = Response{}
	return resp
}

type responseProcessor struct {
	config *Config
}

func newResponseProcessor(config *Config) *responseProcessor {
	return &responseProcessor{
		config: config,
	}
}

func (p *responseProcessor) Process(httpResp *http.Response) (*Response, error) {
	if httpResp == nil {
		return nil, fmt.Errorf("HTTP response is nil")
	}

	// Direct map lookup with pre-canonicalized key avoids the
	// textproto.CanonicalMIMEHeaderKey overhead of Header.Get on every
	// response. The encoding string is passed to readBody so it doesn't
	// need to repeat this lookup.
	encoding := ""
	if vals := httpResp.Header[hdrContentEncoding]; len(vals) > 0 && vals[0] != "" {
		encoding = vals[0]
	}
	wasCompressed := encoding != ""

	body, err := p.readBody(httpResp, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	contentLength := httpResp.ContentLength
	// Strict content-length validation: skip for HEAD requests (no body expected)
	// and compressed responses (body size differs from Content-Length header)
	if !wasCompressed && p.config.StrictContentLength && contentLength > 0 && contentLength != int64(len(body)) {
		// Safe nil check with short-circuit evaluation before accessing Method
		if httpResp.Request == nil || httpResp.Request.Method != "HEAD" {
			return nil, fmt.Errorf("content-length mismatch: expected %d, got %d", contentLength, len(body))
		}
	}

	if wasCompressed {
		contentLength = int64(len(body))
	}

	// Use pooled Response object to reduce allocations
	resp := getResponse()
	resp.SetStatusCode(httpResp.StatusCode)
	resp.SetStatus(httpResp.Status)
	// Transfer ownership of httpResp.Header directly instead of cloning.
	// Each *http.Response from RoundTrip is a fresh, unshared object whose Header
	// map remains valid after Body.Close() (net/http retains the connection, not
	// the Response/Header). Nothing mutates this map between here and the deferred
	// body close in executeRequest, and the Set-Cookie read below only reads it.
	// This mirrors the streaming path (executeRequest) and lets TransferHeaders()
	// hand the map to the public Result with zero header copies on the happy path.
	resp.SetHeaders(httpResp.Header)
	resp.SetRawBody(body)
	// Body string is lazily converted on first access via Body() to avoid
	// doubling memory when caller only uses RawBody
	resp.SetContentLength(contentLength)
	resp.SetProto(httpResp.Proto)
	// Only parse cookies when Set-Cookie header is present to avoid unnecessary allocation
	if _, ok := httpResp.Header["Set-Cookie"]; ok {
		resp.SetCookies(httpResp.Cookies())
	}

	return resp, nil
}

// readBody reads and optionally decompresses the response body with size limits.
// Uses buffer and limit reader pools to reduce heap allocations.
// The encoding parameter (from the Content-Encoding header, read once by the
// caller) controls decompression — passing it avoids a second Header.Get call.
//
// # SECURITY CONTRACT
//
// This function MUST return a freshly allocated []byte.
// The returned slice must not be retained by any other reference (pool or shared buffer).
//
// SECURITY: Implements protection against decompression bomb attacks.
func (p *responseProcessor) readBody(httpResp *http.Response, encoding string) ([]byte, error) {
	if httpResp.Body == nil {
		return nil, nil
	}

	reader := io.Reader(httpResp.Body)
	isCompressed := false
	var compressedLr *pooledLimitReader
	var compressedBr *bufio.Reader
	var decompressedLr *pooledLimitReader
	var decompressor io.ReadCloser // Track decompressor for cleanup

	if encoding != "" {
		isCompressed = true
		var err error
		// SECURITY: Limit compressed data size before decompression to prevent zip bombs
		compressedLr = getLimitReader(httpResp.Body, maxCompressedSize+1)
		// Wrap the limited body in a pooled *bufio.Reader so the decompressor's
		// Reset reuses it instead of allocating a fresh 4KB buffered reader
		// per compressed response.
		compressedBr = getBufioReader(compressedLr)
		decompressor, err = p.createDecompressor(compressedBr, encoding)
		if err != nil {
			putBufioReader(compressedBr)
			putLimitReader(compressedLr)
			return nil, fmt.Errorf("failed to create decompressor for %s: %w", encoding, err)
		}
		reader = decompressor
	}

	// SECURITY: Apply the body-size limit using a pooled reader.
	//
	// Compressed responses are capped by MaxDecompressedBodySize (falling back
	// to MaxResponseBodySize, then the 100MB default) — the limit governs the
	// inflated size. Identity (non-compressed) bodies are capped by
	// MaxResponseBodySize alone: the decompressed limit applies only to bytes
	// the client actually inflates, so preferring it unconditionally let the
	// default 100MB MaxDecompressedBodySize silently replace the documented
	// 10MB MaxResponseBodySize cap for every DefaultConfig user (verified: a
	// 50MB identity body was accepted). This also matches the streaming path
	// in executeRequest, which caps at MaxResponseBodySize.
	maxSize := p.config.MaxDecompressedBodySize
	if !isCompressed {
		maxSize = p.config.MaxResponseBodySize
	}
	if maxSize <= 0 {
		maxSize = p.config.MaxResponseBodySize
		if maxSize <= 0 {
			// Engine-constructed configs with no body limit keep the same
			// 100MB ceiling the compressed fallback chain uses.
			maxSize = defaultMaxDecompressedSize
		}
	}
	decompressedLr = getLimitReader(reader, maxSize+1)
	reader = decompressedLr

	// Cleanup decompressor and limit readers. The bufio wrapper is recycled
	// only after decompressor.Close() — the decompressor reads from it up to
	// that point (gzip/flate wrapper Close re-points their input at an empty
	// reader, dropping the reference).
	defer func() {
		if decompressor != nil {
			_ = decompressor.Close()
		}
		putBufioReader(compressedBr) // no-op for nil (uncompressed path)
		if compressedLr != nil {
			putLimitReader(compressedLr)
		}
		if decompressedLr != nil {
			putLimitReader(decompressedLr)
		}
	}()

	contentLength := httpResp.ContentLength

	// Fast path: known Content-Length, not compressed, within safe size.
	// Read directly into a pre-sized slice — avoids bytes.Buffer allocation entirely.
	// Extended to maxBufferSize (512KB) to cover most API responses without buffer pool overhead.
	if !isCompressed && contentLength > 0 && contentLength <= int64(maxBufferSize) {
		// Fail fast with the clear "exceeds limit" message instead of the
		// misleading "unexpected EOF" that io.ReadFull produces when the limit
		// reader stops it short of the declared Content-Length. HEAD responses
		// carry Content-Length with no body and must keep passing (n==0, EOF).
		isHead := httpResp.Request != nil && httpResp.Request.Method == http.MethodHead
		if contentLength > maxSize && !isHead {
			return nil, fmt.Errorf("response body exceeds limit of %d bytes", maxSize)
		}
		body := make([]byte, contentLength)
		n, err := io.ReadFull(reader, body)
		if err != nil {
			// A declared Content-Length with zero bytes read is legitimate for
			// HEAD responses (net/http returns EOF immediately without a body);
			// those keep the historical empty-body result. Any other EOF —
			// partial data (io.ErrUnexpectedEOF) or EOF on the first read of a
			// non-HEAD request — means the server truncated the body, which
			// must surface as an error instead of a short but "successful"
			// response. Process's strict content-length check is a second line
			// of defense, but it is disabled by StrictContentLength=false
			// (e.g. PerformanceConfig), which previously let truncated bodies
			// pass silently on this path while the slow path (io.Copy) errored.
			if err != io.EOF || n != 0 {
				// Return the bare error: Process wraps every readBody error
				// with "failed to read response body: %w" — repeating that
				// prefix here tripled it once ClientError.Error() layered the
				// classifier's message on top.
				return nil, err
			}
			n = 0
		}
		body = body[:n]

		if int64(len(body)) > maxSize {
			return nil, fmt.Errorf("response body exceeds limit of %d bytes", maxSize)
		}
		return body, nil
	}

	// Slow path: unknown size (chunked), compressed, or large response.
	// *bytes.Buffer implements io.ReaderFrom, so io.Copy delegates to
	// Buffer.ReadFrom — a pooled 32KB copy buffer fetched here would never be
	// used (io.CopyBuffer also prefers ReadFrom over its buffer argument),
	// which is why none is fetched.
	buf := getBuffer()
	defer func() {
		if buf.Cap() <= maxBufferSize {
			putBuffer(buf)
		}
	}()

	_, err := io.Copy(buf, reader)
	if err != nil {
		return nil, err // Process adds the "failed to read response body" context
	}

	body := buf.Bytes()

	// SECURITY: After decompression, check body size against configured limit.
	if isCompressed && int64(len(body)) > maxSize {
		return nil, fmt.Errorf("decompressed response body exceeds limit of %d bytes (potential zip bomb)", maxSize)
	}

	if int64(len(body)) > maxSize {
		return nil, fmt.Errorf("response body exceeds limit of %d bytes", maxSize)
	}

	// Copy the body into a right-sized slice and return the buffer to the pool.
	// The previous "steal" optimization (detaching the buffer for 2–32KB bodies
	// to skip a copy) was removed because it emptied the pool on every call,
	// forcing a fresh buffer allocation (struct + 4KB array) on the next
	// request — 2 extra allocs that outweighed the single memcpy saved.
	// Copying keeps the pool warm (0 allocs on the next read) at the cost of one
	// memcpy, which is sub-microsecond for typical API responses.
	// A 2026-10-05 re-attempt (steal for >32KB bodies + same-capacity pool
	// backfill) measured +22% B/op and was reverted: Buffer.ReadFrom's
	// grow(MinRead) lookahead rounds a 64KB body up to a 128KB array, so a
	// capacity-sized backfill pays double the terminal copy, while a
	// length-sized backfill reintroduces per-request growth churn. The
	// terminal copy is the B/op floor for this shape — the result array must
	// be freshly allocated every request regardless.
	result := make([]byte, len(body))
	copy(result, body)
	return result, nil
}

// createDecompressor creates an appropriate decompressor based on the encoding type.
// Uses pooled readers for gzip and deflate to reduce allocations.
func (p *responseProcessor) createDecompressor(reader io.Reader, encoding string) (io.ReadCloser, error) {
	// EqualFold instead of ToLower: Content-Encoding tokens are ASCII, and
	// the case-insensitive comparison avoids a per-response string allocation.
	// TrimSpace tolerates servers that pad the header value (" gzip") without
	// rejecting the request outright.
	encoding = strings.TrimSpace(encoding)
	switch {
	case strings.EqualFold(encoding, "gzip"):
		// Try to get a pooled gzip reader
		if pooled, ok := gzipReaderPool.Get().(*gzip.Reader); ok && pooled != nil {
			if err := pooled.Reset(reader); err != nil {
				// SECURITY: Reset failed - discard the reader instead of returning to pool.
				// A reader in error state may cause issues for subsequent users.
				// The discarded reader will be garbage collected.
				// Return the Reset error directly: Reset may already have
				// consumed header bytes from the bufio wrapper, so a fresh
				// gzip.NewReader over the same partially-drained stream would
				// misreport the corruption as a different "invalid header" error.
				return nil, fmt.Errorf("gzip reset: %w", err)
			}
			wrapper, _ := gzipReaderWrapperPool.Get().(*pooledGzipReader)
			if wrapper == nil {
				wrapper = &pooledGzipReader{}
			}
			wrapper.Reader = pooled
			return wrapper, nil
		}
		return gzip.NewReader(reader)
	case strings.EqualFold(encoding, "deflate"):
		// Try to get a pooled flate reader
		if pooled, ok := flateReaderPool.Get().(io.ReadCloser); ok && pooled != nil {
			// Check if it also implements flate.Resetter
			if resetter, ok := pooled.(flate.Resetter); ok {
				if err := resetter.Reset(reader, nil); err != nil {
					// SECURITY: Reset failed - close and discard the reader instead of returning to pool.
					// A reader in error state may cause issues for subsequent users.
					_ = pooled.Close()
					return flate.NewReader(reader), nil
				}
				wrapper, _ := flateReaderWrapperPool.Get().(*pooledFlateReader)
				if wrapper == nil {
					wrapper = &pooledFlateReader{}
				}
				wrapper.reader = pooled
				return wrapper, nil
			}
			// Doesn't implement Resetter, close and discard
			_ = pooled.Close()
		}
		return flate.NewReader(reader), nil
	case strings.EqualFold(encoding, "br"):
		return nil, fmt.Errorf("brotli compression not supported")
	case strings.EqualFold(encoding, "compress"), strings.EqualFold(encoding, "x-compress"):
		return nil, fmt.Errorf("LZW compression not supported")
	case strings.EqualFold(encoding, "identity"), encoding == "":
		return io.NopCloser(reader), nil
	default:
		// SECURITY: an unrecognized Content-Encoding (e.g. "zstd", "br", or a
		// multi-token list like "gzip, br") must not silently pass raw
		// compressed bytes off as the response body. Fail loudly so the caller
		// knows the payload is not the decoded representation.
		return nil, fmt.Errorf("unsupported Content-Encoding %q: only gzip, deflate and identity are supported", encoding)
	}
}

// pooledGzipReader wraps a pooled gzip.Reader and returns it to the pool on Close.
type pooledGzipReader struct {
	*gzip.Reader
}

// gzipReaderWrapperPool reduces allocations for the pooledGzipReader wrapper struct.
var gzipReaderWrapperPool = sync.Pool{
	New: func() any { return &pooledGzipReader{} },
}

func (r *pooledGzipReader) Close() error {
	if r.Reader == nil {
		return nil
	}
	err := r.Reader.Close()
	// Re-point the input at the shared empty reader before pooling: this
	// drops the reference to the request-scoped pooled bufio wrapper and
	// clears any error state. emptyReader is safe to share — a zero-length
	// bytes.Reader returns EOF from every Read/ReadByte without mutating
	// position, so concurrent Reset calls cannot interfere.
	_ = r.Reset(emptyReader)
	gzipReaderPool.Put(r.Reader)
	r.Reader = nil
	// Return wrapper to pool
	gzipReaderWrapperPool.Put(r)
	return err
}

// pooledFlateReader wraps a pooled flate reader and returns it to the pool on Close.
// flate.NewReader returns an io.ReadCloser that also implements flate.Resetter.
type pooledFlateReader struct {
	reader io.ReadCloser
}

// flateReaderWrapperPool reduces allocations for the pooledFlateReader wrapper struct.
var flateReaderWrapperPool = sync.Pool{
	New: func() any { return &pooledFlateReader{} },
}

func (r *pooledFlateReader) Read(p []byte) (n int, err error) {
	if r.reader == nil {
		return 0, io.EOF
	}
	return r.reader.Read(p)
}

func (r *pooledFlateReader) Close() error {
	if r.reader == nil {
		return nil
	}
	var closeErr error
	// Get the Resetter interface to reset and return to pool
	if resetter, ok := r.reader.(flate.Resetter); ok {
		// A failed Reset leaves the reader in an unknown state — discard it
		// for GC instead of pooling it for a future request, and surface the
		// error (matching the gzip path; a swallowed error hid flush
		// failures that can indicate truncated streams).
		if err := resetter.Reset(emptyReader, nil); err != nil {
			closeErr = fmt.Errorf("flate reset: %w", err)
		} else {
			flateReaderPool.Put(r.reader) // return original io.ReadCloser, not the Resetter interface
		}
	} else {
		// SECURITY: If the reader doesn't implement Resetter, close it directly
		// to prevent resource leaks. This shouldn't happen with standard library,
		// but we handle it defensively for custom implementations.
		closeErr = r.reader.Close()
	}
	r.reader = nil
	// Return wrapper to pool
	flateReaderWrapperPool.Put(r)
	return closeErr
}

// ReleaseResponse returns a Response to the pool for reuse.
// Call this when the Response data has been consumed and copied elsewhere.
// After calling this, the Response must not be used.
func ReleaseResponse(r *Response) {
	if r == nil {
		return
	}
	// Read the stream fields under the same lock SetRawBodyReader writes
	// with, so a concurrent Set cannot swap the reader between the nil check
	// and the close (matching the bodyMu discipline of RawBody/RawBodyReader).
	r.bodyMu.RLock()
	rawBodyReader := r.rawBodyReader
	cancelFunc := r.cancelFunc
	r.bodyMu.RUnlock()

	if rawBodyReader != nil {
		_ = rawBodyReader.Close()
	}
	if cancelFunc != nil {
		cancelFunc()
	}
	*r = Response{}
	responsePool.Put(r)
}

// Response represents an HTTP response.
// Response objects are safe to read from multiple goroutines after they are returned.
//
// The exported accessor and mutator methods below implement the
// types.ResponseMutator interface (which embeds ResponseReader and write
// methods). They are trivial field pass-throughs and intentionally lack
// per-method godoc; refer to the interface definition for their contract.
type Response struct {
	statusCode     int
	status         string
	headers        http.Header
	body           string
	rawBody        []byte
	bodyMu         sync.RWMutex       // Protects body/bodyReady for concurrent SetBody/Body access
	bodyReady      bool               // True after body string has been computed from rawBody
	rawBodyReader  io.ReadCloser      // Set when streamBody=true; caller must close
	cancelFunc     context.CancelFunc // Stored for streaming mode cleanup
	contentLength  int64
	proto          string
	duration       time.Duration
	attempts       int
	proxyURL       string
	cookies        []*http.Cookie
	redirectChain  []string
	redirectCount  int
	requestHeaders http.Header // Actual headers sent with the request
	requestURL     string      // The actual URL that was requested (with query params)
	requestMethod  string      // The HTTP method used
}

// Compile-time interface check
var _ types.ResponseMutator = (*Response)(nil)

// Accessors (implement ResponseAccessor)
func (r *Response) StatusCode() int      { return r.statusCode }
func (r *Response) Status() string       { return r.status }
func (r *Response) Headers() http.Header { return r.headers }
func (r *Response) Body() string {
	r.bodyMu.RLock()
	if r.bodyReady {
		b := r.body
		r.bodyMu.RUnlock()
		return b
	}
	r.bodyMu.RUnlock()

	// Slow path: compute body string under write lock.
	r.bodyMu.Lock()
	// Double-check after acquiring write lock.
	if !r.bodyReady && r.rawBody != nil {
		r.body = string(r.rawBody)
		r.bodyReady = true
	}
	b := r.body
	r.bodyMu.Unlock()
	return b
}

// RawBody returns the raw response body bytes. Read-locked so a concurrent
// SetRawBody (e.g. from another middleware goroutine) cannot race with this
// read — mirroring the locking discipline of Body and SetRawBody.
func (r *Response) RawBody() []byte {
	r.bodyMu.RLock()
	b := r.rawBody
	r.bodyMu.RUnlock()
	return b
}
func (r *Response) ContentLength() int64        { return r.contentLength }
func (r *Response) Proto() string               { return r.proto }
func (r *Response) Duration() time.Duration     { return r.duration }
func (r *Response) Attempts() int               { return r.attempts }
func (r *Response) ProxyURL() string            { return r.proxyURL }
func (r *Response) Cookies() []*http.Cookie     { return r.cookies }
func (r *Response) RedirectChain() []string     { return r.redirectChain }
func (r *Response) RedirectCount() int          { return r.redirectCount }
func (r *Response) RequestHeaders() http.Header { return r.requestHeaders }
func (r *Response) RequestURL() string          { return r.requestURL }
func (r *Response) RequestMethod() string       { return r.requestMethod }

// RawBodyReader returns the streaming-mode body reader. Read-locked for the
// same reason as RawBody: SetRawBodyReader writes the field under bodyMu.
func (r *Response) RawBodyReader() io.ReadCloser {
	r.bodyMu.RLock()
	rc := r.rawBodyReader
	r.bodyMu.RUnlock()
	return rc
}

// TransferHeaders returns the response headers and clears the internal reference.
// The caller takes ownership of the returned map. Used by the public layer to
// avoid a redundant CloneHeader when converting engine.Response to Result.
func (r *Response) TransferHeaders() http.Header {
	h := r.headers
	r.headers = nil
	return h
}

// TransferRequestHeaders returns the request headers and clears the internal reference.
func (r *Response) TransferRequestHeaders() http.Header {
	h := r.requestHeaders
	r.requestHeaders = nil
	return h
}

// SetRawBodyReader replaces the raw body reader. Passing nil transfers ownership
// away from the response so that ReleaseResponse will not close it.
func (r *Response) SetRawBodyReader(rc io.ReadCloser) {
	r.bodyMu.Lock()
	r.rawBodyReader = rc
	r.bodyMu.Unlock()
}

// Mutators (implement ResponseMutator)
func (r *Response) SetStatusCode(v int)      { r.statusCode = v }
func (r *Response) SetStatus(v string)       { r.status = v }
func (r *Response) SetHeaders(v http.Header) { r.headers = v }
func (r *Response) SetBody(v string) {
	r.bodyMu.Lock()
	r.body = v
	r.bodyReady = true
	r.bodyMu.Unlock()
}
func (r *Response) SetRawBody(v []byte) {
	r.bodyMu.Lock()
	r.rawBody = v
	r.bodyReady = false
	r.bodyMu.Unlock()
}
func (r *Response) SetContentLength(v int64)        { r.contentLength = v }
func (r *Response) SetProto(v string)               { r.proto = v }
func (r *Response) SetDuration(v time.Duration)     { r.duration = v }
func (r *Response) SetAttempts(v int)               { r.attempts = v }
func (r *Response) SetProxyURL(v string)            { r.proxyURL = v }
func (r *Response) SetCookies(v []*http.Cookie)     { r.cookies = v }
func (r *Response) SetRedirectChain(v []string)     { r.redirectChain = v }
func (r *Response) SetRedirectCount(v int)          { r.redirectCount = v }
func (r *Response) SetRequestHeaders(v http.Header) { r.requestHeaders = v }
func (r *Response) SetRequestURL(v string)          { r.requestURL = v }
func (r *Response) SetRequestMethod(v string)       { r.requestMethod = v }

// SetHeader sets a header with multiple values (implements ResponseMutator)
func (r *Response) SetHeader(key string, values ...string) {
	if r.headers == nil {
		r.headers = make(http.Header)
	}
	r.headers[key] = values
}
