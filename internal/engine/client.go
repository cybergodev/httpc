// Package engine implements the core HTTP client engine with request processing,
// response handling, connection pooling, retry logic, and middleware support.
package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybergodev/httpc/internal/connection"
	"github.com/cybergodev/httpc/internal/proxypool"
	"github.com/cybergodev/httpc/internal/security"
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

func (p *requestPool) put(req *Request) {
	putHeadersMap(req.headers)
	putQueryParamsMap(req.queryParams)
	*req = Request{maxRetries: maxRetriesUnset}
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
	putHeadersMap(req.headers)
	putQueryParamsMap(req.queryParams)
	*req = Request{maxRetries: maxRetriesUnset}
	sharedRequestPool.Put(req)
}

// Client is the internal HTTP client that manages requests, responses, retries,
// and connection pooling.
type Client struct {
	config *Config

	transport         transportManager
	requestProcessor  *requestProcessor
	responseProcessor *responseProcessor
	retryEngine       *retryEngine
	validator         *security.Validator

	connectionPool *connection.PoolManager

	// requestPool reduces allocations for Request objects
	requestPool requestPool
	// execRequestPool reduces allocations for Request copies in executeRequest
	execRequestPool requestPool
	// securityRequestPool reduces allocations for security.Request objects
	securityRequestPool sync.Pool

	// metrics tracks request statistics
	metrics *metrics

	closed int32

	closeOnce sync.Once
}

// Config defines the HTTP client configuration.
// Config should be treated as immutable after creation.
type Config struct {
	Timeout                time.Duration
	DialTimeout            time.Duration
	KeepAlive              time.Duration
	TLSHandshakeTimeout    time.Duration
	ResponseHeaderTimeout  time.Duration
	IdleConnTimeout        time.Duration
	MaxResponseHeaderBytes int64
	MaxIdleConns           int
	MaxIdleConnsPerHost    int
	MaxConnsPerHost        int
	ProxyURL               string

	// System proxy configuration
	EnableSystemProxy bool // Automatically detect and use system proxy settings

	// Proxy pool configuration
	ProxyPool             []string
	ProxyPoolStrategy     proxypool.Strategy
	ProxyFailureThreshold int
	ProxyCooldown         time.Duration

	TLSConfig               *tls.Config
	MinTLSVersion           uint16
	MaxTLSVersion           uint16
	InsecureSkipVerify      bool
	MaxResponseBodySize     int64
	MaxRequestBodySize      int64
	MaxDecompressedBodySize int64
	ValidateURL             bool
	ValidateHeaders         bool
	AllowPrivateIPs         bool
	ExemptNets              []*net.IPNet
	StrictContentLength     bool

	MaxRetries    int
	RetryDelay    time.Duration
	MaxRetryDelay time.Duration
	BackoffFactor float64
	Jitter        bool

	// ExtraRetryableStatusCodes are HTTP status codes beyond the built-in set
	// (408/429/500/502/503/504) that should trigger a retry. Seeded from
	// Connection.ProxyRotateOnStatus to rotate proxies on WAF/CF blocks.
	ExtraRetryableStatusCodes []int

	// CustomRetryPolicy allows providing a custom retry policy implementation.
	// If set, it overrides the built-in retry logic.
	CustomRetryPolicy types.RetryPolicy

	UserAgent       string
	Headers         map[string]string
	FollowRedirects bool
	MaxRedirects    int
	EnableHTTP2     bool

	CookieJar     http.CookieJar
	EnableCookies bool

	// DNS configuration
	EnableDoH   bool
	DoHCacheTTL time.Duration

	// Redirect whitelist configuration
	RedirectWhitelist *security.DomainWhitelist

	// Certificate pinning
	CertificatePinner security.CertificatePinner
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
}

// Compile-time interface check
var _ types.RequestMutator = (*Request)(nil)

// Accessors (implement RequestMutator)
func (r *Request) Method() string              { return r.method }
func (r *Request) URL() string                 { return r.url }
func (r *Request) Headers() map[string]string  { return r.headers }
func (r *Request) QueryParams() map[string]any { return r.queryParams }
func (r *Request) Body() any                   { return r.body }
func (r *Request) Timeout() time.Duration      { return r.timeout }
func (r *Request) MaxRetries() int             { return r.maxRetries }
func (r *Request) Context() context.Context    { return r.context }
func (r *Request) Cookies() []http.Cookie      { return r.cookies }
func (r *Request) FollowRedirects() *bool      { return r.followRedirects }
func (r *Request) MaxRedirects() *int          { return r.maxRedirects }
func (r *Request) AllowPrivateIPs() *bool      { return r.allowPrivateIPs }
func (r *Request) SanitizedURL() string        { return r.sanitizedURL }
func (r *Request) SetSanitizedURL(v string)    { r.sanitizedURL = v }

// Mutators
func (r *Request) SetMethod(v string)             { r.method = v }
func (r *Request) SetURL(v string)                { r.url = v }
func (r *Request) SetHeaders(v map[string]string) { r.headers = v }
func (r *Request) SetHeader(key, value string) {
	if r.headers == nil {
		r.headers = getHeadersMap()
	}
	r.headers[key] = value
}
func (r *Request) SetQueryParams(v map[string]any) { r.queryParams = v }
func (r *Request) EnsureQueryParams() map[string]any {
	if r.queryParams == nil {
		r.queryParams = getQueryParamsMap()
	}
	return r.queryParams
}
func (r *Request) SetBody(v any)                { r.body = v }
func (r *Request) SetTimeout(v time.Duration)   { r.timeout = v }
func (r *Request) SetMaxRetries(v int)          { r.maxRetries = v }
func (r *Request) SetContext(v context.Context) { r.context = v }
func (r *Request) SetCookies(v []http.Cookie)   { r.cookies = v }
func (r *Request) SetFollowRedirects(v *bool)   { r.followRedirects = v }
func (r *Request) SetMaxRedirects(v *int)       { r.maxRedirects = v }
func (r *Request) SetAllowPrivateIPs(v *bool)   { r.allowPrivateIPs = v }
func (r *Request) StreamBody() bool             { return r.streamBody }
func (r *Request) SetStreamBody(v bool)         { r.streamBody = v }

// Callback accessors
func (r *Request) OnRequest() requestCallback        { return r.onRequest }
func (r *Request) OnResponse() responseCallback      { return r.onResponse }
func (r *Request) SetOnRequest(cb requestCallback)   { r.onRequest = cb }
func (r *Request) SetOnResponse(cb responseCallback) { r.onResponse = cb }

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
func (r *Response) RawBody() []byte              { return r.rawBody }
func (r *Response) ContentLength() int64         { return r.contentLength }
func (r *Response) Proto() string                { return r.proto }
func (r *Response) Duration() time.Duration      { return r.duration }
func (r *Response) Attempts() int                { return r.attempts }
func (r *Response) Cookies() []*http.Cookie      { return r.cookies }
func (r *Response) RedirectChain() []string      { return r.redirectChain }
func (r *Response) RedirectCount() int           { return r.redirectCount }
func (r *Response) RequestHeaders() http.Header  { return r.requestHeaders }
func (r *Response) RequestURL() string           { return r.requestURL }
func (r *Response) RequestMethod() string        { return r.requestMethod }
func (r *Response) RawBodyReader() io.ReadCloser { return r.rawBodyReader }

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

// NewClient creates a new engine Client with the given configuration and optional client options.
func NewClient(config *Config, opts ...clientOption) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Process options
	options := &clientOptions{}
	for _, opt := range opts {
		opt(options)
	}

	client := &Client{
		config:          config,
		metrics:         &metrics{},
		requestPool:     newRequestPool(),
		execRequestPool: newRequestPool(),
		securityRequestPool: sync.Pool{
			New: func() any {
				return &security.Request{}
			},
		},
	}

	var err error

	// Use custom transport if provided, otherwise create default
	if options.customTransport != nil {
		client.transport = options.customTransport
		// Connection pool not needed for custom transport
	} else {
		connConfig := connection.DefaultConfig()
		connConfig.MaxIdleConns = config.MaxIdleConns
		connConfig.MaxIdleConnsPerHost = config.MaxIdleConnsPerHost
		connConfig.MaxConnsPerHost = config.MaxConnsPerHost
		connConfig.MaxResponseHeaderBytes = config.MaxResponseHeaderBytes
		connConfig.DialTimeout = config.DialTimeout
		connConfig.KeepAlive = config.KeepAlive
		connConfig.TLSHandshakeTimeout = config.TLSHandshakeTimeout
		connConfig.ResponseHeaderTimeout = config.ResponseHeaderTimeout
		connConfig.IdleConnTimeout = config.IdleConnTimeout
		connConfig.MinTLSVersion = config.MinTLSVersion
		connConfig.MaxTLSVersion = config.MaxTLSVersion
		connConfig.InsecureSkipVerify = config.InsecureSkipVerify
		connConfig.EnableHTTP2 = config.EnableHTTP2
		connConfig.ProxyURL = config.ProxyURL
		connConfig.EnableSystemProxy = config.EnableSystemProxy
		connConfig.ProxyPool = config.ProxyPool
		connConfig.ProxyPoolStrategy = config.ProxyPoolStrategy
		connConfig.ProxyFailureThreshold = config.ProxyFailureThreshold
		connConfig.ProxyCooldown = config.ProxyCooldown
		connConfig.CookieJar = config.CookieJar
		connConfig.AllowPrivateIPs = config.AllowPrivateIPs
		connConfig.ExemptNets = config.ExemptNets
		connConfig.EnableDoH = config.EnableDoH
		connConfig.DoHCacheTTL = config.DoHCacheTTL
		connConfig.TLSConfig = config.TLSConfig

		if config.CertificatePinner != nil {
			connConfig.SetCertPinner(config.CertificatePinner)
		}

		client.connectionPool, err = connection.NewPoolManager(connConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create connection pool: %w", err)
		}

		client.transport, err = newTransport(config, client.connectionPool)
		if err != nil {
			client.connectionPool.Close()
			return nil, fmt.Errorf("failed to create transport: %w", err)
		}
	}

	client.requestProcessor = newRequestProcessor(config)
	client.responseProcessor = newResponseProcessor(config)
	client.retryEngine = newRetryEngine(config)

	validatorConfig := &security.Config{
		ValidateURL:         config.ValidateURL,
		ValidateHeaders:     config.ValidateHeaders,
		MaxResponseBodySize: config.MaxResponseBodySize,
		MaxRequestBodySize:  config.MaxRequestBodySize,
		AllowPrivateIPs:     config.AllowPrivateIPs,
		ExemptNets:          config.ExemptNets,
	}
	client.validator = security.NewValidatorWithConfig(validatorConfig)

	return client, nil
}

// ErrClientClosed is returned when attempting to use a closed client.
var ErrClientClosed = errors.New("client is closed")

// Request executes an HTTP request with the given method, URL, and options.
// It acquires a pooled Request, applies the options, processes it through the
// transport layer with retry support, and returns the resulting Response.
// Returns ErrClientClosed if the client has been closed.
func (c *Client) Request(ctx context.Context, method, url string, options ...RequestOption) (*Response, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return nil, ErrClientClosed
	}

	startTime := time.Now()

	// Get Request from pool (already zeroed by putRequest via *req = Request{})
	req := c.getRequest()
	req.SetMethod(method)
	req.SetURL(url)
	req.SetContext(ctx)

	// Ensure request is returned to pool after processing
	defer c.putRequest(req)

	for _, option := range options {
		if option != nil {
			if err := option(req); err != nil {
				// Caller-side configuration error, not a transport failure —
				// do not count it against health metrics.
				return nil, fmt.Errorf("failed to apply request option: %w", err)
			}
		}
	}

	// Propagate a per-request AllowPrivateIPs override to the connection dialer
	// and the redirect-target validator via the request context. The pre-flight
	// validator reads the same override directly from secReq below.
	if override := req.AllowPrivateIPs(); override != nil {
		req.SetContext(connection.WithAllowPrivateIPsOverride(req.Context(), *override))
	}

	// Use pooled security.Request for validation
	secReq := c.getSecurityRequest()
	secReq.Method = req.Method()
	secReq.URL = req.URL()
	secReq.Headers = req.Headers()
	secReq.QueryParams = req.QueryParams()
	secReq.Body = req.Body()
	secReq.AllowPrivateIPs = req.AllowPrivateIPs()

	validationErr := c.validator.ValidateRequest(secReq)
	c.putSecurityRequest(secReq)

	if validationErr != nil {
		// Caller-side validation error, not a transport failure — do not
		// count it against health metrics.
		return nil, fmt.Errorf("request validation failed: %w", validationErr)
	}

	response, err := c.executeWithRetry(req)
	duration := time.Since(startTime)

	if err != nil {
		c.metrics.recordRequest(duration.Nanoseconds(), false)
		return nil, err
	}

	c.metrics.recordRequest(duration.Nanoseconds(), true)
	response.SetDuration(duration)
	return response, nil
}

// getRequest retrieves a Request object from the pool with safe type assertion
func (c *Client) getRequest() *Request {
	return c.requestPool.get()
}

// putRequest returns a Request object to the pool
func (c *Client) putRequest(req *Request) {
	c.requestPool.put(req)
}

// getSecurityRequest retrieves a security.Request from the pool
func (c *Client) getSecurityRequest() *security.Request {
	req, ok := c.securityRequestPool.Get().(*security.Request)
	if !ok || req == nil {
		return &security.Request{}
	}
	return req
}

// putSecurityRequest returns a security.Request to the pool after clearing its fields
func (c *Client) putSecurityRequest(req *security.Request) {
	if req == nil {
		return
	}
	*req = security.Request{}
	c.securityRequestPool.Put(req)
}

// getExecRequest retrieves a Request object from the exec pool for request copies with safe type assertion
func (c *Client) getExecRequest() *Request {
	return c.execRequestPool.get()
}

// putExecRequest returns a Request object to the exec pool
func (c *Client) putExecRequest(req *Request) {
	c.execRequestPool.put(req)
}

// timerPool reduces allocations for time.Timer objects used in sleepWithContext.
var timerPool = sync.Pool{
	New: func() any { return time.NewTimer(0) },
}

func (c *Client) sleepWithContext(ctx context.Context, duration time.Duration) error {
	if ctx == nil {
		time.Sleep(duration)
		return nil
	}

	timer, _ := timerPool.Get().(*time.Timer)
	if timer == nil {
		timer = time.NewTimer(duration)
	} else {
		timer.Reset(duration)
	}

	select {
	case <-ctx.Done():
		// Per time.Timer docs: when Stop returns false the timer already fired
		// and a value is buffered in timer.C. Drain it so the next pooled reuse
		// does not observe a stale tick (which would wake a sleeper early).
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerPool.Put(timer)
		return ctx.Err()
	case <-timer.C:
		timerPool.Put(timer)
		return nil
	}
}

// executeWithRetry executes a request with intelligent retry logic.
// Optimized for performance with minimal allocations and efficient error handling.
func (c *Client) executeWithRetry(req *Request) (*Response, error) {
	// Determine max retries: maxRetriesUnset = not configured (use config default), 0 = explicitly disabled
	maxRetries := req.MaxRetries()
	if maxRetries < 0 {
		if c.config.CustomRetryPolicy != nil {
			maxRetries = c.config.CustomRetryPolicy.MaxRetries()
		} else {
			maxRetries = c.retryEngine.MaxRetries()
		}
	}

	// Fast path: no retries configured (most common case)
	// Skip deep copy since request is only executed once — original req
	// is returned to pool by caller's defer putRequest regardless.
	if maxRetries == 0 {
		resp, err := c.executeRequest(req, true)
		if err != nil {
			return nil, classifyError(err, req.URL(), req.Method(), 1)
		}
		if resp != nil {
			resp.SetAttempts(1)
		}
		return resp, nil
	}

	// Slow path: retry loop
	policy := types.RetryPolicy(c.retryEngine)
	if c.config.CustomRetryPolicy != nil {
		policy = c.config.CustomRetryPolicy
	}

	// Create a shared timeout context for all retry attempts.
	// This ensures WithTimeout is a total budget across retries,
	// not per-attempt. Without this, each retry gets a fresh full timeout,
	// allowing WithTimeout(900s)+3 retries to take ~3600s instead of 900s.
	retryCtx := req.Context()
	if retryCtx == nil {
		retryCtx = backgroundCtx
	}
	retryTimeout := req.Timeout()
	if retryTimeout <= 0 && c.config.Timeout > 0 {
		retryTimeout = c.config.Timeout
	}
	var overallCancel context.CancelFunc
	if retryTimeout > 0 {
		if existingDeadline, hasDeadline := retryCtx.Deadline(); !hasDeadline {
			retryCtx, overallCancel = context.WithTimeout(retryCtx, retryTimeout)
		} else if timeUntil := time.Until(existingDeadline); timeUntil > retryTimeout {
			retryCtx, overallCancel = context.WithTimeout(retryCtx, retryTimeout)
		}
	}
	req.SetContext(retryCtx)
	// Ensure overallCancel is called on all non-success exit paths.
	// For streaming success, overallCancel is transferred to the response
	// and set to nil before this defer runs.
	if overallCancel != nil {
		defer func() {
			if overallCancel != nil {
				overallCancel()
			}
		}()
	}

	// Cache sanitized URL once — URL doesn't change across retry attempts
	sanitizedURL := validation.SanitizeURL(req.URL())
	reqMethod := req.Method()

	var lastErr error
	var lastResp *Response

	// Buffer io.Reader body for retry safety. io.Reader is consumed on
	// first use, so subsequent retry attempts would send an empty body.
	// Converting to []byte allows Build() to create a fresh reader per attempt.
	// SECURITY: Cap at maxRetryBodySize to prevent OOM from large streams.
	if req.body != nil {
		if r, ok := req.body.(io.Reader); ok {
			const maxRetryBodySize int64 = 100 * 1024 * 1024 // 100MB
			limited := io.LimitReader(r, maxRetryBodySize+1)
			buf, readErr := io.ReadAll(limited)
			if readErr != nil {
				if overallCancel != nil {
					overallCancel()
				}
				return nil, classifyError(fmt.Errorf("buffer request body failed: %w", readErr), req.URL(), req.Method(), 0)
			}
			if int64(len(buf)) > maxRetryBodySize {
				if overallCancel != nil {
					overallCancel()
				}
				return nil, classifyError(
					fmt.Errorf("retry not supported for streaming bodies exceeding %d bytes", maxRetryBodySize),
					req.URL(), req.Method(), 0,
				)
			}
			req.body = buf
		}
	}

	// Deterministic proxy rotation: when a proxy pool is configured with
	// status-based rotation (ExtraRetryableStatusCodes), reserve a unique base
	// proxy index per request via NextProxyIndex. Each retry attempt then uses
	// baseProxyIdx + attempt as the SelectIndex argument, guaranteeing:
	//   - Inter-request rotation: different requests get different base indices.
	//   - Intra-request rotation: retry N lands on a different proxy than N-1.
	//   - Redirect-safe: all Proxy calls within one attempt share the same index,
	//     so redirect-following cannot desynchronize the rotation.
	retryBaseCtx := req.Context()
	baseProxyIdx := 0
	useProxyRotation := len(c.config.ExtraRetryableStatusCodes) > 0
	if useProxyRotation && c.connectionPool != nil {
		var ok bool
		baseProxyIdx, ok = c.connectionPool.NextProxyIndex()
		useProxyRotation = ok // false if pool wasn't actually created
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if useProxyRotation {
			req.SetContext(connection.WithProxyAttempt(retryBaseCtx, baseProxyIdx+attempt))
		} else {
			req.SetContext(retryBaseCtx)
		}

		resp, err := c.executeRequest(req, false)

		if os.Getenv("HTTPC_DEBUG") != "" {
			if err != nil {
				fmt.Fprintf(os.Stderr, "[httpc] attempt=%d ERROR: %v (retryable=%v)\n",
					attempt, err, classifyError(err, "", "", 0).IsRetryable())
			} else if resp != nil {
				shouldRetry := policy.ShouldRetry(resp, nil, attempt)
				fmt.Fprintf(os.Stderr, "[httpc] attempt=%d status=%d shouldRetry=%v attemptLtMax=%v proxyIdx=%d\n",
					attempt, resp.StatusCode(), shouldRetry, attempt < maxRetries,
					func() int {
						if useProxyRotation {
							return baseProxyIdx + attempt
						}
						return -1
					}())
			}
		}

		if err != nil {
			clientErr := classifyErrorWithSanitizedURL(err, sanitizedURL, reqMethod, attempt+1)
			lastErr = clientErr

			// Fast path: non-retryable errors or max retries reached
			if !clientErr.IsRetryable() || attempt >= maxRetries {
				releaseLastResp(&lastResp)
				clientErr.Attempts = attempt + 1
				return nil, clientErr
			}

			// Check retry policy
			if !policy.ShouldRetry(nil, err, attempt) {
				releaseLastResp(&lastResp)
				clientErr.Attempts = attempt + 1
				return nil, clientErr
			}

			// Calculate delay and sleep
			delay := policy.GetDelay(attempt)

			// Close idle connections to force Proxy() re-evaluation on retry
			// (see comment in the response-path retry block below).
			if useProxyRotation && c.connectionPool != nil {
				c.connectionPool.CloseIdleConnections()
			}

			if sleepErr := c.sleepWithContext(req.Context(), delay); sleepErr != nil {
				releaseLastResp(&lastResp)
				return nil, classifyError(sleepErr, req.URL(), req.Method(), attempt+1)
			}
			continue
		}

		if resp != nil {
			// Release previous intermediate response to prevent pool leak
			if lastResp != nil && lastResp != resp {
				ReleaseResponse(lastResp)
			}
			lastResp = resp

			// Check if response status is retryable using policy
			if policy.ShouldRetry(resp, nil, attempt) && attempt < maxRetries {
				// Compute the delay while resp is still valid — the built-in
				// policy may read a Retry-After header from it.
				var delay time.Duration
				if engPolicy, ok := policy.(*retryEngine); ok {
					delay = engPolicy.GetDelayWithResponse(attempt, resp)
				} else {
					delay = policy.GetDelay(attempt)
				}

				if os.Getenv("HTTPC_DEBUG") != "" {
					fmt.Fprintf(os.Stderr, "[httpc] attempt=%d retrying after %v delay\n", attempt, delay)
				}

				// Release this discarded response now rather than carrying it as
				// lastResp across the backoff sleep and the next attempt. For a
				// streaming response the body reader pins a connection until
				// ReleaseResponse closes it, so releasing before the sleep frees
				// that slot for the full delay instead of holding it idle.
				ReleaseResponse(resp)
				lastResp = nil

				// Close idle connections so the next attempt's transport
				// MUST call Proxy() again to select a (different) proxy.
				// Without this, HTTP/2 connection reuse through a CONNECT
				// tunnel silently reuses the failed attempt's tunnel,
				// bypassing Proxy() and defeating proxy rotation.
				if useProxyRotation && c.connectionPool != nil {
					c.connectionPool.CloseIdleConnections()
				}

				if sleepErr := c.sleepWithContext(req.Context(), delay); sleepErr != nil {
					return nil, classifyErrorWithSanitizedURL(sleepErr, sanitizedURL, reqMethod, attempt+1)
				}
				continue
			}

			// Success - set attempt count and return
			resp.SetAttempts(attempt + 1)
			// Transfer context cancel ownership: streaming responses
			// need the cancel to stay alive until ReleaseResponse.
			// Setting overallCancel=nil prevents the defer from cancelling.
			if overallCancel != nil && resp.rawBodyReader != nil {
				resp.cancelFunc = overallCancel
				overallCancel = nil
			}
			return resp, nil
		}
	}

	// Defensive fallback: loop exited without early return.
	// This can only happen if executeRequest returns (nil, nil), which should
	// never occur with the current implementation. Included for robustness.
	if lastResp != nil {
		lastResp.SetAttempts(maxRetries + 1)
		// Transfer context cancel ownership for streaming responses,
		// matching the success-path logic above.
		if overallCancel != nil && lastResp.rawBodyReader != nil {
			lastResp.cancelFunc = overallCancel
			overallCancel = nil
		}
		return lastResp, nil
	}

	if lastErr != nil {
		if clientErr, ok := lastErr.(*ClientError); ok {
			clientErr.Attempts = maxRetries + 1
			clientErr.Type = ErrorTypeRetryExhausted
			return nil, clientErr
		}
		return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries+1, lastErr)
	}

	return nil, fmt.Errorf("request failed after %d attempts", maxRetries+1)
}

// captureRequestHeaders builds a complete header map from an http.Request by
// taking ownership of httpReq.Header and enriching it with Content-Length and
// Host (which net/http stores as separate Request fields, not in the Header map).
//
// Rather than cloning the pooled header map built by requestProcessor.Build, it
// transfers ownership to the caller (which retains it via the Result). This
// mirrors the response-header transfer pattern (Response.TransferHeaders) and
// removes the per-request CloneHeader copy — saving the clone's map allocation,
// its backing-array allocation, and the value-copy loop.
//
// httpReq.Header is set to nil so the caller's deferred putHTTPHeader observes
// nil at function-exit and skips recycling a map still referenced by the Result.
// On error paths where this function is never reached, httpReq.Header stays
// non-nil and is recycled by the deferred putHTTPHeader as before. Consuming one
// pooled map per success-path request is safe: sync.Pool simply allocates a fresh
// map on the next get when the pool is empty — no leak, no double-recycle.
//
// Uses direct map lookups with pre-canonicalized keys ("Content-Length" and
// "Host" are already canonical) to avoid the textproto.CanonicalMIMEHeaderKey
// overhead of h.Get, and batches both value slices into a single backing array
// to reduce N []string{value} allocations to 1.
func captureRequestHeaders(httpReq *http.Request) http.Header {
	if httpReq == nil {
		return nil
	}
	h := httpReq.Header
	httpReq.Header = nil // transfer ownership; deferred putHTTPHeader reads nil and skips
	if h == nil {
		h = make(http.Header, 4)
	}
	// Batch the header value slices into one backing allocation. Each entry is a
	// cap-1 window so the two values never alias each other, matching Set's
	// single-value semantics.
	headerVals := make([]string, 0, 2)
	if httpReq.ContentLength > 0 && headerValueIsEmpty(h, hdrContentLength) {
		var numBuf [20]byte
		idx := len(headerVals)
		headerVals = append(headerVals, string(strconv.AppendInt(numBuf[:0], httpReq.ContentLength, 10)))
		h[hdrContentLength] = headerVals[idx : idx+1 : idx+1]
	}
	if httpReq.Host != "" && headerValueIsEmpty(h, hdrHost) {
		idx := len(headerVals)
		headerVals = append(headerVals, httpReq.Host)
		h[hdrHost] = headerVals[idx : idx+1 : idx+1]
	}
	return h
}

// releaseLastResp releases the intermediate response object back to the pool.
// Takes a pointer to the caller's lastResp so it can nil the reference after release,
// preventing double-release in deferred cleanup paths.
func releaseLastResp(lastResp **Response) {
	if *lastResp != nil {
		ReleaseResponse(*lastResp)
		*lastResp = nil
	}
}

const (
	defaultMaxDrain int64 = 10 * 1024 * 1024 // 10MB
)

// backgroundCtx is a convenience alias for context.Background(), used as the
// default context when no context is provided. context.Background() is an
// immutable singleton, so this is purely stylistic — it does not violate
// the "do not store context in struct" guideline.
// Note: the public httpc package also defines its own backgroundCtx — this is
// intentional since unexported vars cannot be shared across packages.
var backgroundCtx = context.Background()

// executeRequest executes a single HTTP request with comprehensive error handling.
// When skipCopy is true, the request is used directly without deep copy (safe when
// the caller guarantees single-use, i.e., no retries).
func (c *Client) executeRequest(req *Request, skipCopy bool) (*Response, error) {
	// Context setup with timeout handling
	execCtx := req.Context()
	if execCtx == nil {
		execCtx = backgroundCtx
	}

	timeout := req.Timeout()
	if timeout <= 0 && c.config.Timeout > 0 {
		timeout = c.config.Timeout
	}

	// Optimized: only create new context if absolutely necessary
	var streamCancel context.CancelFunc
	if timeout > 0 {
		if existingDeadline, hasDeadline := execCtx.Deadline(); !hasDeadline {
			execCtx, streamCancel = context.WithTimeout(execCtx, timeout)
		} else if timeUntil := time.Until(existingDeadline); timeUntil > timeout {
			execCtx, streamCancel = context.WithTimeout(execCtx, timeout)
		}
	}
	// Always defer cancel to prevent timer leaks on early error returns.
	// For streaming requests, cancelFunc is stored in the Response and the
	// defer becomes a no-op after setCancelFuncToNil is called.
	cancelCtx := streamCancel
	if cancelCtx != nil {
		defer func() {
			if cancelCtx != nil {
				cancelCtx()
			}
		}()
	}
	// setCancelFuncToNil is called after storing the cancel in the streaming
	// response, preventing the deferred cleanup from double-cancelling.
	setCancelFuncToNil := func() { cancelCtx = nil }

	select {
	case <-execCtx.Done():
		return nil, classifyErrorWithSanitizedURL(execCtx.Err(), validation.SanitizeURL(req.URL()), req.Method(), 0)
	default:
	}

	// Get a pooled Request copy — deep copy reference types to prevent cross-retry mutation
	// Optimization: skip deep copy in no-retry fast path (skipCopy=true) to avoid
	// unnecessary map/slice allocations for headers, query params, and cookies.
	var reqCopy *Request
	if skipCopy {
		req.context = execCtx
		reqCopy = req
	} else {
		reqCopy = c.getExecRequest()
		*reqCopy = *req
		reqCopy.context = execCtx
		if req.headers != nil {
			reqCopy.headers = getHeadersMap()
			maps.Copy(reqCopy.headers, req.headers)
		}
		if req.queryParams != nil {
			reqCopy.queryParams = getQueryParamsMap()
			maps.Copy(reqCopy.queryParams, req.queryParams)
		}
		if len(req.cookies) > 0 {
			reqCopy.cookies = make([]http.Cookie, len(req.cookies))
			copy(reqCopy.cookies, req.cookies)
		}
		defer c.putExecRequest(reqCopy)
	}

	followRedirects := c.config.FollowRedirects
	if req.FollowRedirects() != nil {
		followRedirects = *req.FollowRedirects()
	}
	maxRedirects := c.config.MaxRedirects
	if req.MaxRedirects() != nil {
		maxRedirects = *req.MaxRedirects()
	}
	// Set redirect policy via context for thread-safety
	// SECURITY: settings must be returned to pool to prevent memory leak
	var redirectSettings *redirectSettings
	reqCopy.context, redirectSettings = c.transport.SetRedirectPolicy(execCtx, followRedirects, maxRedirects)
	if redirectSettings != nil {
		defer putRedirectSettings(redirectSettings)
	}

	// Lazy sanitized URL: only compute when an error occurs.
	// Most requests succeed, so this avoids the SanitizeURL allocation entirely
	// on the happy path.
	var sanitizedURL string
	sanitizeOnce := func() string {
		if sanitizedURL == "" {
			sanitizedURL = validation.SanitizeURL(req.URL())
		}
		return sanitizedURL
	}

	// Invoke OnRequest callback before building the HTTP request
	if reqCopy.onRequest != nil {
		if err := reqCopy.onRequest(reqCopy); err != nil {
			return nil, classifyErrorWithSanitizedURL(fmt.Errorf("onRequest callback failed: %w", err), sanitizeOnce(), req.Method(), 0)
		}
	}

	httpReq, err := c.requestProcessor.Build(reqCopy)
	if err != nil {
		return nil, classifyErrorWithSanitizedURL(err, sanitizeOnce(), req.Method(), 0)
	}
	// Read httpReq.Header at defer-run time, not at registration: captureRequestHeaders
	// transfers header ownership to the Result on success and nils the field, so the
	// closure observes nil and skips recycling. On error paths captureRequestHeaders is
	// never reached, the field stays non-nil, and the header is recycled normally.
	defer func() { putHTTPHeader(httpReq.Header) }()

	httpResp, err := c.transport.RoundTrip(httpReq)

	if err != nil {
		return nil, classifyErrorWithSanitizedURL(err, sanitizeOnce(), req.Method(), 0)
	}

	// Streaming mode: skip body buffering, hand raw reader to caller.
	// Caller is responsible for closing the body reader.
	if reqCopy.StreamBody() {
		resp := getResponse()
		resp.SetStatusCode(httpResp.StatusCode)
		resp.SetStatus(httpResp.Status)
		resp.SetHeaders(httpResp.Header)
		resp.SetContentLength(httpResp.ContentLength)
		resp.SetProto(httpResp.Proto)
		resp.SetCookies(httpResp.Cookies())
		streamLimit := c.config.MaxResponseBodySize
		if streamLimit <= 0 {
			streamLimit = defaultMaxDecompressedSize
		}
		lr := getLimitReader(httpResp.Body, streamLimit)
		resp.rawBodyReader = &streamBodyReader{reader: lr, source: httpResp.Body}
		resp.cancelFunc = streamCancel
		setCancelFuncToNil() // Prevent deferred cancel; ReleaseResponse handles cleanup

		if httpResp.Request != nil {
			resp.SetRequestHeaders(captureRequestHeaders(httpResp.Request))
			if httpResp.Request.URL != nil {
				resp.SetRequestURL(httpResp.Request.URL.String())
			}
			resp.SetRequestMethod(httpResp.Request.Method)
		}

		// Capture redirect metadata for streaming responses
		if redirectChain := c.transport.GetRedirectChain(reqCopy.context); len(redirectChain) > 0 {
			resp.SetRedirectChain(redirectChain)
			resp.SetRedirectCount(len(redirectChain))
		}

		// Invoke OnResponse callback for streaming responses
		if reqCopy.onResponse != nil {
			if err := reqCopy.onResponse(resp); err != nil {
				ReleaseResponse(resp)
				return nil, classifyErrorWithSanitizedURL(fmt.Errorf("onResponse callback failed: %w", err), sanitizeOnce(), req.Method(), 0)
			}
		}

		return resp, nil
	}

	defer func() {
		if httpResp.Body != nil {
			maxDrain := defaultMaxDrain
			if c.config.MaxResponseBodySize > 0 && c.config.MaxResponseBodySize < maxDrain {
				maxDrain = c.config.MaxResponseBodySize
			}
			// io.Discard implements io.ReaderFrom with its own internal pooled buffer,
			// so io.Copy(io.Discard, ...) already avoids per-call heap allocation.
			drainLr := getLimitReader(httpResp.Body, maxDrain)
			_, _ = io.Copy(io.Discard, drainLr)
			putLimitReader(drainLr)
			_ = httpResp.Body.Close() // best-effort cleanup
		}
	}()

	resp, err := c.responseProcessor.Process(httpResp)
	if err != nil {
		return nil, classifyErrorWithSanitizedURL(err, sanitizeOnce(), req.Method(), 0)
	}

	if redirectChain := c.transport.GetRedirectChain(reqCopy.context); len(redirectChain) > 0 {
		resp.SetRedirectChain(redirectChain)
		resp.SetRedirectCount(len(redirectChain))
	}

	if httpResp.Request != nil {
		resp.SetRequestHeaders(captureRequestHeaders(httpResp.Request))
		// Set the actual request URL and method
		if httpResp.Request.URL != nil {
			resp.SetRequestURL(httpResp.Request.URL.String())
		}
		resp.SetRequestMethod(httpResp.Request.Method)
	}

	// Invoke OnResponse callback after response processing
	if reqCopy.onResponse != nil {
		if err := reqCopy.onResponse(resp); err != nil {
			ReleaseResponse(resp)
			return nil, classifyErrorWithSanitizedURL(fmt.Errorf("onResponse callback failed: %w", err), sanitizeOnce(), req.Method(), 0)
		}
	}

	return resp, nil
}

// getHealthStatus returns the current health status of the client.
// Reserved for future public health check API — currently only used in tests.
func (c *Client) getHealthStatus() healthStatus {
	return c.metrics.getHealthStatus()
}

// isHealthy returns true if the client is healthy (error rate < 10%).
// Reserved for future public health check API — currently only used in tests.
func (c *Client) isHealthy() bool {
	return c.metrics.isHealthy()
}

// IsClosed returns true if the client has been closed.
func (c *Client) IsClosed() bool {
	return atomic.LoadInt32(&c.closed) == 1
}

// Close releases the client's resources, including the connection pool and
// transport. It is safe to call multiple times; subsequent calls are no-ops.
// Returns any error encountered while closing sub-components.
func (c *Client) Close() error {
	var closeErr error

	c.closeOnce.Do(func() {
		atomic.StoreInt32(&c.closed, 1)

		if c.connectionPool != nil {
			if err := c.connectionPool.Close(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("failed to close connection pool: %w", err))
			}
		}

		if c.transport != nil {
			if err := c.transport.Close(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("failed to close transport: %w", err))
			}
		}
	})

	return closeErr
}

// RequestOption is a function that modifies a Request before it is sent.
type RequestOption func(*Request) error

// clientOption is a functional option for configuring the Client.
type clientOption func(*clientOptions)

type clientOptions struct {
	customTransport transportManager
}
