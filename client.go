package httpc

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"sync/atomic"

	"github.com/cybergodev/httpc/internal/engine"
)

// backgroundCtx is a convenience alias for context.Background(), used as the
// default context in methods that don't accept one (e.g., Get, Post, doRequest).
// context.Background() returns the same immutable singleton on every call,
// so caching it in a package variable is purely stylistic.
// Note: internal/engine also defines its own backgroundCtx — this is intentional
// since unexported vars cannot be shared across packages.
var backgroundCtx = context.Background()

// Doer is a minimal interface for executing HTTP requests.
// Users who need custom implementations can implement this smaller interface
// instead of the full Client interface.
type Doer interface {
	// Request executes an HTTP request with the given method and URL.
	Request(ctx context.Context, method, url string, options ...RequestOption) (*Result, error)
}

// Client is the main interface for making HTTP requests.
// It extends Doer with convenience methods and lifecycle management.
type Client interface {
	Doer

	// Convenience methods for common HTTP verbs. Each issues a request with
	// the corresponding method and returns the buffered Result; none of them
	// take a context — use Request for cancellation/deadline control.

	// Get issues a GET request to url.
	Get(url string, options ...RequestOption) (*Result, error)
	// Post issues a POST request to url (non-idempotent: not retried by default).
	Post(url string, options ...RequestOption) (*Result, error)
	// Put issues a PUT request to url.
	Put(url string, options ...RequestOption) (*Result, error)
	// Patch issues a PATCH request to url (non-idempotent: not retried by default).
	Patch(url string, options ...RequestOption) (*Result, error)
	// Delete issues a DELETE request to url.
	Delete(url string, options ...RequestOption) (*Result, error)
	// Head issues a HEAD request to url.
	Head(url string, options ...RequestOption) (*Result, error)
	// Options issues an OPTIONS request to url.
	Options(url string, options ...RequestOption) (*Result, error)

	// Download downloads a file from url to the path specified in cfg.
	// cfg must be non-nil and cfg.FilePath must be set (ErrEmptyFilePath otherwise).
	// Use DefaultDownloadConfig() as the starting point, then set FilePath and any
	// of ProgressCallback / Overwrite / ResumeDownload / Checksum as needed.
	// The download is subject to the client's Security.MaxResponseBodySize
	// (default 10 MB); oversize bodies fail with an error, never a silent
	// truncation — see DownloadConfig.
	Download(ctx context.Context, url string, cfg *DownloadConfig, options ...RequestOption) (*DownloadResult, error)

	// Close releases resources held by the client
	Close() error
}

// DomainClienter extends Client with domain-scoped operations.
// It provides session management for cookies and headers across requests
// to a specific domain.
type DomainClienter interface {
	Client

	// URL accessors

	// URL returns the base URL this client was constructed with.
	URL() string
	// Domain returns the host:port of the base URL, scoping sessions and
	// credential reuse to that exact origin.
	Domain() string

	// Session header management

	// SetHeader sets a session header applied to every subsequent request.
	SetHeader(key, value string) error
	// SetHeaders replaces all session headers with the given map.
	SetHeaders(headers map[string]string) error
	// DeleteHeader removes one session header.
	DeleteHeader(key string)
	// ClearHeaders removes all session headers.
	ClearHeaders()
	// GetHeaders returns a copy of the current session headers.
	GetHeaders() map[string]string

	// Session cookie management

	// SetCookie adds a cookie to the domain session.
	SetCookie(cookie *http.Cookie) error
	// SetCookies adds multiple cookies to the domain session.
	SetCookies(cookies []*http.Cookie) error
	// DeleteCookie removes one session cookie by name.
	DeleteCookie(name string)
	// ClearCookies removes all session cookies.
	ClearCookies()
	// GetCookies returns the session cookies.
	GetCookies() []*http.Cookie
	// GetCookie returns one session cookie by name, or nil.
	GetCookie(name string) *http.Cookie

	// Session access

	// Session returns the underlying SessionManager for direct inspection.
	Session() *SessionManager
}

// engineClient defines the interface for the internal engine.Client.
// This enables testing clientImpl without a real engine.Client.
type engineClient interface {
	Request(ctx context.Context, method, url string, opts ...engine.RequestOption) (*engine.Response, error)
	Close() error
	IsClosed() bool
}

// Compile-time check that engine.Client satisfies engineClient.
var _ engineClient = (*engine.Client)(nil)

type clientImpl struct {
	engine          engineClient
	middlewareChain Handler
	hasMiddlewares  bool
}

// New creates a new HTTP client with the given configuration.
// Pass DefaultConfig() for sensible defaults, or use a preset like SecureConfig().
//
// Returns an error if the configuration fails validation (e.g., invalid
// Security.SSRFExemptCIDRs, mutually exclusive security settings) or if the
// underlying engine client cannot be created.
//
// Examples:
//
//	// Use default configuration (or call NewDefault() for the same result)
//	client, err := httpc.New(httpc.DefaultConfig())
//
//	// Use custom configuration
//	cfg := httpc.DefaultConfig()
//	cfg.Timeouts.Request = 60 * time.Second
//	client, err := httpc.New(cfg)
//
//	// Use preset configuration
//	client, err := httpc.New(httpc.SecureConfig())
func New(cfg Config) (Client, error) {
	cfg, err := validatedCopy(cfg)
	if err != nil {
		return nil, err
	}
	return newFromConfig(cfg)
}

// validatedCopy runs the constructor pipeline shared by New and NewDomain:
// validate, deep-copy (callers may reuse their Config), and pre-parse the
// SSRF exemption CIDRs. Keeping the sequence in one place prevents the two
// constructors from drifting apart when a step is added.
func validatedCopy(cfg Config) (Config, error) {
	if err := ValidateConfig(&cfg); err != nil {
		return Config{}, fmt.Errorf("invalid configuration: %w", err)
	}
	cfg = copyConfig(cfg)
	if err := cfg.parseSSRFExemptCIDRs(); err != nil {
		return Config{}, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

// NewDefault creates a new HTTP client with default configuration.
// It is a convenience shortcut for New(DefaultConfig()); see New for possible
// error conditions (default configuration is always valid, so this effectively
// never returns an error in practice).
//
// Example:
//
//	client, err := httpc.NewDefault()
//	defer func() { _ = client.Close() }()
func NewDefault() (Client, error) {
	return New(DefaultConfig())
}

// newFromConfig creates a client from an already-validated and copied config.
// Used internally by New and NewDomain.
func newFromConfig(cfg Config) (Client, error) {
	engineConfig, err := convertToEngineConfig(&cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert configuration: %w", err)
	}

	// Warn if InsecureSkipVerify is enabled outside test environment.
	// Check both the top-level flag and a custom TLSConfig that sets it —
	// otherwise a Security.TLSConfig{InsecureSkipVerify: true} silently
	// disables verification with no warning.
	insecureVerify := cfg.Security.InsecureSkipVerify ||
		(cfg.Security.TLSConfig != nil && cfg.Security.TLSConfig.InsecureSkipVerify)
	if insecureVerify && !isTestEnvironment() {
		insecureSkipVerifyWarnOnce.Do(func() {
			w := getSecurityWarnOutput()
			fmt.Fprintf(w, "[SECURITY WARNING] InsecureSkipVerify is enabled - TLS certificate verification is DISABLED\n")
			fmt.Fprintf(w, "[SECURITY WARNING] This should only be used in testing. Use SecureConfig() for production.\n")
		})
	}

	engineClient, err := engine.NewClient(engineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	client := &clientImpl{
		engine:         engineClient,
		hasMiddlewares: len(cfg.Middleware.Middlewares) > 0,
	}

	// Build middleware chain if middlewares are configured
	if client.hasMiddlewares {
		client.middlewareChain = client.buildMiddlewareChain(cfg.Middleware.Middlewares)
	}

	return client, nil
}

// copyConfig returns an independent copy of cfg. Value-type sub-configs are
// copied by the struct assignment; this function deep-copies the remaining
// reference types (maps, slices, *tls.Config) so the caller cannot mutate the
// client's configuration after construction.
//
// Note: RetryConfig.CustomPolicy is NOT deep-copied. If the policy
// implementation contains mutable state, do not share the same Config
// instance across multiple clients concurrently.
func copyConfig(src Config) Config {
	dst := src // value copy — all sub-config structs are independent

	// Deep copy reference types within sub-configs
	if dst.Defaults.Headers != nil {
		dst.Defaults.Headers = make(map[string]string, len(src.Defaults.Headers))
		maps.Copy(dst.Defaults.Headers, src.Defaults.Headers)
	}

	if len(dst.Middleware.Middlewares) > 0 {
		dst.Middleware.Middlewares = make([]MiddlewareFunc, len(src.Middleware.Middlewares))
		copy(dst.Middleware.Middlewares, src.Middleware.Middlewares)
	}

	if len(dst.Security.RedirectWhitelist) > 0 {
		dst.Security.RedirectWhitelist = make([]string, len(src.Security.RedirectWhitelist))
		copy(dst.Security.RedirectWhitelist, src.Security.RedirectWhitelist)
	}

	if len(dst.Connection.ProxyPool) > 0 {
		dst.Connection.ProxyPool = make([]string, len(src.Connection.ProxyPool))
		copy(dst.Connection.ProxyPool, src.Connection.ProxyPool)
	}

	if len(dst.Connection.ProxyRotateOnStatus) > 0 {
		dst.Connection.ProxyRotateOnStatus = make([]int, len(src.Connection.ProxyRotateOnStatus))
		copy(dst.Connection.ProxyRotateOnStatus, src.Connection.ProxyRotateOnStatus)
	}

	if dst.Security.TLSConfig != nil {
		dst.Security.TLSConfig = src.Security.TLSConfig.Clone()
	}

	if dst.Security.CookieSecurity != nil {
		cookieSec := *src.Security.CookieSecurity
		dst.Security.CookieSecurity = &cookieSec
	}

	if len(dst.Security.SSRFExemptCIDRs) > 0 {
		dst.Security.SSRFExemptCIDRs = make([]string, len(src.Security.SSRFExemptCIDRs))
		copy(dst.Security.SSRFExemptCIDRs, src.Security.SSRFExemptCIDRs)
	}

	if len(src.parsedCIDRs) > 0 {
		dst.parsedCIDRs = make([]*net.IPNet, len(src.parsedCIDRs))
		copy(dst.parsedCIDRs, src.parsedCIDRs)
	}

	return dst
}

// buildMiddlewareChain constructs a middleware chain from the provided middlewares.
// The terminal handler copies the middleware-modified request fields into a fresh engine
// request and executes it. This avoids re-applying user options (double execution) and
// uses a single option closure to forward all mutable state.
//
// Callbacks (OnRequest/OnResponse) and the per-request SSRF override (AllowPrivateIPs)
// live on the concrete *engine.Request, not on the shared RequestMutator interface:
// their signatures reference *engine.Request/*engine.Response, and surfacing them
// through internal/types would create an import cycle (engine -> types). The terminal
// handler therefore reads them via a concrete-type assertion. This is a deliberate,
// bounded coupling to *engine.Request with a graceful fallback — see finalHandler.
func (c *clientImpl) buildMiddlewareChain(middlewares []MiddlewareFunc) Handler {
	finalHandler := func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
		reqCtx := req.Context()
		if reqCtx == nil {
			reqCtx = ctx
		}

		// The concrete *engine.Request carries engine-specific hooks (callbacks,
		// per-request SSRF override) that are not part of RequestMutator (see the
		// buildMiddlewareChain doc above). Apply() forwards them along with every
		// other field when the assertion succeeds. A middleware that replaces req
		// with a non-*engine.Request value loses them; request replacement is
		// therefore unsupported for callbacks/SSRF-override (mirrors
		// getOrComputeSanitizedURL).
		engReq, isEngineReq := req.(*engine.Request)

		// Single option closure forwards all mutable fields from the middleware-modified request.
		resp, err := c.engine.Request(reqCtx, req.Method(), req.URL(),
			func(r *engine.Request) error {
				// Fast path: src is the concrete *engine.Request (all built-in
				// middleware mutates in place). Apply is owned by the engine, so
				// new Request fields are forwarded here by construction — the
				// facade no longer enumerates them.
				if isEngineReq {
					r.Apply(engReq)
					return nil
				}
				// Fallback for a middleware that replaced req with a non-*engine.Request
				// RequestMutator: forward via the interface accessors. Callbacks and
				// the SSRF override are unavailable in this case (see doc above).
				//
				// Headers and query params are passed as-is: engine
				// SetHeaders/SetQueryParams COPY into engine-pooled maps, which
				// is exactly what this path needs — a replacing middleware's
				// accessors may return the engineReq's pooled maps, and copying
				// at the engine boundary prevents the same pooled map being
				// returned to the pool twice (double-release → concurrent map
				// writes across future requests). No facade-side copy required;
				// the engine setter is the single copy point.
				if headers := req.Headers(); headers != nil {
					r.SetHeaders(headers)
				}
				if qp := req.QueryParams(); qp != nil {
					r.SetQueryParams(qp)
				}
				r.SetBody(req.Body())
				r.SetTimeout(req.Timeout())
				r.SetMaxRetries(req.MaxRetries())
				r.SetCookies(req.Cookies())
				if fr := req.FollowRedirects(); fr != nil {
					r.SetFollowRedirects(fr)
				}
				if mr := req.MaxRedirects(); mr != nil {
					r.SetMaxRedirects(mr)
				}
				r.SetStreamBody(req.StreamBody())
				return nil
			})
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	return Chain(middlewares...)(finalHandler)
}

// Get makes a GET request to the specified URL using the client's configuration.
func (c *clientImpl) Get(url string, options ...RequestOption) (*Result, error) {
	return c.doRequest("GET", url, options)
}

// Post makes a POST request to the specified URL using the client's configuration.
func (c *clientImpl) Post(url string, options ...RequestOption) (*Result, error) {
	return c.doRequest("POST", url, options)
}

// Put makes a PUT request to the specified URL using the client's configuration.
func (c *clientImpl) Put(url string, options ...RequestOption) (*Result, error) {
	return c.doRequest("PUT", url, options)
}

// Patch makes a PATCH request to the specified URL using the client's configuration.
func (c *clientImpl) Patch(url string, options ...RequestOption) (*Result, error) {
	return c.doRequest("PATCH", url, options)
}

// Delete makes a DELETE request to the specified URL using the client's configuration.
func (c *clientImpl) Delete(url string, options ...RequestOption) (*Result, error) {
	return c.doRequest("DELETE", url, options)
}

// Head makes a HEAD request to the specified URL using the client's configuration.
func (c *clientImpl) Head(url string, options ...RequestOption) (*Result, error) {
	return c.doRequest("HEAD", url, options)
}

// Options makes an OPTIONS request to the specified URL using the client's configuration.
func (c *clientImpl) Options(url string, options ...RequestOption) (*Result, error) {
	return c.doRequest("OPTIONS", url, options)
}

// doRequest executes an HTTP request with the given method and options.
// It delegates to Request with a background context for convenience methods.
func (c *clientImpl) doRequest(method, url string, options []RequestOption) (*Result, error) {
	return c.Request(backgroundCtx, method, url, options...)
}

// Request executes an HTTP request with the given context, method, URL, and options.
// The context parameter allows for timeout and cancellation control.
func (c *clientImpl) Request(ctx context.Context, method, url string, options ...RequestOption) (result *Result, err error) {
	// SEC-003: default panic safety net. An unexpected runtime panic anywhere in the
	// execution path (engine, transport, TLS, response conversion) is converted to an
	// error instead of crashing the caller. Pool hygiene is unaffected: executeRequest's
	// own deferred releases and the releaseResponseMutator defer below run during stack
	// unwinding before this recover (LIFO), so no pooled Response is leaked on panic.
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = panicToError(r)
		}
	}()
	resp, err := c.executeRequest(ctx, method, url, options)
	if err != nil {
		return nil, err
	}
	// WithStreamBody has no effect on this path: the body is buffered into a
	// Result below and the stream is closed by releaseResponseMutator, so the
	// caller would silently get an empty body. Fail loudly instead and point
	// at Download, which is the streaming entry point.
	//
	// The type assertion covers both the direct engine path and the middleware
	// path (whose terminal handler returns the engine Response unwrapped). A
	// user middleware that *wraps* the Response in its own type escapes this
	// guard — such authors own the streaming contract (see TimeoutMiddleware
	// for the reject-up-front pattern).
	if engineResp, ok := resp.(*engine.Response); ok && engineResp.RawBodyReader() != nil {
		releaseResponseMutator(resp)
		return nil, ErrStreamBodyRequiresDownload
	}
	defer releaseResponseMutator(resp)
	return convertResponseToResult(resp), nil
}

// releaseResponseMutator safely releases a ResponseMutator back to the engine pool.
// If the response is an *engine.Response, it is returned via ReleaseResponse.
// Custom ResponseMutator implementations (e.g., from middleware wrapping) are not
// pooled — middleware authors are responsible for their own resource cleanup.
func releaseResponseMutator(resp ResponseMutator) {
	if resp == nil {
		return
	}
	if engineResp, ok := resp.(*engine.Response); ok {
		engine.ReleaseResponse(engineResp)
	}
}

// acquireMiddlewareRequest gets a Request from the engine's shared pool.
func acquireMiddlewareRequest() *engine.Request {
	return engine.AcquireRequest()
}

// releaseMiddlewareRequest returns a Request to the engine's shared pool.
func releaseMiddlewareRequest(req *engine.Request) {
	engine.ReleaseRequest(req)
}

// executeRequest executes an HTTP request through the middleware chain (if configured)
// or directly via the engine. Returns the raw ResponseMutator; the caller must
// release the response via engine.ReleaseResponse() or convert it via convertResponseToResult().
//
// Middleware contract: if a middleware calls next() and obtains a non-nil response,
// it must either return that response (directly or via a later next() call) or
// explicitly release it via releaseResponseMutator(). Returning (nil, error) while
// holding an unreleased response will cause a pool leak.
func (c *clientImpl) executeRequest(ctx context.Context, method, url string, options []RequestOption) (ResponseMutator, error) {
	if c.engine != nil && c.engine.IsClosed() {
		return nil, ErrClientClosed
	}
	if !c.hasMiddlewares {
		return c.engine.Request(ctx, method, url, options...)
	}

	engineReq := acquireMiddlewareRequest()
	// Clear sensitive data (cookies, headers, auth tokens) before returning to pool.
	// SAFETY: middlewareChain executes synchronously — defer runs only after
	// the chain returns. If async middleware is ever introduced, this pool
	// pattern will cause data races and must be redesigned.
	defer releaseMiddlewareRequest(engineReq)

	engineReq.SetMethod(method)
	engineReq.SetURL(url)
	engineReq.SetContext(ctx)

	for _, opt := range options {
		if opt != nil {
			if err := opt(engineReq); err != nil {
				return nil, fmt.Errorf("failed to apply request option: %w", err)
			}
		}
	}

	resp, err := c.middlewareChain(ctx, engineReq)
	// Safety net: if middleware returned an error but also a response,
	// release the response to prevent pool leaks. This handles user-written
	// middlewares that call next() (obtaining a response) then return an error
	// without passing it along.
	if err != nil && resp != nil {
		releaseResponseMutator(resp)
		return nil, err
	}
	// A middleware contract violation: neither a response nor an error.
	// Without this guard the caller would receive (nil, nil), and the nil-safe
	// Result accessors would silently report StatusCode 0 as a "success".
	// Mirrors the defensive fallback in engine executeWithRetry.
	if resp == nil && err == nil {
		return nil, fmt.Errorf("middleware chain returned neither a response nor an error")
	}
	return resp, err
}

// Close releases resources held by the client including connection pools and transport.
// After calling Close, the client must not be used for further requests.
func (c *clientImpl) Close() error {
	if c.engine == nil {
		return nil
	}
	if err := c.engine.Close(); err != nil {
		return fmt.Errorf("failed to close client: %w", err)
	}
	return nil
}

var (
	defaultClient   atomic.Pointer[clientImpl]
	defaultClientMu sync.Mutex
)

func getDefaultClient() (Client, error) {
	// Fast path: check if already initialized (lock-free).
	// A closed default client is treated as absent so the singleton
	// self-heals after CloseDefaultClient() or a direct client.Close().
	if client := defaultClient.Load(); client != nil && !client.engine.IsClosed() {
		return client, nil
	}

	// Slow path: mutex-protected initialization ensures exactly one client
	defaultClientMu.Lock()
	defer defaultClientMu.Unlock()

	// Double-check after acquiring lock
	if client := defaultClient.Load(); client != nil && !client.engine.IsClosed() {
		return client, nil
	}

	newClient, err := NewDefault()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize default client: %w", err)
	}

	impl, ok := newClient.(*clientImpl)
	if !ok {
		_ = newClient.Close() // Prevent resource leak on unexpected type
		return nil, fmt.Errorf("unexpected client type")
	}

	defaultClient.Store(impl)
	return impl, nil
}

// CloseDefaultClient closes the default client and resets it.
// After calling this, the next package-level function call will create a new client.
// This function is safe for concurrent use.
func CloseDefaultClient() error {
	defaultClientMu.Lock()
	defer defaultClientMu.Unlock()

	client := defaultClient.Load()
	if client == nil {
		return nil
	}
	defaultClient.Store(nil)
	return client.Close()
}

// withDefault resolves the default client and dispatches a request through it.
// It is the single dispatch point for every package-level HTTP function, so the
// package-level verbs and Request share one code path instead of duplicating the
// default-client resolution in two separate helpers.
func withDefault(ctx context.Context, method, url string, options []RequestOption) (*Result, error) {
	client, err := getDefaultClient()
	if err != nil {
		return nil, err
	}
	return client.Request(ctx, method, url, options...)
}

// Package-level HTTP convenience functions (Get, Post, Put, Patch, Delete,
// Head, Options, Request) use a shared default client managed internally.
// Each delegates to the corresponding method on that singleton client (see
// SetDefaultClient, CloseDefaultClient). For production services, prefer an
// explicit client created with NewDefault() to control configuration
// and lifecycle.

// Get makes a GET request to the specified URL using the default client.
func Get(url string, options ...RequestOption) (*Result, error) {
	return withDefault(backgroundCtx, "GET", url, options)
}

// Post makes a POST request to the specified URL using the default client.
func Post(url string, options ...RequestOption) (*Result, error) {
	return withDefault(backgroundCtx, "POST", url, options)
}

// Put makes a PUT request to the specified URL using the default client.
func Put(url string, options ...RequestOption) (*Result, error) {
	return withDefault(backgroundCtx, "PUT", url, options)
}

// Patch makes a PATCH request to the specified URL using the default client.
func Patch(url string, options ...RequestOption) (*Result, error) {
	return withDefault(backgroundCtx, "PATCH", url, options)
}

// Delete makes a DELETE request to the specified URL using the default client.
func Delete(url string, options ...RequestOption) (*Result, error) {
	return withDefault(backgroundCtx, "DELETE", url, options)
}

// Head makes a HEAD request to the specified URL using the default client.
func Head(url string, options ...RequestOption) (*Result, error) {
	return withDefault(backgroundCtx, "HEAD", url, options)
}

// Options makes an OPTIONS request to the specified URL using the default client.
func Options(url string, options ...RequestOption) (*Result, error) {
	return withDefault(backgroundCtx, "OPTIONS", url, options)
}

// Request executes an HTTP request with the given method using the default client.
// The context parameter allows for timeout and cancellation control.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	result, err := httpc.Request(ctx, "GET", "https://api.example.com/data")
func Request(ctx context.Context, method, url string, options ...RequestOption) (*Result, error) {
	return withDefault(ctx, method, url, options)
}

// SetDefaultClient sets a custom client as the default for package-level functions.
// The previous default client is closed automatically.
//
// Concurrency: closing the previous default aborts any requests still in
// flight on it — goroutines that already resolved the old client may observe
// connection errors. Swap the default only at startup or during a quiescent
// window, never under live traffic.
// Only *clientImpl instances created by this package are supported.
// Returns an error if client is nil, not created by this package, or already closed.
func SetDefaultClient(client Client) error {
	if client == nil {
		return fmt.Errorf("cannot set nil client as default")
	}

	impl, ok := client.(*clientImpl)
	if !ok {
		return fmt.Errorf("only clients created by this package are supported")
	}

	defaultClientMu.Lock()
	defer defaultClientMu.Unlock()

	if impl.engine.IsClosed() {
		return fmt.Errorf("cannot set a closed client as default")
	}

	// Swap the old client with the new one
	var closeErr error
	oldClient := defaultClient.Load()
	defaultClient.Store(impl)
	if oldClient != nil && oldClient != impl {
		closeErr = oldClient.Close()
	}
	return closeErr
}

// resultBundle co-locates a Result and its three nested info structs in a single
// heap allocation. convertResponseToResult returns &b.result, whose Request,
// Response, and Meta fields point into the same bundle. This collapses four
// separate allocations (Result + RequestInfo + ResponseInfo + RequestMeta) into
// one while remaining transparent to callers — the public API exposes only the
// *Result pointer, and the bundle is reclaimed by GC once the result is.
// Pooling is unsuitable here because callers retain the returned Result
// indefinitely.
type resultBundle struct {
	result Result
	req    RequestInfo
	resp   ResponseInfo
	meta   RequestMeta
}

func convertResponseToResult(resp ResponseMutator) *Result {
	if resp == nil {
		return nil
	}

	// Optimization: transfer request header ownership from the engine Response
	// instead of cloning. Fall back to Headers() for middleware-wrapped responses.
	var requestHeaders http.Header
	if engineResp, ok := resp.(*engine.Response); ok {
		requestHeaders = engineResp.TransferRequestHeaders()
	} else {
		requestHeaders = resp.RequestHeaders()
	}
	requestCookies := extractRequestCookies(requestHeaders)

	// Single allocation for Result and its three nested structs (see resultBundle).
	b := &resultBundle{
		req: RequestInfo{
			URL:     resp.RequestURL(),
			Method:  resp.RequestMethod(),
			Headers: requestHeaders,
			Cookies: requestCookies,
		},
		resp: ResponseInfo{
			StatusCode: resp.StatusCode(),
			Status:     resp.Status(),
			Proto:      resp.Proto(),
		},
		meta: RequestMeta{
			Duration:      resp.Duration(),
			Attempts:      resp.Attempts(),
			RedirectChain: resp.RedirectChain(),
			RedirectCount: resp.RedirectCount(),
		},
	}
	result := &b.result
	result.Request = &b.req
	result.Response = &b.resp
	result.Meta = &b.meta

	// Transfer header ownership from engine Response.
	// Fall back to clone for middleware-wrapped ResponseMutator.
	if engineResp, ok := resp.(*engine.Response); ok {
		result.Response.Headers = engineResp.TransferHeaders()
		b.meta.ProxyURL = engineResp.ProxyURL()
	} else {
		result.Response.Headers = cloneHeaders(resp.Headers())
	}
	result.Response.RawBody = resp.RawBody()
	if len(result.Response.RawBody) > 0 {
		result.Response.Body = string(result.Response.RawBody)
	}
	result.Response.ContentLength = resp.ContentLength()
	result.Response.Cookies = resp.Cookies()

	return result
}

func extractRequestCookies(headers http.Header) []*http.Cookie {
	if headers == nil {
		return nil
	}

	// Direct map lookup with the pre-canonicalized key "Cookie" avoids the
	// textproto.CanonicalMIMEHeaderKey overhead of headers.Get on every request.
	cookieVals := headers["Cookie"]
	if len(cookieVals) == 0 || cookieVals[0] == "" {
		return nil
	}

	return parseCookieHeader(cookieVals[0])
}

// cloneHeaders returns a deep copy of http.Header. Delegates to the engine's
// batch-allocation CloneHeader to avoid duplicating the logic.
func cloneHeaders(h http.Header) http.Header {
	return engine.CloneHeader(h)
}

func createCookieJar(enableCookies bool, psl cookiejar.PublicSuffixList) (http.CookieJar, error) {
	if !enableCookies {
		return nil, nil
	}
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: psl,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}
	return jar, nil
}
