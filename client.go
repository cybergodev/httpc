package httpc

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/http"
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

	// Convenience methods for common HTTP verbs
	Get(url string, options ...RequestOption) (*Result, error)
	Post(url string, options ...RequestOption) (*Result, error)
	Put(url string, options ...RequestOption) (*Result, error)
	Patch(url string, options ...RequestOption) (*Result, error)
	Delete(url string, options ...RequestOption) (*Result, error)
	Head(url string, options ...RequestOption) (*Result, error)
	Options(url string, options ...RequestOption) (*Result, error)

	// Download downloads a file from url to the path specified in cfg.
	// cfg must be non-nil and cfg.FilePath must be set (ErrEmptyFilePath otherwise).
	// Use DefaultDownloadConfig() as the starting point, then set FilePath and any
	// of ProgressCallback / Overwrite / ResumeDownload / Checksum as needed.
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
	URL() string
	Domain() string

	// Session header management
	SetHeader(key, value string) error
	SetHeaders(headers map[string]string) error
	DeleteHeader(key string)
	ClearHeaders()
	GetHeaders() map[string]string

	// Session cookie management
	SetCookie(cookie *http.Cookie) error
	SetCookies(cookies []*http.Cookie) error
	DeleteCookie(name string)
	ClearCookies()
	GetCookies() []*http.Cookie
	GetCookie(name string) *http.Cookie

	// Session access
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
// If no configuration is provided or nil is passed, DefaultConfig() is used.
//
// Examples:
//
//	// Use default configuration
//	client, err := httpc.New()
//
//	// Use default configuration (explicit nil)
//	client, err := httpc.New(nil)
//
//	// Use custom configuration
//	cfg := httpc.DefaultConfig()
//	cfg.Timeouts.Request = 60 * time.Second
//	client, err := httpc.New(cfg)
//
//	// Use preset configuration
//	client, err := httpc.New(httpc.SecureConfig())
func New(config ...*Config) (Client, error) {
	var in *Config
	if len(config) > 0 {
		in = config[0]
	}
	cfg, err := prepareConfig(in)
	if err != nil {
		return nil, err
	}
	return newFromPreparedConfig(cfg)
}

// prepareConfig validates, deep-copies, parses SSRF exempt CIDRs, and fills nil
// sub-configs from the defaults. Returns DefaultConfig() when in is nil.
// Shared by New and NewDomain so the two constructors cannot drift apart; the
// error wrapping matches the previously inlined logic exactly.
func prepareConfig(in *Config) (*Config, error) {
	if in == nil {
		return DefaultConfig(), nil
	}
	if err := ValidateConfig(in); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	cfg := deepCopyConfig(in)
	if err := cfg.parseSSRFExemptCIDRs(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return mergeNilSubConfigs(cfg), nil
}

// newFromPreparedConfig creates a client from an already-validated and deep-copied config.
// Used internally by NewDomain to avoid redundant validation and deep copy.
func newFromPreparedConfig(cfg *Config) (Client, error) {
	engineConfig, err := convertToEngineConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert configuration: %w", err)
	}

	// Warn if InsecureSkipVerify is enabled outside test environment.
	if cfg.Security != nil && cfg.Security.InsecureSkipVerify && !isTestEnvironment() {
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
		hasMiddlewares: cfg.Middleware != nil && len(cfg.Middleware.Middlewares) > 0,
	}

	// Build middleware chain if middlewares are configured
	if client.hasMiddlewares && cfg.Middleware != nil {
		client.middlewareChain = client.buildMiddlewareChain(cfg.Middleware.Middlewares)
	}

	return client, nil
}

// deepCopyConfig creates a deep copy of the configuration to prevent
// accidental mutation of shared config state. This is called internally
// when creating a new client to ensure each client has its own
// independent configuration.
//
// Note: RetryConfig.CustomPolicy is NOT deep-copied. If the policy
// implementation contains mutable state, do not share the same Config
// instance across multiple clients concurrently.
func deepCopyConfig(src *Config) *Config {
	dst := *src

	// Deep copy each sub-config pointer
	if src.Timeouts != nil {
		cp := *src.Timeouts
		dst.Timeouts = &cp
	}
	if src.Connection != nil {
		cp := *src.Connection
		dst.Connection = &cp
	}
	if src.Security != nil {
		cp := *src.Security
		dst.Security = &cp
		// Note: CertificatePinner is an interface copied by reference (shared),
		// not deep-copied. Pinner implementations are concurrency-safe, so
		// sharing across clients is intentional. See SecurityConfig.CertificatePinner.
	}
	if src.Retry != nil {
		cp := *src.Retry
		dst.Retry = &cp
	}
	if src.Middleware != nil {
		cp := *src.Middleware
		dst.Middleware = &cp
	}

	// Deep copy middleware headers
	if src.Middleware != nil && src.Middleware.Headers != nil {
		dst.Middleware.Headers = make(map[string]string, len(src.Middleware.Headers))
		maps.Copy(dst.Middleware.Headers, src.Middleware.Headers)
	}

	// Deep copy middlewares slice
	if src.Middleware != nil && len(src.Middleware.Middlewares) > 0 {
		dst.Middleware.Middlewares = make([]MiddlewareFunc, len(src.Middleware.Middlewares))
		copy(dst.Middleware.Middlewares, src.Middleware.Middlewares)
	}

	// Deep copy redirect whitelist
	if src.Security != nil && len(src.Security.RedirectWhitelist) > 0 {
		dst.Security.RedirectWhitelist = make([]string, len(src.Security.RedirectWhitelist))
		copy(dst.Security.RedirectWhitelist, src.Security.RedirectWhitelist)
	}

	// Clone TLS config if present
	if src.Security != nil && src.Security.TLSConfig != nil {
		dst.Security.TLSConfig = src.Security.TLSConfig.Clone()
	}

	// Deep copy cookie security config if present
	if src.Security != nil && src.Security.CookieSecurity != nil {
		cookieSec := *src.Security.CookieSecurity
		dst.Security.CookieSecurity = &cookieSec
	}

	// Deep copy SSRF exempt CIDRs
	if src.Security != nil && len(src.Security.SSRFExemptCIDRs) > 0 {
		dst.Security.SSRFExemptCIDRs = make([]string, len(src.Security.SSRFExemptCIDRs))
		copy(dst.Security.SSRFExemptCIDRs, src.Security.SSRFExemptCIDRs)
	}

	// Transfer cached parsed CIDRs (pointer slice is safe to share — net.IPNet is read-only)
	if len(src.parsedCIDRs) > 0 {
		dst.parsedCIDRs = make([]*net.IPNet, len(src.parsedCIDRs))
		copy(dst.parsedCIDRs, src.parsedCIDRs)
	}

	return &dst
}

// mergeNilSubConfigs fills nil sub-config pointers with copies of the defaults
// from DefaultConfig. This allows callers to partially configure a Config — any
// nil sub-config gets sensible defaults, while non-nil sub-configs are used as-is.
//
// Each default is copied (not aliased) so the resulting Config owns its sub-configs
// exclusively, matching the isolation that deepCopyConfig already provides for the
// non-nil sub-configs. Without this, every client built from a partially-specified
// Config would share the same DefaultConfig() sub-config pointers.
func mergeNilSubConfigs(cfg *Config) *Config {
	def := DefaultConfig()
	if cfg.Timeouts == nil {
		cp := *def.Timeouts
		cfg.Timeouts = &cp
	}
	if cfg.Connection == nil {
		cp := *def.Connection
		cfg.Connection = &cp
	}
	if cfg.Security == nil {
		cp := *def.Security
		cfg.Security = &cp
	}
	if cfg.Retry == nil {
		cp := *def.Retry
		cfg.Retry = &cp
	}
	if cfg.Middleware == nil {
		cp := *def.Middleware
		// Give each client its own headers map rather than aliasing the default's.
		cp.Headers = make(map[string]string, len(def.Middleware.Headers))
		maps.Copy(cp.Headers, def.Middleware.Headers)
		cfg.Middleware = &cp
	}
	return cfg
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

		// Read the engine-specific hooks (callbacks + per-request SSRF override) from
		// the concrete *engine.Request. These are not part of RequestMutator (see the
		// buildMiddlewareChain doc above), so we assert once here and forward the
		// captured values through the option closure below. Middleware that mutates the
		// request in place — as all built-in middlewares do — leaves req as an
		// *engine.Request, so the assertion succeeds and the hooks are forwarded.
		// Should a middleware replace req with a non-*engine.Request value, the
		// assertion fails and these hooks are silently skipped; request replacement is
		// therefore unsupported for callbacks/SSRF-override (mirrors getOrComputeSanitizedURL).
		var onRequest func(*engine.Request) error
		var onResponse func(*engine.Response) error
		var allowPrivateIPs *bool
		if engReq, ok := req.(*engine.Request); ok {
			if cb := engReq.OnRequest(); cb != nil {
				onRequest = cb
			}
			if cb := engReq.OnResponse(); cb != nil {
				onResponse = cb
			}
			allowPrivateIPs = engReq.AllowPrivateIPs()
		}

		// Single option closure forwards all mutable fields from the middleware-modified request.
		resp, err := c.engine.Request(reqCtx, req.Method(), req.URL(),
			func(r *engine.Request) error {
				r.SetHeaders(req.Headers())
				r.SetQueryParams(req.QueryParams())
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
				if allowPrivateIPs != nil {
					r.SetAllowPrivateIPs(allowPrivateIPs)
				}
				r.SetStreamBody(req.StreamBody())
				// Forward pre-extracted callbacks
				if onRequest != nil {
					r.SetOnRequest(onRequest)
				}
				if onResponse != nil {
					r.SetOnResponse(onResponse)
				}
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

	newClient, err := New()
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

	// Fast path: avoid map lookup when no Cookie header exists
	cookieHeader := headers.Get("Cookie")
	if cookieHeader == "" {
		return nil
	}

	return parseCookieHeader(cookieHeader)
}

// cloneHeaders returns a deep copy of http.Header. Delegates to the engine's
// batch-allocation CloneHeader to avoid duplicating the logic.
func cloneHeaders(h http.Header) http.Header {
	return engine.CloneHeader(h)
}

func createCookieJar(enableCookies bool) (http.CookieJar, error) {
	if !enableCookies {
		return nil, nil
	}
	jar, err := newCookieJar()
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}
	return jar, nil
}
