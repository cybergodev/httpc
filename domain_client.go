package httpc

import (
	"context"
	"fmt"
	"net/url"
	stdpath "path"
	"strings"
)

// DomainClient provides a client scoped to a specific domain with session management.
// It maintains cookies and headers across requests and provides convenient methods
// for making HTTP requests relative to a base URL.
//
// For better flexibility, use the DomainClienter interface instead of the concrete type:
//
//	var dc httpc.DomainClienter
//	dc, err := httpc.NewDomain("https://api.example.com", httpc.DefaultConfig())
type DomainClient struct {
	client    Client
	baseURL   string
	parsedURL *url.URL // Cached parsed URL for efficient URL building
	domain    string
	*SessionManager
}

// NewDomain creates a new DomainClient scoped to the specified base URL.
// The client automatically manages cookies and headers across requests.
// Pass DefaultConfig() for defaults, or use NewDomainDefault(baseURL) as a
// zero-argument shortcut. Cookies are automatically enabled for DomainClient.
//
// Returns a DomainClienter interface for flexibility and testability.
// Type-assert to *DomainClient if access to the concrete type is needed.
//
// Examples:
//
//	// Use default configuration
//	dc, err := httpc.NewDomain("https://api.example.com", httpc.DefaultConfig())
//
//	// Use custom configuration
//	cfg := httpc.DefaultConfig()
//	cfg.Timeouts.Request = 60 * time.Second
//	dc, err := httpc.NewDomain("https://api.example.com", cfg)
//
//	// Set session headers
//	dc.SetHeader("Authorization", "Bearer token")
//
//	// Make requests relative to base URL
//	result, err := dc.Get("/users")
func NewDomain(baseURL string, cfg Config) (DomainClienter, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("base URL must include scheme and host")
	}

	if err := ValidateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	cfg = copyConfig(cfg)
	if err := cfg.parseSSRFExemptCIDRs(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	cfg.Connection.EnableCookies = true
	client, err := newFromConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create domain client: %w", err)
	}

	session, err := NewSessionManager(DefaultSessionConfig())
	if err != nil {
		_ = client.Close() // best-effort cleanup
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &DomainClient{
		client:         client,
		baseURL:        baseURL,
		parsedURL:      parsedURL,
		domain:         parsedURL.Hostname(),
		SessionManager: session,
	}, nil
}

// NewDomainDefault creates a DomainClient scoped to baseURL using DefaultConfig().
// It is a convenience shortcut for NewDomain(baseURL, DefaultConfig()), mirroring
// NewDefault() for the main client.
//
// Example:
//
//	dc, err := httpc.NewDomainDefault("https://api.example.com")
//	defer func() { _ = dc.Close() }()
func NewDomainDefault(baseURL string) (DomainClienter, error) {
	return NewDomain(baseURL, DefaultConfig())
}

// Get makes a GET request to the specified path relative to the base URL.
// If path is a full URL (with scheme), it is used directly.
func (dc *DomainClient) Get(path string, options ...RequestOption) (*Result, error) {
	return dc.request("GET", path, options...)
}

// Post makes a POST request to the specified path relative to the base URL.
// If path is a full URL (with scheme), it is used directly.
func (dc *DomainClient) Post(path string, options ...RequestOption) (*Result, error) {
	return dc.request("POST", path, options...)
}

// Put makes a PUT request to the specified path relative to the base URL.
// If path is a full URL (with scheme), it is used directly.
func (dc *DomainClient) Put(path string, options ...RequestOption) (*Result, error) {
	return dc.request("PUT", path, options...)
}

// Patch makes a PATCH request to the specified path relative to the base URL.
// If path is a full URL (with scheme), it is used directly.
func (dc *DomainClient) Patch(path string, options ...RequestOption) (*Result, error) {
	return dc.request("PATCH", path, options...)
}

// Delete makes a DELETE request to the specified path relative to the base URL.
// If path is a full URL (with scheme), it is used directly.
func (dc *DomainClient) Delete(path string, options ...RequestOption) (*Result, error) {
	return dc.request("DELETE", path, options...)
}

// Head makes a HEAD request to the specified path relative to the base URL.
// If path is a full URL (with scheme), it is used directly.
func (dc *DomainClient) Head(path string, options ...RequestOption) (*Result, error) {
	return dc.request("HEAD", path, options...)
}

// Options makes an OPTIONS request to the specified path relative to the base URL.
// If path is a full URL (with scheme), it is used directly.
func (dc *DomainClient) Options(path string, options ...RequestOption) (*Result, error) {
	return dc.request("OPTIONS", path, options...)
}

// Request makes an HTTP request with the specified method and path relative to the base URL.
// If path is a full URL (with scheme), it is used directly.
// The context parameter allows for timeout and cancellation control.
// This method makes DomainClient compatible with the Client interface.
//
// Note: RequestOptions are executed twice internally — once to capture session state
// (cookies, headers) and once for the actual request. Avoid options with side effects
// (e.g., counters, nonce generation) or use the underlying Client directly if needed.
func (dc *DomainClient) Request(ctx context.Context, method, path string, options ...RequestOption) (*Result, error) {
	if err := dc.checkInit(); err != nil {
		return nil, err
	}

	fullURL, err := dc.buildURL(path)
	if err != nil {
		return nil, err
	}

	allOptions := dc.prepareSessionOptions(options)

	result, err := dc.client.Request(ctx, method, fullURL, allOptions...)
	if err != nil {
		return nil, err
	}

	if result != nil {
		dc.UpdateFromResult(result)
	}

	return result, nil
}

// Download downloads a file from the specified path to cfg.FilePath.
// Response cookies are captured into the session. Like Request, request options are
// applied twice internally (once for session capture, once for the actual request) —
// avoid options with side effects (e.g., counters, nonce generation).
//
// cfg must be non-nil; cfg.FilePath must be set (ErrEmptyFilePath otherwise).
// Use DefaultDownloadConfig() as the starting point, then set FilePath and any
// of ProgressCallback / Overwrite / ResumeDownload / Checksum as needed.
func (dc *DomainClient) Download(ctx context.Context, path string, cfg *DownloadConfig, options ...RequestOption) (*DownloadResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("download config cannot be nil")
	}
	return dc.downloadWithContext(ctx, path,
		func(ctx context.Context, url string, opts *DownloadConfig, additional ...RequestOption) (*DownloadResult, error) {
			return dc.client.Download(ctx, url, opts, additional...)
		},
		cfg, options,
	)
}

// downloadFunc is the signature for delegating a download to the underlying client.
type downloadFunc func(ctx context.Context, url string, opts *DownloadConfig, options ...RequestOption) (*DownloadResult, error)

// downloadWithContext is the shared implementation for DomainClient download methods.
// It handles initialization checks, URL building, session option merging, and cookie capture.
func (dc *DomainClient) downloadWithContext(ctx context.Context, path string, doDownload downloadFunc, downloadOpts *DownloadConfig, options []RequestOption) (*DownloadResult, error) {
	if err := dc.checkInit(); err != nil {
		return nil, err
	}

	fullURL, err := dc.buildURL(path)
	if err != nil {
		return nil, err
	}

	allOptions := dc.prepareSessionOptions(options)

	result, err := doDownload(ctx, fullURL, downloadOpts, allOptions...)
	if err != nil {
		return nil, err
	}

	dc.captureDownloadCookies(result)
	return result, nil
}

// prepareSessionOptions merges session state (headers, cookies) with user-provided options.
// The read-then-write sequence is intentionally non-atomic: session state is eventually
// consistent by design. A concurrent request may interleave, but each request captures
// a consistent snapshot at prepareOptions() time.
func (dc *DomainClient) prepareSessionOptions(options []RequestOption) []RequestOption {
	managedOptions := dc.prepareOptions()
	allOptions := append(managedOptions, options...)
	dc.captureFromOptions(options)
	return allOptions
}

// captureDownloadCookies captures response cookies from a download result into the session.
func (dc *DomainClient) captureDownloadCookies(result *DownloadResult) {
	if result != nil {
		dc.UpdateFromCookies(result.ResponseCookies)
	}
}

// request is an internal helper that delegates to Request with a background context.
// This eliminates code duplication between Request() and the convenience methods.
func (dc *DomainClient) request(method, path string, options ...RequestOption) (*Result, error) {
	return dc.Request(backgroundCtx, method, path, options...)
}

// checkInit validates that the DomainClient is properly initialized.
func (dc *DomainClient) checkInit() error {
	if dc == nil {
		return fmt.Errorf("domain client is nil")
	}
	if dc.SessionManager == nil || dc.client == nil {
		return fmt.Errorf("domain client is not properly initialized; use httpc.NewDomain(baseURL, cfg)")
	}
	return nil
}

func (dc *DomainClient) buildURL(pathStr string) (string, error) {
	if pathStr == "" {
		return dc.baseURL, nil
	}

	// Check if pathStr is already a full URL
	if strings.HasPrefix(pathStr, "http://") || strings.HasPrefix(pathStr, "https://") {
		parsedURL, err := url.Parse(pathStr)
		if err == nil && parsedURL.Scheme != "" && parsedURL.Host != "" {
			return pathStr, nil
		}
	}

	// Use cached parsed URL (initialized in NewDomain, read-only here)
	if dc.parsedURL == nil {
		return "", fmt.Errorf("base URL was not properly initialized")
	}

	// Clone the cached URL to avoid modifying the original
	result := *dc.parsedURL

	// Parse pathStr to separate path from query/fragment
	parsed, err := url.Parse(pathStr)
	if err != nil {
		return "", fmt.Errorf("invalid path %q: %w", pathStr, err)
	}
	wantTrailingSlash := strings.HasSuffix(parsed.Path, "/")
	result.Path = stdpath.Join(dc.parsedURL.Path, parsed.Path)
	// path.Join strips trailing slashes; restore if the original path had one.
	if wantTrailingSlash && !strings.HasSuffix(result.Path, "/") {
		result.Path += "/"
	}
	// Prevent path traversal: ensure result stays within base path scope.
	// Use path-separator-aware comparison to block prefix collisions
	// (e.g., base "/a" must not allow escape to "/ab").
	// Skip check when base path is empty (no scope restriction needed).
	if dc.parsedURL.Path != "" && dc.parsedURL.Path != "/" {
		if result.Path != dc.parsedURL.Path &&
			!strings.HasPrefix(result.Path, dc.parsedURL.Path+"/") {
			return "", fmt.Errorf("path %q escapes base URL scope", pathStr)
		}
	}
	// Preserve trailing slash from base URL when request path is empty
	if parsed.Path == "" && strings.HasSuffix(dc.parsedURL.Path, "/") &&
		!strings.HasSuffix(result.Path, "/") {
		result.Path += "/"
	}
	// Merge query params: base URL params + path params
	if parsed.RawQuery != "" {
		if result.RawQuery != "" {
			result.RawQuery = result.RawQuery + "&" + parsed.RawQuery
		} else {
			result.RawQuery = parsed.RawQuery
		}
	}
	if parsed.Fragment != "" {
		result.Fragment = parsed.Fragment
	}
	return result.String(), nil
}

// URL returns the base URL.
// Returns empty string if the receiver is nil.
func (dc *DomainClient) URL() string {
	if dc == nil {
		return ""
	}
	return dc.baseURL
}

// Domain returns the domain name (host without port).
// Returns empty string if the receiver is nil.
func (dc *DomainClient) Domain() string {
	if dc == nil {
		return ""
	}
	return dc.domain
}

// Session returns the underlying SessionManager for advanced session management.
// Returns nil if the receiver is nil.
func (dc *DomainClient) Session() *SessionManager {
	if dc == nil {
		return nil
	}
	return dc.SessionManager
}

// Compile-time interface check to ensure DomainClient implements Client.
var _ Client = (*DomainClient)(nil)

// Compile-time interface check to ensure DomainClient implements DomainClienter.
var _ DomainClienter = (*DomainClient)(nil)

// Close closes the underlying HTTP client and releases resources.
// Returns nil if the receiver or underlying client is nil.
func (dc *DomainClient) Close() error {
	if dc == nil || dc.client == nil {
		return nil
	}
	return dc.client.Close()
}
