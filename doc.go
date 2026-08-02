// Package httpc provides a high-performance HTTP client library with secure
// defaults.
//
// # Key Features
//
//   - Secure by default with TLS 1.2+, CRLF injection prevention, header validation
//   - High performance with connection pooling, HTTP/2, and goroutine-safe operations
//   - Built-in resilience with smart retry and exponential backoff
//   - Clean API with simplified request options
//
// # Quick Start
//
// Basic usage with package-level functions:
//
//	result, err := httpc.Get("https://api.example.com/data")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(result.Body())
//
// # Two API Layers
//
// httpc offers two equivalent request paths, mirroring the net/http split
// between http.Get and http.Client:
//
//   - Package-level functions (httpc.Get, httpc.Post, ...) use a lazily
//     initialized default client. Best for scripts and one-off requests.
//   - Client instance methods (client.Get, client.Post, ...) give full control
//     over configuration, connection pooling, and lifecycle.
//
// Both layers accept the same request options (WithHeader, WithJSON, ...) and
// return the same *Result type:
//
//	// Package-level — zero setup, shared default client
//	result, err := httpc.Get("https://api.example.com/data")
//
//	// Client instance — full control, explicit lifecycle
//	client, err := httpc.NewDefault()
//	defer func() { _ = client.Close() }()
//	result, err := client.Get("https://api.example.com/data")
//
// Package-level functions are thin wrappers around a singleton client managed
// internally (see SetDefaultClient, CloseDefaultClient). For long-running
// services, prefer an explicit client instance so you control its configuration
// and lifetime.
//
// # Client Creation
//
// Create a client with default configuration:
//
//	client, err := httpc.NewDefault()
//	defer func() { _ = client.Close() }()
//
// Create a client with custom configuration:
//
//	cfg := httpc.DefaultConfig()
//	cfg.Timeouts.Request = 60 * time.Second
//	cfg.Retry.MaxRetries = 5
//	client, err := httpc.New(cfg)
//
// Use preset configurations:
//
//	client, err := httpc.New(httpc.SecureConfig())      // Security-focused
//	client, err := httpc.New(httpc.PerformanceConfig()) // High-throughput
//	client, err := httpc.New(httpc.TestingConfig())     // Testing only!
//
// # Configuration Conventions
//
// All httpc constructors follow the same pattern:
//
//   - Instance configuration uses Config structs, not functional options.
//   - Every Config struct has a Default*Config() function returning sensible
//     defaults — start from it, then modify fields as needed.
//   - The main Config and SessionConfig are passed by value (required). Middleware
//     configs are passed by pointer and may be nil to accept defaults;
//     DownloadConfig is passed by pointer but is required (FilePath must be set).
//
// Per-request modifiers (WithHeader, WithJSON, WithTimeout, ...) are functional
// options applied to individual requests. This is a separate concern from
// instance configuration: instance config lives in Config structs; per-request
// config lives in With* options.
//
//	// Main client: shortcut for defaults
//	client, err := httpc.NewDefault()
//
//	// Main client: Config by value (customized)
//	cfg := httpc.DefaultConfig()
//	cfg.Timeouts.Request = 60 * time.Second
//	client, err := httpc.New(cfg)
//
//	// Session manager: required SessionConfig (NewSessionManagerDefault() for defaults)
//	sm, err := httpc.NewSessionManagerDefault()
//
//	// Download: *DownloadConfig (required, must set FilePath)
//	dcfg := httpc.DefaultDownloadConfig()
//	dcfg.FilePath = "/path/to/file"
//
// # SSRF Protection
//
// By default, AllowPrivateIPs is false, blocking connections to private/reserved
// IP addresses (127.0.0.1, 10.x, 192.168.x, 169.254.x, etc.). This protects
// against Server-Side Request Forgery attacks.
//
// Set AllowPrivateIPs to true only when connecting to internal services:
//
//	// Allow internal service access (VPNs, proxies, corporate networks)
//	cfg := httpc.DefaultConfig()
//	cfg.Security.AllowPrivateIPs = true
//	client, err := httpc.New(cfg)
//
//	// Or use the secure preset (SSRF protection already enabled)
//	client, err := httpc.New(httpc.SecureConfig())
//
// # Request Options
//
// Core options:
//
//	// Headers
//	httpc.WithHeader("Authorization", "Bearer token")
//	httpc.WithHeaderMap(map[string]string{"X-Custom": "value"})
//	httpc.WithUserAgent("my-app/1.0")
//
//	// Body
//	httpc.WithJSON(data)
//	httpc.WithXML(data)
//	httpc.WithForm(map[string]string{"key": "value"})
//	httpc.WithFormData(multipartData)
//	httpc.WithFile("file", "document.pdf", fileBytes)
//	httpc.WithBody(rawData)
//	httpc.WithBinary(binaryData)
//
//	// Query parameters
//	httpc.WithQuery("page", 1)
//	httpc.WithQueryMap(map[string]any{"page": 1, "limit": 10})
//
//	// Authentication
//	httpc.WithBearerToken(token)
//	httpc.WithBasicAuth(username, password)
//
//	// Cookies
//	httpc.WithCookie(http.Cookie{Name: "session", Value: "abc"})
//	httpc.WithCookieString("session=abc; token=xyz")
//	httpc.WithCookieMap(map[string]string{"session": "abc"})
//	httpc.WithSecureCookie(securityConfig)
//
//	// Request control
//	httpc.WithContext(ctx)
//	httpc.WithTimeout(30 * time.Second)
//	httpc.WithMaxRetries(3)
//	httpc.WithFollowRedirects(false)
//	httpc.WithMaxRedirects(5)
//	httpc.WithStreamBody(true)
//
//	// Callbacks
//	httpc.WithOnRequest(callback)
//	httpc.WithOnResponse(callback)
//
// # DomainClient
//
// For session management across requests to the same domain:
//
//	dc, err := httpc.NewDomain("https://api.example.com", httpc.DefaultConfig())
//	defer dc.Close()
//
//	dc.SetHeader("Authorization", "Bearer "+token)
//
//	// Headers automatically included
//	result, err := dc.Request(ctx, "GET", "/users")
//
// # Context Handling
//
// Use context for timeout and cancellation:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	result, err := client.Request(ctx, "GET", "https://api.example.com/data")
//
// # Timeout Behavior
//
// By default, TimeoutConfig.ResponseHeader is 0 (disabled). The context-level
// timeout from Timeouts.Request (default 180s) or WithTimeout() is the sole
// mechanism controlling how long to wait for a response.
//
// This design ensures WithTimeout() has full control over request duration,
// which is essential for AI APIs and long-polling endpoints that need extended
// response times:
//
//	// AI API that may take minutes to respond
//	result, err := httpc.Post(url,
//	    httpc.WithJSON(payload),
//	    httpc.WithTimeout(900*time.Second),
//	)
//
// For security-critical applications, use SecureConfig() which sets a strict
// transport-level ResponseHeaderTimeout as defense-in-depth against slowloris
// attacks.
//
// # Request Defaults (RequestDefaults)
//
// Per-request defaults — User-Agent, default headers, redirect policy — live on
// Config.Defaults (RequestDefaults), populated by DefaultConfig():
//
//	cfg := httpc.DefaultConfig()
//	cfg.Defaults.UserAgent = "myapp/2.0"
//	cfg.Defaults.FollowRedirects = false
//	cfg.Defaults.Headers["Authorization"] = "Bearer token"
//	client, err := httpc.New(cfg)
//
// # Middleware Configuration
//
// Every configurable middleware follows the same pattern: a XxxConfig struct, a
// DefaultXxxConfig() constructor, and a XxxMiddleware(cfg) factory that
// accepts a nil config (selecting defaults). Start from the default, modify fields,
// then pass to the constructor:
//
//	mw := httpc.LoggingMiddleware(&httpc.LoggingConfig{
//	    LogFunc: log.Printf,
//	})
//	mw := httpc.MetricsMiddleware(&httpc.MetricsConfig{
//	    OnMetrics: func(method, url string, code int, d time.Duration, err error) { ... },
//	})
//	mw := httpc.RequestIDMiddleware(httpc.DefaultRequestIDConfig())
//	auditCfg := httpc.DefaultAuditConfig()
//	auditCfg.OnAudit = func(event httpc.AuditEvent) { ... }
//	mw := httpc.AuditMiddleware(auditCfg)
//	mw := httpc.TimeoutMiddleware(&httpc.TimeoutMiddlewareConfig{
//	    Duration: 30 * time.Second,
//	})
//	mw := httpc.HeaderMiddleware(&httpc.HeaderConfig{
//	    Headers: map[string]string{"X-Service": "api"},
//	})
//
// For more information, see https://github.com/cybergodev/httpc
package httpc
