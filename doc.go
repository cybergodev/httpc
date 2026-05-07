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
// # Client Creation
//
// Create a client with default configuration:
//
//	client, err := httpc.New()
//	defer client.Close()
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
//	dc, err := httpc.NewDomain("https://api.example.com")
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
// For more information, see https://github.com/cybergodev/httpc
package httpc
