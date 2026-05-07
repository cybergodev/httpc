# HTTPC - Secure HTTP Client for Go

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://golang.org)
[![Go Reference](https://pkg.go.dev/badge/github.com/cybergodev/httpc.svg)](https://pkg.go.dev/github.com/cybergodev/httpc)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Hardened-red.svg)](SECURITY.md)
[![Zero Deps](https://img.shields.io/badge/deps-zero-brightgreen.svg)](go.mod)
[![Thread Safe](https://img.shields.io/badge/thread%20safe-%E2%9C%93-brightgreen.svg)](docs/09_concurrency-safety.md)

A fast, secure HTTP client library for Go with sensible defaults, minimal dependencies, and built-in resilience.

**[中文文档](README_zh-CN.md)** | **[www.cybergo.dev/httpc](https://www.cybergo.dev/httpc)**

---

## Features

| Feature | Description |
|---------|-------------|
| **Secure by Default** | TLS 1.2+, SSRF protection, CRLF injection prevention, path traversal blocking |
| **High Performance** | Connection pooling, HTTP/2, goroutine-safe, `sync.Pool` optimization |
| **Built-in Resilience** | Smart retry with exponential backoff and jitter |
| **Developer Friendly** | Clean API, intuitive options pattern, comprehensive documentation |
| **Minimal Dependencies** | Only `golang.org/x/sys` for system-level operations |
| **Reliable Defaults** | Well-tested defaults, extensive test coverage |
| **Cookie Management** | Full cookie jar support with security validation |
| **File Operations** | Secure file download with progress tracking and resume support |

---

## Installation

```bash
go get -u github.com/cybergodev/httpc
```

**Requirements:** Go 1.25+

---

## Quick Start (5 Minutes)

### Simple GET Request

```go
package main

import (
    "fmt"
    "log"

    "github.com/cybergodev/httpc"
)

func main() {
    // Package-level function - convenient for simple requests
    result, err := httpc.Get("https://httpbin.org/get")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Status: %d, Duration: %v\n", result.StatusCode(), result.Meta.Duration)
}
```

### POST JSON with Authentication

```go
package main

import (
    "fmt"
    "log"
    "time"

    "github.com/cybergodev/httpc"
)

func main() {
    user := map[string]string{"name": "John", "email": "john@example.com"}
    result, err := httpc.Post("https://httpbin.org/post",
        httpc.WithJSON(user),
        httpc.WithBearerToken("your-token"),
        httpc.WithTimeout(30*time.Second),
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Response: %s\n", result.Body())
}
```

### Using Client Instance (Recommended)

```go
package main

import (
    "fmt"
    "log"

    "github.com/cybergodev/httpc"
)

func main() {
    // Create a reusable client (New() uses DefaultConfig() when no config provided)
    client, err := httpc.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Make multiple requests
    result, err := client.Get("https://api.example.com/users",
        httpc.WithQuery("page", 1),
        httpc.WithQuery("limit", 20),
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Status: %d\n", result.StatusCode())
}
```

---

## HTTP Methods

```go
// GET with query parameters
result, _ := httpc.Get("https://api.example.com/users",
    httpc.WithQuery("page", 1),
    httpc.WithQueryMap(map[string]any{"limit": 20}),
)

// POST JSON body
result, _ := httpc.Post("https://api.example.com/users",
    httpc.WithJSON(map[string]string{"name": "John"}),
)

// PUT / PATCH / DELETE
result, _ := httpc.Put(url, httpc.WithJSON(data))
result, _ := httpc.Patch(url, httpc.WithJSON(partialData))
result, _ := httpc.Delete(url)

// HEAD / OPTIONS
result, _ := httpc.Head(url)
result, _ := httpc.Options(url)

// Generic request with custom method
result, _ := httpc.Request(ctx, "PROPFIND", url)
```

---

## Request Options

### Headers

```go
// Single header
httpc.WithHeader("Authorization", "Bearer token")

// Multiple headers
httpc.WithHeaderMap(map[string]string{
    "X-Custom":      "value",
    "X-Request-ID":  "123",
})

// User-Agent
httpc.WithUserAgent("my-app/1.0")
```

### Authentication

```go
// Bearer token
httpc.WithBearerToken("your-jwt-token")

// Basic auth
httpc.WithBasicAuth("username", "password")
```

### Query Parameters

```go
// Single parameter
httpc.WithQuery("page", 1)

// Multiple parameters
httpc.WithQueryMap(map[string]any{"page": 1, "limit": 20})
```

### Request Body

```go
// JSON
httpc.WithJSON(data)

// XML
httpc.WithXML(data)

// Form data (application/x-www-form-urlencoded)
httpc.WithForm(map[string]string{"key": "value"})

// Multipart form data (file upload)
formData := &httpc.FormData{
    Fields: map[string]string{"key": "value"},
    Files: map[string]*httpc.FileData{
        "upload": {Filename: "doc.pdf", Content: fileBytes, ContentType: "application/pdf"},
    },
}
httpc.WithFormData(formData)

// Or use shorthand for single file upload
httpc.WithFile("file", "document.pdf", fileBytes)

// Raw body (auto-detect Content-Type)
httpc.WithBody([]byte("raw data"))
httpc.WithBody(data, httpc.BodyJSON) // explicit BodyKind

// BodyKind constants: BodyAuto, BodyJSON, BodyXML, BodyForm, BodyBinary, BodyMultipart

httpc.WithBinary(binaryData, "application/pdf")

// Stream body (for large request bodies)
httpc.WithStreamBody(true)
```

### Cookies

```go
// Single cookie
httpc.WithCookie(http.Cookie{Name: "session", Value: "abc123"})

// Multiple cookies from map
httpc.WithCookieMap(map[string]string{
    "session_id": "abc123",
    "user_pref":  "dark_mode",
})

// Cookie string
httpc.WithCookieString("session=abc123; token=xyz")

// Secure cookie with validation (validates cookie security attributes)
cfg := httpc.DefaultCookieSecurityConfig()
cfg.RequireSecure = true
httpc.WithSecureCookie(cfg)
```

### Request Control

```go
// Context for cancellation
httpc.WithContext(ctx)

// Timeout
httpc.WithTimeout(30 * time.Second)

// Retry configuration
httpc.WithMaxRetries(3)

// Redirect control
httpc.WithFollowRedirects(false)
httpc.WithMaxRedirects(5)
```

### Callbacks

```go
// Before request
httpc.WithOnRequest(func(req httpc.RequestMutator) error {
    log.Printf("Sending %s %s", req.Method(), req.URL())
    return nil
})

// After response
httpc.WithOnResponse(func(resp httpc.ResponseMutator) error {
    log.Printf("Received %d", resp.StatusCode())
    return nil
})
```

### Complete Options Reference

| Category | Options |
|----------|---------|
| **Headers** | `WithHeader(key, value)`, `WithHeaderMap(map)`, `WithUserAgent(ua)` |
| **Auth** | `WithBearerToken(token)`, `WithBasicAuth(user, pass)` |
| **Query** | `WithQuery(key, value)`, `WithQueryMap(map)` |
| **Body** | `WithJSON(data)`, `WithXML(data)`, `WithForm(map)`, `WithFormData(*FormData)`, `WithFile(field, filename, content)`, `WithBody(data, ...BodyKind)`, `WithBinary([]byte, ...contentType)`, `WithStreamBody(bool)` |
| **Cookies** | `WithCookie(cookie)`, `WithCookieMap(map)`, `WithCookieString("a=1; b=2")`, `WithSecureCookie(config)` |
| **Control** | `WithTimeout(dur)`, `WithMaxRetries(n)`, `WithContext(ctx)` |
| **Redirects** | `WithFollowRedirects(bool)`, `WithMaxRedirects(n)` |
| **Callbacks** | `WithOnRequest(fn)`, `WithOnResponse(fn)` |

---

## Response Handling

```go
result, _ := httpc.Get("https://api.example.com/users/123")

// Result struct composition:
// result.Request  -> *RequestInfo  (URL, Method, Headers, Cookies)
// result.Response -> *ResponseInfo (StatusCode, Status, Proto, Headers, Body, RawBody, ContentLength, Cookies)
// result.Meta     -> *RequestMeta  (Duration, Attempts, RedirectCount, RedirectChain)

// Quick access methods (nil-safe)
fmt.Println(result.StatusCode())     // 200
fmt.Println(result.Proto())          // "HTTP/1.1" or "HTTP/2.0"
fmt.Println(result.RawBody())        // Response body ([]byte)
fmt.Println(result.Body())           // Response body (string)

// Status checks
if result.IsSuccess() { }            // 2xx
if result.IsRedirect() { }           // 3xx
if result.IsClientError() { }        // 4xx
if result.IsServerError() { }        // 5xx

// Parse JSON response
var data map[string]interface{}
if err := result.Unmarshal(&data); err != nil {
    log.Fatal(err)
}

// Cookie access
cookie := result.GetCookie("session")
if result.HasCookie("session") { }

// Request cookies sent
reqCookie := result.GetRequestCookie("token")
if result.HasRequestCookie("token") { }

// Get all cookies
allResponse := result.ResponseCookies()
allRequest := result.RequestCookies()

// Save response to file
if err := result.SaveToFile("response.json"); err != nil {
    log.Fatal(err)
}

// Metadata
fmt.Println(result.Meta.Duration)      // Request duration
fmt.Println(result.Meta.Attempts)      // Retry count
fmt.Println(result.Meta.RedirectCount) // Redirect count
fmt.Println(result.Meta.RedirectChain) // Redirect URLs

// String representation (safe for logging - masks sensitive headers)
fmt.Println(result.String())
```

---

## Context & Cancellation

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

result, err := httpc.Get("https://api.example.com",
    httpc.WithContext(ctx),
)
if errors.Is(err, context.DeadlineExceeded) {
    fmt.Println("Request timed out")
}
```

---

## File Download

### Simple Download

File downloads include built-in security protections:
- **UNC path blocking** - Prevents access to Windows network paths
- **System path protection** - Blocks writes to critical system directories
- **Path traversal detection** - Prevents directory escape attacks
- **Resume support** - Automatically resumes interrupted downloads

```go
result, _ := httpc.DownloadFile(
    "https://example.com/file.zip",
    "downloads/file.zip",
)
fmt.Printf("Downloaded: %s at %s/s\n",
    httpc.FormatBytes(result.BytesWritten),
    httpc.FormatSpeed(result.AverageSpeed))
```

### Download with Progress

```go
opts := httpc.DefaultDownloadConfig()
opts.FilePath = "downloads/large.zip"
opts.ProgressCallback = func(downloaded, total int64, speed float64) {
    pct := float64(downloaded) / float64(total) * 100
    fmt.Printf("\r%.1f%% - %s/s", pct, httpc.FormatSpeed(speed))
}
result, _ := httpc.DownloadWithOptions(url, opts)
```

### Resume Download

```go
opts := httpc.DefaultDownloadConfig()
opts.FilePath = "downloads/large.zip"
opts.ResumeDownload = true
result, _ := httpc.DownloadWithOptions(url, opts)
if result.Resumed {
    fmt.Println("Download resumed from previous position")
}
```

### Download with Context

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
defer cancel()

result, _ := httpc.DownloadFileWithContext(ctx,
    "https://example.com/large.zip",
    "downloads/large.zip",
)

// Full control with download config + context
result, _ := httpc.DownloadWithOptionsWithContext(ctx, url, opts)
```

### DownloadConfig Fields

| Field | Type | Description |
|-------|------|-------------|
| `FilePath` | `string` | Destination path for the downloaded file |
| `ProgressCallback` | `DownloadProgressCallback` | Progress callback: `func(downloaded, total int64, speed float64)` |
| `Overwrite` | `bool` | Overwrite existing file (default: `false`) |
| `ResumeDownload` | `bool` | Resume interrupted download (default: `false`) |

### Download Functions

| Function | Description |
|----------|-------------|
| `DownloadFile(url, filePath, ...options)` | Simple download |
| `DownloadWithOptions(url, config, ...options)` | Download with progress/resume config |
| `DownloadFileWithContext(ctx, url, filePath, ...options)` | Download with cancellation |
| `DownloadWithOptionsWithContext(ctx, url, config, ...options)` | Full control with config + context |

### DownloadResult Fields

| Field | Type | Description |
|-------|------|-------------|
| `FilePath` | `string` | Local file path written to |
| `BytesWritten` | `int64` | Total bytes written |
| `Duration` | `time.Duration` | Download duration |
| `AverageSpeed` | `float64` | Average download speed (bytes/sec) |
| `StatusCode` | `int` | HTTP status code |
| `ContentLength` | `int64` | Content-Length from server |
| `Resumed` | `bool` | Whether download was resumed |
| `ResponseCookies` | `[]*http.Cookie` | Cookies from response |

---

## Domain Client (Session Management)

For multiple requests to the same domain with automatic cookie and header management:

```go
client, _ := httpc.NewDomain("https://api.example.com")
defer client.Close()

// Login - server sets cookies
client.Post("/login", httpc.WithJSON(credentials))

// Set persistent header (used for all requests)
client.SetHeader("Authorization", "Bearer "+token)

// Subsequent requests include cookies + headers automatically
profile, _ := client.Get("/profile")
data, _ := client.Get("/data")
```

### Cookie Management

```go
// Single cookie
client.SetCookie(&http.Cookie{Name: "session", Value: "abc"})

// Multiple cookies
client.SetCookies([]*http.Cookie{
    {Name: "session", Value: "abc"},
    {Name: "token", Value: "xyz"},
})

// Read cookies
cookie := client.GetCookie("session")   // Single cookie
allCookies := client.GetCookies()        // All cookies

// Remove cookies
client.DeleteCookie("session")
client.ClearCookies()
```

### Header Management

```go
client.SetHeader("X-Custom", "value")
client.SetHeaders(map[string]string{"X-App": "v1", "X-Version": "1.0"})
headers := client.GetHeaders()
client.DeleteHeader("X-Old")
client.ClearHeaders()
```

### Accessors

```go
client.URL()     // Full base URL
client.Domain()  // Domain only
client.Session() // Underlying SessionManager
```

### File Downloads (relative paths)

```go
result, _ := client.DownloadFile("/files/data.csv", "data.csv")
result, _ := client.DownloadWithOptions("/files/large.zip", downloadOpts)
result, _ := client.DownloadFileWithContext(ctx, "/files/data.csv", "data.csv")
result, _ := client.DownloadWithOptionsWithContext(ctx, "/files/large.zip", downloadOpts)
```

### All HTTP Methods

```go
result, _ := client.Get("/users")
result, _ := client.Post("/users", httpc.WithJSON(data))
result, _ := client.Put("/users/1", httpc.WithJSON(data))
result, _ := client.Patch("/users/1", httpc.WithJSON(data))
result, _ := client.Delete("/users/1")
result, _ := client.Head("/users")
result, _ := client.Options("/users")
result, _ := client.Request(ctx, "PROPFIND", "/resource")
```

---

## Session Manager

The `SessionManager` provides thread-safe cookie and header management, used internally by `DomainClient` but also available standalone:

```go
// Create session manager
sm, _ := httpc.NewSessionManager()

// Or with cookie security validation
cfg := httpc.DefaultSessionConfig()
cfg.CookieSecurity = httpc.StrictCookieSecurityConfig()
sm, _ := httpc.NewSessionManager(cfg)

// Manage cookies
sm.SetCookie(&http.Cookie{Name: "session", Value: "abc"})
sm.SetCookies([]*http.Cookie{{Name: "token", Value: "xyz"}})
cookie := sm.GetCookie("session")
allCookies := sm.GetCookies()
sm.DeleteCookie("session")
sm.ClearCookies()

// Manage headers
sm.SetHeader("Authorization", "Bearer token")
sm.SetHeaders(map[string]string{"X-App": "v1"})
headers := sm.GetHeaders()
sm.DeleteHeader("X-Old")
sm.ClearHeaders()

// Update from response
sm.UpdateFromResult(result)
sm.UpdateFromCookies(responseCookies)

// Cookie security
sm.SetCookieSecurity(httpc.StrictCookieSecurityConfig())
```

---

## Configuration

### Preset Configurations

```go
// Recommended defaults (same as httpc.New() with no arguments)
client, _ := httpc.New(httpc.DefaultConfig())

// Maximum security (SSRF protection enabled)
client, _ := httpc.New(httpc.SecureConfig())

// High throughput
client, _ := httpc.New(httpc.PerformanceConfig())

// Lightweight (no retries)
client, _ := httpc.New(httpc.MinimalConfig())

// Testing only - disables security features!
client, _ := httpc.New(httpc.TestingConfig())
```

### Custom Configuration

```go
config := &httpc.Config{
    // Timeouts
    Timeouts: httpc.TimeoutConfig{
        Request:        30 * time.Second,
        Dial:           10 * time.Second,
        TLSHandshake:   10 * time.Second,
        ResponseHeader: 30 * time.Second,
        IdleConn:       90 * time.Second,
    },

    // Connection
    Connection: httpc.ConnectionConfig{
        MaxIdleConns:    100,
        MaxConnsPerHost: 20,
        EnableHTTP2:     true,
        EnableCookies:   false,
    },

    // Security
    Security: httpc.SecurityConfig{
        MinTLSVersion:       tls.VersionTLS12,
        MaxTLSVersion:       tls.VersionTLS13,
        MaxResponseBodySize: 50 * 1024 * 1024, // 50 MB
        AllowPrivateIPs:     false,
    },

    // Retry
    Retry: httpc.RetryConfig{
        MaxRetries:    3,
        Delay:         1 * time.Second,
        BackoffFactor: 2.0,
        EnableJitter:  true,
    },

    // Middleware
    Middleware: httpc.MiddlewareConfig{
        UserAgent:       "MyApp/1.0",
        FollowRedirects: true,
        MaxRedirects:    10,
    },
}

// Validate configuration before creating client (New() also validates internally)
if err := httpc.ValidateConfig(config); err != nil {
    log.Fatal(err)
}

client, _ := httpc.New(config)
```

### Configuration Options

| Function | Description |
|----------|-------------|
| `DefaultConfig()` | Recommended defaults |
| `SecureConfig()` | Maximum security (SSRF protection enabled) |
| `PerformanceConfig()` | High throughput |
| `MinimalConfig()` | Lightweight (no retries) |
| `TestingConfig()` | Testing only - disables security features |
| `ValidateConfig(cfg)` | Validate configuration, returns error |

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| **Timeouts** (nested: `Timeouts: httpc.TimeoutConfig{...}`) ||||
| `Timeouts.Request` | `time.Duration` | `30s` | Overall request timeout |
| `Timeouts.Dial` | `time.Duration` | `10s` | TCP connection timeout |
| `Timeouts.TLSHandshake` | `time.Duration` | `10s` | TLS handshake timeout |
| `Timeouts.ResponseHeader` | `time.Duration` | `30s` | Response header timeout |
| `Timeouts.IdleConn` | `time.Duration` | `90s` | Idle connection timeout |
| **Connection** (nested: `Connection: httpc.ConnectionConfig{...}`) ||||
| `Connection.MaxIdleConns` | `int` | `50` | Max idle connections |
| `Connection.MaxConnsPerHost` | `int` | `10` | Max connections per host |
| `Connection.ProxyURL` | `string` | `""` | Proxy URL (http/socks5) |
| `Connection.EnableSystemProxy` | `bool` | `false` | Auto-detect system proxy |
| `Connection.EnableHTTP2` | `bool` | `true` | Enable HTTP/2 |
| `Connection.EnableCookies` | `bool` | `false` | Enable cookie jar |
| `Connection.EnableDoH` | `bool` | `false` | Enable DNS-over-HTTPS |
| `Connection.DoHCacheTTL` | `time.Duration` | `5m` | DoH cache duration |
| **Security** (nested: `Security: httpc.SecurityConfig{...}`) ||||
| `Security.TLSConfig` | `*tls.Config` | `nil` | Custom TLS config |
| `Security.MinTLSVersion` | `uint16` | `TLS 1.2` | Minimum TLS version |
| `Security.MaxTLSVersion` | `uint16` | `TLS 1.3` | Maximum TLS version |
| `Security.InsecureSkipVerify` | `bool` | `false` | Skip TLS verification (testing only!) |
| `Security.MaxResponseBodySize` | `int64` | `10MB` | Max response body size |
| `Security.MaxRequestBodySize` | `int64` | `0` | Max request body size (0 = uses MaxResponseBodySize) |
| `Security.AllowPrivateIPs` | `bool` | `false` | Allow private IPs (SSRF protection enabled by default) |
| `Security.ValidateURL` | `bool` | `true` | Enable URL validation |
| `Security.ValidateHeaders` | `bool` | `true` | Enable header validation |
| `Security.StrictContentLength` | `bool` | `true` | Strict content-length check |
| `Security.RedirectWhitelist` | `[]string` | `nil` | Allowed redirect domains |
| `Security.MaxDecompressedBodySize` | `int64` | `100MB` | Max decompressed body size (zip bomb protection) |
| `Security.SSRFExemptCIDRs` | `[]string` | `nil` | CIDR ranges exempted from SSRF blocking |
| `Security.CookieSecurity` | `*httpc.CookieSecurityConfig` | `nil` | Cookie security validation rules |
| **Retry** (nested: `Retry: httpc.RetryConfig{...}`) ||||
| `Retry.MaxRetries` | `int` | `3` | Max retry attempts |
| `Retry.Delay` | `time.Duration` | `1s` | Initial retry delay |
| `Retry.BackoffFactor` | `float64` | `2.0` | Backoff multiplier |
| `Retry.EnableJitter` | `bool` | `true` | Add jitter to retries |
| `Retry.CustomPolicy` | `RetryPolicy` | `nil` | Custom retry logic |
| **Middleware** (nested: `Middleware: httpc.MiddlewareConfig{...}`) ||||
| `Middleware.Middlewares` | `[]MiddlewareFunc` | `nil` | Middleware chain |
| `Middleware.UserAgent` | `string` | `"httpc/1.0"` | Default User-Agent |
| `Middleware.Headers` | `map[string]string` | `{}` | Default headers |
| `Middleware.FollowRedirects` | `bool` | `true` | Follow redirects |
| `Middleware.MaxRedirects` | `int` | `10` | Max redirect count |

---

## Middleware

### Built-in Middleware

```go
// Request logging
httpc.LoggingMiddleware(log.Printf)

// Panic recovery
httpc.RecoveryMiddleware()

// Request ID
httpc.RequestIDMiddleware("X-Request-ID", nil)

// Timeout enforcement
httpc.TimeoutMiddleware(30*time.Second)

// Static headers
httpc.HeaderMiddleware(map[string]string{
    "X-App-Version": "1.0.0",
})

// Metrics collection
httpc.MetricsMiddleware(func(method, url string, statusCode int, duration time.Duration, err error) {
    metrics.Record(method, url, statusCode, duration)
})

// Security audit
httpc.AuditMiddleware(func(a httpc.AuditEvent) {
    log.Printf("[AUDIT] %s %s -> %d (%v)", a.Method, a.URL, a.StatusCode, a.Duration)
})

// Audit with custom config
auditCfg := httpc.DefaultAuditMiddlewareConfig()
auditCfg.IncludeHeaders = true
auditCfg.Format = "json"
httpc.AuditMiddlewareWithConfig(func(a httpc.AuditEvent) {
    log.Printf("[AUDIT] %v", a)
}, auditCfg)
```

### AuditEvent Fields

| Field | Type | Description |
|-------|------|-------------|
| `Timestamp` | `time.Time` | Request timestamp |
| `Method` | `string` | HTTP method |
| `URL` | `string` | Request URL |
| `StatusCode` | `int` | Response status code |
| `Duration` | `time.Duration` | Request duration |
| `Attempts` | `int` | Retry attempts |
| `Error` | `error` | Error if any |
| `SourceIP` | `string` | Source IP (set via context key `SourceIPKey`) |
| `UserID` | `string` | User ID (set via context key `UserIDKey`) |
| `RedirectChain` | `[]string` | Redirect URLs |
| `ReqHeaders` | `map[string][]string` | Request headers (when `IncludeHeaders: true`) |
| `RespHeaders` | `map[string][]string` | Response headers (when `IncludeHeaders: true`) |

### Chain Multiple Middleware

```go
chainedMiddleware := httpc.Chain(
    httpc.RecoveryMiddleware(),
    httpc.LoggingMiddleware(log.Printf),
    httpc.RequestIDMiddleware("X-Request-ID", nil),
    httpc.HeaderMiddleware(map[string]string{"X-App": "v1"}),
)
config.Middleware.Middlewares = []httpc.MiddlewareFunc{chainedMiddleware}
```

### Custom Middleware

```go
func CustomMiddleware() httpc.MiddlewareFunc {
    return func(next httpc.Handler) httpc.Handler {
        return func(ctx context.Context, req httpc.RequestMutator) (httpc.ResponseMutator, error) {
            // Before request
            req.SetHeader("X-Custom", "value")

            // Call next handler
            resp, err := next(ctx, req)

            // After response
            return resp, err
        }
    }
}
```

---

## Proxy Configuration

```go
// Manual proxy
config := httpc.DefaultConfig()
config.Connection.ProxyURL = "http://127.0.0.1:8080"
// Or SOCKS5: "socks5://127.0.0.1:1080"

// System proxy auto-detection (Windows/macOS/Linux)
config := httpc.DefaultConfig()
config.Connection.EnableSystemProxy = true // Reads from environment and system settings
```

---

## Security Features

| Feature | Description |
|---------|-------------|
| **TLS 1.2+** | Modern encryption standards by default |
| **SSRF Protection** | Two-layer DNS validation blocks private IPs |
| **CRLF Injection Prevention** | Header and URL validation |
| **Path Traversal Protection** | Safe file operations |
| **Domain Whitelist** | Restrict redirects to allowed domains |
| **Response Size Limit** | Configurable limit to prevent memory exhaustion |

### Redirect Domain Whitelist

```go
config := httpc.DefaultConfig()
config.Security.RedirectWhitelist = []string{"api.example.com", "secure.example.com"}
```

### SSRF Protection

By default, `AllowPrivateIPs` is `false` (SSRF protection enabled), blocking connections to private/reserved IP addresses. Set to `true` only when connecting to internal services:

```go
// SSRF protection is enabled by default
client, _ := httpc.New(httpc.DefaultConfig())

// Allow private IPs for internal service access
cfg := httpc.DefaultConfig()
cfg.Security.AllowPrivateIPs = true
client, _ := httpc.New(cfg)

// Or exempt specific CIDRs (e.g., VPN/VPC ranges)
cfg := httpc.DefaultConfig()
cfg.Security.SSRFExemptCIDRs = []string{"10.0.0.0/8", "100.64.0.0/10"}
client, _ := httpc.New(cfg)
```

---

## Error Handling

```go
result, err := httpc.Get(url)
if err != nil {
    var clientErr *httpc.ClientError
    if errors.As(err, &clientErr) {
        fmt.Printf("Error: %s (code: %s)\n", clientErr.Message, clientErr.Code())
        fmt.Printf("Retryable: %v\n", clientErr.IsRetryable())
    }
    return err
}

// Check response status
if !result.IsSuccess() {
    return fmt.Errorf("unexpected status code: %d", result.StatusCode())
}
```

### ClientError Fields

| Field | Type | Description |
|-------|------|-------------|
| `Type` | `ErrorType` | Error classification |
| `Message` | `string` | Human-readable error description |
| `Cause` | `error` | Underlying error (unwrap with `%w`) |
| `URL` | `string` | Request URL |
| `Method` | `string` | HTTP method |
| `Attempts` | `int` | Number of retry attempts |
| `StatusCode` | `int` | HTTP status code (if applicable) |
| `Host` | `string` | Target host |

### Error Types

```go
const (
    ErrorTypeUnknown        // Unknown or unclassified error
    ErrorTypeNetwork        // Network-level error (connection refused, DNS failure)
    ErrorTypeTimeout        // Request timeout
    ErrorTypeContextCanceled // Context canceled
    ErrorTypeResponseRead   // Error reading response body
    ErrorTypeTransport      // HTTP transport error
    ErrorTypeRetryExhausted // All retries exhausted
    ErrorTypeTLS            // TLS handshake error
    ErrorTypeCertificate    // Certificate validation error
    ErrorTypeDNS            // DNS resolution error
    ErrorTypeValidation     // Request validation error
    ErrorTypeHTTP           // HTTP-level error (4xx, 5xx)
)
```

### Sentinel Errors

```go
var (
    ErrClientClosed         // Client has been closed
    ErrNilConfig            // Nil configuration provided
    ErrInvalidURL           // URL validation failed
    ErrInvalidHeader        // Header validation failed
    ErrInvalidTimeout       // Timeout is negative or exceeds limits
    ErrInvalidRetry         // Retry configuration is invalid
    ErrInvalidConnection    // Connection configuration is invalid
    ErrInvalidSecurity      // Security configuration is invalid
    ErrInvalidMiddleware    // Middleware configuration is invalid
    ErrEmptyFilePath        // File path is empty
    ErrFileExists           // File already exists (and Overwrite is false)
    ErrResponseBodyEmpty    // Response body is empty
    ErrResponseBodyTooLarge // Response body exceeds size limit
)
```

### Error Classification

```go
// Check error type using errors.As
var clientErr *httpc.ClientError
if errors.As(err, &clientErr) {
    fmt.Printf("Type: %s, Retryable: %v\n", clientErr.Code(), clientErr.IsRetryable())
}
```

---

## Concurrency Safety

HTTPC is designed to be goroutine-safe:

```go
client, _ := httpc.New() // Uses DefaultConfig() internally
defer client.Close()

var wg sync.WaitGroup
for i := 0; i < 100; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        result, _ := client.Get("https://api.example.com")
        // Process response...
    }()
}
wg.Wait()
```

### Performance Optimization

```go
// Release Result back to pool after use (reduces GC pressure for high-throughput scenarios)
result, _ := httpc.Get(url)
defer httpc.ReleaseResult(result)
```

### Default Client Management

Package-level functions (`Get`, `Post`, etc.) use a shared default client. You can customize it:

```go
// Set a custom default client
customClient, _ := httpc.New(httpc.SecureConfig())
_ = httpc.SetDefaultClient(customClient)

// Close and reset the default client
_ = httpc.CloseDefaultClient()
```

**Thread Safety Guarantees:**
- All `Client` methods are safe for concurrent use
- Package-level functions safely use a shared default client
- Response objects can be safely read from multiple goroutines
- Internal metrics use atomic operations

---

## Documentation

| Resource | Description |
|----------|-------------|
| [Getting Started](docs/01_getting-started.md) | Installation and first steps |
| [Configuration](docs/02_configuration.md) | Client configuration and presets |
| [Request Options](docs/03_request-options.md) | Complete options reference |
| [Error Handling](docs/04_error-handling.md) | Error handling patterns |
| [HTTP Redirects](docs/05_redirects.md) | Redirect handling and tracking |
| [Cookie API](docs/06_cookie-api.md) | Cookie management |
| [File Download](docs/07_file-download.md) | File download with progress |
| [Request Inspection](docs/08_request-inspection.md) | Request/response inspection |
| [Concurrency Safety](docs/09_concurrency-safety.md) | Thread safety guarantees |
| [Security](SECURITY.md) | Security features and best practices |

### Example Code

19 runnable examples covering all features, ordered from basic to advanced.

| Category | Examples |
|----------|----------|
| **Basics** | [01_basic_usage](examples/01_basic_usage.go), [02_http_methods](examples/02_http_methods.go), [03_response_handling](examples/03_response_handling.go), [04_compression](examples/04_compression.go) |
| **Core Features** | [05_request_options](examples/05_request_options.go), [06_error_handling](examples/06_error_handling.go), [07_timeout_retry](examples/07_timeout_retry.go), [08_client_configuration](examples/08_client_configuration.go), [09_redirects](examples/09_redirects.go), [10_cookies_advanced](examples/10_cookies_advanced.go) |
| **Stateful Clients** | [11_session](examples/11_session.go), [12_domain_client](examples/12_domain_client.go), [13_proxy_configuration](examples/13_proxy_configuration.go), [14_doh](examples/14_doh.go) |
| **Advanced** | [15_middleware](examples/15_middleware.go), [16_concurrent_requests](examples/16_concurrent_requests.go), [17_file_operations](examples/17_file_operations.go), [18_rest_api_client](examples/18_rest_api_client.go), [19_advanced_patterns](examples/19_advanced_patterns.go) |

Run any example:

```bash
go run examples/01_basic_usage.go
```

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

If this project helps you, please give it a Star!
