# Request Inspection

This document explains how to inspect the actual HTTP request that was sent, including headers and cookies.

> **Prerequisite**: This is an advanced debugging guide. Ensure you're familiar with [basic patterns](01_getting-started.md#common-patterns) and [request options](03_request-options.md) first.

## Overview

When making HTTP requests, you may need to verify what was actually sent to the server. The `Result` struct provides access to request information including headers and cookies.

## Request vs Response Cookies

It's important to understand the difference:

- **Request Cookies**: Cookies sent TO the server in the `Cookie` header
- **Response Cookies**: Cookies received FROM the server in the `Set-Cookie` header

```go
result, err := client.Get("https://api.example.com",
    httpc.WithCookie(http.Cookie{Name: "session", Value: "abc123"}),  // Request cookie
)

// Response cookies (from server's Set-Cookie header)
for _, cookie := range result.Response.Cookies {
    fmt.Printf("Server sent: %s=%s\n", cookie.Name, cookie.Value)
}

// Request cookies (from request's Cookie header)
for _, cookie := range result.Request.Cookies {
    fmt.Printf("We sent: %s=%s\n", cookie.Name, cookie.Value)
}
```

## Inspecting Request Headers

The `Result.Request.Headers` field contains all headers that were actually sent in the HTTP request:

```go
result, err := client.Get("https://api.example.com",
    httpc.WithHeader("X-API-Key", "secret"),
    httpc.WithCookie(http.Cookie{Name: "session", Value: "abc123"}),
)

// Access all request headers
for name, values := range result.Request.Headers {
    for _, value := range values {
        fmt.Printf("%s: %s\n", name, value)
    }
}

// Access specific header
userAgent := result.Request.Headers.Get("User-Agent")
cookieHeader := result.Request.Headers.Get("Cookie")
```

## Inspecting Request Cookies

### Method 1: Direct Access to Cookie Header

```go
result, err := client.Get("https://api.example.com",
    httpc.WithCookie(http.Cookie{Name: "session", Value: "abc123"}),
    httpc.WithCookie(http.Cookie{Name: "token", Value: "xyz789"}),
)

// Get raw Cookie header
cookieHeader := result.Request.Headers.Get("Cookie")
fmt.Println(cookieHeader)  // Output: session=abc123; token=xyz789
```

### Method 2: Using Result Methods (Recommended)

The Result struct provides convenient methods to access request cookies:

```go
// Get all request cookies
requestCookies := result.Request.Cookies
for _, cookie := range requestCookies {
    fmt.Printf("%s = %s\n", cookie.Name, cookie.Value)
}

// Get specific request cookie
sessionCookie := result.GetRequestCookie("session")
if sessionCookie != nil {
    fmt.Printf("Session: %s\n", sessionCookie.Value)
}

// Check if cookie was sent
if result.HasRequestCookie("session") {
    fmt.Println("Session cookie was sent")
}
```

## Result Methods

### Request.Cookies

Direct access to all cookies sent in the request:

```go
cookies := result.Request.Cookies  // []*http.Cookie
```

Returns `nil` if no cookies were sent.

### GetRequestCookie

Returns a specific cookie by name:

```go
func (r *Result) GetRequestCookie(name string) *http.Cookie
```

Returns `nil` if the cookie is not found.

### HasRequestCookie

Checks if a specific cookie was sent:

```go
func (r *Result) HasRequestCookie(name string) bool
```

## Use Cases

### 1. Debugging Cookie Issues

Verify that cookies are being sent correctly:

```go
result, err := client.Get("https://api.example.com",
    httpc.WithCookie(http.Cookie{Name: "auth", Value: "token123"}),
)

if !result.HasRequestCookie("auth") {
    log.Println("Warning: auth cookie was not sent!")
}
```

### 2. Logging Request Details

Log complete request information for debugging:

```go
result, err := client.Get("https://api.example.com",
    httpc.WithCookie(http.Cookie{Name: "session", Value: "abc123"}),
)

log.Printf("Request URL: %s", result.Request.URL)
log.Printf("User-Agent: %s", result.Request.Headers.Get("User-Agent"))
log.Printf("Cookies sent: %s", result.Request.Headers.Get("Cookie"))
```

### 3. Verifying Cookie Jar Behavior

Check that cookie jar is working correctly:

```go
config := httpc.DefaultConfig()
config.Connection.EnableCookies = true
client, _ := httpc.New(config)

// First request - server sets cookie
result1, _ := client.Get("https://api.example.com/login")

// Second request - verify cookie jar sent the cookie
result2, _ := client.Get("https://api.example.com/profile")

if result2.HasRequestCookie("session") {
    fmt.Println("Cookie jar is working!")
}
```

### 4. Comparing Request vs Response

Compare what you sent vs what you received:

```go
result, err := client.Get("https://api.example.com",
    httpc.WithCookie(http.Cookie{Name: "client_cookie", Value: "value1"}),
)

fmt.Println("Sent to server:")
for _, cookie := range result.Request.Cookies {
    fmt.Printf("  → %s = %s\n", cookie.Name, cookie.Value)
}

fmt.Println("Received from server:")
for _, cookie := range result.Response.Cookies {
    fmt.Printf("  ← %s = %s\n", cookie.Name, cookie.Value)
}
```

## Complete Example

```go
package main

import (
    "fmt"
    "log"
    "github.com/cybergodev/httpc"
)

func main() {
    client, err := httpc.NewDefault()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Make request with cookies
    result, err := client.Get("https://httpbin.org/cookies",
        httpc.WithCookie(http.Cookie{Name: "session", Value: "abc123"}),
        httpc.WithCookie(http.Cookie{Name: "user_id", Value: "12345"}),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Inspect request cookies
    fmt.Println("Cookies sent in request:")
    requestCookies := result.Request.Cookies
    for _, cookie := range requestCookies {
        fmt.Printf("  %s = %s\n", cookie.Name, cookie.Value)
    }

    // Inspect all request headers
    fmt.Println("\nAll request headers:")
    for name, values := range result.Request.Headers {
        for _, value := range values {
            fmt.Printf("  %s: %s\n", name, value)
        }
    }

    // Check specific cookie
    if result.HasRequestCookie("session") {
        session := result.GetRequestCookie("session")
        fmt.Printf("\nSession cookie value: %s\n", session.Value)
    }
}
```

## Notes

- `Request.Headers` captures headers after all modifications (defaults, custom headers, etc.)
- `Request.Cookies` contains parsed cookie objects sent in the request
- Cookie header format: `name1=value1; name2=value2`
- Helper functions handle parsing and whitespace trimming
- Works with both manual cookies and cookie jar

## Result Struct Reference

### RequestInfo Fields

| Field | Type | Description |
|-------|------|-------------|
| `URL` | `string` | The request URL |
| `Method` | `string` | HTTP method (GET, POST, etc.) |
| `Headers` | `http.Header` | All request headers sent |
| `Cookies` | `[]*http.Cookie` | All cookies sent in the request |

### ResponseInfo Fields

| Field | Type | Description |
|-------|------|-------------|
| `StatusCode` | `int` | HTTP status code |
| `Status` | `string` | HTTP status text (e.g., "200 OK") |
| `Proto` | `string` | HTTP protocol (e.g., "HTTP/1.1") |
| `Headers` | `http.Header` | Response headers |
| `Body` | `string` | Response body as string |
| `RawBody` | `[]byte` | Response body as raw bytes |
| `ContentLength` | `int64` | Content-Length from response |
| `Cookies` | `[]*http.Cookie` | Cookies from Set-Cookie headers |

### RequestMeta Fields

| Field | Type | Description |
|-------|------|-------------|
| `Duration` | `time.Duration` | Total request duration |
| `Attempts` | `int` | Number of attempts (including retries) |
| `RedirectChain` | `[]string` | URLs visited during redirects |
| `RedirectCount` | `int` | Number of redirects followed |

### Result Convenience Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `Body()` | `string` | Response body as string |
| `RawBody()` | `[]byte` | Response body as raw bytes |
| `StatusCode()` | `int` | HTTP status code |
| `Proto()` | `string` | HTTP protocol version |
| `IsSuccess()` | `bool` | True for 2xx status codes |
| `IsRedirect()` | `bool` | True for 3xx status codes |
| `IsClientError()` | `bool` | True for 4xx status codes |
| `IsServerError()` | `bool` | True for 5xx status codes |
| `Unmarshal(v any)` | `error` | Parse JSON response into struct (max 50 MB; returns `ErrResponseBodyTooLarge` if exceeded) |
| `GetCookie(name)` | `*http.Cookie` | Get response cookie by name |
| `HasCookie(name)` | `bool` | Check if response cookie exists |
| `GetRequestCookie(name)` | `*http.Cookie` | Get request cookie by name |
| `HasRequestCookie(name)` | `bool` | Check if request cookie was sent |
| `RequestCookies()` | `[]*http.Cookie` | All request cookies |
| `ResponseCookies()` | `[]*http.Cookie` | All response cookies |
| `SaveToFile(path)` | `error` | Save response body to file |
| `String()` | `string` | Safe string representation (masks sensitive headers) |

## See Also

- [Cookie API Reference](./06_cookie-api.md) - Cookie handling documentation
- [Configuration](./02_configuration.md) - Cookie jar configuration
- [Examples](../examples/) - More examples
