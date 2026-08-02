# Cookie API Reference

Quick reference for working with cookies in httpc.

> **Prerequisite**: This guide assumes you understand the [Client Setup and Error Handling patterns](01_getting-started.md#common-patterns) from the Getting Started guide.

## Request Cookies vs Response Cookies

| Type | Description | Source | Usage |
|------|-------------|--------|-------|
| **Request Cookies** | Cookies sent TO the server | `Cookie` header | Authentication, session tracking |
| **Response Cookies** | Cookies received FROM the server | `Set-Cookie` header | Server setting new cookies |

## API Methods

### Response Cookies (from server)

Methods to access cookies returned by the server via `Set-Cookie` header:

| Method | Description | Example |
|--------|-------------|---------|
| `result.Response.Cookies` | All response cookies | `for _, c := range result.Response.Cookies { ... }` |
| `result.ResponseCookies()` | All response cookies (method) | `cookies := result.ResponseCookies()` |
| `result.GetCookie(name)` | Get specific cookie | `cookie := result.GetCookie("session")` |
| `result.HasCookie(name)` | Check if cookie exists | `if result.HasCookie("session") { ... }` |

### Request Cookies (sent to server)

Methods to inspect cookies that were sent in the request via `Cookie` header:

| Method | Description | Example |
|--------|-------------|---------|
| `result.Request.Cookies` | All request cookies | `for _, c := range result.Request.Cookies { ... }` |
| `result.RequestCookies()` | All request cookies (method) | `cookies := result.RequestCookies()` |
| `result.GetRequestCookie(name)` | Get specific cookie | `cookie := result.GetRequestCookie("session")` |
| `result.HasRequestCookie(name)` | Check if cookie was sent | `if result.HasRequestCookie("session") { ... }` |

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

    // Send request with cookies
    result, err := client.Get("https://api.example.com",
        httpc.WithCookie(http.Cookie{Name: "auth", Value: "token123"}),
        httpc.WithCookie(http.Cookie{Name: "session", Value: "abc456"}),
    )
    if err != nil {
        log.Fatal(err)
    }

    // ============================================
    // REQUEST COOKIES (what we sent)
    // ============================================
    
    // Get all request cookies
    requestCookies := result.Request.Cookies
    fmt.Printf("Sent %d cookies\n", len(requestCookies))
    
    // Get specific request cookie
    authCookie := result.GetRequestCookie("auth")
    if authCookie != nil {
        fmt.Printf("Auth: %s\n", authCookie.Value)
    }
    
    // Check if cookie was sent
    if result.HasRequestCookie("session") {
        fmt.Println("Session cookie was sent")
    }

    // ============================================
    // RESPONSE COOKIES (what server sent back)
    // ============================================
    
    // Get all response cookies
    fmt.Printf("Received %d cookies\n", len(result.Response.Cookies))
    
    // Get specific response cookie
    newSession := result.GetCookie("new_session")
    if newSession != nil {
        fmt.Printf("New session: %s\n", newSession.Value)
    }
    
    // Check if server set a cookie
    if result.HasCookie("new_session") {
        fmt.Println("Server set new session")
    }
}
```

## Setting Request Cookies

Multiple ways to add cookies to requests:

```go
// Method 1: http.Cookie struct (full control over attributes)
result, err := client.Get(url,
    httpc.WithCookie(http.Cookie{
        Name:  "session",
        Value: "abc123",
        Path:  "/",
        Secure: true,
        HttpOnly: true,
    }),
)

// Method 2: Multiple cookies (use multiple WithCookie calls)
result, err := client.Get(url,
    httpc.WithCookie(http.Cookie{Name: "cookie1", Value: "value1"}),
    httpc.WithCookie(http.Cookie{Name: "cookie2", Value: "value2"}),
)

// Method 3: Cookie map (convenient for simple name-value pairs)
cookies := map[string]string{
    "session_id": "abc123",
    "user_pref":  "dark_mode",
    "lang":       "en",
}
result, err := client.Get(url,
    httpc.WithCookieMap(cookies),
)

// Method 4: Cookie string (from browser dev tools)
// Parse and send multiple cookies from a cookie string
result, err := client.Get(url,
    httpc.WithCookieString("session=abc123; token=xyz789; user_id=12345"),
)
```

## Cookie Jar (Automatic Cookie Management)

Enable cookie jar for automatic cookie persistence:

```go
config := httpc.DefaultConfig()
config.Connection.EnableCookies = true
client, err := httpc.New(config)
if err != nil {
    log.Fatal(err)
}

// First request - server sets cookies
result1, _ := client.Get("https://api.example.com/login")
fmt.Printf("Server set %d cookies\n", len(result1.Response.Cookies))

// Second request - cookie jar automatically sends cookies
result2, _ := client.Get("https://api.example.com/profile")

// Verify cookies were sent automatically
if result2.HasRequestCookie("session") {
    fmt.Println("Cookie jar automatically sent session cookie")
}
```

## Debugging Cookies

### Verify cookies were sent correctly

```go
result, err := client.Get(url,
    httpc.WithCookie(http.Cookie{Name: "auth", Value: "token123"}),
)

// Check if cookie was actually sent
if !result.HasRequestCookie("auth") {
    log.Println("WARNING: auth cookie was not sent!")
}

// Get the actual value that was sent
authCookie := result.GetRequestCookie("auth")
if authCookie != nil && authCookie.Value != "token123" {
    log.Printf("WARNING: auth cookie value mismatch: %s", authCookie.Value)
}
```

### Compare request vs response

```go
result, err := client.Get(url,
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

## Common Patterns

### Authentication Flow

```go
// Login request
loginResult, _ := client.Post("https://api.example.com/login",
    httpc.WithJSON(map[string]string{
        "username": "user",
        "password": "pass",
    }),
)

// Get session cookie from response
sessionCookie := loginResult.GetCookie("session")
if sessionCookie == nil {
    log.Fatal("Login failed: no session cookie")
}

// Use session cookie in subsequent requests
profileResult, _ := client.Get("https://api.example.com/profile",
    httpc.WithCookie(*sessionCookie),
)

// Verify session was sent
if !profileResult.HasRequestCookie("session") {
    log.Println("WARNING: session cookie not sent")
}
```

### Cookie Validation

```go
result, err := client.Get(url,
    httpc.WithCookie(http.Cookie{Name: "required_cookie", Value: "value"}),
)

// Validate required cookies were sent
requiredCookies := []string{"required_cookie", "csrf_token"}
for _, name := range requiredCookies {
    if !result.HasRequestCookie(name) {
        log.Printf("ERROR: Required cookie '%s' was not sent", name)
    }
}
```

## API Design

All cookie inspection methods are available as Result methods for clean, intuitive API:

```go
// Result methods
cookies := result.Request.Cookies
cookie := result.GetRequestCookie("session")
exists := result.HasRequestCookie("session")
```

## See Also

- [Request Inspection](./08_request-inspection.md) - Detailed guide on inspecting requests
- [10_cookies_advanced.go](../examples/10_cookies_advanced.go) - More cookie examples
- [Configuration](./02_configuration.md) - Cookie jar configuration

## SessionManager Cookie API

For cross-request cookie persistence without a cookie jar, use `SessionManager`:

```go
// Create a session manager
session, err := httpc.NewSessionManagerDefault()
if err != nil {
    log.Fatal(err)
}

// Set cookies in the session
session.SetCookie(&http.Cookie{Name: "session", Value: "abc123"})
session.SetCookies([]*http.Cookie{
    {Name: "token", Value: "xyz789"},
})

// Retrieve cookies
allCookies := session.GetCookies()
singleCookie := session.GetCookie("session")

// Update session from a response
session.UpdateFromResult(result)

// Cookie security validation
config := httpc.DefaultSessionConfig()
config.CookieSecurity = httpc.StrictCookieSecurityConfig()
session, err := httpc.NewSessionManager(config)

// Remove cookies
session.DeleteCookie("session")
session.ClearCookies()
```

**SessionManager Methods:**

| Method | Description |
|--------|-------------|
| `SetCookie(cookie *http.Cookie) error` | Add or update a cookie |
| `SetCookies(cookies []*http.Cookie) error` | Add multiple cookies |
| `GetCookie(name string) *http.Cookie` | Get a specific cookie |
| `GetCookies() []*http.Cookie` | Get all cookies |
| `DeleteCookie(name string)` | Remove a cookie by name |
| `ClearCookies()` | Remove all cookies |
| `UpdateFromResult(result *Result)` | Update session cookies from a response |
| `UpdateFromCookies(cookies []*http.Cookie)` | Update session from cookie list |
| `SetCookieSecurity(config *CookieSecurityConfig)` | Set cookie security validation rules (use `httpc.DefaultCookieSecurityConfig()` or `httpc.StrictCookieSecurityConfig()`) |

## DomainClient Cookie API

`DomainClient` provides built-in cookie management through its session:

```go
dc, err := httpc.NewDomainDefault("https://api.example.com")
if err != nil {
    log.Fatal(err)
}

// Set cookies (safe for concurrent use)
if err := dc.SetCookie(&http.Cookie{Name: "session", Value: "abc123"}); err != nil {
    log.Fatal(err)
}

// Set multiple cookies
if err := dc.SetCookies([]*http.Cookie{
    {Name: "token", Value: "xyz789"},
}); err != nil {
    log.Fatal(err)
}

// Retrieve cookies
cookies := dc.GetCookies()
cookie := dc.GetCookie("session")

// Remove cookies
dc.DeleteCookie("session")
dc.ClearCookies()
```

**DomainClienter Cookie Methods:**

| Method | Description |
|--------|-------------|
| `SetCookie(cookie *http.Cookie) error` | Add or update a cookie |
| `SetCookies(cookies []*http.Cookie) error` | Add multiple cookies |
| `GetCookie(name string) *http.Cookie` | Get a specific cookie |
| `GetCookies() []*http.Cookie` | Get all cookies |
| `DeleteCookie(name string)` | Remove a cookie by name |
| `ClearCookies()` | Remove all cookies |
