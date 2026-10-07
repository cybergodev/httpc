# HTTP Redirects

HTTPC provides comprehensive support for HTTP redirects with automatic following, configurable limits, redirect chain tracking, and manual control.

> **Prerequisite**: This guide assumes you understand the [Client Setup pattern](01_getting-started.md#common-patterns) from the Getting Started guide.

## Table of Contents

- [Overview](#overview)
- [Automatic Redirect Following](#automatic-redirect-following)
- [Redirect Configuration](#redirect-configuration)
- [Per-Request Control](#per-request-control)
- [Redirect Tracking](#redirect-tracking)
- [Manual Redirect Handling](#manual-redirect-handling)
- [Redirect Whitelist](#redirect-whitelist)
- [Redirect Security](#redirect-security)
- [Supported Status Codes](#supported-status-codes)
- [Best Practices](#best-practices)
- [Error Handling](#error-handling)
- [Examples](#examples)
- [Summary](#summary)

## Overview

HTTP redirects (3xx status codes) instruct the client to request a different URL. HTTPC handles redirects automatically by default, following the redirect chain until reaching the final destination or hitting a limit.

**Key Features:**
- ✅ Automatic redirect following (enabled by default)
- ✅ Configurable redirect limits (default: 10, max: 50)
- ✅ Redirect chain tracking (URLs visited)
- ✅ Per-request redirect control
- ✅ Manual redirect handling
- ✅ Support for all redirect status codes (301, 302, 303, 307, 308) — 307/308 replay the request body when it is held in memory (see [Method Preservation](#method-preservation))

## Automatic Redirect Following

By default, HTTPC automatically follows redirects. The default limit is `MaxRedirects = 10`, which — matching `net/http` — counts the initial request, so at most **9 redirects** are followed:

```go
client, err := httpc.NewDefault()
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Automatically follows redirects
result, err := client.Get("https://example.com/redirect")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Final Status: %d\n", result.StatusCode())
fmt.Printf("Redirects Followed: %d\n", result.Meta.RedirectCount)
```

## Redirect Configuration

### Client-Level Configuration

Configure redirect behavior when creating the client:

```go
config := httpc.DefaultConfig()
config.Defaults.FollowRedirects = true  // Enable automatic following (default)
config.Defaults.MaxRedirects = 5        // At most 4 redirects: the limit counts the initial request (default: 10)

client, err := httpc.New(config)
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

### Disable Redirect Following

To receive redirect responses without following them:

```go
config := httpc.DefaultConfig()
config.Defaults.FollowRedirects = false

client, err := httpc.New(config)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

result, err := client.Get("https://example.com/redirect")
if err != nil {
    log.Fatal(err)
}

// result.Response.StatusCode will be 301, 302, etc.
// result.Response.Headers.Get("Location") contains the redirect URL
fmt.Printf("Redirect to: %s\n", result.Response.Headers.Get("Location"))
```

### Configuration Limits

- **MaxRedirects**: 0-50 (0 = fall back to the default limit of 10)
- **Default**: 10 (at most 9 redirects are followed)
- **Validation**: Config validation ensures MaxRedirects is within valid range

**Note:** Setting `MaxRedirects` to 0 does NOT disable redirects — it uses the built-in default of 10. To disable redirects entirely, set `FollowRedirects = false`.

**Counting semantics:** the limit includes the initial request, matching `net/http`. `MaxRedirects = n` allows at most `n-1` redirects, so the default of 10 follows 9. To permit exactly `k` redirects, set `MaxRedirects = k + 1`.

```go
config := httpc.DefaultConfig()
config.Defaults.MaxRedirects = 50  // Maximum allowed

// Invalid values will fail validation
config.Defaults.MaxRedirects = -1  // Error: invalid configuration: invalid middleware configuration: Defaults.MaxRedirects must be 0-50, got -1
config.Defaults.MaxRedirects = 51  // Error: invalid configuration: invalid middleware configuration: Defaults.MaxRedirects must be 0-50, got 51
```

## Per-Request Control

Override client configuration for specific requests:

### Disable Redirects for One Request

```go
// Client follows redirects by default
client, err := httpc.NewDefault()
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Override to not follow redirects for this request
result, err := client.Get("https://example.com/redirect",
    httpc.WithFollowRedirects(false),
)
if err != nil {
    log.Fatal(err)
}

if result.IsRedirect() {
    fmt.Printf("Redirect to: %s\n", result.Response.Headers.Get("Location"))
}
```

### Set Custom Redirect Limit

```go
// Override max redirects for this request
result, err := client.Get("https://example.com/redirect",
    httpc.WithMaxRedirects(3),  // At most 2 redirects (limit counts the initial request)
)
if err != nil {
    log.Fatal(err)
}
```

### Combine Options

```go
result, err := client.Get("https://example.com/redirect",
    httpc.WithFollowRedirects(true),
    httpc.WithMaxRedirects(5),
    httpc.WithTimeout(30*time.Second),
)
```

## Redirect Tracking

HTTPC tracks the redirect chain and provides detailed information:

### Response Fields

Redirect information is available in the `Result.Meta` field:

```go
type RequestMeta struct {
    Duration      time.Duration
    Attempts      int
    RedirectChain []string // URLs visited during redirect chain
    RedirectCount int      // Number of redirects followed
    ProxyURL      string   // Proxy used by the attempt that produced this response ("" = direct)
}

type Result struct {
    Request  *RequestInfo
    Response *ResponseInfo
    Meta     *RequestMeta  // Contains redirect information
}
```

### Example: Track Redirect Chain

```go
result, err := client.Get("https://example.com/redirect")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Final Status: %d\n", result.StatusCode())
fmt.Printf("Total Redirects: %d\n", result.Meta.RedirectCount)

if len(result.Meta.RedirectChain) > 0 {
    fmt.Println("\nRedirect Chain:")
    for i, url := range result.Meta.RedirectChain {
        fmt.Printf("  %d. %s\n", i+1, url)
    }
}
```

**Output:**
```
Final Status: 200
Total Redirects: 3

Redirect Chain:
  1. https://example.com/redirect
  2. https://example.com/redirect2
  3. https://example.com/redirect3
```

### Check for Redirects

```go
result, err := client.Get(url)
if err != nil {
    log.Fatal(err)
}

// Check if response is a redirect (3xx)
if result.IsRedirect() {
    fmt.Println("Response is a redirect")
}

// Check if redirects were followed
if result.Meta.RedirectCount > 0 {
    fmt.Printf("Followed %d redirects\n", result.Meta.RedirectCount)
}
```

## Manual Redirect Handling

For complete control, disable automatic redirects and handle them manually:

```go
config := httpc.DefaultConfig()
config.Defaults.FollowRedirects = false
client, err := httpc.New(config)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

currentURL := "https://example.com/redirect"
redirectCount := 0
maxRedirects := 5

for redirectCount < maxRedirects {
    result, err := client.Get(currentURL)
    if err != nil {
        log.Fatal(err)
    }

    // Check if it's a redirect
    if !result.IsRedirect() {
        fmt.Println("Reached final destination")
        break
    }

    // Get the redirect location
    location := result.Response.Headers.Get("Location")
    if location == "" {
        fmt.Println("Redirect without Location header")
        break
    }

    // Location may be relative — resolve it against the current URL
    base, baseErr := url.Parse(currentURL)
    if baseErr != nil {
        log.Fatalf("invalid current URL: %v", baseErr)
    }
    ref, parseErr := url.Parse(location)
    if parseErr != nil {
        log.Fatalf("invalid redirect URL: %v", parseErr)
    }
    currentURL = base.ResolveReference(ref).String()

    fmt.Printf("Redirecting to: %s\n", currentURL)
    redirectCount++
}

if redirectCount >= maxRedirects {
    fmt.Printf("Stopped after %d redirects\n", maxRedirects)
}
```

### Use Cases for Manual Handling

- **Custom redirect logic**: Implement special handling for certain URLs
- **Redirect analysis**: Inspect each redirect response before following
- **Conditional following**: Follow redirects based on custom criteria
- **Redirect logging**: Log each redirect for debugging or analytics

## Redirect Whitelist

Restrict redirect destinations to specific domains for security:

```go
config := httpc.DefaultConfig()
config.Security.RedirectWhitelist = []string{
    "api.example.com",
    "cdn.example.com",
}

client, err := httpc.New(config)
```

When `RedirectWhitelist` is set, redirects to domains not in the list will be rejected. This prevents open redirect attacks and ensures redirects only go to trusted domains.

**Use Cases:**
- Preventing open redirect vulnerabilities
- Restricting redirects to known CDN domains
- Compliance with security policies

## Redirect Security

Beyond the limit counter, the engine enforces three protections while following redirects:

### Cross-Origin Credential Stripping

When a redirect changes the request's origin — a different host, a different port (with scheme-default ports normalized, so `example.com` and `example.com:80` under http are the same origin while `example.com:8080` is not), or a different scheme — the `Authorization`, `Proxy-Authorization`, and `Cookie` headers are removed before the next hop. This includes the https → http downgrade (credentials must not travel over a plaintext hop) and, matching net/http's own behavior, the http → https upgrade on the same host.

### SSRF Re-Validation of Redirect Targets

Every redirect target is validated against the SSRF policy (private/reserved IP blocking) before it is followed — a public URL cannot be used to bounce the client onto an internal address. A per-request `WithAllowPrivateIPs(true)` override also applies to redirect targets.

### Circular Redirect Detection

True cycles (A → B → A, where the target URL appeared earlier in the chain reached from a different URL) fail immediately with Message `"circular redirect detected"`. Consecutive same-URL repeats (A → A) are allowed because the server may legitimately respond differently per visit.

Failures from these protections (SSRF re-validation and circular-redirect detection; cross-origin credential stripping is silent and never fails) — along with `Security.RedirectWhitelist` rejections — are classified as `*httpc.ClientError` with `Type == httpc.ErrorTypeValidation` (`Code()` returns `"VALIDATION_ERROR"`).

## Supported Status Codes

HTTPC automatically follows these redirect status codes:

| Code | Name                  | Description                                    |
|------|-----------------------|------------------------------------------------|
| 301  | Moved Permanently     | Resource permanently moved to new URL          |
| 302  | Found                 | Resource temporarily at different URL          |
| 303  | See Other             | Response at different URL (use GET)            |
| 307  | Temporary Redirect    | Temporary redirect (method and body preserved) |
| 308  | Permanent Redirect    | Permanent redirect (method and body preserved) |

### Method Preservation

- **301, 302, 303**: May change POST to GET (per HTTP spec)
- **307, 308**: Preserve original HTTP method **and body**

Method preservation relies on Go's `http.Client`, which replays the request body on 307/308 via `Request.GetBody`. HTTPC sets `GetBody` for every body held in memory — `string`, `[]byte`, JSON, XML, and multipart (`WithBody`, `WithJSON`, `WithXML`, `WithBinary`, `WithForm`/`WithFormData`/`WithFile`, ...) — so such requests follow 307/308 with the full body re-sent on every hop.

One exception mirrors `net/http`'s own rules:

- A raw `io.Reader` body with `Retry.MaxRetries == 0` passes through unbuffered and **cannot be replayed** — the 307/308 response is returned as-is, as if `WithFollowRedirects(false)` had been set. Use an in-memory body, or handle the redirect manually (see [Manual Redirect Handling](#manual-redirect-handling)).
- With `Retry.MaxRetries > 0` (default 3), `io.Reader` bodies are buffered to `[]byte` for retry safety — which also makes them replayable across 307/308 hops.

## Best Practices

### 1. Set Reasonable Limits

```go
config := httpc.DefaultConfig()
config.Defaults.MaxRedirects = 10  // Prevent infinite redirect loops

client, err := httpc.New(config)
```

### 2. Check Redirect Count

```go
result, err := client.Get(url)
if err != nil {
    log.Fatal(err)
}

if result.Meta.RedirectCount > 5 {
    log.Printf("Warning: Followed %d redirects", result.Meta.RedirectCount)
}
```

### 3. Handle Redirect Errors

```go
result, err := client.Get(url)
if err != nil {
    // Check if error is due to too many redirects
    if strings.Contains(err.Error(), "redirects") {
        log.Printf("Too many redirects: %v", err)
        return
    }
    log.Fatal(err)
}
```

### 4. Validate Redirect Locations

When handling redirects manually, validate the redirect URL:

```go
location := result.Response.Headers.Get("Location")
if location == "" {
    return fmt.Errorf("redirect without Location header")
}

// Parse and validate URL
redirectURL, err := url.Parse(location)
if err != nil {
    return fmt.Errorf("invalid redirect URL: %w", err)
}

// Check scheme
if redirectURL.Scheme != "http" && redirectURL.Scheme != "https" {
    return fmt.Errorf("invalid redirect scheme: %s", redirectURL.Scheme)
}
```

### 5. Use Per-Request Overrides Sparingly

```go
// Good: Configure at client level for consistent behavior
config := httpc.DefaultConfig()
config.Defaults.MaxRedirects = 5
client, err := httpc.New(config)

// Use per-request overrides only when necessary
resp, err := client.Get(specialURL, httpc.WithMaxRedirects(10))
```

### 6. Monitor Redirect Chains

```go
result, err := client.Get(url)
if err != nil {
    log.Fatal(err)
}

// Log redirect chain for debugging
if len(result.Meta.RedirectChain) > 0 {
    log.Printf("Redirect chain: %v", result.Meta.RedirectChain)
}
```

## Error Handling

### Too Many Redirects

```go
config := httpc.DefaultConfig()
config.Defaults.MaxRedirects = 3
client, err := httpc.New(config)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

result, err := client.Get(url)
if err != nil {
    // Exceeding the redirect limit surfaces as *httpc.ClientError with
    // Type == httpc.ErrorTypeValidation and Message "redirect limit
    // exceeded"; the "stopped after 3 redirects" text from HTTPC's
    // redirect policy (wording identical to net/http) is preserved
    // in the cause chain.
    var clientErr *httpc.ClientError
    if errors.As(err, &clientErr) && clientErr.Message == "redirect limit exceeded" {
        log.Printf("Redirect error: %v", err)
        return
    }
    log.Fatal(err)
}
```

### Infinite Redirect Loop

```go
// Server redirects to itself infinitely
// HTTPC will stop after MaxRedirects and return an error

result, err := client.Get("https://example.com/infinite-loop")
if err != nil {
    // A→B→A cycles are detected early and fail with Message
    // "circular redirect detected"; only chains that grow without
    // repeating a URL reach the MaxRedirects limit
    // ("redirect limit exceeded").
    log.Printf("Possible infinite loop: %v", err)
}
```

## Examples

See [09_redirects.go](../examples/09_redirects.go) for complete working examples:

1. **Automatic redirect following** - Default behavior
2. **Disable redirect following** - Get redirect response
3. **Limit maximum redirects** - Prevent excessive redirects
4. **Per-request redirect control** - Override client settings
5. **Track redirect chain** - Monitor redirect path
6. **Manual redirect handling** - Complete control
7. **Redirect whitelist** - Restrict redirect destinations for security

## Summary

HTTPC provides flexible redirect handling:

- **Default**: Automatically follows redirects (default limit 10 → at most 9 redirects)
- **Configurable**: Set limits at client or request level
- **Trackable**: Monitor redirect chain and count
- **Controllable**: Disable or manually handle redirects
- **Safe**: Prevents infinite loops with configurable limits

Choose the approach that best fits your use case:
- Use **automatic following** for most scenarios
- Use **custom limits** to prevent excessive redirects
- Use **manual handling** for special redirect logic
- Use **tracking** for debugging and analytics
