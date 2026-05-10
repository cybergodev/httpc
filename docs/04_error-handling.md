# Error Handling

This guide covers comprehensive error handling patterns and best practices for HTTPC.

> **Prerequisite**: This guide builds on the [Error Handling Pattern](01_getting-started.md#error-handling-pattern) from the Getting Started guide. Master that pattern first before exploring advanced techniques.

## Table of Contents

- [Overview](#overview)
- [Error Types](#error-types)
- [Response Status Checking](#response-status-checking)
- [Error Handling Patterns](#error-handling-patterns)
- [Timeout Errors](#timeout-errors)
- [Network Errors](#network-errors)
- [Best Practices](#best-practices)

## Overview

HTTPC provides multiple layers of error handling:

1. **Network-level errors** - Connection failures, timeouts, DNS errors
2. **HTTP-level errors** - Status codes (4xx, 5xx)
3. **Application-level errors** - Circuit breaker, validation errors
4. **Response parsing errors** - JSON/XML unmarshaling failures

## Error Types

### Network Errors

```go
resp, err := client.Get(url)
if err != nil {
    // Network error occurred
    log.Printf("Request failed: %v", err)
    return err
}
```

**Common network errors:**
- Connection refused
- DNS lookup failed
- Connection timeout
- TLS handshake failed
- Context canceled

### HTTP Status Errors

```go
result, err := client.Get(url)
if err != nil {
    return err
}

// Check HTTP status
if !result.IsSuccess() {
    return fmt.Errorf("unexpected status: %d", result.StatusCode())
}
```

### Parsing Errors

```go
var data MyStruct
if err := result.Unmarshal(&data); err != nil {
    return fmt.Errorf("failed to parse JSON: %w", err)
}
```

## Response Status Checking

### Status Helper Methods

```go
result, err := client.Get(url)
if err != nil {
    return err
}

// Check status categories
if result.IsSuccess() {        // 2xx
    fmt.Println("Success!")
}

if result.IsClientError() {    // 4xx
    fmt.Println("Client error")
}

if result.IsServerError() {    // 5xx
    fmt.Println("Server error")
}
```

### Specific Status Codes

```go
switch result.StatusCode() {
case 200:
    // OK
case 201:
    // Created
case 400:
    // Bad Request
case 401:
    // Unauthorized
case 403:
    // Forbidden
case 404:
    // Not Found
case 429:
    // Too Many Requests
case 500:
    // Internal Server Error
case 503:
    // Service Unavailable
default:
    return fmt.Errorf("unexpected status: %d", result.StatusCode())
}
```

### Status Code Ranges

```go
statusCode := result.StatusCode()
if statusCode >= 200 && statusCode < 300 {
    // Success
} else if statusCode >= 400 && statusCode < 500 {
    // Client error
} else if statusCode >= 500 {
    // Server error
}
```

## Error Handling Patterns

### Pattern 1: Basic Error Handling

```go
func fetchUser(client httpc.Client, userID int) (*User, error) {
    url := fmt.Sprintf("https://api.example.com/users/%d", userID)
    
    result, err := client.Get(url)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    
    if !result.IsSuccess() {
        return nil, fmt.Errorf("API returned status %d: %s", 
            result.StatusCode(), result.Body())
    }
    
    var user User
    if err := result.Unmarshal(&user); err != nil {
        return nil, fmt.Errorf("failed to parse response: %w", err)
    }
    
    return &user, nil
}
```

### Pattern 2: Detailed Error Information

```go
type APIError struct {
    StatusCode int
    Message    string
    Body       string
}

func (e *APIError) Error() string {
    return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Message)
}

func fetchData(client httpc.Client, url string) ([]byte, error) {
    result, err := client.Get(url)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    
    if !result.IsSuccess() {
        return nil, &APIError{
            StatusCode: result.StatusCode(),
            Message:    result.Response.Status,
            Body:       result.Body(),
        }
    }
    
    return result.RawBody(), nil
}
```

### Pattern 3: Error with Retry Logic

```go
func fetchWithRetry(client httpc.Client, url string) (*httpc.Result, error) {
    result, err := client.Get(url,
        httpc.WithMaxRetries(3),
        httpc.WithTimeout(10*time.Second),
    )
    
    if err != nil {
        // Check if it's a temporary error
        if strings.Contains(err.Error(), "timeout") {
            return nil, fmt.Errorf("request timed out after retries: %w", err)
        }
        return nil, fmt.Errorf("request failed: %w", err)
    }
    
    return result, nil
}
```

### Pattern 4: Context-Aware Error Handling

```go
func fetchWithContext(ctx context.Context, client httpc.Client, url string) ([]byte, error) {
    result, err := client.Get(url,
        httpc.WithContext(ctx),
        httpc.WithTimeout(30*time.Second),
    )
    
    if err != nil {
        // Check if context was canceled
        if ctx.Err() == context.Canceled {
            return nil, fmt.Errorf("request canceled: %w", err)
        }
        if ctx.Err() == context.DeadlineExceeded {
            return nil, fmt.Errorf("request deadline exceeded: %w", err)
        }
        return nil, fmt.Errorf("request failed: %w", err)
    }
    
    if !result.IsSuccess() {
        return nil, fmt.Errorf("status %d: %s", result.StatusCode(), result.Body())
    }
    
    return result.RawBody(), nil
}
```

### Pattern 5: Fallback on Error

```go
func fetchWithFallback(client httpc.Client, primaryURL, fallbackURL string) ([]byte, error) {
    // Try primary
    result, err := client.Get(primaryURL)
    if err == nil && result.IsSuccess() {
        return result.RawBody(), nil
    }
    
    // Log primary failure
    log.Printf("Primary failed: %v, trying fallback", err)
    
    // Try fallback
    result, err = client.Get(fallbackURL)
    if err != nil {
        return nil, fmt.Errorf("both primary and fallback failed: %w", err)
    }
    
    if !result.IsSuccess() {
        return nil, fmt.Errorf("fallback returned status %d", result.StatusCode())
    }
    
    return result.RawBody(), nil
}
```

## Retry Behavior

HTTPC automatically retries failed requests based on the configuration. The retry logic handles:
- Network errors (connection refused, timeout, DNS failures)
- Retryable HTTP status codes (408, 429, 500, 502, 503, 504)
- Exponential backoff with jitter

### Configuring Retry Behavior

```go
// Client-level retry configuration
config := httpc.DefaultConfig()
config.Retry.MaxRetries = 3
config.Retry.Delay = 1 * time.Second
config.Retry.BackoffFactor = 2.0

client, err := httpc.New(config)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Request-level retry override
resp, err := client.Get(url,
    httpc.WithMaxRetries(5),
)
```

### Understanding Retry Attempts

```go
result, err := client.Get(url)
if err != nil {
    log.Printf("Request failed after retries: %v", err)
    return err
}

// Check how many attempts were made
log.Printf("Request succeeded after %d attempt(s)", result.Meta.Attempts)
```

## Timeout Errors

### Handling Timeouts

```go
result, err := client.Get(url,
    httpc.WithTimeout(10*time.Second),
)

if err != nil {
    if strings.Contains(err.Error(), "timeout") ||
       strings.Contains(err.Error(), "deadline exceeded") {
        log.Printf("Request timed out after 10s")
        return nil, fmt.Errorf("request timeout: %w", err)
    }
    return nil, err
}
```

### Timeout with Retry

```go
func fetchWithTimeoutRetry(client httpc.Client, url string) ([]byte, error) {
    const maxAttempts = 3
    timeout := 5 * time.Second
    
    for attempt := 1; attempt <= maxAttempts; attempt++ {
        result, err := client.Get(url,
            httpc.WithTimeout(timeout),
        )
        
        if err == nil && result.IsSuccess() {
            return result.RawBody(), nil
        }
        
        if err != nil && strings.Contains(err.Error(), "timeout") {
            log.Printf("Attempt %d timed out, retrying...", attempt)
            timeout *= 2  // Exponential backoff
            continue
        }
        
        return nil, err
    }
    
    return nil, fmt.Errorf("all attempts timed out")
}
```

## Network Errors

### Connection Errors

```go
result, err := client.Get(url)
if err != nil {
    if strings.Contains(err.Error(), "connection refused") {
        return nil, fmt.Errorf("service is not running: %w", err)
    }
    if strings.Contains(err.Error(), "no such host") {
        return nil, fmt.Errorf("DNS lookup failed: %w", err)
    }
    if strings.Contains(err.Error(), "TLS handshake") {
        return nil, fmt.Errorf("TLS error: %w", err)
    }
    return nil, err
}
```

### Network Error Recovery

```go
func fetchWithNetworkRetry(client httpc.Client, url string) ([]byte, error) {
    const maxAttempts = 3
    
    for attempt := 1; attempt <= maxAttempts; attempt++ {
        result, err := client.Get(url)
        
        if err == nil && result.IsSuccess() {
            return result.RawBody(), nil
        }
        
        // Check if it's a recoverable network error
        if err != nil {
            if strings.Contains(err.Error(), "connection refused") ||
               strings.Contains(err.Error(), "connection reset") {
                log.Printf("Network error on attempt %d: %v", attempt, err)
                time.Sleep(time.Second * time.Duration(attempt))
                continue
            }
            // Non-recoverable error
            return nil, err
        }
        
        // HTTP error
        if !result.IsSuccess() {
            return nil, fmt.Errorf("status %d", result.StatusCode())
        }
    }
    
    return nil, fmt.Errorf("max attempts reached")
}
```

## Error Type Reference

### ErrorType Constants

Use `clientErr.Type` to classify errors after using `errors.As`:

| Constant | Description |
|----------|-------------|
| `httpc.ErrorTypeUnknown` | Unknown or unclassified error |
| `httpc.ErrorTypeNetwork` | Network-level error (connection refused, DNS, etc.) |
| `httpc.ErrorTypeTimeout` | Request or connection timeout |
| `httpc.ErrorTypeContextCanceled` | Context was canceled by caller |
| `httpc.ErrorTypeResponseRead` | Error reading response body |
| `httpc.ErrorTypeTransport` | HTTP transport-level error |
| `httpc.ErrorTypeRetryExhausted` | All retry attempts exhausted |
| `httpc.ErrorTypeTLS` | TLS handshake or protocol error |
| `httpc.ErrorTypeCertificate` | Certificate validation error |
| `httpc.ErrorTypeDNS` | DNS resolution error |
| `httpc.ErrorTypeValidation` | Input validation error (URL, headers, etc.) |
| `httpc.ErrorTypeHTTP` | HTTP protocol error |

### Sentinel Errors

HTTPC defines sentinel errors for specific failure conditions:

| Variable | Description |
|----------|-------------|
| `httpc.ErrClientClosed` | Client has been closed |
| `httpc.ErrNilConfig` | Configuration is nil |
| `httpc.ErrInvalidURL` | URL validation failed |
| `httpc.ErrInvalidHeader` | Header validation failed |
| `httpc.ErrInvalidTimeout` | Timeout configuration invalid |
| `httpc.ErrInvalidRetry` | Retry configuration invalid |
| `httpc.ErrInvalidConnection` | Connection configuration invalid |
| `httpc.ErrInvalidSecurity` | Security configuration invalid |
| `httpc.ErrInvalidMiddleware` | Middleware configuration invalid |
| `httpc.ErrEmptyFilePath` | Download file path is empty |
| `httpc.ErrFileExists` | File already exists (overwrite not enabled) |
| `httpc.ErrResponseBodyEmpty` | Response body is empty |
| `httpc.ErrResponseBodyTooLarge` | Response body exceeds size limit |

### ClientError Fields

The `ClientError` type provides structured error information:

```go
var clientErr *httpc.ClientError
if errors.As(err, &clientErr) {
    fmt.Printf("Code: %s\n", clientErr.Code())          // String error code (e.g., "TIMEOUT", "NETWORK_ERROR")
    fmt.Printf("Message: %s\n", clientErr.Message)      // Human-readable message
    fmt.Printf("Cause: %v\n", clientErr.Cause)          // Underlying error (use with errors.Is/As)
    fmt.Printf("URL: %s\n", clientErr.URL)              // Request URL (sanitized)
    fmt.Printf("Method: %s\n", clientErr.Method)        // HTTP method
    fmt.Printf("Host: %s\n", clientErr.Host)            // Target host
    fmt.Printf("Attempts: %d\n", clientErr.Attempts)    // Retry attempts made
    fmt.Printf("StatusCode: %d\n", clientErr.StatusCode) // HTTP status (if applicable)
    fmt.Printf("Retryable: %v\n", clientErr.IsRetryable()) // Whether error is retryable
    fmt.Printf("Type: %d\n", clientErr.Type)            // ErrorType constant (int)
}
```

## Best Practices

1. **Always check errors**
   ```go
   result, err := client.Get(url)
   if err != nil {
       return err
   }
   ```

2. **Check HTTP status codes**
   ```go
   if !result.IsSuccess() {
       return fmt.Errorf("status %d", result.StatusCode())
   }
   ```

3. **Wrap errors with context**
   ```go
   if err != nil {
       return fmt.Errorf("failed to fetch user %d: %w", userID, err)
   }
   ```

4. **Use appropriate error types**
   ```go
   type APIError struct {
       StatusCode int
       Message    string
   }
   ```

5. **Log errors appropriately**
   ```go
   if err != nil {
       log.Printf("Request failed: %v", err)
       return err
   }
   ```

6. **Use typed errors for classification**
   ```go
   var clientErr *httpc.ClientError
   if errors.As(err, &clientErr) {
       switch clientErr.Type {
       case httpc.ErrorTypeTimeout:
           // Handle timeout specifically
       case httpc.ErrorTypeNetwork:
           // Handle network errors
       }
   }
   ```

## Complete Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "strings"
    "time"
    
    "github.com/cybergodev/httpc"
)

type User struct {
    ID    int    `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

func fetchUser(ctx context.Context, client httpc.Client, userID int) (*User, error) {
    url := fmt.Sprintf("https://api.example.com/users/%d", userID)
    
    // Make request with context and timeout
    result, err := client.Get(url,
        httpc.WithContext(ctx),
        httpc.WithTimeout(10*time.Second),
        httpc.WithMaxRetries(3),
    )
    
    // Handle network errors
    if err != nil {
        // Check for timeout
        if strings.Contains(err.Error(), "timeout") ||
           strings.Contains(err.Error(), "deadline exceeded") {
            return nil, fmt.Errorf("request timed out: %w", err)
        }
        
        // Check for context cancellation
        if ctx.Err() != nil {
            return nil, fmt.Errorf("request canceled: %w", err)
        }
        
        return nil, fmt.Errorf("request failed: %w", err)
    }
    
    // Handle HTTP errors
    if !result.IsSuccess() {
        switch result.StatusCode() {
        case 404:
            return nil, fmt.Errorf("user %d not found", userID)
        case 401:
            return nil, fmt.Errorf("unauthorized")
        case 429:
            return nil, fmt.Errorf("rate limit exceeded")
        case 500, 502, 503:
            return nil, fmt.Errorf("server error: %d", result.StatusCode())
        default:
            return nil, fmt.Errorf("unexpected status %d: %s", 
                result.StatusCode(), result.Body())
        }
    }
    
    // Parse response
    var user User
    if err := result.Unmarshal(&user); err != nil {
        return nil, fmt.Errorf("failed to parse user data: %w", err)
    }
    
    return &user, nil
}

func main() {
    client, err := httpc.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    ctx := context.Background()
    user, err := fetchUser(ctx, client, 123)
    if err != nil {
        log.Printf("Error: %v", err)
        return
    }
    
    fmt.Printf("User: %+v\n", user)
}
```

---