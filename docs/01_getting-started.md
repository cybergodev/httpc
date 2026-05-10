# Getting Started with HTTPC

This guide will help you get started with HTTPC in just a few minutes.

## Installation

### Requirements

- Go 1.25 or higher
- Internet connection (for downloading dependencies)

### Install via go get

```bash
go get -u github.com/cybergodev/httpc
```

### Verify Installation

Create a simple test file:

```go
package main

import (
    "fmt"
    "log"

    "github.com/cybergodev/httpc"
)

func main() {
    client, err := httpc.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    fmt.Println("HTTPC installed successfully!")
}
```

Run it:

```bash
go run main.go
```

## Your First Request

### Simple GET Request

```go
package main

import (
    "fmt"
    "log"
    "github.com/cybergodev/httpc"
)

func main() {
    // Create a client
    client, err := httpc.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Make a GET request
    result, err := client.Get("https://api.github.com/users/octocat")
    if err != nil {
        log.Fatal(err)
    }

    // Print response
    fmt.Printf("Status: %d\n", result.StatusCode())
    fmt.Printf("Body: %s\n", result.Body())
}
```

### POST JSON Data

```go
package main

import (
    "fmt"
    "log"
    "github.com/cybergodev/httpc"
)

type User struct {
    Name  string `json:"name"`
    Email string `json:"email"`
}

func main() {
    client, err := httpc.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Create user data
    user := User{
        Name:  "John Doe",
        Email: "john@example.com",
    }

    // POST JSON
    result, err := client.Post("https://api.example.com/users",
        httpc.WithJSON(user),
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %d\n", result.StatusCode())
    fmt.Printf("Response: %s\n", result.Body())
}
```

### Parse JSON Response

```go
type User struct {
    ID    int    `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

func main() {
    client, err := httpc.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // GET request
    result, err := client.Get("https://api.example.com/users/1")
    if err != nil {
        log.Fatal(err)
    }

    // Parse JSON response
    var user User
    if err := result.Unmarshal(&user); err != nil {
        log.Fatal(err)
    }

    fmt.Printf("User: %+v\n", user)
}
```

## Basic Concepts

### Client Lifecycle

Always create a client and close it when done:

```go
// Create client
client, err := httpc.New()
if err != nil {
    log.Fatal(err)
}
defer client.Close()  // Important: always close the client

// Use client for multiple requests
resp1, _ := client.Get(url1)
resp2, _ := client.Get(url2)
resp3, _ := client.Post(url3, httpc.WithJSON(data))
```

**Why close?** Closing the client releases resources like connection pools and goroutines.

### Result Pooling

For high-throughput scenarios, return Result objects to the pool:

```go
result, err := client.Get(url)
if err != nil {
    log.Fatal(err)
}

// Process result...
fmt.Println(result.Body())

// Return to pool for reuse (reduces GC pressure)
httpc.ReleaseResult(result)
```

### Request Options

Customize requests with options:

```go
result, err := client.Get(url,
    httpc.WithTimeout(10*time.Second),
    httpc.WithHeader("X-Custom", "value"),
    httpc.WithBearerToken("your-token"),
)
```

**See also:** [Request Options Guide](03_request-options.md) for complete reference.

### Other HTTP Methods

HTTPC supports all standard HTTP methods:

```go
// Through client instance
result, err := client.Put(url, httpc.WithJSON(data))
result, err := client.Patch(url, httpc.WithJSON(data))
result, err := client.Delete(url)
result, err := client.Head(url)
result, err := client.Options(url)

// Low-level Request method with full control
result, err := client.Request(ctx, "DELETE", url,
    httpc.WithBearerToken(token),
)

// Package-level functions (use default client)
result, err := httpc.Put(url, httpc.WithJSON(data))
result, err := httpc.Delete(url)

// Package-level Request with full control
result, err := httpc.Request(ctx, "DELETE", url,
    httpc.WithBearerToken(token),
)
```

### File Downloads

```go
// Simple download
result, err := client.DownloadFile("https://example.com/file.zip", "downloads/file.zip")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Downloaded %s\n", httpc.FormatBytes(result.BytesWritten))

// Download with options
result, err := client.DownloadFile(url, filePath,
    httpc.WithBearerToken(token),
    httpc.WithTimeout(5*time.Minute),
)
```

**See also:** [File Download Guide](07_file-download.md) for progress tracking and advanced options.

### Error Handling

Always check errors:

```go
result, err := client.Get(url)
if err != nil {
    log.Printf("Request failed: %v", err)
    return err
}

// Check response status
if !result.IsSuccess() {
    log.Printf("Unexpected status: %d", result.StatusCode())
    return fmt.Errorf("request failed with status %d", result.StatusCode())
}

// Process response
fmt.Println(result.Body())
```

**See also:** [Error Handling Guide](04_error-handling.md) for comprehensive patterns.

### Response Helpers

```go
result, err := client.Get(url)
if err != nil {
    return err
}

// Status code helpers
if result.IsSuccess() {        // 2xx
    fmt.Println("Success!")
}
if result.IsClientError() {    // 4xx
    fmt.Println("Client error")
}
if result.IsServerError() {    // 5xx
    fmt.Println("Server error")
}

// Parse response
var data map[string]interface{}
if err := result.Unmarshal(&data); err != nil {
    return err
}
```

## Common Patterns

> **Note**: These patterns are referenced throughout the documentation. Master these basics first, then explore specialized guides.

### Client Setup Pattern

**Standard Client (Recommended for Production)**

```go
client, err := httpc.New()
if err != nil {
    log.Fatal(err)
}
defer client.Close()  // Always close to release resources
```

**Custom Client**

```go
config := httpc.DefaultConfig()
config.Timeouts.Request = 30 * time.Second
config.Middleware.UserAgent = "MyApp/1.0"

client, err := httpc.New(config)
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

**Quick One-Off Requests**

```go
// Uses shared default client - good for scripts
result, err := httpc.Get("https://api.example.com/data")
if err != nil {
    log.Fatal(err)
}
```

### Error Handling Pattern

```go
result, err := client.Get(url)
if err != nil {
    // Network error, timeout, or invalid input
    log.Printf("Request failed: %v", err)
    return err
}

// Check HTTP status (HTTPC returns Result for all status codes)
if !result.IsSuccess() {
    // 4xx or 5xx status
    log.Printf("API error: %d - %s", result.StatusCode(), result.Response.Status)
    return fmt.Errorf("request failed with status %d", result.StatusCode())
}

// Process successful response
fmt.Println(result.Body())
```

### Authenticated Request Pattern

```go
result, err := client.Get("https://api.example.com/protected",
    httpc.WithBearerToken("your-token"),
)
if err != nil {
    return err
}
if !result.IsSuccess() {
    return fmt.Errorf("authentication failed: %d", result.StatusCode())
}
```

### JSON Request/Response Pattern

```go
// POST JSON data
payload := map[string]string{"name": "John", "email": "john@example.com"}
result, err := client.Post("https://api.example.com/users",
    httpc.WithJSON(payload),
)
if err != nil {
    return err
}

// Parse JSON response
var response struct {
    ID    int    `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}
if err := result.Unmarshal(&response); err != nil {
    return err
}

fmt.Printf("Created user: %+v\n", response)
```

### Advanced Pattern 1: API Client Wrapper

```go
type APIClient struct {
    client  httpc.Client
    baseURL string
    token   string
}

func NewAPIClient(baseURL, token string) (*APIClient, error) {
    client, err := httpc.New()
    if err != nil {
        return nil, err
    }

    return &APIClient{
        client:  client,
        baseURL: baseURL,
        token:   token,
    }, nil
}

func (c *APIClient) Close() error {
    return c.client.Close()
}

func (c *APIClient) GetUser(id int) (*User, error) {
    url := fmt.Sprintf("%s/users/%d", c.baseURL, id)

    result, err := c.client.Get(url,
        httpc.WithBearerToken(c.token),
        httpc.WithTimeout(10*time.Second),
    )
    if err != nil {
        return nil, err
    }

    if !result.IsSuccess() {
        return nil, fmt.Errorf("API returned status %d", result.StatusCode())
    }

    var user User
    if err := result.Unmarshal(&user); err != nil {
        return nil, err
    }

    return &user, nil
}
```

### Advanced Pattern 2: Context-Aware Requests

```go
func fetchData(ctx context.Context, url string) ([]byte, error) {
    client, err := httpc.New()
    if err != nil {
        return nil, err
    }
    defer client.Close()

    result, err := client.Get(url,
        httpc.WithContext(ctx),
        httpc.WithTimeout(30*time.Second),
    )
    if err != nil {
        return nil, err
    }

    if !result.IsSuccess() {
        return nil, fmt.Errorf("status %d", result.StatusCode())
    }

    return result.RawBody(), nil
}

// Usage with timeout
ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
defer cancel()

data, err := fetchData(ctx, "https://api.example.com/large-data")
```

---

## Next Steps

Now that you understand the basics, explore these guides:

- **[Request Options](03_request-options.md)** - Complete reference for all request options
- **[Configuration](02_configuration.md)** - Client configuration and presets
- **[Domain Client](../examples/12_domain_client.go)** - Domain-specific client with session management
- **[Error Handling](04_error-handling.md)** - Advanced error handling patterns
- **[Redirects](05_redirects.md)** - Handle HTTP redirects
- **[Cookie Management](06_cookie-api.md)** - Automatic and manual cookie handling
- **[File Downloads](07_file-download.md)** - Download files with progress tracking
- **[Request Inspection](08_request-inspection.md)** - Debug and inspect requests
- **[Concurrency Safety](09_concurrency-safety.md)** - Thread-safe usage patterns

---

## Configuration Basics

### Using Defaults

```go
// Uses secure defaults (TLS 1.2+, 30s timeout, 3 retries)
client, err := httpc.New()
```

### Using Presets

```go
// Development - Permissive settings
client, err := httpc.New(httpc.TestingConfig())

// Production - Balanced (default)
client, err := httpc.New(httpc.DefaultConfig())

// High Security - Strict settings
client, err := httpc.New(httpc.SecureConfig())

// High Throughput - Large connection pools, longer timeouts
client, err := httpc.New(httpc.PerformanceConfig())

// Minimal - No retries, no redirects, lightweight
client, err := httpc.New(httpc.MinimalConfig())
```

**See also:** [Configuration Guide](02_configuration.md) for detailed configuration options.


## Quick Tips

✅ **DO:**
- Always close clients with `defer client.Close()`
- Check errors from all operations
- Use `result.IsSuccess()` to check status codes
- Set appropriate timeouts for your use case
- Reuse client instances for multiple requests

❌ **DON'T:**
- Create a new client for each request
- Ignore errors
- Use package-level functions in production code
- Set very long timeouts without good reason
- Forget to close clients

---
