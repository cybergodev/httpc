# Concurrency Safety

This document describes the concurrency safety guarantees and best practices when using HTTPC in concurrent environments.

> **Prerequisite**: This is an advanced guide. Ensure you're familiar with [basic patterns](01_getting-started.md#common-patterns) before reading this guide.

## Overview

HTTPC is designed to be safe for concurrent use across multiple goroutines. This document explains the concurrency guarantees provided by the library and how to use it correctly in concurrent scenarios.

## Concurrency Guarantees

### Client Instances

**✅ Safe for Concurrent Use**

The `Client` type is safe for concurrent use. Multiple goroutines can call methods on the same client instance simultaneously:

```go
client, err := httpc.NewDefault()
if err != nil {
    log.Fatal(err)
}
defer client.Close()

var wg sync.WaitGroup

// Multiple goroutines using the same client
for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()

        result, err := client.Get("https://api.example.com/data")
        if err != nil {
            log.Printf("Request %d failed: %v", id, err)
            return
        }
        log.Printf("Request %d: %d", id, result.StatusCode())
    }(i)
}

wg.Wait()
```

### Connection Pool

The underlying connection pool is thread-safe. HTTPC uses Go's `http.Transport` which manages connections safely across goroutines:

- Connection reuse is handled automatically
- Idle connections are shared across requests
- No manual locking required

### Cookie Jar

When `Connection.EnableCookies` is set to `true`, the cookie jar is safe for concurrent access:

```go
config := httpc.DefaultConfig()
config.Connection.EnableCookies = true

client, err := httpc.New(config)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Safe for concurrent requests - cookies are managed atomically
```

### Result Objects

**⚠️ Not Safe for Concurrent Access**

`Result` objects are NOT safe for concurrent access. Each goroutine should have its own `Result` instance:

```go
// ❌ WRONG: Sharing Result across goroutines
var sharedResult *httpc.Result

// ✅ CORRECT: Each goroutine has its own Result
go func() {
    result, err := client.Get(url1)
    // Use result in this goroutine only
}()

go func() {
    result, err := client.Get(url2)
    // Use result in this goroutine only
}()
```

## DomainClient Concurrency

The `DomainClient` is also safe for concurrent use:

```go
dc, err := httpc.NewDomainDefault("https://api.example.com")
if err != nil {
    log.Fatal(err)
}
defer dc.Close()

// Set headers once (safe)
dc.SetHeader("Authorization", "Bearer "+token)

// Multiple goroutines can use the DomainClient
var wg sync.WaitGroup
for i := 0; i < 5; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()
        result, err := dc.Get(fmt.Sprintf("/users/%d", id))
        // Handle result
    }(i)
}
wg.Wait()
```

## Best Practices

### 1. Reuse Client Instances

Create one client and share it across goroutines:

```go
// ✅ CORRECT: Single shared client
var globalClient httpc.Client

func init() {
    var err error
    globalClient, err = httpc.NewDefault()
    if err != nil {
        log.Fatalf("failed to initialize HTTP client: %v", err)
    }
}

func makeRequest(url string) (*httpc.Result, error) {
    return globalClient.Get(url)
}
```

### 2. Avoid Creating Clients Per Request

```go
// ❌ WRONG: Creating client per request
func makeRequest(url string) (*httpc.Result, error) {
    client, _ := httpc.NewDefault()  // Inefficient!
    defer client.Close()
    return client.Get(url)
}

// ✅ CORRECT: Reuse client
var sharedClient httpc.Client

func init() {
    var err error
    sharedClient, err = httpc.NewDefault()
    if err != nil {
        log.Fatalf("failed to create shared client: %v", err)
    }
}

func makeRequest(url string) (*httpc.Result, error) {
    return sharedClient.Get(url)
}
```

### 3. Use Context for Cancellation

When making concurrent requests, use context for coordinated cancellation:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

var wg sync.WaitGroup
results := make(chan *httpc.Result, 10)

for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()

        result, err := client.Get(
            fmt.Sprintf("https://api.example.com/data/%d", id),
            httpc.WithContext(ctx),  // Shared context for cancellation
        )
        if err != nil {
            return
        }
        results <- result
    }(i)
}

// Wait for completion or context cancellation
go func() {
    wg.Wait()
    close(results)
}()

for result := range results {
    // Process results
}
```

### 4. Close Client When Done

Always close the client when you're finished to release resources:

```go
func main() {
    client, err := httpc.NewDefault()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()  // Called when main exits

    // Use client...
}
```

### 5. Reuse Client for High-Throughput Scenarios

For high-throughput scenarios, reuse a single client instance:

```go
func processResults(client httpc.Client, urls []string) {
    for _, url := range urls {
        result, err := client.Get(url)
        if err != nil {
            continue
        }

        // Process result...
        fmt.Println(result.StatusCode())

        // No manual cleanup needed — GC handles Result objects automatically
    }
}
```

## Internal Synchronization

HTTPC uses the following synchronization mechanisms internally:

| Component | Mechanism | Purpose |
|-----------|-----------|---------|
| Default Client | `sync.Mutex` + `atomic.Pointer` | Lazy initialization |
| Connection Pool | `http.Transport` internal | Connection management |
| SessionManager | `sync.RWMutex` | Thread-safe cookie/header session storage |
| Engine Response Pool | `sync.Pool` | Internal response object reuse |
| Config | Immutable after creation (deep copy) | Configuration safety |

## Thread-Safe Operations Summary

| Operation | Thread-Safe | Notes |
|-----------|-------------|-------|
| `client.Get/Post/etc.` | ✅ Yes | Safe for concurrent calls |
| `client.Close()` | ✅ Yes | Safe to call once |
| `client.Download()` | ✅ Yes | Safe for concurrent downloads |
| `result.Unmarshal()` | ❌ No | Each goroutine needs own Result |
| `result.SaveToFile()` | ❌ No | Each goroutine needs own Result |
| `domainClient.SetHeader()` | ✅ Yes | Safe for concurrent calls |
| `domainClient.SetCookie()` | ✅ Yes | Safe for concurrent calls |
| `domainClient.Close()` | ✅ Yes | Safe to call once |

## Common Pitfalls

### 1. Sharing Result Between Goroutines

```go
// ❌ WRONG
var result *httpc.Result
go func() {
    result, _ = client.Get(url1)  // Race condition!
}()
go func() {
    result, _ = client.Get(url2)  // Race condition!
}()
```

### 2. Closing Client While In Use

```go
// ❌ WRONG
client, _ := httpc.NewDefault()
go func() {
    time.Sleep(100 * time.Millisecond)
    client.Close()  // May close while other goroutines are using it
}()

client.Get(url)  // May fail if closed during request
```

### 3. Not Using Context for Timeout

```go
// ❌ WRONG: No timeout, may hang forever
go func() {
    client.Get("https://slow.example.com")
}()

// ✅ CORRECT: Context with timeout
go func() {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    client.Get("https://slow.example.com", httpc.WithContext(ctx))
}()
```

## See Also

- [Configuration](02_configuration.md) - Client configuration options
- [Error Handling](04_error-handling.md) - Handling errors in concurrent scenarios
- [Examples](../examples/) - More concurrent usage examples
