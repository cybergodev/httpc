//go:build examples

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/httpc"
)

// This example demonstrates advanced patterns and optimization techniques

func main() {
	fmt.Println("=== Advanced Patterns & Optimization ===")

	// 1. Request/Response Callbacks
	demonstrateCallbacks()

	// 2. Result Pool Optimization
	demonstrateResultPool()

	// 3. Stream Body Mode
	demonstrateStreamBody()

	// 4. Testing Configuration
	demonstrateTestingConfig()

	// 5. Default Client Management
	demonstrateDefaultClient()

	// 6. Memory Stats Comparison
	demonstrateMemoryOptimization()

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateCallbacks shows WithOnRequest and WithOnResponse callbacks
func demonstrateCallbacks() {
	fmt.Println("--- Example 1: Request/Response Callbacks ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Request callback - runs before request is sent
	onRequest := func(req httpc.RequestMutator) error {
		fmt.Printf("  [REQUEST] %s %s\n", req.Method(), req.URL())
		fmt.Printf("  [REQUEST] Headers: %d\n", len(req.Headers()))
		return nil
	}

	// Response callback - runs after response is received
	onResponse := func(resp httpc.ResponseMutator) error {
		fmt.Printf("  [RESPONSE] Status: %d %s\n", resp.StatusCode(), resp.Status())
		fmt.Printf("  [RESPONSE] Duration: %v\n", resp.Duration())
		fmt.Printf("  [RESPONSE] Attempts: %d\n", resp.Attempts())
		return nil
	}

	// Make request with callbacks
	resp, err := client.Get("https://httpbin.org/get",
		httpc.WithOnRequest(onRequest),
		httpc.WithOnResponse(onResponse),
		httpc.WithQuery("test", "callbacks"),
	)
	if err != nil {
		log.Printf("Request failed: %v\n", err)
		return
	}

	fmt.Printf("\nStatus: %d\n\n", resp.StatusCode())

	fmt.Println("Use cases for callbacks:")
	fmt.Println("  - Request logging and debugging")
	fmt.Println("  - Response validation before processing")
	fmt.Println("  - Custom metrics collection")
	fmt.Println("  - Request modification on-the-fly")
	fmt.Println()
}

// demonstrateResultPool shows result pool optimization
func demonstrateResultPool() {
	fmt.Println("--- Example 2: Result Pool Optimization ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	const numRequests = 10

	// Internal responses are pooled; Result objects are freshly allocated and GC-reclaimed.
	fmt.Println("Internal responses are pooled; Result objects are reclaimed by GC.")
	start := time.Now()
	for i := 0; i < numRequests; i++ {
		resp, err := client.Get("https://httpbin.org/get")
		if err != nil {
			continue
		}
		_ = resp.Body()
	}
	fmt.Printf("  %d requests completed in %v\n", numRequests, time.Since(start))
	fmt.Println()
}

// demonstrateStreamBody shows streaming mode for large responses
func demonstrateStreamBody() {
	fmt.Println("--- Example 3: Save Response to File ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// SaveToFile writes the response body directly to disk.
	// For large file downloads, prefer Download (with a DownloadConfig),
	// which streams directly to disk and avoids buffering the entire body.
	resp, err := client.Get("https://httpbin.org/get")
	if err != nil {
		log.Printf("Request failed: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	fmt.Printf("Body length: %d bytes\n", len(resp.RawBody()))

	err = resp.SaveToFile("downloads/response.json")
	if err != nil {
		fmt.Printf("SaveToFile: %v\n", err)
	} else {
		fmt.Println("Saved to downloads/response.json")
	}

	fmt.Println("\nWhen to use SaveToFile vs Download:")
	fmt.Println("  - SaveToFile: for small-to-medium responses already in memory")
	fmt.Println("  - Download: for large files (streams directly to disk)")
	fmt.Println("    (set cfg.ProgressCallback / Checksum / ResumeDownload for more)")
	fmt.Println()
}

// demonstrateTestingConfig shows TestingConfig preset
func demonstrateTestingConfig() {
	fmt.Println("--- Example 4: Testing Configuration ---")

	// TestingConfig is optimized for unit tests
	config := httpc.TestingConfig()
	fmt.Println("TestingConfig settings:")
	fmt.Println("  - Reduced timeouts (5-10s)")
	fmt.Println("  - Minimal retries (1 attempt)")
	fmt.Println("  - TLS verification disabled (for mock servers)")
	fmt.Println("  - HTTP/2 disabled (simpler debugging)")
	fmt.Println()

	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Fast request - good for tests
	start := time.Now()
	resp, err := client.Get("https://httpbin.org/get")
	if err != nil {
		log.Printf("Request failed: %v\n", err)
		return
	}
	fmt.Printf("Request completed: Status %d in %v\n", resp.StatusCode(), time.Since(start))

	fmt.Println("\nBest practices for testing:")
	fmt.Println("  1. Use TestingConfig() for fast, reliable tests")
	fmt.Println("  2. Mock external services when possible")
	fmt.Println("  3. Use context.WithTimeout for test timeouts")
	fmt.Println("  4. Example test pattern:")
	fmt.Println()
	fmt.Println("    func TestAPI(t *testing.T) {")
	fmt.Println("        client, _ := httpc.New(httpc.TestingConfig())")
	fmt.Println("        defer client.Close()")
	fmt.Println()
	fmt.Println("        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)")
	fmt.Println("        defer cancel()")
	fmt.Println()
	fmt.Println("        resp, err := client.Request(ctx, \"GET\", testServer.URL)")
	fmt.Println("        // assert.NoError(t, err)")
	fmt.Println("    }")
	fmt.Println()
}

// demonstrateDefaultClient shows default client management
func demonstrateDefaultClient() {
	fmt.Println("--- Example 5: Default Client Management ---")

	// Package-level functions use a shared default client
	fmt.Println("Package-level functions (Get, Post, etc.):")

	resp, err := httpc.Get("https://httpbin.org/get")
	if err != nil {
		log.Printf("Request failed: %v\n", err)
		return
	}
	fmt.Printf("  httpc.Get: Status %d\n", resp.StatusCode())

	// Set custom default client (start from defaults, override only needed fields)
	customCfg := httpc.DefaultConfig()
	customCfg.Timeouts.Request = 5 * time.Second
	customCfg.Retry.MaxRetries = 0
	customClient, err := httpc.New(customCfg)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}

	// Set as default (closes previous default)
	if err := httpc.SetDefaultClient(customClient); err != nil {
		log.Printf("Failed to set default: %v\n", err)
	}
	fmt.Println("  Custom client set as default")

	// Now package-level functions use custom client
	resp, err = httpc.Get("https://httpbin.org/get")
	if err != nil {
		log.Printf("Request failed: %v\n", err)
		return
	}
	fmt.Printf("  httpc.Get (custom): Status %d\n", resp.StatusCode())

	// Close default client (cleanup)
	if err := httpc.CloseDefaultClient(); err != nil {
		log.Printf("Failed to close: %v\n", err)
	}
	fmt.Println("  Default client closed")

	fmt.Println("\nUse cases:")
	fmt.Println("  - Application-wide configuration")
	fmt.Println("  - Lazy initialization")
	fmt.Println("  - Testing with custom client")
	fmt.Println()
}

// demonstrateMemoryOptimization shows memory optimization techniques
func demonstrateMemoryOptimization() {
	fmt.Println("--- Example 6: Memory Optimization Techniques ---")

	fmt.Println("Optimization tips:")
	fmt.Println("  1. Reuse client instances (don't create new clients per request)")
	fmt.Println("  2. Internal responses are pooled for reduced GC pressure")
	fmt.Println("  3. Configure appropriate timeouts to avoid goroutine leaks")
	fmt.Println("  4. Use PerformanceConfig() for high-concurrency applications")
	fmt.Println("  5. Close clients when done (releases connection pool)")
	fmt.Println()
	fmt.Println("For benchmarking, use go test -bench and -memprofile:")
	fmt.Println("  go test -bench=BenchmarkClient -benchmem ./...")
}
