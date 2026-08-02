//go:build examples

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cybergodev/httpc"
)

// This example demonstrates DomainClient for automatic state management

func main() {
	fmt.Println("=== DomainClient Examples ===\n ")

	// 1. Basic Usage
	demonstrateBasicUsage()

	// 2. State Management
	demonstrateStateManagement()

	// 3. Relative Path Usage
	demonstrateRelativePaths()

	// 4. Custom Configuration + Download
	demonstrateCustomConfigAndDownload()

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateBasicUsage shows basic DomainClient usage
func demonstrateBasicUsage() {
	fmt.Println("--- Basic DomainClient Usage ---")

	// Create domain-specific client
	client, err := httpc.NewDomainDefault("https://httpbin.org")
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Access base URL and domain info
	fmt.Printf("Base URL: %s\n", client.URL())
	fmt.Printf("Domain:   %s\n", client.Domain())

	// Set persistent headers (sent with every request)
	err = client.SetHeader("User-Agent", "httpc-domain-client/1.0")
	if err != nil {
		log.Printf("Operation failed: %v\n", err)
		return
	}
	err = client.SetHeader("Accept-Language", "en-US,en;q=0.9")
	if err != nil {
		log.Printf("Operation failed: %v\n", err)
		return
	}

	fmt.Printf("✓ Created DomainClient for httpbin.org\n")
	fmt.Printf("✓ Set %d persistent headers\n", len(client.GetHeaders()))

	// First request
	resp1, err := client.Get("/get")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ First request: Status %d\n", resp1.StatusCode())
	fmt.Printf("✓ Received %d cookies\n", len(resp1.ResponseCookies()))

	// Second request - headers and cookies automatically sent
	resp2, err := client.Get("/get")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Second request: Status %d\n", resp2.StatusCode())
	fmt.Printf("✓ Persistent headers: %d\n", len(client.GetHeaders()))
	fmt.Printf("✓ Persistent cookies: %d\n\n", len(client.GetCookies()))
}

// demonstrateStateManagement shows cookie and header management
func demonstrateStateManagement() {
	fmt.Println("--- State Management ---")

	client, err := httpc.NewDomainDefault("https://httpbin.org")
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Set persistent headers
	if err := client.SetHeaders(map[string]string{
		"X-API-Version": "v1",
		"X-Client-ID":   "client-123",
	}); err != nil {
		log.Printf("Operation failed: %v\n", err)
		return
	}
	fmt.Printf("✓ Set %d headers\n", len(client.GetHeaders()))

	// Add cookies manually
	if err := client.SetCookies([]*http.Cookie{
		{Name: "session", Value: "abc123"},
		{Name: "preferences", Value: "dark_mode"},
	}); err != nil {
		log.Printf("Operation failed: %v\n", err)
		return
	}
	fmt.Printf("✓ Set %d cookies\n", len(client.GetCookies()))

	// Make request - all state automatically sent
	resp, err := client.Get("/cookies")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Request with state: Status %d\n", resp.StatusCode())

	// Override header for single request
	resp, err = client.Get("/get",
		httpc.WithHeader("X-API-Version", "v2"), // Override for this request only
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Request with override: Status %d\n", resp.StatusCode())
	fmt.Printf("✓ Persistent headers still intact: %d\n", len(client.GetHeaders()))

	// Clear state
	client.ClearCookies()
	fmt.Printf("✓ Cleared cookies: %d remaining\n", len(client.GetCookies()))

	client.ClearHeaders()
	fmt.Printf("✓ Cleared headers: %d remaining\n\n", len(client.GetHeaders()))

	// Access underlying SessionManager
	session := client.Session()
	fmt.Printf("Session headers: %d\n", len(session.GetHeaders()))
	fmt.Printf("Session cookies: %d\n\n", len(session.GetCookies()))
}

// demonstrateRelativePaths shows relative path usage
func demonstrateRelativePaths() {
	fmt.Println("--- Relative Path Usage ---")

	client, err := httpc.NewDomainDefault("https://httpbin.org")
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Valid: Relative paths (automatically prefixed with base URL)
	paths := []string{
		"/get",
		"/headers",
		"/user-agent",
	}

	fmt.Println("Relative paths (prefixed with base URL):")
	for _, path := range paths {
		resp, err := client.Get(path)
		if err != nil {
			fmt.Printf("  ✗ %s: %v\n", path, err)
		} else {
			fmt.Printf("  ✓ %s → Status %d\n", path, resp.StatusCode())
		}
	}

	fmt.Println("\nTip: Use relative paths for domain-scoped requests")
	fmt.Println("  Example: client.Get(\"/api/users\") instead of full URLs")
}

// demonstrateCustomConfigAndDownload shows NewDomain with a custom Config
// and the DomainClient.Download method (which captures response cookies
// into the session automatically).
func demonstrateCustomConfigAndDownload() {
	fmt.Println("--- Custom Config & Download ---")

	// NewDomain accepts a full Config — customize timeouts, retries, etc.
	cfg := httpc.DefaultConfig()
	cfg.Timeouts.Request = 15 * time.Second
	cfg.Retry.MaxRetries = 2
	cfg.Defaults.UserAgent = "domain-client-demo/1.0"

	dc, err := httpc.NewDomain("https://httpbin.org", cfg)
	if err != nil {
		log.Printf("Failed to create domain client: %v\n", err)
		return
	}
	defer dc.Close()
	fmt.Printf("✓ Created DomainClient with custom config (UA: %s)\n", cfg.Defaults.UserAgent)

	// DomainClient.Download works like Client.Download but resolves the path
	// against the base URL and captures response cookies into the session.
	if err := os.MkdirAll("downloads", 0755); err != nil {
		log.Printf("Warning: downloads dir: %v\n", err)
	}

	dlCfg := httpc.DefaultDownloadConfig()
	dlCfg.FilePath = "downloads/domain-download.json"
	dlCfg.Overwrite = true

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := dc.Download(ctx, "/get", dlCfg,
		httpc.WithBearerToken("domain-token"),
	)
	if err != nil {
		log.Printf("Download error: %v\n", err)
		return
	}

	fmt.Printf("✓ Downloaded via DomainClient: %s (%s)\n",
		result.FilePath, httpc.FormatBytes(result.BytesWritten))
	fmt.Println("  Response cookies are captured into the session automatically.\n ")
}
