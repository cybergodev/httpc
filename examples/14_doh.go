//go:build examples

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/httpc"
)

// This example demonstrates DNS-over-HTTPS (DoH) configuration
// for encrypted, privacy-preserving DNS resolution.

func main() {
	fmt.Println("=== DNS-over-HTTPS (DoH) Examples ===\n ")

	// Example 1: Enable DoH with default settings
	demonstrateBasicDoH()

	// Example 2: DoH with custom cache TTL
	demonstrateDoHWithCacheTTL()

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateBasicDoH shows enabling DoH with default providers
func demonstrateBasicDoH() {
	fmt.Println("--- Example 1: Basic DoH ---")

	// Enable DoH - uses CF, Google, and Ali DNS providers by default
	config := httpc.DefaultConfig()
	config.Connection.EnableDoH = true

	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	start := time.Now()
	resp, err := client.Get("https://httpbin.org/get",
		httpc.WithTimeout(15*time.Second),
	)
	if err != nil {
		log.Printf("Request failed: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	fmt.Printf("Duration (includes DoH lookup): %v\n\n", time.Since(start))
	fmt.Println("DoH default providers:")
	fmt.Println("  1. Cloudflare (1.1.1.1) - priority 1")
	fmt.Println("  2. Google (8.8.8.8) - priority 2")
	fmt.Println("  3. Ali DNS (223.5.5.5) - priority 3")
	fmt.Println("  Providers are tried in order with automatic failover.\n ")
}

// demonstrateDoHWithCacheTTL shows customizing DoH cache duration
func demonstrateDoHWithCacheTTL() {
	fmt.Println("--- Example 2: DoH with Custom Cache TTL ---")

	// Customize how long DNS results are cached
	config := httpc.DefaultConfig()
	config.Connection.EnableDoH = true
	config.Connection.DoHCacheTTL = 10 * time.Minute // Cache DNS for 10 minutes

	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// First request resolves via DoH and caches
	start1 := time.Now()
	resp, err := client.Get("https://httpbin.org/get",
		httpc.WithTimeout(15*time.Second),
	)
	if err != nil {
		log.Printf("First request failed: %v\n", err)
		return
	}
	dur1 := time.Since(start1)

	// Second request uses cached DNS result (faster)
	start2 := time.Now()
	resp, err = client.Get("https://httpbin.org/get",
		httpc.WithTimeout(15*time.Second),
	)
	if err != nil {
		log.Printf("Second request failed: %v\n", err)
		return
	}
	dur2 := time.Since(start2)

	fmt.Printf("First request:  %d in %v (DoH lookup + request)\n", resp.StatusCode(), dur1)
	fmt.Printf("Second request: %d in %v (cached DNS)\n\n", resp.StatusCode(), dur2)

	fmt.Println("DoH benefits:")
	fmt.Println("  - Encrypted DNS queries (privacy from ISPs)")
	fmt.Println("  - Protection against DNS spoofing/poisoning")
	fmt.Println("  - Automatic provider failover for resilience")
	fmt.Println("  - Built-in cache to reduce latency on repeated lookups")
	fmt.Println("\nBest for:")
	fmt.Println("  - Security-sensitive applications")
	fmt.Println("  - Environments with unreliable DNS")
	fmt.Println("  - Compliance requirements (encrypted DNS)")
}
