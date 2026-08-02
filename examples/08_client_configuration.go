//go:build examples

package main

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/cybergodev/httpc"
)

func main() {
	fmt.Println("=== Client Configuration Examples ===\n ")

	// Example 1: Default configuration
	demonstrateDefaultConfig()

	// Example 2: Secure configuration
	demonstrateSecureConfig()

	// Example 3: Performance configuration
	demonstratePerformanceConfig()

	// Example 4: Custom configuration
	demonstrateCustomConfig()

	// Example 5: Configuration comparison
	demonstrateConfigComparison()

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateDefaultConfig shows default client configuration
func demonstrateDefaultConfig() {
	fmt.Println("--- Example 1: Default Configuration ---")

	// Create client with default settings
	client, err := httpc.NewDefault()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()

	resp, err := client.Get("https://httpbin.org/get")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	fmt.Println("Default config includes:")
	fmt.Println("  - 180s request timeout")
	fmt.Println("  - 3 retries with exponential backoff")
	fmt.Println("  - TLS 1.2+ with certificate validation")
	fmt.Println("  - HTTP/2 enabled")
	fmt.Println("  - Connection pooling\n ")
}

// demonstrateSecureConfig shows secure client configuration
func demonstrateSecureConfig() {
	fmt.Println("--- Example 2: Secure Configuration ---")

	// Create client with enhanced security
	client, err := httpc.New(httpc.SecureConfig())
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()

	// Note: If you're in a network environment that uses VPN (e.g., Tailscale with
	// 100.64.0.0/10) or other reserved IP ranges, the SSRF protection in SecureConfig
	// will block connections. In such cases, configure SSRFExemptCIDRs or use
	// AllowPrivateIPs: true.
	//
	// Example of custom config for such environments:
	// config := httpc.SecureConfig()
	// config.Security.SSRFExemptCIDRs = []string{"100.64.0.0/10"} // Exempt Tailscale
	// client, _ := httpc.New(config)

	resp, err := client.Get("https://httpbin.org/get")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("\nNote: This error may occur if you're in a network environment")
		fmt.Println("that uses reserved IP ranges (e.g., VPN networks using CGNAT).")
		fmt.Println("For such environments, configure SSRFExemptCIDRs or set")
		fmt.Println("AllowPrivateIPs: true in your configuration.\n ")
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	fmt.Println("Secure config includes:")
	fmt.Println("  - TLS 1.2+ with strict certificate validation")
	fmt.Println("  - Private IP blocking (SSRF protection)")
	fmt.Println("  - No redirect following (SSRF prevention)")
	fmt.Println("  - Smaller response limits (5MB)")
	fmt.Println("  - Lower connection limits\n ")
}

// demonstratePerformanceConfig shows performance-optimized configuration
func demonstratePerformanceConfig() {
	fmt.Println("--- Example 3: Performance Configuration ---")

	// Create client optimized for performance
	client, err := httpc.New(httpc.PerformanceConfig())
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()

	resp, err := client.Get("https://httpbin.org/get")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	fmt.Println("Performance config includes:")
	fmt.Println("  - Higher connection limits")
	fmt.Println("  - Longer keep-alive")
	fmt.Println("  - Optimized pooling")
	fmt.Println("  - HTTP/2 with multiplexing\n ")
}

// demonstrateCustomConfig shows custom client configuration
func demonstrateCustomConfig() {
	fmt.Println("--- Example 4: Custom Configuration ---")

	// Create custom configuration using hierarchical sub-structs
	config := httpc.DefaultConfig()
	config.Timeouts.Request = 15 * time.Second
	config.Retry.MaxRetries = 5
	config.Connection.MaxIdleConns = 200
	config.Connection.MaxConnsPerHost = 50
	config.Defaults.UserAgent = "MyApp/1.0"
	config.Defaults.FollowRedirects = true
	config.Connection.EnableCookies = true

	// Validate configuration before use
	if err := httpc.ValidateConfig(&config); err != nil {
		fmt.Printf("Invalid config: %v\n", err)
		return
	}

	client, err := httpc.New(config)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()

	resp, err := client.Get("https://echo.hoppscotch.io",
		httpc.WithQuery("custom", "config"),
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	fmt.Printf("Duration: %v\n", resp.Meta.Duration)
	fmt.Println("Custom config applied successfully\n ")
}

// demonstrateConfigComparison shows different configuration scenarios
func demonstrateConfigComparison() {
	fmt.Println("=== Configuration Comparison ===\n ")

	// Scenario 1: Quick API calls
	fmt.Println("Scenario 1: Quick API Calls (< 5s)")
	quickConfig := httpc.DefaultConfig()
	quickConfig.Timeouts.Request = 2 * time.Second
	quickConfig.Retry.MaxRetries = 0
	fmt.Println("  Timeout: 2s, Retries: 0")
	fmt.Println("  Use case: Health checks, fast endpoints\n ")

	// Scenario 2: Standard API calls
	fmt.Println("Scenario 2: Standard API Calls (5-30s)")
	standardConfig := httpc.DefaultConfig()
	standardConfig.Timeouts.Request = 30 * time.Second
	standardConfig.Retry.MaxRetries = 3
	fmt.Println("  Timeout: 30s, Retries: 3")
	fmt.Println("  Use case: Most REST API calls\n ")

	// Scenario 3: Long operations
	fmt.Println("Scenario 3: Long Operations (15-60s)")
	longConfig := httpc.DefaultConfig()
	longConfig.Timeouts.Request = 30 * time.Second
	longConfig.Retry.MaxRetries = 3
	fmt.Println("  Timeout: 30s, Retries: 3")
	fmt.Println("  Use case: File uploads, complex queries\n ")

	// Scenario 4: Background jobs
	fmt.Println("Scenario 4: Background Jobs (> 60s)")
	backgroundConfig := httpc.DefaultConfig()
	backgroundConfig.Timeouts.Request = 120 * time.Second
	backgroundConfig.Retry.MaxRetries = 5
	fmt.Println("  Timeout: 120s, Retries: 5")
	fmt.Println("  Use case: Batch processing, webhooks\n ")

	// Scenario 5: High security
	fmt.Println("Scenario 5: High Security")
	secureConfig := httpc.SecureConfig()
	secureConfig.Security.MinTLSVersion = tls.VersionTLS13
	secureConfig.Security.StrictContentLength = true
	fmt.Println("  TLS 1.3+, SSRF protection, strict validation")
	fmt.Println("  Use case: Financial, healthcare, sensitive data\n ")

	// Scenario 6: High throughput
	fmt.Println("Scenario 6: High Throughput")
	perfConfig := httpc.PerformanceConfig()
	perfConfig.Connection.MaxIdleConns = 500
	perfConfig.Connection.MaxConnsPerHost = 100
	fmt.Println("  High connection limits, optimized pooling")
	fmt.Println("  Use case: Web scraping, bulk operations\n ")

	// Scenario 7: Special network environments (e.g., VPN with CGNAT addresses)
	fmt.Println("Scenario 7: Special Network Environments")
	fmt.Println("For networks using reserved IP ranges (e.g., Tailscale 100.64.0.0/10):")
	specialConfig := httpc.SecureConfig()
	specialConfig.Security.SSRFExemptCIDRs = []string{"100.64.0.0/10"} // Exempt specific VPN range
	fmt.Println("  Start with SecureConfig()")
	fmt.Println("  Set SSRFExemptCIDRs for specific ranges, or AllowPrivateIPs: true for all")
	fmt.Println("  Use case: Corporate intranets, Tailscale, VPN networks\n ")

	// Scenario 8: Minimal configuration
	fmt.Println("Scenario 8: Minimal Configuration")
	minimalClient, err := httpc.New(httpc.MinimalConfig())
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		return
	}
	resp, err := minimalClient.Get("https://httpbin.org/get")
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
	} else {
		fmt.Printf("  Status: %d\n", resp.StatusCode())
	}
	minimalClient.Close()
	fmt.Println("  No retries, short timeouts, minimal features")
	fmt.Println("  Use case: Simple scripts, CLI tools, one-shot requests\n ")
}
