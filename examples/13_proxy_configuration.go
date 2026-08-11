//go:build examples

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/httpc"
)

func main() {
	fmt.Println("=== Proxy Configuration Examples ===\n ")

	// Example 1: Direct connection (no proxy) - default behavior
	demonstrateDirectConnection()

	// Example 2: System proxy detection
	demonstrateSystemProxy()

	// Example 3: Manual proxy configuration
	demonstrateManualProxy()

	// Example 4: Proxy priority demonstration
	demonstrateProxyPriority()

	// Example 5: Proxy pool with round-robin rotation
	demonstrateProxyPool()

	// Example 6: Status-based proxy rotation (CF/WAF evasion)
	demonstrateStatusRotation()

	// Example 7: Per-request proxy rotation
	demonstratePerRequestRotation()

	// Summary
	printSummary()

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateDirectConnection shows the default behavior without proxy
func demonstrateDirectConnection() {
	fmt.Println("--- Example 1: Direct Connection (Default) ---")

	// Create client without any proxy configuration
	// This is the default behavior - direct connection
	config := httpc.DefaultConfig()
	// ProxyURL is empty and EnableSystemProxy is false by default

	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Make an actual request to verify connectivity
	resp, err := client.Get("https://httpbin.org/ip",
		httpc.WithTimeout(10*time.Second),
	)
	if err != nil {
		log.Printf("Request failed: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	body := resp.Body()
	fmt.Printf("Response: %s\n", body[:min(100, len(body))])
	fmt.Println("Connection: Direct (no proxy)\n ")
}

// demonstrateSystemProxy shows automatic system proxy detection
func demonstrateSystemProxy() {
	fmt.Println("--- Example 2: System Proxy Detection ---")

	// Enable automatic system proxy detection
	// On Windows: reads from registry
	// On Linux/Mac: reads environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY)
	config := httpc.DefaultConfig()
	config.Connection.EnableSystemProxy = true

	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Make a request - will use system proxy if configured
	resp, err := client.Get("https://httpbin.org/ip",
		httpc.WithTimeout(10*time.Second),
	)

	if err != nil {
		log.Printf("Request failed: %v\n", err)
		fmt.Println("Note: If system proxy is configured but unavailable, this may fail")
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	body := resp.Body()
	fmt.Printf("Response: %s\n", body[:min(100, len(body))])
	fmt.Println("Connection: System proxy (if configured) or direct\n ")

	// Show environment variables that affect system proxy
	fmt.Println("Environment variables for system proxy:")
	fmt.Println("  HTTP_PROXY  - Proxy for HTTP requests")
	fmt.Println("  HTTPS_PROXY - Proxy for HTTPS requests")
	fmt.Println("  NO_PROXY    - Hosts to bypass proxy")
	fmt.Println("  (case-insensitive on most systems)\n ")
}

// demonstrateManualProxy shows manual proxy configuration
func demonstrateManualProxy() {
	fmt.Println("--- Example 3: Manual Proxy Configuration ---")

	// Configure a specific proxy URL
	// This bypasses any system proxy settings
	proxyURL := "http://127.0.0.1:7890" // Common proxy port for tools like Clash, V2Ray

	config := httpc.DefaultConfig()
	config.Connection.ProxyURL = proxyURL
	config.Timeouts.Request = 10 * time.Second

	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	fmt.Printf("Proxy URL: %s\n", proxyURL)
	fmt.Println("Attempting request through proxy...")

	// Make a request through the proxy
	// Note: This will fail if the proxy is not running
	resp, err := client.Get("https://httpbin.org/ip",
		httpc.WithTimeout(10*time.Second),
	)

	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		fmt.Println("\nNote: This is expected if no proxy is running at 127.0.0.1:7890")
		fmt.Println("Start your proxy software (Clash, V2Ray, etc.) to test this example.\n ")
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	body := resp.Body()
	fmt.Printf("Response: %s\n", body[:min(100, len(body))])
	fmt.Printf("Connection: Via proxy %s\n\n", proxyURL)
}

// demonstrateProxyPriority shows how proxy settings are prioritized
func demonstrateProxyPriority() {
	fmt.Println("--- Example 4: Proxy Priority ---")

	// When both ProxyURL and EnableSystemProxy are set, ProxyURL takes priority
	config := httpc.DefaultConfig()
	config.Connection.ProxyURL = "http://127.0.0.1:8080" // This takes priority
	config.Connection.EnableSystemProxy = true           // This is ignored
	config.Timeouts.Request = 5 * time.Second

	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	fmt.Println("Configuration:")
	fmt.Println("  ProxyURL: http://127.0.0.1:8080")
	fmt.Println("  EnableSystemProxy: true (ignored)")
	fmt.Println()
	fmt.Println("Result: Manual proxy is used (ProxyURL has higher priority)")

	// Attempt request (will fail if proxy not running)
	resp, err := client.Get("https://httpbin.org/ip")
	if err != nil {
		fmt.Printf("\nRequest failed: %v\n", err)
		fmt.Println("(Expected - no proxy running at 127.0.0.1:8080)\n ")
		return
	}
	_ = resp
	fmt.Println("Request succeeded through manual proxy\n ")
}

// demonstrateProxyPool shows round-robin rotation across multiple proxies.
func demonstrateProxyPool() {
	fmt.Println("--- Example 5: Proxy Pool (Round-Robin) ---")

	config := httpc.DefaultConfig()
	config.Connection.ProxyPool = []string{
		"http://127.0.0.1:7890",
		"http://127.0.0.1:7891",
		"http://127.0.0.1:7892",
	}
	// ProxyPoolStrategy defaults to ProxyStrategyRoundRobin — each request
	// (and each retry) advances to the next proxy automatically.
	config.Timeouts.Request = 10 * time.Second

	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	fmt.Printf("Proxy pool: %d proxies, round-robin strategy\n", len(config.Connection.ProxyPool))
	fmt.Println("Each request rotates to the next proxy IP.")
	fmt.Println("Dead proxies are auto-removed after 3 consecutive failures (circuit breaking).")
	fmt.Println("Customize with ProxyFailureThreshold and ProxyCooldown.\n ")

	// Alternative: random strategy for less predictable distribution
	fmt.Println("To use random selection instead, set ProxyPoolStrategy:")
	fmt.Println(`  config.Connection.ProxyPoolStrategy = httpc.ProxyStrategyRandom`)
	fmt.Println("  Random picks a healthy proxy uniformly — spreads load unpredictably.\n ")
}

// demonstrateStatusRotation shows proxy rotation triggered by HTTP status codes.
func demonstrateStatusRotation() {
	fmt.Println("--- Example 6: Rotate Proxy on 403 (CF/WAF Evasion) ---")

	config := httpc.DefaultConfig()
	config.Connection.ProxyPool = []string{
		"http://127.0.0.1:7890",
		"http://127.0.0.1:7891",
		"http://127.0.0.1:7892",
	}
	// When a response returns 403 (e.g. CF challenge), retry with a
	// different proxy. Under round-robin, the retry naturally picks the next
	// proxy IP. This does NOT circuit-break the proxy — blocks are often
	// target-specific.
	config.Connection.ProxyRotateOnStatus = []int{403}

	// Retry must be enabled for status rotation to take effect.
	config.Retry.MaxRetries = 3
	config.Retry.Delay = 500 * time.Millisecond
	config.Timeouts.Request = 30 * time.Second

	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	fmt.Println("ProxyRotateOnStatus: [403]")
	fmt.Println("On 403 -> retry -> next proxy IP (round-robin advances automatically)")
	fmt.Println("Requires Retry.MaxRetries > 0 to take effect.\n ")
}

// demonstratePerRequestRotation shows how to ensure each independent request
// uses a different proxy from the pool, even without status-based rotation.
func demonstratePerRequestRotation() {
	fmt.Println("--- Example 7: Per-Request Proxy Rotation ---")

	config := httpc.DefaultConfig()
	config.Connection.ProxyPool = []string{
		"http://127.0.0.1:7890",
		"http://127.0.0.1:7891",
		"http://127.0.0.1:7892",
	}
	// ProxyRotatePerRequest closes idle connections at the start of each
	// request so the transport re-evaluates the proxy pool, guaranteeing
	// each Get/Post call routes through a different proxy.
	config.Connection.ProxyRotatePerRequest = true
	config.Timeouts.Request = 10 * time.Second

	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	fmt.Println("ProxyRotatePerRequest: true")
	fmt.Println("Each client.Get() call uses a different proxy IP.")
	fmt.Println("Idle connections are closed between requests (no reuse).\n ")
}

// printSummary shows configuration summary and common use cases
func printSummary() {
	fmt.Println("=== Configuration Priority ===")
	fmt.Println()
	fmt.Println("Priority | Setting              | Behavior")
	fmt.Println("---------|----------------------|------------------------------------------")
	fmt.Println("1 (High) | ProxyURL set         | Always use specified proxy")
	fmt.Println("2        | ProxyPool set        | Rotate across multiple proxies")
	fmt.Println("3        | EnableSystemProxy    | Auto-detect from OS/env vars")
	fmt.Println("4 (Low)  | Neither set          | Direct connection (default)")
	fmt.Println()

	fmt.Println("=== Common Use Cases ===")
	fmt.Println()
	fmt.Println("Use Case                    | Configuration")
	fmt.Println("----------------------------|----------------------------------------")
	fmt.Println("Corporate network           | ProxyURL: \"http://proxy.company.com:8080\"")
	fmt.Println("VPN software (Clash/V2Ray)  | ProxyURL: \"http://127.0.0.1:7890\"")
	fmt.Println("Proxy pool / scraping       | ProxyPool: [\"http://p1:8080\", \"http://p2:8080\"]")
	fmt.Println("Per-request rotation        | ProxyPool + ProxyRotatePerRequest: true")
	fmt.Println("CF/WAF evasion              | ProxyPool + ProxyRotateOnStatus: [403]")
	fmt.Println("System proxy (Windows/Mac)  | EnableSystemProxy: true")
	fmt.Println("Development (no proxy)      | Default (no configuration needed)")
	fmt.Println()

	fmt.Println("=== Environment Variables ===")
	fmt.Println()
	fmt.Println("  # Linux/Mac")
	fmt.Println("  export HTTPS_PROXY=http://127.0.0.1:7890")
	fmt.Println("  export NO_PROXY=localhost,127.0.0.1,.internal")
	fmt.Println()
	fmt.Println("  # Windows (PowerShell)")
	fmt.Println("  $env:HTTPS_PROXY = \"http://127.0.0.1:7890\"")
	fmt.Println()
	fmt.Println("  # Then use EnableSystemProxy: true to read these values")
}
