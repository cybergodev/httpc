//go:build examples

package main

import (
	"fmt"
	"log"
	"net/url"

	"github.com/cybergodev/httpc"
)

func main() {
	fmt.Println("=== HTTPC Redirect Examples ===\n ")

	// Example 1: Automatic redirect following (default behavior)
	example1AutoFollow()

	// Example 2: Disable redirect following
	example2NoFollow()

	// Example 3: Limit maximum redirects
	example3MaxRedirects()

	// Example 4: Per-request redirect control
	example4PerRequestControl()

	// Example 5: Track redirect chain
	example5RedirectChain()

	// Example 6: Manual redirect handling
	example6ManualHandling()

	// Example 7: Redirect whitelist (security)
	example7RedirectWhitelist()
}

func example1AutoFollow() {
	fmt.Println("Example 1: Automatic Redirect Following")
	fmt.Println("----------------------------------------")

	// Default client follows redirects automatically
	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// This URL redirects to the final destination
	resp, err := client.Get("https://httpbin.org/redirect/3")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Final Status: %d\n", resp.StatusCode())
	fmt.Printf("Redirects Followed: %d\n", resp.Meta.RedirectCount)
	fmt.Printf("Redirect Chain Length: %d\n\n", len(resp.Meta.RedirectChain))
}

func example2NoFollow() {
	fmt.Println("Example 2: Disable Redirect Following")
	fmt.Println("--------------------------------------")

	// Configure client to not follow redirects
	config := httpc.DefaultConfig()
	config.Defaults.FollowRedirects = false
	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Get the redirect response without following
	resp, err := client.Get("https://httpbin.org/redirect/1")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Status: %d (redirect response)\n", resp.StatusCode())
	fmt.Printf("Location Header: %s\n", resp.Response.Headers.Get("Location"))
	fmt.Printf("Is Redirect: %v\n", resp.IsRedirect())
	fmt.Printf("Redirects Followed: %d\n\n", resp.Meta.RedirectCount)
}

func example3MaxRedirects() {
	fmt.Println("Example 3: Limit Maximum Redirects")
	fmt.Println("-----------------------------------")

	// Configure client with redirect limit
	config := httpc.DefaultConfig()
	config.Defaults.FollowRedirects = true
	config.Defaults.MaxRedirects = 2 // Only follow up to 2 redirects
	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// This will fail because it tries to redirect 3 times
	resp, err := client.Get("https://httpbin.org/redirect/3")
	if err != nil {
		fmt.Printf("Expected error: %v\n", err)
	} else {
		fmt.Printf("Unexpected success: %d redirects\n", resp.Meta.RedirectCount)
	}

	// This will succeed because it only redirects 2 times
	resp, err = client.Get("https://httpbin.org/redirect/2")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Success: %d redirects (within limit)\n\n", resp.Meta.RedirectCount)
}

func example4PerRequestControl() {
	fmt.Println("Example 4: Per-Request Redirect Control")
	fmt.Println("----------------------------------------")

	// Client configured to follow redirects
	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Override to not follow redirects for this specific request
	resp, err := client.Get("https://httpbin.org/redirect/1",
		httpc.WithFollowRedirects(false),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Request 1 (no follow): Status %d, Redirects: %d\n",
		resp.StatusCode(), resp.Meta.RedirectCount)

	// Override max redirects for this specific request
	resp, err = client.Get("https://httpbin.org/redirect/5",
		httpc.WithMaxRedirects(3),
	)
	if err != nil {
		fmt.Printf("Request 2 (max 3): Expected error: %v\n", err)
	} else {
		fmt.Printf("Request 2: Unexpected success\n")
	}

	// Normal request follows all redirects
	resp, err = client.Get("https://httpbin.org/redirect/2")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Request 3 (default): Status %d, Redirects: %d\n\n",
		resp.StatusCode(), resp.Meta.RedirectCount)
}

func example5RedirectChain() {
	fmt.Println("Example 5: Track Redirect Chain")
	fmt.Println("--------------------------------")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Follow multiple redirects and track the chain
	resp, err := client.Get("https://httpbin.org/redirect/3")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Final Status: %d\n", resp.StatusCode())
	fmt.Printf("Total Redirects: %d\n", resp.Meta.RedirectCount)
	fmt.Println("\nRedirect Chain:")
	for i, url := range resp.Meta.RedirectChain {
		fmt.Printf("  %d. %s\n", i+1, url)
	}
	fmt.Println()
}

// Example 6: Manual redirect handling
func example6ManualHandling() {
	fmt.Println("Example 6: Manual Redirect Handling")
	fmt.Println("------------------------------------")

	// Disable automatic redirects
	config := httpc.DefaultConfig()
	config.Defaults.FollowRedirects = false
	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	currentURL := "https://httpbin.org/redirect/3"
	redirectCount := 0
	maxRedirects := 5

	// Parse base URL for resolving relative redirect locations
	baseURL, err := url.Parse(currentURL)
	if err != nil {
		log.Printf("Error parsing base URL: %v\n", err)
		return
	}

	for redirectCount < maxRedirects {
		resp, err := client.Get(currentURL)
		if err != nil {
			log.Printf("Error: %v\n", err)
			return
		}

		fmt.Printf("Step %d: Status %d\n", redirectCount+1, resp.StatusCode())

		// Check if it's a redirect
		if !resp.IsRedirect() {
			fmt.Printf("Reached final destination after %d redirects\n", redirectCount)
			body := resp.Body()
			if len(body) > 50 {
				body = body[:50]
			}
			fmt.Printf("Final response: %s\n\n", body)
			break
		}

		// Get the redirect location
		location := resp.Response.Headers.Get("Location")
		if location == "" {
			fmt.Println("Redirect without Location header")
			break
		}

		// Resolve relative URL against the current request URL
		nextURL, err := baseURL.Parse(location)
		if err != nil {
			log.Printf("Error parsing redirect location: %v\n", err)
			return
		}

		fmt.Printf("  Redirecting to: %s\n", nextURL.String())
		currentURL = nextURL.String()
		baseURL = nextURL
		redirectCount++
	}

	if redirectCount >= maxRedirects {
		fmt.Printf("Stopped after %d redirects (limit reached)\n\n", maxRedirects)
	}
}

// example7RedirectWhitelist shows how to restrict redirects to trusted domains.
// RedirectWhitelist is a security measure: even when following redirects, the
// client only follows to domains on the whitelist, blocking open-redirect and
// redirect-based SSRF attacks.
func example7RedirectWhitelist() {
	fmt.Println("Example 7: Redirect Whitelist (Security)")
	fmt.Println("-----------------------------------------")

	// Only allow redirects to httpbin.org — redirects to any other domain
	// are blocked even when FollowRedirects is true.
	config := httpc.DefaultConfig()
	config.Defaults.FollowRedirects = true
	config.Security.RedirectWhitelist = []string{"httpbin.org"}

	client, err := httpc.New(config)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Same-domain redirect: allowed (httpbin.org → httpbin.org)
	resp, err := client.Get("https://httpbin.org/redirect/1")
	if err != nil {
		log.Printf("Same-domain redirect error: %v\n", err)
	} else {
		fmt.Printf("Same-domain redirect: allowed (Status %d, %d redirects)\n",
			resp.StatusCode(), resp.Meta.RedirectCount)
	}

	fmt.Println("\nRedirectWhitelist:")
	fmt.Println("  - Only listed domains may receive redirected requests")
	fmt.Println("  - Blocks open-redirect and redirect-based SSRF attacks")
	fmt.Println("  - Combine with SecureConfig() for defense-in-depth\n ")
}
