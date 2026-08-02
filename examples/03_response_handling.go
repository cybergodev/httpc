//go:build examples

package main

import (
	"fmt"
	"log"

	"github.com/cybergodev/httpc"
)

// This example demonstrates comprehensive response handling

func main() {
	fmt.Println("=== Response Handling Examples ===\n ")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// 1. Result API Structure
	demonstrateResultAPI(client)

	// 2. Response Parsing
	demonstrateResponseParsing(client)

	// 3. Status Code Checking
	demonstrateStatusChecking(client)

	// 4. Header Access
	demonstrateHeaderAccess(client)

	// 5. Response Metadata
	demonstrateMetadata(client)

	// 6. Response Formatting
	demonstrateFormatting(client)

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateResultAPI shows the Result API structure
func demonstrateResultAPI(client httpc.Client) {
	fmt.Println("--- Result API Structure ---")

	result, err := client.Post("https://echo.hoppscotch.io",
		httpc.WithJSON(map[string]string{"name": "John"}),
		httpc.WithHeader("X-Custom", "value"),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	// Request information
	fmt.Println("Request:")
	fmt.Printf("  Headers: %d\n", len(result.Request.Headers))
	fmt.Printf("  Custom header: %s\n", result.Request.Headers.Get("X-Custom"))

	// Response information
	fmt.Println("Response:")
	fmt.Printf("  Status: %d %s\n", result.Response.StatusCode, result.Response.Status)
	fmt.Printf("  Content-Length: %d\n", result.Response.ContentLength)
	fmt.Printf("  Headers: %d\n", len(result.Response.Headers))

	// Metadata
	fmt.Println("Metadata:")
	fmt.Printf("  Duration: %v\n", result.Meta.Duration)
	fmt.Printf("  Attempts: %d\n", result.Meta.Attempts)
	fmt.Printf("  Redirect count: %d\n\n", result.Meta.RedirectCount)
}

// demonstrateResponseParsing shows JSON and XML parsing
func demonstrateResponseParsing(client httpc.Client) {
	fmt.Println("--- Response Parsing ---")

	// JSON parsing into struct
	type APIResponse struct {
		Method  string            `json:"method"`
		Args    map[string]string `json:"args"`
		Headers map[string]string `json:"headers"`
	}

	resp, err := client.Get("https://echo.hoppscotch.io",
		httpc.WithQuery("test", "value"),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	var apiResp APIResponse
	if err := resp.Unmarshal(&apiResp); err != nil {
		log.Printf("JSON parse error: %v\n", err)
	} else {
		fmt.Printf("✓ JSON struct: Method=%s, Args=%d\n", apiResp.Method, len(apiResp.Args))
	}

	// JSON parsing into map
	var mapResult map[string]any
	if err := resp.Unmarshal(&mapResult); err != nil {
		log.Printf("JSON map error: %v\n", err)
	} else {
		fmt.Printf("✓ JSON map: %d keys\n", len(mapResult))
	}

	// Raw body access
	bodyStr := resp.Body()
	fmt.Printf("✓ Raw body: %d bytes\n", len(bodyStr))

	// Raw bytes
	bodyBytes := resp.RawBody()
	fmt.Printf("✓ Raw bytes: %d bytes\n\n", len(bodyBytes))
}

// demonstrateStatusChecking shows status code checking methods
func demonstrateStatusChecking(client httpc.Client) {
	fmt.Println("--- Status Code Checking ---")

	resp, err := client.Get("https://echo.hoppscotch.io")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Status Code: %d\n", resp.StatusCode())
	fmt.Printf("Status Text: %s\n", resp.Response.Status)
	fmt.Printf("Is Success (2xx): %v\n", resp.IsSuccess())
	fmt.Printf("Is Redirect (3xx): %v\n", resp.IsRedirect())
	fmt.Printf("Is Client Error (4xx): %v\n", resp.IsClientError())
	fmt.Printf("Is Server Error (5xx): %v\n\n", resp.IsServerError())

	// Practical pattern
	if resp.IsSuccess() {
		fmt.Println("✓ Request successful, safe to process\n ")
	} else if resp.IsClientError() {
		fmt.Println("✗ Client error - check request\n ")
	} else if resp.IsServerError() {
		fmt.Println("✗ Server error - retry may help\n ")
	}
}

// demonstrateHeaderAccess shows response header access
func demonstrateHeaderAccess(client httpc.Client) {
	fmt.Println("--- Response Headers ---")

	resp, err := client.Get("https://echo.hoppscotch.io")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	// Case-insensitive access (recommended)
	contentType := resp.Response.Headers.Get("content-type")
	fmt.Printf("Content-Type: %s\n", contentType)

	// Case-insensitive access (same as Get, but shows Header is http.Header)
	if date := resp.Response.Headers.Get("Date"); date != "" {
		fmt.Printf("Date: %s\n", date)
	}

	// Check if header exists
	if server := resp.Response.Headers.Get("Server"); server != "" {
		fmt.Printf("Server: %s\n", server)
	}

	// Iterate all headers
	fmt.Printf("Total headers: %d\n\n", len(resp.Response.Headers))
}

// demonstrateMetadata shows response metadata access
func demonstrateMetadata(client httpc.Client) {
	fmt.Println("--- Response Metadata ---")

	resp, err := client.Get("https://echo.hoppscotch.io",
		httpc.WithMaxRetries(2),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Duration: %v\n", resp.Meta.Duration)
	fmt.Printf("Attempts: %d\n", resp.Meta.Attempts)
	fmt.Printf("Redirect count: %d\n", resp.Meta.RedirectCount)
	fmt.Printf("Content length: %d bytes\n", resp.Response.ContentLength)
	fmt.Printf("Body size: %d bytes\n\n", len(resp.Body()))
}

// demonstrateFormatting shows response formatting methods
func demonstrateFormatting(client httpc.Client) {
	fmt.Println("--- Response Formatting ---")

	resp, err := client.Get("https://httpbin.org/json")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	// String() - Concise text representation
	fmt.Println("String() format:")
	fmt.Println(resp.String())
	fmt.Println()

	// Body() - Raw response body content
	fmt.Println("Body() format (first 200 chars):")
	bodyOutput := resp.Body()
	if len(bodyOutput) > 200 {
		fmt.Println(bodyOutput[:200] + "...")
	} else {
		fmt.Println(bodyOutput)
	}
}
