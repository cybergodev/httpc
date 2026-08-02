//go:build examples

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/httpc"
)

func main() {
	fmt.Println("=== Error Handling Examples ===\n ")

	// Example 1: Basic error handling
	demonstrateBasicErrors()

	// Example 2: HTTP status errors
	demonstrateHTTPErrors()

	// Example 3: Timeout errors
	demonstrateTimeoutErrors()

	// Example 4: Context cancellation
	demonstrateContextCancellation()

	// Example 5: Parsing errors
	demonstrateParsingErrors()

	// Example 6: Comprehensive error handling pattern
	demonstrateComprehensivePattern()

	// Example 7: Structured error types
	demonstrateStructuredErrors()

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateBasicErrors shows basic error handling
func demonstrateBasicErrors() {
	fmt.Println("--- Example 1: Basic Error Handling ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	resp, err := client.Get("https://echo.hoppscotch.io")
	if err != nil {
		// Network error, DNS error, etc.
		log.Printf("Request failed: %v\n", err)
		return
	}

	// Check if request was successful
	if !resp.IsSuccess() {
		log.Printf("HTTP error: %d - %s\n", resp.StatusCode(), resp.Response.Status)
		return
	}

	fmt.Printf("Request successful: %d\n\n", resp.StatusCode())
}

// demonstrateHTTPErrors shows HTTP status code error handling
func demonstrateHTTPErrors() {
	fmt.Println("--- Example 2: HTTP Status Errors ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Simulate different status codes
	testURL := "https://echo.hoppscotch.io"

	resp, err := client.Get(testURL)
	if err != nil {
		log.Printf("Request error: %v\n", err)
		return
	}

	// Detailed status code checking
	switch {
	case resp.IsSuccess():
		// 2xx - Success
		fmt.Println("Success (2xx)")
	case resp.IsRedirect():
		// 3xx - Redirection
		fmt.Printf("Redirect (3xx): %s\n", resp.Response.Headers.Get("Location"))
	case resp.IsClientError():
		// 4xx - Client error
		fmt.Printf("Client error (4xx): %d\n", resp.StatusCode())
		switch resp.StatusCode() {
		case 400:
			fmt.Println("  Bad Request")
		case 401:
			fmt.Println("  Unauthorized - check authentication")
		case 403:
			fmt.Println("  Forbidden - insufficient permissions")
		case 404:
			fmt.Println("  Not Found")
		case 429:
			fmt.Println("  Too Many Requests - rate limited")
		}
	case resp.IsServerError():
		// 5xx - Server error
		fmt.Printf("Server error (5xx): %d\n", resp.StatusCode())
		fmt.Println("  Server is experiencing issues, retry may help")
	}
	fmt.Println()
}

// demonstrateTimeoutErrors shows timeout error handling
func demonstrateTimeoutErrors() {
	fmt.Println("--- Example 3: Timeout Errors ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Very short timeout to demonstrate timeout handling
	resp, err := client.Get("https://echo.hoppscotch.io",
		httpc.WithTimeout(1*time.Nanosecond), // Intentionally too short
	)
	if err != nil {
		// Check if it's a timeout error
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Println("Request timed out")
			fmt.Println("  Consider increasing timeout or checking network")
		} else {
			fmt.Printf("Request failed: %v\n", err)
		}
		fmt.Println()
		return
	}

	fmt.Printf("Request completed: %d\n\n", resp.StatusCode())
}

// demonstrateContextCancellation shows context cancellation handling
func demonstrateContextCancellation() {
	fmt.Println("--- Example 4: Context Cancellation ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Create a context that we'll cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately to demonstrate cancellation
	cancel()

	resp, err := client.Get("https://echo.hoppscotch.io",
		httpc.WithContext(ctx),
	)
	if err != nil {
		// Check if it's a cancellation error
		if errors.Is(err, context.Canceled) {
			fmt.Println("Request was cancelled")
			fmt.Println("  This is expected when context is cancelled")
		} else {
			fmt.Printf("Request failed: %v\n", err)
		}
		fmt.Println()
		return
	}

	fmt.Printf("Request completed: %d\n\n", resp.StatusCode())
}

// demonstrateParsingErrors shows JSON/XML parsing error handling
func demonstrateParsingErrors() {
	fmt.Println("--- Example 5: Parsing Errors ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	resp, err := client.Get("https://echo.hoppscotch.io")
	if err != nil {
		log.Printf("Request failed: %v\n", err)
		return
	}

	// Try to parse as JSON
	type User struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}

	var user User
	if err := resp.Unmarshal(&user); err != nil {
		fmt.Println("Failed to parse JSON response")
		fmt.Printf("  Error: %v\n", err)
		fmt.Println("  Tip: Check if response is valid JSON")
		fmt.Println("  Tip: Verify struct tags match response fields")
		fmt.Println()
		return
	}

	fmt.Printf("Successfully parsed: %+v\n\n", user)
}

// demonstrateComprehensivePattern shows comprehensive error handling
func demonstrateComprehensivePattern() {
	fmt.Println("=== Comprehensive Error Handling Pattern ===\n ")

	result, err := fetchUserData(123)
	if err != nil {
		log.Printf("Failed to fetch user data: %v\n", err)
		return
	}

	fmt.Printf("Successfully fetched user data: %+v\n\n", result)
}

// fetchUserData demonstrates a function with comprehensive error handling
func fetchUserData(userID int) (map[string]any, error) {
	client, err := httpc.NewDefault()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	defer client.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Make request
	url := fmt.Sprintf("https://echo.hoppscotch.io/api/users/%d", userID)
	resp, err := client.Get(url,
		httpc.WithContext(ctx),
		httpc.WithBearerToken("your-token"),
		httpc.WithHeader("Accept", "application/json"),
		httpc.WithMaxRetries(2),
	)
	if err != nil {
		// Check specific error types using Code() string
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("request timed out after 10s: %w", err)
		}
		if errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("request was cancelled: %w", err)
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Check HTTP status
	if !resp.IsSuccess() {
		switch {
		case resp.StatusCode() == 404:
			return nil, fmt.Errorf("user %d not found", userID)
		case resp.StatusCode() == 401:
			return nil, fmt.Errorf("authentication failed")
		case resp.StatusCode() == 403:
			return nil, fmt.Errorf("access denied")
		case resp.StatusCode() == 429:
			return nil, fmt.Errorf("rate limit exceeded, retry after: %s",
				resp.Response.Headers.Get("Retry-After"))
		case resp.IsClientError():
			return nil, fmt.Errorf("client error: %d - %s", resp.StatusCode(), resp.Response.Status)
		case resp.IsServerError():
			return nil, fmt.Errorf("server error: %d - %s", resp.StatusCode(), resp.Response.Status)
		default:
			return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode())
		}
	}

	// Parse response
	var result map[string]any
	if err := resp.Unmarshal(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// demonstrateStructuredErrors shows ClientError type checking
func demonstrateStructuredErrors() {
	fmt.Println("--- Example 7: Structured Error Types ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Trigger a timeout to get a structured error
	resp, err := client.Get("https://echo.hoppscotch.io",
		httpc.WithTimeout(1*time.Nanosecond),
	)
	if err != nil {
		// Type-assert to ClientError for structured inspection
		var clientErr *httpc.ClientError
		if errors.As(err, &clientErr) {
			fmt.Printf("ClientError detected:\n")
			fmt.Printf("  Code:       %s\n", clientErr.Code())
			fmt.Printf("  Attempts:   %d\n", clientErr.Attempts)
			fmt.Printf("  Message:    %s\n", clientErr.Message)
			fmt.Printf("  URL:        %s\n", clientErr.URL)
			fmt.Printf("  Method:     %s\n", clientErr.Method)
			fmt.Printf("  Retryable:  %v\n", clientErr.IsRetryable())

			// Check specific error types using Code() string
			switch clientErr.Code() {
			case "TIMEOUT":
				fmt.Println("  Category:   Timeout error")
			case "NETWORK_ERROR":
				fmt.Println("  Category:   Network error")
			case "DNS_ERROR":
				fmt.Println("  Category:   DNS resolution error")
			case "TLS_ERROR":
				fmt.Println("  Category:   TLS/SSL error")
			case "HTTP_ERROR":
				fmt.Printf("  Category:   HTTP error (status %d)\n", clientErr.StatusCode)
			case "RETRY_EXHAUSTED":
				fmt.Println("  Category:   Retry limit exceeded")
			}
		} else {
			fmt.Printf("Standard error: %v\n", err)
		}
	} else {
		fmt.Printf("Request succeeded: %d\n", resp.StatusCode())
	}
	fmt.Println()
}
