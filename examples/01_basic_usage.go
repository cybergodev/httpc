//go:build examples

package main

import (
	"fmt"
	"time"

	"github.com/cybergodev/httpc"
)

// This example demonstrates the quickest way to get started with httpc
// Perfect for: Quick testing, simple scripts, learning the basics

// UserList represents a user data structure
type UserList struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// APIResponse represents a typical API response
type APIResponse struct {
	Method  string            `json:"method"`
	Args    map[string]string `json:"args"`
	Data    string            `json:"data"`
	Headers map[string]string `json:"headers"`
}

func main() {
	fmt.Println("=== HTTPC Quick Start Examples ===")
	fmt.Println("Learn the basics in 5 minutes!\n ")

	// Example 1: Simplest GET request (package-level function)
	simpleGET()

	// Example 2: POST with JSON data
	postJSON()

	// Example 3: Using a client instance
	useClientInstance()

	// Example 4: PUT request
	putRequest()

	// Example 5: DELETE request
	deleteRequest()

	fmt.Println("\n=== All Quick Start Examples Completed ===")
}

// Example 1: Simplest GET request using package-level function
func simpleGET() {
	fmt.Println("--- Example 1: Simple GET Request ---")

	// No need to create a client - just call httpc.Get()
	resp, err := httpc.Get("https://echo.hoppscotch.io")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	fmt.Printf("Success: %v\n", resp.IsSuccess())
	fmt.Printf("Duration: %v\n\n", resp.Meta.Duration)
}

// Example 2: POST with JSON data
func postJSON() {
	fmt.Println("--- Example 2: POST with JSON Data ---")

	user := UserList{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	// Package-level POST with JSON
	resp, err := httpc.Post("https://echo.hoppscotch.io",
		httpc.WithJSON(user),
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Parse JSON response
	var result APIResponse
	if err := resp.Unmarshal(&result); err != nil {
		fmt.Printf("Failed to parse JSON: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	fmt.Printf("Method: %s\n", result.Method)
	fmt.Printf("Content-Type: %s\n\n", result.Headers["content-type"])
}

// Example 3: Using a client instance (recommended for reusable clients)
func useClientInstance() {
	fmt.Println("--- Example 3: Using Client Instance ---")

	// Create a client with default configuration
	client, err := httpc.NewDefault()
	if err != nil {
		fmt.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close() // Always close the client

	// GET with query parameters
	resp, err := client.Get("https://echo.hoppscotch.io",
		httpc.WithQuery("name", "Alice"),
		httpc.WithQuery("age", 25),
		httpc.WithTimeout(10*time.Second),
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	var result APIResponse
	if err := resp.Unmarshal(&result); err != nil {
		fmt.Printf("Failed to parse JSON: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	fmt.Printf("Query Parameters: %+v\n\n", result.Args)
}

// Example 4: PUT request to update data
func putRequest() {
	fmt.Println("--- Example 4: PUT Request ---")

	updateData := map[string]any{
		"name":   "Jane Smith",
		"email":  "jane@example.com",
		"status": "active",
	}

	resp, err := httpc.Put("https://echo.hoppscotch.io/users/123",
		httpc.WithJSON(updateData),
		httpc.WithBearerToken("your-token-here"),
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode())
	fmt.Printf("Success: %v\n\n", resp.IsSuccess())
}

// Example 5: DELETE request
func deleteRequest() {
	fmt.Println("--- Example 5: DELETE Request ---")

	resp, err := httpc.Delete("https://echo.hoppscotch.io/users/123",
		httpc.WithBearerToken("your-token-here"),
		httpc.WithHeader("X-Request-ID", "delete-123"),
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Check response status
	if resp.IsSuccess() {
		fmt.Println("[OK] Resource deleted successfully")
	} else {
		fmt.Printf("[X] Delete failed with status: %d\n", resp.StatusCode())
	}

	fmt.Printf("Duration: %v\n\n", resp.Meta.Duration)
}
