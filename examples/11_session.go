//go:build examples

package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/cybergodev/httpc"
)

// This example demonstrates session management with SessionManager
// for persisting headers and cookies across multiple requests

func main() {
	fmt.Println("=== Session Management Examples ===\n ")

	// 1. Basic session usage
	demonstrateBasicSession()

	// 2. Session with client
	demonstrateSessionWithClient()

	// 3. Session state management
	demonstrateSessionState()

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateBasicSession shows creating and using a SessionManager
func demonstrateBasicSession() {
	fmt.Println("--- Basic Session Usage ---")

	// Create a session manager
	session, err := httpc.NewSessionManagerDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}

	// Set persistent headers that apply to all requests
	if err := session.SetHeader("Authorization", "Bearer my-token"); err != nil {
		log.Printf("Operation failed: %v\n", err)
		return
	}
	if err := session.SetHeader("Accept", "application/json"); err != nil {
		log.Printf("Operation failed: %v\n", err)
		return
	}

	// Set multiple headers at once
	if err := session.SetHeaders(map[string]string{
		"X-API-Version": "v2",
		"X-Client-ID":   "session-demo",
	}); err != nil {
		log.Printf("Operation failed: %v\n", err)
		return
	}

	fmt.Printf("Session headers: %d\n", len(session.GetHeaders()))

	// Set cookies
	if err := session.SetCookies([]*http.Cookie{
		{Name: "session_id", Value: "abc123"},
		{Name: "preferences", Value: "theme_dark"},
	}); err != nil {
		log.Printf("Operation failed: %v\n", err)
		return
	}

	fmt.Printf("Session cookies: %d\n", len(session.GetCookies()))

	// Get specific cookie
	if c := session.GetCookie("session_id"); c != nil {
		fmt.Printf("Found cookie: %s = %s\n", c.Name, c.Value)
	}

	// Clean up
	session.DeleteHeader("X-API-Version")
	fmt.Printf("After delete: %d headers\n\n", len(session.GetHeaders()))
}

// demonstrateSessionWithClient shows using session with DomainClient
func demonstrateSessionWithClient() {
	fmt.Println("--- Session with DomainClient ---")

	// DomainClient has a built-in session
	client, err := httpc.NewDomainDefault("https://httpbin.org")
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// Configure session headers
	if err := client.SetHeader("Accept", "application/json"); err != nil {
		log.Printf("Operation failed: %v\n", err)
		return
	}

	// Make request - session headers are sent automatically
	resp, err := client.Get("/headers")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Request sent with session headers: Status %d\n", resp.StatusCode())

	// Update session from response cookies
	session := client.Session()
	session.UpdateFromResult(resp)
	fmt.Printf("Session cookies after update: %d\n\n", len(session.GetCookies()))
}

// demonstrateSessionState shows full session state lifecycle
func demonstrateSessionState() {
	fmt.Println("--- Session State Lifecycle ---")

	session, err := httpc.NewSessionManagerDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}

	// Set initial state
	if err := session.SetHeaders(map[string]string{
		"Authorization": "Bearer token-123",
		"Accept":        "application/json",
	}); err != nil {
		log.Printf("Operation failed: %v\n", err)
		return
	}

	cookies := []*http.Cookie{
		{Name: "session", Value: "active"},
		{Name: "tracking", Value: "enabled"},
	}
	if err := session.SetCookies(cookies); err != nil {
		log.Printf("Operation failed: %v\n", err)
		return
	}

	fmt.Printf("Initial state: %d headers, %d cookies\n",
		len(session.GetHeaders()), len(session.GetCookies()))

	// Remove specific items
	session.DeleteCookie("tracking")
	session.DeleteHeader("Accept")
	fmt.Printf("After selective removal: %d headers, %d cookies\n",
		len(session.GetHeaders()), len(session.GetCookies()))

	// Clear all state
	session.ClearHeaders()
	session.ClearCookies()
	fmt.Printf("After clearing: %d headers, %d cookies\n",
		len(session.GetHeaders()), len(session.GetCookies()))
}
