//go:build examples

package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cybergodev/httpc"
)

// This example demonstrates comprehensive cookie handling

func main() {
	fmt.Println("=== Advanced Cookie Handling ===\n ")

	// 1. Request Cookies
	demonstrateRequestCookies()

	// 2. Response Cookies
	demonstrateResponseCookies()

	// 3. Cookie Jar (Automatic Management)
	demonstrateCookieJar()

	// 4. Cookie String Parsing
	demonstrateCookieString()

	// 5. Advanced Cookie Scenarios
	demonstrateAdvancedScenarios()

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateRequestCookies shows how to send cookies with requests
func demonstrateRequestCookies() {
	fmt.Println("--- Request Cookies ---")

	client, err := httpc.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Method 1: Single cookie using WithCookie
	resp, err := client.Get("https://httpbin.org/cookies",
		httpc.WithCookie(http.Cookie{Name: "session_id", Value: "abc123"}),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Single cookie: Status %d\n", resp.StatusCode())

	// Method 2: Batch multiple cookies using WithCookies (efficient)
	resp, err = client.Get("https://httpbin.org/cookies",
		httpc.WithCookies([]http.Cookie{
			{Name: "session_id", Value: "abc123"},
			{Name: "user_pref", Value: "dark_mode"},
			{Name: "lang", Value: "en"},
		}),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Batch cookies (WithCookies): Status %d\n", resp.StatusCode())

	// Method 3: Cookie with attributes (full http.Cookie struct)
	cookie := http.Cookie{
		Name:     "auth_token",
		Value:    "xyz789",
		Path:     "/api",
		Expires:  time.Now().Add(24 * time.Hour),
		Secure:   true,
		HttpOnly: true,
	}
	resp, err = client.Get("https://httpbin.org/cookies",
		httpc.WithCookie(cookie),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Cookie with attributes: Status %d\n", resp.StatusCode())

	// Method 4: Multiple cookies using cookie string
	cookieString := "cookie1=value1; cookie2=value2; cookie3=value3"
	resp, err = client.Get("https://httpbin.org/cookies",
		httpc.WithCookieString(cookieString),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Multiple cookies (string): Status %d\n", resp.StatusCode())

	// Method 5: Multiple cookies using map
	cookieMap := map[string]string{
		"theme":    "dark",
		"language": "en",
		"region":   "us",
	}
	resp, err = client.Get("https://httpbin.org/cookies",
		httpc.WithCookieMap(cookieMap),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Cookie map: Status %d\n\n", resp.StatusCode())
}

// demonstrateResponseCookies shows how to read cookies from responses
func demonstrateResponseCookies() {
	fmt.Println("--- Response Cookies ---")

	client, err := httpc.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Server sets cookies
	resp, err := client.Get("https://httpbin.org/response-headers?Set-Cookie=session=abc123&Set-Cookie=user=john")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Cookies received: %d\n", len(resp.Response.Cookies))

	// Method 1: Iterate through all cookies
	for _, cookie := range resp.Response.Cookies {
		fmt.Printf("  %s = %s\n", cookie.Name, cookie.Value)
	}

	// Method 2: Get specific cookie by name
	if sessionCookie := resp.GetCookie("session"); sessionCookie != nil {
		fmt.Printf("✓ Session cookie: %s\n", sessionCookie.Value)
	}

	// Method 3: Check if cookie exists
	if resp.HasCookie("user") {
		fmt.Println("✓ User cookie present")
	}
	if !resp.HasCookie("nonexistent") {
		fmt.Println("✓ Nonexistent cookie not present\n ")
	}
}

// demonstrateCookieJar shows automatic cookie management
func demonstrateCookieJar() {
	fmt.Println("--- Cookie Jar (Automatic Management) ---")

	// Create client with cookie jar enabled
	config := httpc.DefaultConfig()
	config.Connection.EnableCookies = true
	client, err := httpc.New(config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Step 1: Server sets cookies via redirect
	fmt.Println("Step 1: Server sets cookies")
	resp1, err := client.Get("https://httpbin.org/cookies/set?session=xyz789&user=alice")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Status: %d (cookies stored in jar)\n", resp1.StatusCode())

	// Step 2: Cookies automatically sent in subsequent requests
	fmt.Println("\nStep 2: Cookies automatically sent")
	resp2, err := client.Get("https://httpbin.org/cookies")
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Status: %d\n", resp2.StatusCode())
	fmt.Printf("✓ Cookies persisted across requests\n\n")
}

// demonstrateCookieString shows cookie string parsing
func demonstrateCookieString() {
	fmt.Println("--- Cookie String Parsing ---")

	client, err := httpc.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Parse cookie string (like from browser DevTools)
	cookieString := "BSID=4418ECBB1281B550; PSTM=1733760779; UPN=12314753"
	resp, err := client.Get("https://httpbin.org/cookies",
		httpc.WithCookieString(cookieString),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Parsed cookie string: Status %d\n", resp.StatusCode())

	// Combine with other cookie methods
	resp, err = client.Get("https://httpbin.org/cookies",
		httpc.WithCookieString("session=abc123; token=xyz789"),
		httpc.WithCookie(http.Cookie{Name: "manual", Value: "cookie"}),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Combined cookies: Status %d\n\n", resp.StatusCode())
}

// demonstrateAdvancedScenarios shows real-world cookie patterns
func demonstrateAdvancedScenarios() {
	fmt.Println("--- Advanced Cookie Scenarios ---")

	client, err := httpc.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Scenario 1: Session management
	sessionCookie := http.Cookie{
		Name:     "session_token",
		Value:    "secure_token_12345",
		Path:     "/",
		MaxAge:   3600, // 1 hour
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	resp, err := client.Post("https://httpbin.org/post",
		httpc.WithCookie(sessionCookie),
		httpc.WithJSON(map[string]string{"action": "login"}),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Session management: Status %d\n", resp.StatusCode())

	// Scenario 2: Multiple purpose cookies (using WithCookies batch)
	resp, err = client.Get("https://httpbin.org/cookies",
		httpc.WithCookies([]http.Cookie{
			{Name: "auth", Value: "bearer_token"},
			{Name: "preferences", Value: "theme_dark_lang_en"},
			{Name: "analytics", Value: "tracking_id_123"},
		}),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Multiple purpose cookies (WithCookies): Status %d\n", resp.StatusCode())

	// Scenario 3: Cookies with authentication
	resp, err = client.Get("https://httpbin.org/cookies",
		httpc.WithCookie(http.Cookie{Name: "session", Value: "active"}),
		httpc.WithBearerToken("jwt_token_here"),
		httpc.WithHeader("X-Request-ID", "12345"),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Cookies with auth: Status %d\n", resp.StatusCode())

	// Scenario 4: Secure cookie with validation
	// Note: WithSecureCookie validates cookies already on the request,
	// so add cookies first, then validate.
	resp, err = client.Get("https://httpbin.org/cookies",
		httpc.WithCookie(http.Cookie{
			Name:     "secure_session",
			Value:    "encrypted_value",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		}),
		httpc.WithSecureCookie(httpc.StrictCookieSecurityConfig()),
	)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✓ Secure cookie: Status %d\n", resp.StatusCode())
}
