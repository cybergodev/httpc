//go:build examples

package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/httpc"
)

// This example demonstrates all request options: body formats, headers, authentication, and query parameters

func main() {
	fmt.Println("=== Request Options Examples ===\n ")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// 1. Body Formats
	demonstrateBodyFormats(client)

	// 2. Headers and Authentication
	demonstrateHeadersAuth(client)

	// 3. Query Parameters
	demonstrateQueryParams(client)

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateBodyFormats shows different request body formats
func demonstrateBodyFormats(client httpc.Client) {
	fmt.Println("--- Body Formats ---")

	// JSON (most common)
	user := map[string]any{
		"name":  "John Doe",
		"email": "john@example.com",
		"age":   30,
	}
	resp, err := client.Post("https://echo.hoppscotch.io",
		httpc.WithJSON(user),
	)
	if err != nil {
		log.Printf("JSON error: %v\n", err)
	} else {
		fmt.Printf("✓ JSON: Status %d\n", resp.StatusCode())
	}

	// Form data (application/x-www-form-urlencoded)
	formData := map[string]string{
		"username": "johndoe",
		"password": "secret123",
	}
	resp, err = client.Post("https://echo.hoppscotch.io",
		httpc.WithForm(formData),
	)
	if err != nil {
		log.Printf("Form error: %v\n", err)
	} else {
		fmt.Printf("✓ Form: Status %d\n", resp.StatusCode())
	}

	// Plain text (Content-Type auto-detected as text/plain for string input)
	resp, err = client.Post("https://echo.hoppscotch.io",
		httpc.WithBody("Hello, this is plain text!"),
	)
	if err != nil {
		log.Printf("Text error: %v\n", err)
	} else {
		fmt.Printf("✓ Text: Status %d\n", resp.StatusCode())
	}

	// XML
	type Person struct {
		XMLName xml.Name `xml:"person"`
		Name    string   `xml:"name"`
		Age     int      `xml:"age"`
	}
	person := Person{Name: "Jane", Age: 28}
	resp, err = client.Post("https://echo.hoppscotch.io",
		httpc.WithXML(person),
	)
	if err != nil {
		log.Printf("XML error: %v\n", err)
	} else {
		fmt.Printf("✓ XML: Status %d\n", resp.StatusCode())
	}

	// Binary data
	binaryData := []byte{0x89, 0x50, 0x4E, 0x47} // PNG header
	resp, err = client.Post("https://echo.hoppscotch.io",
		httpc.WithBinary(binaryData, "image/png"),
	)
	if err != nil {
		log.Printf("Binary error: %v\n", err)
	} else {
		fmt.Printf("✓ Binary: Status %d (%d bytes)\n", resp.StatusCode(), len(binaryData))
	}

	// WithBody with explicit BodyKind (forces encoding regardless of input type)
	bodyData := map[string]string{"key": "value"}
	resp, err = client.Post("https://echo.hoppscotch.io",
		httpc.WithBody(bodyData, httpc.BodyJSON),
	)
	if err != nil {
		log.Printf("WithBody error: %v\n", err)
	} else {
		fmt.Printf("✓ WithBody(BodyJSON): Status %d\n", resp.StatusCode())
	}

	// File upload
	fileContent := []byte("Document content here")
	resp, err = client.Post("https://echo.hoppscotch.io",
		httpc.WithFile("document", "report.pdf", fileContent),
	)
	if err != nil {
		log.Printf("File error: %v\n", err)
	} else {
		fmt.Printf("✓ File upload: Status %d\n\n", resp.StatusCode())
	}
}

// demonstrateHeadersAuth shows headers and authentication methods
func demonstrateHeadersAuth(client httpc.Client) {
	fmt.Println("--- Headers & Authentication ---")

	// Single header
	resp, err := client.Get("https://echo.hoppscotch.io",
		httpc.WithHeader("X-Custom-Header", "CustomValue"),
	)
	if err != nil {
		log.Printf("Header error: %v\n", err)
	} else {
		fmt.Printf("✓ Custom header: Status %d\n", resp.StatusCode())
	}

	// Multiple headers
	headers := map[string]string{
		"X-API-Version": "v1",
		"X-Client-ID":   "client-123",
	}
	resp, err = client.Get("https://echo.hoppscotch.io",
		httpc.WithHeaderMap(headers),
	)
	if err != nil {
		log.Printf("Headers error: %v\n", err)
	} else {
		fmt.Printf("✓ Multiple headers: Status %d\n", resp.StatusCode())
	}

	// Bearer token (JWT)
	resp, err = client.Get("https://echo.hoppscotch.io",
		httpc.WithBearerToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example"),
	)
	if err != nil {
		log.Printf("Bearer error: %v\n", err)
	} else {
		fmt.Printf("✓ Bearer token: Status %d\n", resp.StatusCode())
	}

	// Basic authentication
	resp, err = client.Get("https://echo.hoppscotch.io",
		httpc.WithBasicAuth("username", "password"),
	)
	if err != nil {
		log.Printf("Basic auth error: %v\n", err)
	} else {
		fmt.Printf("✓ Basic auth: Status %d\n", resp.StatusCode())
	}

	// API key
	resp, err = client.Get("https://echo.hoppscotch.io",
		httpc.WithHeader("X-API-Key", "your-api-key-here"),
	)
	if err != nil {
		log.Printf("API key error: %v\n", err)
	} else {
		fmt.Printf("✓ API key: Status %d\n", resp.StatusCode())
	}

	// User agent
	resp, err = client.Get("https://echo.hoppscotch.io",
		httpc.WithUserAgent("MyApp/1.0"),
	)
	if err != nil {
		log.Printf("User agent error: %v\n", err)
	} else {
		fmt.Printf("✓ User agent: Status %d\n\n", resp.StatusCode())
	}
}

// demonstrateQueryParams shows query parameter handling
func demonstrateQueryParams(client httpc.Client) {
	fmt.Println("--- Query Parameters ---")

	// Single parameters
	resp, err := client.Get("https://echo.hoppscotch.io",
		httpc.WithQuery("name", "John"),
		httpc.WithQuery("age", 30),
	)
	if err != nil {
		log.Printf("Query error: %v\n", err)
	} else {
		fmt.Printf("✓ Single params: Status %d\n", resp.StatusCode())
	}

	// Multiple parameters (recommended)
	params := map[string]any{
		"page":     1,
		"per_page": 20,
		"sort":     "date",
		"order":    "desc",
	}
	resp, err = client.Get("https://echo.hoppscotch.io",
		httpc.WithQueryMap(params),
	)
	if err != nil {
		log.Printf("Query map error: %v\n", err)
	} else {
		fmt.Printf("✓ Query map: Status %d\n", resp.StatusCode())
	}

	// Real-world pattern: Pagination + Filtering + Sorting
	searchParams := map[string]any{
		"q":        "golang http",
		"category": "technology",
		"page":     1,
		"limit":    10,
		"sort_by":  "relevance",
	}
	resp, err = client.Get("https://echo.hoppscotch.io/search",
		httpc.WithQueryMap(searchParams),
		httpc.WithTimeout(10*time.Second),
	)
	if err != nil {
		log.Printf("Search error: %v\n", err)
	} else {
		fmt.Printf("✓ Search with filters: Status %d\n", resp.StatusCode())
	}

	// Special characters (automatically URL-encoded)
	specialParams := map[string]any{
		"query": "hello world & goodbye",
		"email": "user@example.com",
	}
	resp, err = client.Get("https://echo.hoppscotch.io",
		httpc.WithQueryMap(specialParams),
	)
	if err != nil {
		log.Printf("Special chars error: %v\n", err)
	} else {
		fmt.Printf("✓ Special characters (auto-encoded): Status %d\n", resp.StatusCode())
	}
}
