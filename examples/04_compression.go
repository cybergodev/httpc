//go:build examples

package main

import (
	"fmt"
	"log"

	"github.com/cybergodev/httpc"
)

func main() {
	fmt.Println("=== HTTP Response Decompression Example ===\n ")

	// Example 1: Automatic gzip decompression
	demonstrateGzipDecompression()

	// Example 2: Gzip from another server
	demonstrateGzipFromServer()

	// Example 3: Without compression
	demonstrateNoCompression()

	fmt.Println("\n[OK] All compression examples completed successfully!")
	fmt.Println("\nNote:")
	fmt.Println("  - The library automatically detects and decompresses gzip and deflate responses")
	fmt.Println("  - Decompression is based on the Content-Encoding header")
	fmt.Println("  - Legacy compress formats (LZW) are not supported")
	fmt.Println("  - To request compressed responses, set Accept-Encoding header")
}

// demonstrateGzipDecompression shows automatic gzip decompression
func demonstrateGzipDecompression() {
	fmt.Println("1. Automatic gzip decompression:")
	headers := map[string]string{
		"Accept-Encoding": "gzip, deflate",
		"User-Agent":      "httpc-example/1.0",
	}

	resp, err := httpc.Get("https://httpbin.org/gzip", httpc.WithHeaderMap(headers))
	if err != nil {
		log.Printf("Request failed: %v\n", err)
		return
	}

	fmt.Printf("   Status: %d\n", resp.StatusCode())
	fmt.Printf("   Content-Encoding: %s\n", resp.Response.Headers.Get("Content-Encoding"))
	body := resp.Body()
	fmt.Printf("   Decompressed body length: %d bytes\n", len(body))
	fmt.Printf("   Body preview: %.200s...\n\n", body)
}

// demonstrateGzipFromServer shows gzip decompression from another server
func demonstrateGzipFromServer() {
	fmt.Println("2. Testing with another gzip endpoint:")
	headers := map[string]string{
		"Accept-Encoding": "gzip, deflate",
		"User-Agent":      "httpc-example/1.0",
	}

	resp, err := httpc.Get("https://www.github.com", httpc.WithHeaderMap(headers))
	if err != nil {
		log.Printf("Request failed: %v\n", err)
		return
	}

	fmt.Printf("   Status: %d\n", resp.StatusCode())
	fmt.Printf("   Content-Encoding: %s\n", resp.Response.Headers.Get("Content-Encoding"))
	body := resp.Body()
	fmt.Printf("   Decompressed body length: %d bytes\n", len(body))
	fmt.Printf("   Body preview: \n%.200s...\n\n", body)
}

// demonstrateNoCompression shows response without compression
func demonstrateNoCompression() {
	fmt.Println("3. Without compression (no Accept-Encoding header):")

	resp, err := httpc.Get("https://httpbin.org/get")
	if err != nil {
		log.Printf("Request failed: %v\n", err)
		return
	}

	fmt.Printf("   Status: %d\n", resp.StatusCode())
	fmt.Printf("   Content-Encoding: %s\n", resp.Response.Headers.Get("Content-Encoding"))
	body := resp.Body()
	fmt.Printf("   Body length: %d bytes\n", len(body))
	fmt.Printf("   Body preview: %.200s...\n\n", body)
}
