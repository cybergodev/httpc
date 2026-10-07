package httpc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// INTEGRATION TESTS - Real-world Scenarios
// ============================================================================

func TestIntegration_RESTfulAPI(t *testing.T) {
	// Simulate a RESTful API server
	users := make(map[string]map[string]interface{})
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		switch r.Method {
		case "GET":
			if strings.HasPrefix(r.URL.Path, "/users/") {
				id := strings.TrimPrefix(r.URL.Path, "/users/")
				if user, ok := users[id]; ok {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(user)
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			} else if r.URL.Path == "/users" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(users)
			}

		case "POST":
			if r.URL.Path == "/users" {
				var user map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				id := fmt.Sprintf("%d", len(users)+1)
				user["id"] = id
				users[id] = user
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(user)
			}

		case "PUT":
			if strings.HasPrefix(r.URL.Path, "/users/") {
				id := strings.TrimPrefix(r.URL.Path, "/users/")
				var user map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				user["id"] = id
				users[id] = user
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(user)
			}

		case "DELETE":
			if strings.HasPrefix(r.URL.Path, "/users/") {
				id := strings.TrimPrefix(r.URL.Path, "/users/")
				delete(users, id)
				w.WriteHeader(http.StatusNoContent)
			}
		}
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	// Test CREATE
	t.Run("Create User", func(t *testing.T) {
		user := map[string]interface{}{
			"name":  "John Doe",
			"email": "john@example.com",
		}

		resp, err := client.Post(server.URL+"/users", WithJSON(user))
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		if resp.StatusCode() != http.StatusCreated {
			t.Errorf("Expected status 201, got %d", resp.StatusCode())
		}

		var created map[string]interface{}
		if err := resp.Unmarshal(&created); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if created["name"] != "John Doe" {
			t.Errorf("Expected name 'John Doe', got %v", created["name"])
		}
	})

	// Test READ
	t.Run("Get User", func(t *testing.T) {
		resp, err := client.Get(server.URL + "/users/1")
		if err != nil {
			t.Fatalf("Failed to get user: %v", err)
		}

		if resp.StatusCode() != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode())
		}
	})

	// Test UPDATE
	t.Run("Update User", func(t *testing.T) {
		user := map[string]interface{}{
			"name":  "Jane Doe",
			"email": "jane@example.com",
		}

		resp, err := client.Put(server.URL+"/users/1", WithJSON(user))
		if err != nil {
			t.Fatalf("Failed to update user: %v", err)
		}

		if resp.StatusCode() != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode())
		}
	})

	// Test DELETE
	t.Run("Delete User", func(t *testing.T) {
		resp, err := client.Delete(server.URL + "/users/1")
		if err != nil {
			t.Fatalf("Failed to delete user: %v", err)
		}

		if resp.StatusCode() != http.StatusNoContent {
			t.Errorf("Expected status 204, got %d", resp.StatusCode())
		}
	})
}

func TestIntegration_UnauthorizedAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode() != http.StatusUnauthorized {
		t.Errorf("Expected status 401 without auth, got %d", resp.StatusCode())
	}
}

func TestIntegration_QueryParameterVariations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"page": page}) // best-effort test response
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	tests := []struct {
		page string
	}{
		{"1"}, {"2"}, {"99"}, {""},
	}

	for _, tt := range tests {
		t.Run("page_"+tt.page, func(t *testing.T) {
			opts := []RequestOption{}
			if tt.page != "" {
				opts = append(opts, WithQuery("page", tt.page))
			}
			resp, err := client.Get(server.URL, opts...)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			var result map[string]string
			if err := resp.Unmarshal(&result); err != nil {
				t.Fatalf("Failed to parse response: %v", err)
			}
			if result["page"] != tt.page {
				t.Errorf("Expected page %q, got %q", tt.page, result["page"])
			}
		})
	}
}

// ============================================================================
// STRESS TESTS
// ============================================================================

func TestStress_HighConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	// Detect environment and adjust parameters
	numGoroutines := 50       // Reduce concurrency
	requestsPerGoroutine := 5 // Reduce requests per goroutine

	// Further reduce in CI environment
	if os.Getenv("CI") == "true" || os.Getenv("GITHUB_ACTIONS") == "true" {
		numGoroutines = 20
		requestsPerGoroutine = 2
	}

	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		time.Sleep(2 * time.Millisecond) // Reduce server delay
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Use more lenient configuration
	config := DefaultConfig()
	config.Timeouts.Request = 30 * time.Second // Increase timeout
	config.Security.AllowPrivateIPs = true     // Allow access to test server
	client, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*requestsPerGoroutine)

	start := time.Now()

	// Use semaphore to control concurrent startup
	sem := make(chan struct{}, 10) // Limit concurrent goroutines

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			for j := 0; j < requestsPerGoroutine; j++ {
				// Add small delay to avoid burst requests
				if j > 0 {
					time.Sleep(time.Millisecond)
				}

				_, err := client.Get(server.URL)
				if err != nil {
					select {
					case errors <- err:
					default:
						// Error channel is full, ignore
						//
					}
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	duration := time.Since(start)

	errorCount := 0
	for err := range errors {
		t.Logf("Error: %v", err)
		errorCount++
	}

	totalRequests := numGoroutines * requestsPerGoroutine
	successRate := float64(totalRequests-errorCount) / float64(totalRequests) * 100

	t.Logf("Stress Test Results:")
	t.Logf("  Total Requests: %d", totalRequests)
	t.Logf("  Successful: %d", totalRequests-errorCount)
	t.Logf("  Failed: %d", errorCount)
	t.Logf("  Success Rate: %.2f%%", successRate)
	t.Logf("  Duration: %v", duration)
	t.Logf("  Throughput: %.2f req/s", float64(totalRequests)/duration.Seconds())

	// Adjust expected success rate based on environment
	expectedSuccessRate := 95.0
	if os.Getenv("CI") == "true" || os.Getenv("GITHUB_ACTIONS") == "true" {
		expectedSuccessRate = 85.0 // Lower expectations in CI environment
	}

	if successRate < expectedSuccessRate {
		t.Errorf("Success rate too low: %.2f%% (expected: %.1f%%)", successRate, expectedSuccessRate)
	}
}

func TestStress_MemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send 1KB response
		data := make([]byte, 1024)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)

	// Make many requests to test memory management
	for i := 0; i < 10000; i++ {
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		_ = resp.RawBody() // Use the response

		if i%1000 == 0 {
			t.Logf("Completed %d requests", i)
		}
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	heapGrowth := int64(after.HeapAlloc) - int64(baseline.HeapAlloc)
	// Allow up to 10MB growth — pools should keep allocations bounded
	maxGrowth := int64(10 * 1024 * 1024)
	if heapGrowth > maxGrowth {
		t.Errorf("Heap grew by %d bytes (baseline=%d, after=%d), expected < %d",
			heapGrowth, baseline.HeapAlloc, after.HeapAlloc, maxGrowth)
	}
}
