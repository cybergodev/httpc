package httpc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
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
	defer func() { _ = client.Close() }()

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
	defer func() { _ = client.Close() }()

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode() != http.StatusUnauthorized {
		t.Errorf("Expected status 401 without auth, got %d", resp.StatusCode())
	}
}

// TestIntegration_QueryParameterVariations was removed: its four subtests
// differed only in the literal page value already round-tripped by the
// WithQuery coverage in request_test.go.
//
// TestStress_HighConcurrency and TestStress_MemoryUsage were removed: the
// former duplicated TestClient_Concurrency's contract with env-dependent
// success-rate thresholds (flaky on slow CI), the latter asserted GC-timing
// heap growth via runtime.MemStats — not library behavior. Concurrent client
// safety is asserted (with error checks) by TestClient_Concurrency
// (client_test.go) and internal/concurrency.
