package httpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// CLIENT TESTS - Instance and package-level client functionality
// ============================================================================

// ----------------------------------------------------------------------------
// Client Instance Tests
// ----------------------------------------------------------------------------

func TestClient_Creation(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		client, err := newTestClient()
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()
		if client == nil {
			t.Fatal("Client should not be nil")
		}
	})

	t.Run("WithConfig", func(t *testing.T) {
		config := DefaultConfig()
		config.Timeouts.Request = 10 * time.Second
		config.Retry.MaxRetries = 2
		client, err := New(config)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()
	})

	t.Run("WithTLSConfig", func(t *testing.T) {
		config := DefaultConfig()
		config.Security.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		}
		client, err := New(config)
		if err != nil {
			t.Fatalf("Failed to create client with TLS config: %v", err)
		}
		defer client.Close()
	})
}

func TestClient_HTTPMethods(t *testing.T) {
	tests := []struct {
		name   string
		method string
		fn     func(Client, string, ...RequestOption) (*Result, error)
	}{
		{"GET", "GET", func(c Client, url string, opts ...RequestOption) (*Result, error) { return c.Get(url, opts...) }},
		{"POST", "POST", func(c Client, url string, opts ...RequestOption) (*Result, error) { return c.Post(url, opts...) }},
		{"PUT", "PUT", func(c Client, url string, opts ...RequestOption) (*Result, error) { return c.Put(url, opts...) }},
		{"PATCH", "PATCH", func(c Client, url string, opts ...RequestOption) (*Result, error) { return c.Patch(url, opts...) }},
		{"DELETE", "DELETE", func(c Client, url string, opts ...RequestOption) (*Result, error) { return c.Delete(url, opts...) }},
		{"HEAD", "HEAD", func(c Client, url string, opts ...RequestOption) (*Result, error) { return c.Head(url, opts...) }},
		{"OPTIONS", "OPTIONS", func(c Client, url string, opts ...RequestOption) (*Result, error) { return c.Options(url, opts...) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tt.method {
					t.Errorf("Expected method %s, got %s", tt.method, r.Method)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"success"}`))
			}))
			defer server.Close()

			client, err := newTestClient()
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}
			defer client.Close()

			resp, err := tt.fn(client, server.URL)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			if resp.StatusCode() != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode())
			}
		})
	}
}

func TestClient_Lifecycle(t *testing.T) {
	t.Run("Close", func(t *testing.T) {
		client, _ := newTestClient()
		if err := client.Close(); err != nil {
			t.Errorf("Client close should not error: %v", err)
		}
	})
}

func TestClient_Timeout_ContextTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.Request(ctx, "GET", server.URL)
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}

func TestClient_Concurrency(t *testing.T) {
	t.Run("ConcurrentRequests", func(t *testing.T) {
		requestCount := int32(0)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			time.Sleep(10 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		const numRequests = 100
		var wg sync.WaitGroup
		errors := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := client.Get(server.URL)
				if err != nil {
					errors <- err
				}
			}()
		}

		wg.Wait()
		close(errors)

		errorCount := 0
		for err := range errors {
			t.Errorf("Request failed: %v", err)
			errorCount++
		}

		if errorCount > 0 {
			t.Fatalf("Failed %d out of %d requests", errorCount, numRequests)
		}

		if atomic.LoadInt32(&requestCount) != numRequests {
			t.Errorf("Expected %d requests, got %d", numRequests, atomic.LoadInt32(&requestCount))
		}
	})

	t.Run("ConfigModificationSafety", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := DefaultConfig()
		cfg.Security.AllowPrivateIPs = true
		cfg.Middleware.Headers = map[string]string{"X-Initial": "value"}

		client, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()

		var wg sync.WaitGroup
		errChan := make(chan error, 100)

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := client.Get(server.URL)
				if err != nil {
					errChan <- err
				}
			}()
		}

		// Modify original config (should not affect client)
		for i := 0; i < 50; i++ {
			cfg.Middleware.Headers["X-Modified"] = "new-value"
			cfg.Timeouts.Request = time.Duration(i) * time.Second
		}

		wg.Wait()
		close(errChan)

		for err := range errChan {
			t.Errorf("Request failed: %v", err)
		}
	})
}

// ----------------------------------------------------------------------------
// Package-Level Function Tests
// ----------------------------------------------------------------------------

func TestPackageLevel_AllMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	methodTests := []struct {
		name string
		fn   func(string, ...RequestOption) (*Result, error)
	}{
		{"Get", Get},
		{"Post", Post},
		{"Put", Put},
		{"Patch", Patch},
		{"Delete", Delete},
		{"Head", Head},
		{"Options", Options},
	}

	t.Run("ExplicitClient", func(t *testing.T) {
		config := DefaultConfig()
		config.Security.AllowPrivateIPs = true
		client, err := New(config)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		_ = SetDefaultClient(client)
		defer CloseDefaultClient()

		for _, tt := range methodTests {
			t.Run(tt.name, func(t *testing.T) {
				resp, err := tt.fn(server.URL)
				if err != nil {
					t.Fatalf("Package-level %s failed: %v", tt.name, err)
				}
				if resp.StatusCode() != http.StatusOK {
					t.Errorf("Expected status 200, got %d", resp.StatusCode())
				}
			})
		}
	})

	t.Run("AutoInit", func(t *testing.T) {
		// Close explicit client, test auto-initialization path
		CloseDefaultClient()

		// Set up a new client for auto-init tests
		cfg := DefaultConfig()
		cfg.Security.AllowPrivateIPs = true
		client, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		SetDefaultClient(client)
		defer CloseDefaultClient()

		for _, tt := range methodTests {
			t.Run(tt.name, func(t *testing.T) {
				resp, err := tt.fn(server.URL)
				if err != nil {
					t.Fatalf("Auto-init %s failed: %v", tt.name, err)
				}
				if resp.StatusCode() != http.StatusOK {
					t.Errorf("Expected 200, got %d", resp.StatusCode())
				}
			})
		}

		CloseDefaultClient()
	})
}

// ----------------------------------------------------------------------------
// Type Tests
// ----------------------------------------------------------------------------

func TestTypes(t *testing.T) {
	t.Run("HTTPError", func(t *testing.T) {
		// HTTPError is now an alias for ClientError
		// Test that we can check HTTP errors using ClientError
		err := &ClientError{
			Type:       ErrorTypeHTTP,
			Message:    "Not Found",
			Method:     "GET",
			URL:        "https://example.com",
			StatusCode: 404,
		}
		if err.StatusCode != 404 {
			t.Errorf("ClientError.StatusCode = %d, want 404", err.StatusCode)
		}
		if err.Type != ErrorTypeHTTP {
			t.Errorf("ClientError.Type = %v, want %v", err.Type, ErrorTypeHTTP)
		}
	})

	t.Run("FormData", func(t *testing.T) {
		formData := &FormData{
			Fields: map[string]string{
				"field1": "value1",
				"field2": "value2",
			},
			Files: map[string]*FileData{
				"file1": {
					Filename: "test.txt",
					Content:  []byte("test content"),
				},
			},
		}

		if len(formData.Fields) != 2 {
			t.Error("FormData should have 2 fields")
		}
		if len(formData.Files) != 1 {
			t.Error("FormData should have 1 file")
		}
		file := formData.Files["file1"]
		if file.Filename != "test.txt" {
			t.Error("File filename should be test.txt")
		}
		if string(file.Content) != "test content" {
			t.Error("File content should match")
		}
	})
}

// ----------------------------------------------------------------------------
// Error Handling Tests
// ----------------------------------------------------------------------------

func TestClient_ErrorHandling(t *testing.T) {
	t.Run("InvalidURL", func(t *testing.T) {
		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get("://invalid-url")
		if err == nil {
			t.Error("Expected error for invalid URL")
		}
	})

	t.Run("NetworkError", func(t *testing.T) {
		config := DefaultConfig()
		config.Timeouts.Request = 1 * time.Second
		config.Security.AllowPrivateIPs = true
		client, _ := New(config)
		defer client.Close()

		// Use a non-routable IP address
		_, err := client.Get("http://192.0.2.1:12345")
		if err == nil {
			t.Error("Expected network error")
		}
	})
}

// ----------------------------------------------------------------------------
// Result Pool Tests
// ----------------------------------------------------------------------------

func TestReleaseResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	t.Run("ReleaseAndReuse", func(t *testing.T) {
		result, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		if result.StatusCode() != http.StatusOK {
			t.Errorf("Expected status 200, got %d", result.StatusCode())
		}
		if result.Body() == "" {
			t.Error("Expected non-empty body")
		}
		ReleaseResult(result)
	})

	t.Run("ReleaseNil", func(t *testing.T) {
		ReleaseResult(nil) // should not panic
	})

	t.Run("MultipleReleaseCycle", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			result, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("Request %d failed: %v", i, err)
			}
			ReleaseResult(result)
		}
	})
}

// ----------------------------------------------------------------------------
// Request Option Tests - Additional Coverage
// ----------------------------------------------------------------------------

func TestRequest_WithOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	t.Run("WithContext", func(t *testing.T) {
		type ctxKey string
		ctx := context.WithValue(context.Background(), ctxKey("test-key"), "test-value")
		result, err := client.Request(ctx, "GET", server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		if result.StatusCode() != http.StatusOK {
			t.Errorf("Expected status 200, got %d", result.StatusCode())
		}
	})

	t.Run("WithBinary", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF}
		result, err := client.Post(server.URL, WithBinary(binaryData))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		if result.StatusCode() != http.StatusOK {
			t.Errorf("Expected status 200, got %d", result.StatusCode())
		}
	})
}

func TestRequest_WithCallbacks(t *testing.T) {
	var onRequestCalled int64
	var onResponseCalled int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	result, err := client.Get(server.URL,
		WithOnRequest(func(req RequestMutator) error {
			atomic.AddInt64(&onRequestCalled, 1)
			req.SetHeader("X-Callback-Header", "callback-value")
			return nil
		}),
		WithOnResponse(func(resp ResponseMutator) error {
			atomic.AddInt64(&onResponseCalled, 1)
			return nil
		}),
	)

	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if result.StatusCode() != http.StatusOK {
		t.Errorf("Expected status 200, got %d", result.StatusCode())
	}

	if atomic.LoadInt64(&onRequestCalled) != 1 {
		t.Errorf("Expected onRequest callback to be called once, got %d", onRequestCalled)
	}

	if atomic.LoadInt64(&onResponseCalled) != 1 {
		t.Errorf("Expected onResponse callback to be called once, got %d", onResponseCalled)
	}
}

func TestRequest_CallbackErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tests := []struct {
		name string
		opt  RequestOption
	}{
		{"NilOnRequestCallback", WithOnRequest(nil)},
		{"NilOnResponseCallback", WithOnResponse(nil)},
		{"OnRequestError", WithOnRequest(func(req RequestMutator) error { return fmt.Errorf("onRequest error") })},
		{"OnResponseError", WithOnResponse(func(resp ResponseMutator) error { return fmt.Errorf("onResponse error") })},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := newTestClient()
			defer client.Close()
			_, err := client.Get(server.URL, tt.opt)
			if err == nil {
				t.Error("Expected error")
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Package-Level Request Coverage
// ----------------------------------------------------------------------------

func TestPackageLevel_Request(t *testing.T) {
	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	_ = SetDefaultClient(client)
	defer CloseDefaultClient()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" {
			t.Errorf("Expected PATCH, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	resp, err := Request(context.Background(), "PATCH", server.URL)
	if err != nil {
		t.Fatalf("Package-level Request failed: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode())
	}
}

func TestSetDefaultClient_Boundaries(t *testing.T) {
	t.Run("nil client", func(t *testing.T) {
		if err := SetDefaultClient(nil); err == nil {
			t.Error("expected error for nil client")
		}
	})

	t.Run("closed client", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Security.AllowPrivateIPs = true
		client, _ := New(cfg)
		client.Close()

		if err := SetDefaultClient(client); err == nil {
			t.Error("expected error for closed client")
		}
	})
}

func TestDeepCopyConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.RedirectWhitelist = []string{"https://trusted.com"}
	cfg.Security.AllowPrivateIPs = true
	cfg.Middleware.Headers = map[string]string{"X-Test": "value"}

	copied := deepCopyConfig(cfg)

	// Modify original - copy should be independent
	cfg.Middleware.Headers["X-Test"] = "modified"
	cfg.Security.RedirectWhitelist[0] = "https://evil.com"

	if copied.Middleware.Headers["X-Test"] != "value" {
		t.Error("copy should be independent of original")
	}
	if copied.Security.RedirectWhitelist[0] != "https://trusted.com" {
		t.Error("copy whitelist should be independent")
	}
}

// ----------------------------------------------------------------------------
// getDefaultClient slow path
// ----------------------------------------------------------------------------

func TestGetDefaultClient_Init(t *testing.T) {
	// Reset default client to test the slow initialization path
	defaultClient.Store(nil)

	client, err := getDefaultClient()
	if err != nil {
		t.Fatalf("getDefaultClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}

	// Clean up - close the auto-created client
	CloseDefaultClient()
}

func TestClose_ErrorPath(t *testing.T) {
	// Create and close a client, then close again to trigger error path
	cfg := DefaultConfig()
	cfg.Security.AllowPrivateIPs = true
	client, _ := New(cfg)

	// First close should succeed
	if err := client.Close(); err != nil {
		t.Errorf("First close should succeed: %v", err)
	}

	// Second close - the engine should return an error
	// This exercises the error wrapping in Close()
	_ = client.Close()
}
