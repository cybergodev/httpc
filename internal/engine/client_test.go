package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	config := &Config{
		Timeout:             30 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     20,

		MaxResponseBodySize: 50 * 1024 * 1024,
		ValidateURL:         true,
		ValidateHeaders:     true,
		AllowPrivateIPs:     true,
		MaxRetries:          3,
		RetryDelay:          100 * time.Millisecond,
		BackoffFactor:       2.0,
		UserAgent:           "test-client/1.0",
		EnableCookies:       true,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	if client == nil {
		t.Fatal("Client should not be nil")
	}

	// Test that client is properly initialized
	// Note: Config is deep-copied for thread safety, so pointer comparison won't work
	if client.config == nil {
		t.Error("Config not properly set")
	}

	// Verify config values are copied correctly
	if client.config.Timeout != config.Timeout {
		t.Error("Timeout not properly copied")
	}
	if client.config.MaxRetries != config.MaxRetries {
		t.Error("MaxRetries not properly copied")
	}
}

func TestNewClient_InvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{name: "Nil config", config: nil, wantErr: true},
		{name: "Zero timeout falls back to default", config: &Config{Timeout: 0}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			if client != nil {
				defer func() { _ = client.Close() }()
			}
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected success, got: %v", err)
			}
			if tt.wantErr && client != nil {
				t.Error("expected nil client on error")
			}
		})
	}
}

// TestClient_HTTPMethods removed - duplicate of TestClient_ConvenienceMethods below

func TestClient_Request(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      1,
		UserAgent:       "test-client/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Use a context with timeout to ensure the request doesn't hang
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Request(ctx, "GET", server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode() != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}
}

func TestClient_RequestWithOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check custom header
		if r.Header.Get("X-Test") != "test-value" {
			t.Errorf("Expected X-Test header, got: %s", r.Header.Get("X-Test"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      1,
		UserAgent:       "test-client/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Create a request option that adds a header
	headerOption := func(req *Request) error {
		req.SetHeader("X-Test", "test-value")
		return nil
	}

	resp, err := client.Request(backgroundCtx, "GET", server.URL, headerOption)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode() != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}
}

func TestClient_Close(t *testing.T) {
	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      1,
		UserAgent:       "test-client/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Close should not error
	err = client.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Multiple closes should be safe
	err = client.Close()
	if err != nil {
		t.Errorf("Second close failed: %v", err)
	}
}

// TestClient_Statistics was removed: it asserted totalRequests >= 0 on a
// monotonic counter (could never fail). Request-count tracking is asserted
// with a real request by TestClient_IsHealthy.

func TestClient_ConcurrentRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add small delay to test concurrency
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      1,

		UserAgent: "test-client/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Make concurrent requests
	const numRequests = 5
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			_, err := client.Request(backgroundCtx, "GET", server.URL)
			results <- err
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		if err := <-results; err != nil {
			t.Errorf("Concurrent request failed: %v", err)
		}
	}
}

func TestClient_TLSConfig(t *testing.T) {
	// Create HTTPS test server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      1,
		UserAgent:       "test-client/1.0",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // For testing only
		},
		InsecureSkipVerify: true,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Request(backgroundCtx, "GET", server.URL)
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}

	if resp.StatusCode() != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}
}

// TestClient_ContextCancellation removed (early version) - the surviving
// test of the same name lives further down in this file.

// TestClient_InvalidURL removed - duplicate of TestClient_ErrorHandling in client_test.go

func TestClient_LargeResponse(t *testing.T) {
	// Create large response content
	largeContent := strings.Repeat("x", 1024*1024) // 1MB

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(largeContent))
	}))
	defer server.Close()

	config := &Config{
		Timeout:             30 * time.Second,
		AllowPrivateIPs:     true,
		MaxRetries:          1,
		MaxResponseBodySize: 2 * 1024 * 1024, // 2MB limit
		UserAgent:           "test-client/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Request(backgroundCtx, "GET", server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if len(resp.RawBody()) != len(largeContent) {
		t.Errorf("Expected response size %d, got %d", len(largeContent), len(resp.RawBody()))
	}
}

func TestClient_ConvenienceMethods(t *testing.T) {
	methods := []struct {
		name   string
		method string
	}{
		{"Post", "POST"},
		{"Put", "PUT"},
		{"Patch", "PATCH"},
		{"Delete", "DELETE"},
		{"Head", "HEAD"},
		{"Options", "OPTIONS"},
	}

	for _, tt := range methods {
		t.Run(tt.name, func(t *testing.T) {
			var gotMethod string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			config := &Config{
				Timeout:         30 * time.Second,
				AllowPrivateIPs: true,
				MaxRetries:      0,
				UserAgent:       "test/1.0",
			}
			client, err := NewClient(config)
			if err != nil {
				t.Fatalf("NewClient failed: %v", err)
			}
			defer func() { _ = client.Close() }()

			resp, err := client.Request(backgroundCtx, tt.method, server.URL)
			if err != nil {
				t.Fatalf("%s failed: %v", tt.name, err)
			}
			if resp.StatusCode() != http.StatusOK {
				t.Errorf("Status = %d, want 200", resp.StatusCode())
			}
			if gotMethod != tt.method {
				t.Errorf("Method = %q, want %q", gotMethod, tt.method)
			}
		})
	}
}

func TestClient_IsHealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      0,
		UserAgent:       "test/1.0",
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Make a successful request
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = client.Request(ctx, "GET", server.URL)

	if !client.isHealthy() {
		t.Error("Client should be healthy after successful request")
	}

	status := client.getHealthStatus()
	if status.totalRequests < 1 {
		t.Errorf("totalRequests = %d, want >= 1", status.totalRequests)
	}
}

func TestClient_OnRequestOnResponse(t *testing.T) {
	var onRequestVal, onResponseVal bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      0,
		UserAgent:       "test/1.0",
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	onReqOption := func(req *Request) error {
		req.SetOnRequest(func(r *Request) error {
			onRequestVal = true
			return nil
		})
		return nil
	}
	onRespOption := func(req *Request) error {
		req.SetOnResponse(func(r *Response) error {
			onResponseVal = true
			return nil
		})
		return nil
	}

	_, err = client.Request(ctx, "GET", server.URL, onReqOption, onRespOption)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if !onRequestVal {
		t.Error("OnRequest callback was not called")
	}
	if !onResponseVal {
		t.Error("OnResponse callback was not called")
	}
}

// TestClient_ResponseProcessing validates response handling for various server responses.
func TestClient_ResponseProcessing(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		validate       func(*testing.T, *Response)
	}{
		{
			name: "JSON response",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"success","code":200}`))
			},
			validate: func(t *testing.T, resp *Response) {
				if resp.StatusCode() != 200 {
					t.Errorf("Expected status 200, got %d", resp.StatusCode())
				}
				if !strings.Contains(resp.Body(), "success") {
					t.Error("Response body doesn't contain expected content")
				}
				if len(resp.RawBody()) == 0 {
					t.Error("RawBody should not be empty")
				}
			},
		},
		{
			name: "Error response",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid request"}`))
			},
			validate: func(t *testing.T, resp *Response) {
				if resp.StatusCode() != 400 {
					t.Errorf("Expected status 400, got %d", resp.StatusCode())
				}
				if !strings.Contains(resp.Body(), "error") {
					t.Error("Response body doesn't contain error message")
				}
			},
		},
		{
			name: "Large response",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				// Write large amount of data
				data := strings.Repeat("A", 1024*1024) // 1MB
				_, _ = w.Write([]byte(data))
			},
			validate: func(t *testing.T, resp *Response) {
				if resp.StatusCode() != 200 {
					t.Errorf("Expected status 200, got %d", resp.StatusCode())
				}
				if len(resp.RawBody()) < 1024*1024 {
					t.Error("Large response not handled correctly")
				}
			},
		},
		{
			name: "Response with cookies",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{
					Name:  "session_id",
					Value: "abc123",
					Path:  "/",
				})
				http.SetCookie(w, &http.Cookie{
					Name:  "user_pref",
					Value: "dark_mode",
					Path:  "/",
				})
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			},
			validate: func(t *testing.T, resp *Response) {
				cookies := resp.Cookies()
				if len(cookies) != 2 {
					t.Errorf("Expected 2 cookies, got %d", len(cookies))
				}

				foundSession := false
				foundPref := false
				for _, cookie := range cookies {
					if cookie.Name == "session_id" && cookie.Value == "abc123" {
						foundSession = true
					}
					if cookie.Name == "user_pref" && cookie.Value == "dark_mode" {
						foundPref = true
					}
				}

				if !foundSession {
					t.Error("Session cookie not found")
				}
				if !foundPref {
					t.Error("Preference cookie not found")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.serverResponse))
			defer server.Close()

			config := &Config{
				Timeout: 60 * time.Second,

				ValidateURL:     true,
				ValidateHeaders: true,
				AllowPrivateIPs: true, // Allow test server access
			}

			client, err := NewClient(config)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}
			defer func() { _ = client.Close() }()

			resp, err := client.Request(backgroundCtx, "GET", server.URL)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}

			tt.validate(t, resp)
		})
	}
}

// TestClient_ErrorHandling validates error handling for various failure scenarios.
func TestClient_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		setupServer func() *httptest.Server
		expectError bool
		errorCheck  func(*testing.T, error)
	}{
		{
			name: "Connection refused",
			setupServer: func() *httptest.Server {
				// Return a closed server
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				server.Close() // Close immediately
				return server
			},
			expectError: true,
			errorCheck: func(t *testing.T, err error) {
				if err == nil {
					t.Error("Expected connection error, got nil")
				}
			},
		},
		{
			name: "Server timeout",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(2 * time.Second) // Exceed client timeout
					w.WriteHeader(http.StatusOK)
				}))
			},
			expectError: true,
			errorCheck: func(t *testing.T, err error) {
				if err == nil {
					t.Error("Expected timeout error, got nil")
				}
			},
		},
		{
			name: "Invalid response",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Send invalid HTTP response
					w.Header().Set("Content-Length", "100")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("short")) // Content length mismatch
				}))
			},
			expectError: true, // Our enhanced security now detects this
			errorCheck: func(t *testing.T, err error) {
				if err == nil {
					t.Error("Expected content-length mismatch error, got nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			if server != nil {
				defer server.Close()
			}

			config := &Config{
				Timeout: 1 * time.Second, // Short timeout for testing

				ValidateURL:         true,
				ValidateHeaders:     true,
				AllowPrivateIPs:     true, // Allow test server access
				StrictContentLength: true, // Enable strict content-length validation
			}

			client, err := NewClient(config)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}
			defer func() { _ = client.Close() }()

			_, err = client.Request(backgroundCtx, "GET", server.URL)

			if tt.expectError && err == nil {
				t.Error("Expected error, got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if tt.errorCheck != nil {
				tt.errorCheck(t, err)
			}
		})
	}
}

// TestClient_ContextCancellation validates that context cancellation aborts requests promptly.
func TestClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // Long processing time
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:     true,
		ValidateHeaders: true,
		AllowPrivateIPs: true, // Allow test server access
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = client.Request(ctx, "GET", server.URL)
	duration := time.Since(start)

	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	}

	if duration > 1*time.Second {
		t.Errorf("Request took too long to cancel: %v", duration)
	}

	t.Logf("Context cancellation worked correctly in %v", duration)
}

func TestClient_OnResponseErrorReleasesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test body")) // best-effort test response
	}))
	defer server.Close()

	client, err := NewClient(&Config{
		FollowRedirects: true,
	}, withMockTransport(newMockTransport(200, "test response body")))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	// onResponse callback that returns an error
	onRespOption := func(req *Request) error {
		req.SetOnResponse(func(r *Response) error {
			return fmt.Errorf("simulated callback error")
		})
		return nil
	}

	// This should return error but NOT leak the pooled Response
	_, err = client.Request(backgroundCtx, "GET", server.URL, onRespOption)
	if err == nil {
		t.Fatal("expected error from onResponse callback")
	}
	if !strings.Contains(err.Error(), "onResponse callback failed") {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify the response pool is still functional by making another request
	resp, err := client.Request(backgroundCtx, "GET", server.URL)
	if err != nil {
		t.Fatalf("subsequent request failed: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode())
	}
}

func TestClient_SetRawBodyReader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "body=%s,content-type=%s", string(body), r.Header.Get("Content-Type")) // best-effort test response
	}))
	defer server.Close()

	cfg := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      1,
		UserAgent:       "test-client/1.0",
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Request(backgroundCtx, "GET", server.URL)
	if err != nil {
		t.Fatalf("Request error: %v", err)
	}

	// Test SetRawBodyReader on the response
	originalReader := resp.RawBodyReader()

	// Create a new io.ReadCloser and set it
	newReader := io.NopCloser(strings.NewReader("replacement body"))
	resp.SetRawBodyReader(newReader)

	// Verify it was set
	gotReader := resp.RawBodyReader()
	if gotReader != newReader {
		t.Error("expected RawBodyReader to be the new reader after SetRawBodyReader")
	}

	// Test setting to nil (ownership transfer scenario)
	resp.SetRawBodyReader(nil)
	if resp.RawBodyReader() != nil {
		t.Error("expected RawBodyReader to be nil after SetRawBodyReader(nil)")
	}

	// Restore original to avoid leak if it was non-nil
	_ = originalReader
}

// TestRequestApply verifies Apply forwards every per-request mutable field
// and transfers ownership of the pooled maps (src's references cleared).
func TestRequestApply(t *testing.T) {
	src := &Request{}
	src.SetMethod("POST")
	src.SetURL("https://api.example.com/apply")
	src.SetHeader("X-Test", "value")
	src.EnsureQueryParams()["q"] = "1"
	src.SetBody(map[string]string{"k": "v"})
	src.SetTimeout(7 * time.Second)
	src.SetMaxRetries(3)
	src.SetCookies([]http.Cookie{{Name: "c", Value: "v"}})
	fr, mr, ap := true, 4, true
	src.SetFollowRedirects(&fr)
	src.SetMaxRedirects(&mr)
	src.SetAllowPrivateIPs(&ap)
	src.SetStreamBody(true)

	dst := &Request{}
	dst.Apply(src)

	if dst.Method() != "POST" || dst.URL() != "https://api.example.com/apply" {
		t.Errorf("method/url not forwarded: %s %s", dst.Method(), dst.URL())
	}
	if dst.Headers()["X-Test"] != "value" {
		t.Errorf("headers not forwarded: %v", dst.Headers())
	}
	if dst.QueryParams()["q"] != "1" {
		t.Errorf("query params not forwarded: %v", dst.QueryParams())
	}
	if dst.Body() == nil || dst.Timeout() != 7*time.Second || dst.MaxRetries() != 3 {
		t.Errorf("body/timeout/retries not forwarded: %v %v %v", dst.Body(), dst.Timeout(), dst.MaxRetries())
	}
	if len(dst.Cookies()) != 1 || dst.Cookies()[0].Name != "c" {
		t.Errorf("cookies not forwarded: %v", dst.Cookies())
	}
	if dst.FollowRedirects() == nil || !*dst.FollowRedirects() {
		t.Error("followRedirects not forwarded")
	}
	if dst.MaxRedirects() == nil || *dst.MaxRedirects() != 4 {
		t.Error("maxRedirects not forwarded")
	}
	if dst.AllowPrivateIPs() == nil || !*dst.AllowPrivateIPs() {
		t.Error("allowPrivateIPs not forwarded")
	}
	if !dst.StreamBody() {
		t.Error("streamBody not forwarded")
	}

	// Ownership transfer: pooled maps must be detached from src so a later
	// release of src cannot double-pool them.
	if src.Headers() != nil || src.QueryParams() != nil {
		t.Errorf("src pooled maps not cleared: headers=%v queryParams=%v", src.Headers(), src.QueryParams())
	}
	// dst still sees the transferred maps.
	if dst.Headers()["X-Test"] != "value" {
		t.Error("headers lost after ownership transfer")
	}
}

// TestExecuteWithRetry_ProxyRotationPaths covers the proxy-rotation branches
// of executeWithRetry that plain mock-transport retry tests cannot reach:
// recorder attachment + NextProxyIndex reservation in both the no-retry fast
// path and the retry loop, and per-attempt WithProxyAttempt context wiring.
// The mock transport bypasses the real Proxy callback, so ProxyURL stays
// empty — the branches, not the value, are the point here.
func TestExecuteWithRetry_ProxyRotationPaths(t *testing.T) {
	newPoolCfg := func(maxRetries int) *Config {
		return &Config{
			Timeout:               5 * time.Second,
			AllowPrivateIPs:       true,
			MaxRetries:            maxRetries,
			RetryDelay:            time.Millisecond,
			ProxyPool:             []string{"http://p1.example.com:8080", "http://p2.example.com:8080"},
			ProxyRotatePerRequest: true,
		}
	}

	t.Run("fast path attaches recorder and reserves index", func(t *testing.T) {
		mt := newMockTransport(200, "ok")
		client, err := NewClient(newPoolCfg(0), withMockTransport(mt))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer func() { _ = client.Close() }()

		resp, err := client.Request(context.Background(), "GET", "https://example.com")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if resp.Attempts() != 1 {
			t.Errorf("Attempts = %d, want 1 (no-retry fast path)", resp.Attempts())
		}
		ReleaseResponse(resp)
	})

	t.Run("retry loop rotates proxy index across attempts", func(t *testing.T) {
		mt := newMockTransport(200, "ok")
		mt.failFirst = 2 // two retryable failures, success on attempt 3
		client, err := NewClient(newPoolCfg(2), withMockTransport(mt))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer func() { _ = client.Close() }()

		resp, err := client.Request(context.Background(), "GET", "https://example.com")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if resp.Attempts() != 3 {
			t.Errorf("Attempts = %d, want 3", resp.Attempts())
		}
		if mt.GetCallCount() != 3 {
			t.Errorf("transport calls = %d, want 3", mt.GetCallCount())
		}
		ReleaseResponse(resp)
	})
}

// TestExecuteWithRetry_CustomPolicyVetoAndSleepError covers the two
// custom-policy exits of the retry loop: a policy that vetoes a retryable
// error (ShouldRetry=false → immediate return), and a sleep aborted by the
// request deadline during the inter-attempt delay.
func TestExecuteWithRetry_CustomPolicyVetoAndSleepError(t *testing.T) {
	t.Run("policy vetoes retryable error", func(t *testing.T) {
		mt := newMockTransport(200, "ok")
		mt.failFirst = 1 // retryable connection-reset, but policy says stop
		client, err := NewClient(&Config{
			Timeout:           5 * time.Second,
			AllowPrivateIPs:   true,
			MaxRetries:        2,
			CustomRetryPolicy: &testRetryPolicy{maxRetries: 0, delay: time.Millisecond},
		}, withMockTransport(mt))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer func() { _ = client.Close() }()

		_, err = client.Request(context.Background(), "GET", "https://example.com")
		if err == nil {
			t.Fatal("expected error: policy must stop after first failure")
		}
		if mt.GetCallCount() != 1 {
			t.Errorf("transport calls = %d, want 1 (veto honored)", mt.GetCallCount())
		}
	})

	t.Run("sleep aborted by request deadline", func(t *testing.T) {
		mt := newMockTransport(200, "ok")
		mt.failFirst = 1
		client, err := NewClient(&Config{
			Timeout:         30 * time.Second, // > ctx deadline: ctx deadline wins
			AllowPrivateIPs: true,
			MaxRetries:      1,
			CustomRetryPolicy: &testRetryPolicy{
				maxRetries: 1,
				delay:      500 * time.Millisecond, // longer than the ctx deadline
			},
		}, withMockTransport(mt))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer func() { _ = client.Close() }()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err = client.Request(ctx, "GET", "https://example.com")
		if err == nil {
			t.Fatal("expected error: sleep must be aborted by the deadline")
		}
	})
}

// TestSecurityRequestPool_FallbackAndReset covers the defensive branches of
// getSecurityRequest/putSecurityRequest: a wrong-typed pooled value must fall
// back to a fresh security.Request, and put must clear every field so a
// recycled request never leaks prior-request state. Mirrors the poisoned-pool
// tests the other engine pools already have.
func TestSecurityRequestPool_FallbackAndReset(t *testing.T) {
	client, err := NewClient(&Config{Timeout: 30 * time.Second, AllowPrivateIPs: true})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	t.Run("wrong-typed pooled value falls back to fresh", func(t *testing.T) {
		client.securityRequestPool.Put(42) //nolint:staticcheck // intentional wrong-type poisoning

		req := client.getSecurityRequest()
		if req == nil {
			t.Fatal("getSecurityRequest returned nil from poisoned pool")
		}
		// Must be a usable zero value.
		if req.Method != "" || req.URL != "" || req.Headers != nil {
			t.Errorf("fallback request not zero-valued: %+v", req)
		}
	})

	t.Run("put clears all fields", func(t *testing.T) {
		req := client.getSecurityRequest()
		req.Method = "POST"
		req.URL = "https://example.com"
		req.Headers = map[string]string{"X-A": "1"}
		req.QueryParams = map[string]any{"q": 1}

		client.putSecurityRequest(req)

		if req.Method != "" || req.URL != "" || req.Headers != nil || req.QueryParams != nil {
			t.Errorf("putSecurityRequest did not reset: %+v", req)
		}
	})

	t.Run("put nil is a no-op", func(t *testing.T) {
		client.putSecurityRequest(nil) // must not panic
	})
}
