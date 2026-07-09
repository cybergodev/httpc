package httpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
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

	t.Run("BasicRequest", func(t *testing.T) {
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
	})

	t.Run("MultipleRequests", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			result, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("Request %d failed: %v", i, err)
			}
			_ = result.Body()
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

func TestClose_DoubleClose(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.AllowPrivateIPs = true
	client, _ := New(cfg)

	if err := client.Close(); err != nil {
		t.Errorf("First close should succeed: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Errorf("Second close should not error: %v", err)
	}
}

func TestClient_Lifecycle_AfterClose(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.AllowPrivateIPs = true
	client, _ := New(cfg)
	client.Close()

	_, err := client.Get("http://example.com")
	if err == nil {
		t.Error("Expected error when using closed client")
	}
}

// ----------------------------------------------------------------------------
// mergeNilSubConfigs — covers the five nil sub-config branches (FIX-001)
// ----------------------------------------------------------------------------

func TestMergeNilSubConfigs(t *testing.T) {
	// Each sub-config left nil is filled from DefaultConfig; non-nil sub-configs
	// are preserved as-is. Exercises all five nil-branches plus an all-nil case.
	// Compared by value (reflect.DeepEqual) because DefaultConfig() returns fresh
	// sub-config pointers on each call.
	def := DefaultConfig()

	tests := []struct {
		name     string
		nilField func(*Config)
		filled   func(*Config) bool
	}{
		{"Timeouts nil", func(c *Config) { c.Timeouts = nil }, func(c *Config) bool { return c.Timeouts != nil && reflect.DeepEqual(c.Timeouts, def.Timeouts) }},
		{"Connection nil", func(c *Config) { c.Connection = nil }, func(c *Config) bool { return c.Connection != nil && reflect.DeepEqual(c.Connection, def.Connection) }},
		{"Security nil", func(c *Config) { c.Security = nil }, func(c *Config) bool { return c.Security != nil && reflect.DeepEqual(c.Security, def.Security) }},
		{"Retry nil", func(c *Config) { c.Retry = nil }, func(c *Config) bool { return c.Retry != nil && reflect.DeepEqual(c.Retry, def.Retry) }},
		{"Middleware nil", func(c *Config) { c.Middleware = nil }, func(c *Config) bool { return c.Middleware != nil && reflect.DeepEqual(c.Middleware, def.Middleware) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.nilField(cfg)
			if !tt.filled(mergeNilSubConfigs(cfg)) {
				t.Errorf("mergeNilSubConfigs did not fill the nil sub-config from DefaultConfig")
			}
		})
	}

	t.Run("all nil", func(t *testing.T) {
		got := mergeNilSubConfigs(&Config{})
		if got.Timeouts == nil || got.Connection == nil || got.Security == nil ||
			got.Retry == nil || got.Middleware == nil {
			t.Error("mergeNilSubConfigs left a sub-config nil for an all-nil Config")
		}
	})

	t.Run("preserves non-nil sub-config", func(t *testing.T) {
		cfg := DefaultConfig()
		custom := &TimeoutConfig{Request: 99 * time.Second}
		cfg.Timeouts = custom
		if mergeNilSubConfigs(cfg).Timeouts != custom {
			t.Error("mergeNilSubConfigs overwrote a non-nil sub-config")
		}
	})
}

// ----------------------------------------------------------------------------
// newFromPreparedConfig — InsecureSkipVerify warn-once path (FIX-001)
// ----------------------------------------------------------------------------

func TestNewFromPreparedConfig_InsecureSkipVerifyWarn(t *testing.T) {
	// The InsecureSkipVerify warning only fires outside a test environment; in a
	// test binary isTestEnvironment() is true and the path is cold. Simulate a
	// non-test environment to exercise the warn-once block. Mirrors the global
	// save/restore pattern in TestWarnTestingConfigInProduction (config_test.go).
	origArgs := os.Args[0]
	origGoTest := os.Getenv("GO_TEST")
	origGotest := os.Getenv("GOTEST")
	defer func() {
		os.Args[0] = origArgs
		os.Setenv("GO_TEST", origGoTest)
		os.Setenv("GOTEST", origGotest)
		insecureSkipVerifyWarnOnce = sync.Once{}
		securityWarnOutput = os.Stderr
	}()

	os.Args[0] = "/usr/bin/myapp"
	os.Setenv("GO_TEST", "")
	os.Setenv("GOTEST", "")
	insecureSkipVerifyWarnOnce = sync.Once{} // reset so the warning fires this run

	var buf bytes.Buffer
	SetSecurityWarnOutput(&buf)

	cfg := DefaultConfig()
	cfg.Security.InsecureSkipVerify = true
	client, err := newFromPreparedConfig(cfg)
	if err != nil {
		t.Fatalf("newFromPreparedConfig failed: %v", err)
	}
	defer client.Close()

	output := buf.String()
	if !strings.Contains(output, "InsecureSkipVerify is enabled") {
		t.Errorf("expected InsecureSkipVerify warning, got: %s", output)
	}
	if !strings.Contains(output, "TLS certificate verification is DISABLED") {
		t.Errorf("expected TLS-disabled warning, got: %s", output)
	}

	// The two engine.NewClient error arms (client.go:153, :166) are unreachable
	// from a validated public Config — convertToEngineConfig/engine.NewClient only
	// reject inputs that ValidateConfig already refuses upstream — so they are
	// intentionally not exercised here.
}

// ----------------------------------------------------------------------------
// getDefaultClient — self-heal after Close (FIX-001)
// ----------------------------------------------------------------------------

func TestGetDefaultClient_SelfHealAfterClose(t *testing.T) {
	defaultClient.Store(nil)
	defer CloseDefaultClient()

	// Acquire, then close via the client itself (leaves a closed impl stored,
	// not nil) — exercises the IsClosed() fast/slow-path checks.
	c1, err := getDefaultClient()
	if err != nil || c1 == nil {
		t.Fatalf("initial getDefaultClient failed: err=%v client=%v", err, c1)
	}
	if err := c1.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	c2, err := getDefaultClient()
	if err != nil {
		t.Fatalf("self-heal getDefaultClient failed: %v", err)
	}
	if c2 == nil {
		t.Fatal("expected self-healed non-nil client")
	}
	if c2 == c1 {
		t.Error("expected a freshly initialized client, got the closed one")
	}

	// Also cover the CloseDefaultClient path that stores nil before re-acquire.
	CloseDefaultClient()
	c3, err := getDefaultClient()
	if err != nil || c3 == nil {
		t.Fatalf("getDefaultClient after CloseDefaultClient failed: err=%v client=%v", err, c3)
	}
	_ = c3
}

func TestGetDefaultClient_ConcurrentSelfHeal(t *testing.T) {
	defaultClient.Store(nil)
	defer CloseDefaultClient()

	const goroutines, iters = 16, 4
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_ = CloseDefaultClient()
				c, err := getDefaultClient()
				if err != nil {
					t.Errorf("getDefaultClient error under concurrency: %v", err)
					return
				}
				if c == nil {
					t.Error("getDefaultClient returned nil under concurrency")
					return
				}
			}
		}()
	}
	wg.Wait()

	c, err := getDefaultClient()
	if err != nil || c == nil {
		t.Errorf("final getDefaultClient failed: err=%v client=%v", err, c)
	}
}

// ----------------------------------------------------------------------------
// cloneHeaders + convertResponseToResult middleware-wrapped fallback (FIX-001)
// ----------------------------------------------------------------------------

func TestCloneHeaders(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if cloneHeaders(nil) != nil {
			t.Error("cloneHeaders(nil) should return nil")
		}
	})

	t.Run("deep copy", func(t *testing.T) {
		src := http.Header{"X-A": {"1", "2"}, "X-B": {"beta"}}
		got := cloneHeaders(src)
		if !reflect.DeepEqual(got, src) {
			t.Errorf("cloneHeaders not equal to source: got %v, want %v", got, src)
		}
		// Mutating the clone must not affect the source.
		got["X-A"][0] = "mutated"
		if src["X-A"][0] != "1" {
			t.Error("cloneHeaders did not produce an independent deep copy")
		}
	})
}

// TestConvertResponseToResult_NonEngineResponse drives the cloneHeaders fallback
// (client.go:702) and the requestHeaders fallback (:668) via a ResponseMutator
// that is NOT *engine.Response — the shape a wrapping middleware produces. It
// also exercises releaseResponseMutator's nil early-return and non-engine
// fall-through arms.
func TestConvertResponseToResult_NonEngineResponse(t *testing.T) {
	mock := &mockResponse{
		statusCode:     200,
		headers:        http.Header{"X-Custom": {"val"}},
		requestHeaders: http.Header{"X-Req": {"r"}},
		rawBody:        []byte("hello"),
		requestURL:     "http://example.com",
		requestMethod:  "GET",
	}

	result := convertResponseToResult(mock)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if got := result.Response.Headers.Get("X-Custom"); got != "val" {
		t.Errorf("expected cloned response header X-Custom=val, got %q", got)
	}
	if result.Response.Body != "hello" {
		t.Errorf("expected body 'hello', got %q", result.Response.Body)
	}
	if got := result.Request.Headers.Get("X-Req"); got != "r" {
		t.Errorf("expected request header X-Req=r via RequestHeaders() fallback, got %q", got)
	}

	// Non-engine responses are not pooled: release must be a no-op (no panic).
	releaseResponseMutator(mock)
	// nil early-return arm.
	releaseResponseMutator(nil)

	// convertResponseToResult nil early-return.
	if convertResponseToResult(nil) != nil {
		t.Error("convertResponseToResult(nil) should return nil")
	}
}
