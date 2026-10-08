package httpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// TestClient_Creation was removed: all four subtests only asserted that a
// constructor returned without error — a precondition of every other test in
// this package. Config variety is asserted field-by-field in config_test.go
// (TestConfig_Presets), and NewDefault's lifecycle by the GetDefaultClient
// tests below.

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
			defer func() { _ = client.Close() }()

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
	defer func() { _ = client.Close() }()

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
		defer func() { _ = client.Close() }()

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
		cfg.Defaults.Headers = map[string]string{"X-Initial": "value"}

		client, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer func() { _ = client.Close() }()

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
			cfg.Defaults.Headers["X-Modified"] = "new-value"
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
		defer func() { _ = CloseDefaultClient() }() // best-effort cleanup

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

		// The context-taking Request variant is a separate public entry point.
		t.Run("Request", func(t *testing.T) {
			resp, err := Request(context.Background(), "PATCH", server.URL)
			if err != nil {
				t.Fatalf("Package-level Request failed: %v", err)
			}
			if resp.StatusCode() != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode())
			}
		})
	})
	// True lazy auto-initialization (no prior SetDefaultClient) is covered by
	// TestGetDefaultClient_Init, which resets defaultClient and forces the
	// slow-init path directly.
}

// ----------------------------------------------------------------------------
// Error Handling Tests
// ----------------------------------------------------------------------------

func TestClient_ErrorHandling(t *testing.T) {
	t.Run("InvalidURL", func(t *testing.T) {
		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

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
		defer func() { _ = client.Close() }()

		// Use a non-routable IP address
		_, err := client.Get("http://192.0.2.1:12345")
		if err == nil {
			t.Error("Expected network error")
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
	defer func() { _ = client.Close() }()

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
		_, _ = w.Write([]byte("response")) // best-effort test response
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer func() { _ = client.Close() }()

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
			defer func() { _ = client.Close() }()
			_, err := client.Get(server.URL, tt.opt)
			if err == nil {
				t.Error("Expected error")
			}
		})
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
		_ = client.Close()

		if err := SetDefaultClient(client); err == nil {
			t.Error("expected error for closed client")
		}
	})
}

func TestCopyConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.RedirectWhitelist = []string{"https://trusted.com"}
	cfg.Security.AllowPrivateIPs = true
	cfg.Defaults.Headers = map[string]string{"X-Test": "value"}

	copied := copyConfig(cfg)

	// Modify original - copy should be independent
	cfg.Defaults.Headers["X-Test"] = "modified"
	cfg.Security.RedirectWhitelist[0] = "https://evil.com"

	if copied.Defaults.Headers["X-Test"] != "value" {
		t.Error("copy should be independent of original")
	}
	if copied.Security.RedirectWhitelist[0] != "https://trusted.com" {
		t.Error("copy whitelist should be independent")
	}
}

// ----------------------------------------------------------------------------
// getDefaultClient slow path
// ----------------------------------------------------------------------------

// TestGetDefaultClient_Init was removed: the fresh-reinit-after-nil path it
// forced is the same path TestGetDefaultClient_SelfHealAfterClose exercises
// (its c3 block), which additionally verifies the closed-client self-heal.

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
	_ = client.Close()

	_, err := client.Get("http://example.com")
	if err == nil {
		t.Error("Expected error when using closed client")
	}
}

// ----------------------------------------------------------------------------
// newFromConfig — InsecureSkipVerify warn-once path (FIX-001)
// ----------------------------------------------------------------------------

// TestNewFromPreparedConfig_InsecureSkipVerifyWarn consolidates the former
// standalone Security-config and TLSConfig-embedded variants (byte-identical
// scaffolding; only the flag's location differed). The warning fires once
// per process outside a test environment; the environment is simulated and
// the warn-once state reset per row. Mirrors the save/restore pattern in
// TestWarnTestingConfigInProduction (config_test.go).
func TestNewFromPreparedConfig_InsecureSkipVerifyWarn(t *testing.T) {
	tests := []struct {
		name    string
		setFlag func(*Config)
	}{
		{"Security.InsecureSkipVerify", func(c *Config) {
			c.Security.InsecureSkipVerify = true
		}},
		{"TLSConfig-embedded InsecureSkipVerify", func(c *Config) {
			c.Security.InsecureSkipVerify = false // only the embedded TLSConfig sets it
			c.Security.TLSConfig = &tls.Config{InsecureSkipVerify: true}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origArgs := os.Args[0]
			origGoTest := os.Getenv("GO_TEST")
			origGotest := os.Getenv("GOTEST")
			defer func() {
				os.Args[0] = origArgs
				_ = os.Setenv("GO_TEST", origGoTest)
				_ = os.Setenv("GOTEST", origGotest)
				insecureSkipVerifyWarnOnce = sync.Once{}
				securityWarnOutput = os.Stderr
			}()

			os.Args[0] = "/usr/bin/myapp"
			_ = os.Setenv("GO_TEST", "")
			_ = os.Setenv("GOTEST", "")
			insecureSkipVerifyWarnOnce = sync.Once{} // reset so the warning fires this run

			var buf bytes.Buffer
			SetSecurityWarnOutput(&buf)

			cfg := DefaultConfig()
			tt.setFlag(&cfg)
			client, err := newFromConfig(cfg)
			if err != nil {
				t.Fatalf("newFromConfig failed: %v", err)
			}
			defer func() { _ = client.Close() }()

			output := buf.String()
			if !strings.Contains(output, "InsecureSkipVerify is enabled") {
				t.Errorf("expected InsecureSkipVerify warning, got: %s", output)
			}
			if !strings.Contains(output, "TLS certificate verification is DISABLED") {
				t.Errorf("expected TLS-disabled warning, got: %s", output)
			}
		})
	}

	// The two engine.NewClient error arms (client.go:153, :166) are unreachable
	// from a validated public Config — convertToEngineConfig/engine.NewClient only
	// reject inputs that ValidateConfig already refuses upstream — so they are
	// intentionally not exercised here.
}

// fakePSL is a minimal cookiejar.PublicSuffixList that treats "com" as a
// public suffix — enough to prove the list is plumbed into the jar.
type fakePSL struct{}

func (fakePSL) PublicSuffix(domain string) string {
	if domain == "com" {
		return "com"
	}
	return "example.com" // everything else maps to one suffix
}
func (fakePSL) String() string { return "fakepsl" }

// TestCreateCookieJar_PublicSuffixList verifies Connection.PublicSuffixList is
// plumbed into the cookie jar, and that disabling cookies yields a nil jar.
func TestCreateCookieJar_PublicSuffixList(t *testing.T) {
	exampleURL := &url.URL{Scheme: "http", Host: "example.com"}
	supercookie := []*http.Cookie{{Name: "a", Value: "1", Domain: "com"}}

	t.Run("with PSL rejects public-suffix domain cookie", func(t *testing.T) {
		jar, err := createCookieJar(true, fakePSL{})
		if err != nil {
			t.Fatalf("createCookieJar failed: %v", err)
		}
		jar.SetCookies(exampleURL, supercookie)
		if got := jar.Cookies(exampleURL); len(got) != 0 {
			t.Errorf("PSL jar must reject Domain=com supercookie, got %v", got)
		}
	})

	t.Run("without PSL accepts public-suffix domain cookie", func(t *testing.T) {
		jar, err := createCookieJar(true, nil)
		if err != nil {
			t.Fatalf("createCookieJar failed: %v", err)
		}
		jar.SetCookies(exampleURL, supercookie)
		if got := jar.Cookies(exampleURL); len(got) == 0 {
			t.Error("nil-PSL jar exhibits the historical looser matching (baseline for comparison)")
		}
	})

	t.Run("cookies disabled returns nil jar", func(t *testing.T) {
		jar, err := createCookieJar(false, fakePSL{})
		if err != nil || jar != nil {
			t.Errorf("expected nil jar without error, got jar=%v err=%v", jar, err)
		}
	})
}

// TestRequest_StreamBodyRejectedOnFacade verifies Get + WithStreamBody fails
// with ErrStreamBodyRequiresDownload instead of silently returning a Result
// with an empty body (the pre-fix behavior).
func TestRequest_StreamBodyRejectedOnFacade(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("stream me"))
	}))
	defer ts.Close()

	client, err := newTestClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Get(ts.URL, WithStreamBody(true))
	if !errors.Is(err, ErrStreamBodyRequiresDownload) {
		t.Fatalf("expected ErrStreamBodyRequiresDownload, got %v", err)
	}

	// Sanity: the same request without streaming still succeeds.
	result, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("plain Get failed: %v", err)
	}
	if result.Body() == "" {
		t.Fatal("plain Get should return the buffered body")
	}
}

// ----------------------------------------------------------------------------
// getDefaultClient — self-heal after Close (FIX-001)
// ----------------------------------------------------------------------------

func TestGetDefaultClient_SelfHealAfterClose(t *testing.T) {
	defaultClient.Store(nil)
	defer func() { _ = CloseDefaultClient() }() // best-effort cleanup

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
	_ = CloseDefaultClient() // best-effort cleanup
	c3, err := getDefaultClient()
	if err != nil || c3 == nil {
		t.Fatalf("getDefaultClient after CloseDefaultClient failed: err=%v client=%v", err, c3)
	}
	_ = c3
}

func TestGetDefaultClient_ConcurrentSelfHeal(t *testing.T) {
	defaultClient.Store(nil)
	defer func() { _ = CloseDefaultClient() }() // best-effort cleanup

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

// Moved from quality_regression_test.go (dissolved grab-bag file). Lives here rather
// than domain_client_test.go because buildURL is unexported and that file is
// the black-box httpc_test package:
// TestBuildURLCaseInsensitiveScheme guards the case-insensitive absolute-URL
// detection in DomainClient.buildURL: "HTTP://host" is an absolute URL per
// url.Parse (which lowercases schemes), not a relative path to be joined.
func TestBuildURLCaseInsensitiveScheme(t *testing.T) {
	dc, err := NewDomain("https://api.example.com/v1", TestingConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dc.Close() }()
	impl := dc.(*DomainClient)

	for _, abs := range []string{
		"HTTP://other.example.com/x",
		"http://other.example.com/x",
		"https://other.example.com/x",
		"HTTPS://other.example.com/x",
	} {
		got, err := impl.buildURL(abs)
		if err != nil {
			t.Fatalf("buildURL(%q): %v", abs, err)
		}
		if got != abs {
			t.Errorf("buildURL(%q) = %q, want the URL used as-is", abs, got)
		}
	}

	// Relative paths must still join onto the base path.
	got, err := impl.buildURL("users")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://api.example.com/v1/users"; got != want {
		t.Errorf("buildURL(users) = %q, want %q", got, want)
	}
}
