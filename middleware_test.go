package httpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestChain(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		expected []string
	}{
		{"zero middlewares", 0, []string{"handler"}},
		{"single middleware", 1, []string{"m1-before", "handler", "m1-after"}},
		{"two middlewares", 2, []string{"m1-before", "m2-before", "handler", "m2-after", "m1-after"}},
		{"three middlewares", 3, []string{"m1-before", "m2-before", "m3-before", "handler", "m3-after", "m2-after", "m1-after"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var order []string
			var mu sync.Mutex

			createMiddleware := func(name string) MiddlewareFunc {
				return func(next Handler) Handler {
					return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
						mu.Lock()
						order = append(order, name+"-before")
						mu.Unlock()
						resp, err := next(ctx, req)
						mu.Lock()
						order = append(order, name+"-after")
						mu.Unlock()
						return resp, err
					}
				}
			}

			finalHandler := func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
				mu.Lock()
				order = append(order, "handler")
				mu.Unlock()
				return &mockResponse{statusCode: 200}, nil
			}

			middlewares := make([]MiddlewareFunc, tt.count)
			for i := 0; i < tt.count; i++ {
				middlewares[i] = createMiddleware(fmt.Sprintf("m%d", i+1))
			}

			chain := Chain(middlewares...)
			handler := chain(finalHandler)
			_, _ = handler(context.Background(), &mockRequest{})

			if len(order) != len(tt.expected) {
				t.Fatalf("expected %d calls, got %d: %v", len(tt.expected), len(order), order)
			}
			for i, exp := range tt.expected {
				if order[i] != exp {
					t.Errorf("position %d: expected %s, got %s", i, exp, order[i])
				}
			}
		})
	}
}

func TestLoggingMiddleware(t *testing.T) {
	var loggedMessages []string
	var mu sync.Mutex

	logger := func(format string, args ...any) {
		mu.Lock()
		loggedMessages = append(loggedMessages, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		LoggingMiddleware(&LoggingConfig{LogFunc: logger}),
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	_, _ = client.Get(ts.URL)

	mu.Lock()
	if len(loggedMessages) == 0 {
		t.Error("expected log message, got none")
	}
	msg := loggedMessages[0]
	mu.Unlock()

	if !strings.Contains(msg, "GET") {
		t.Errorf("expected log to contain GET, got: %s", msg)
	}
	if !strings.Contains(msg, "200") {
		t.Errorf("expected log to contain 200, got: %s", msg)
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	var receivedID string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		RequestIDMiddleware(&RequestIDConfig{
			HeaderName: "X-Request-ID",
			Generator:  func() string { return "test-request-id-123" },
		}),
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	_, err = client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if receivedID != "test-request-id-123" {
		t.Errorf("expected request ID 'test-request-id-123', got: %s", receivedID)
	}
}

func TestTimeoutMiddleware(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Timeouts.Request = 5 * time.Second
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		TimeoutMiddleware(&TimeoutMiddlewareConfig{Duration: 10 * time.Millisecond}),
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	start := time.Now()
	_, err = client.Get(ts.URL)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected timeout error, got nil")
	}

	if elapsed > 100*time.Millisecond {
		t.Errorf("request took too long: %v", elapsed)
	}
}

// TestMiddleware_NilConfig verifies each middleware constructor accepts a nil
// config, applying documented defaults without panicking or breaking requests.
// Consolidates the former Timeout/Header/RequestID/Metrics nil-config tests.
func TestMiddleware_NilConfig(t *testing.T) {
	var receivedID string
	tests := []struct {
		name       string
		middleware MiddlewareFunc
		verify     func(t *testing.T)
	}{
		{
			name:       "TimeoutMiddleware nil config = disabled",
			middleware: TimeoutMiddleware(nil),
		},
		{
			name:       "HeaderMiddleware nil config = no headers",
			middleware: HeaderMiddleware(nil),
		},
		{
			name:       "MetricsMiddleware nil config",
			middleware: MetricsMiddleware(nil),
		},
		{
			name:       "RequestIDMiddleware nil config sets default header",
			middleware: RequestIDMiddleware(nil),
			verify: func(t *testing.T) {
				if receivedID == "" {
					t.Error("expected request ID to be set")
				}
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Middleware.Middlewares = []MiddlewareFunc{tt.middleware}

			client, err := New(cfg)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}
			defer client.Close()

			if _, err := client.Get(ts.URL); err != nil {
				t.Fatalf("request with nil-config middleware failed: %v", err)
			}
			if tt.verify != nil {
				tt.verify(t)
			}
		})
	}
}

func TestTimeoutMiddleware_CancelledContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		TimeoutMiddleware(&TimeoutMiddlewareConfig{Duration: 5 * time.Second}),
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Already-cancelled context should fail immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client.Get(ts.URL, WithContext(ctx))
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestDefaultTimeoutMiddlewareConfig(t *testing.T) {
	config := DefaultTimeoutMiddlewareConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}
	if config.Duration != 0 {
		t.Errorf("expected Duration 0 (disabled), got %v", config.Duration)
	}
}

func TestHeaderMiddleware(t *testing.T) {
	var receivedHeaders map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = map[string]string{
			"X-Custom-Header": r.Header.Get("X-Custom-Header"),
			"Authorization":   r.Header.Get("Authorization"),
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		HeaderMiddleware(&HeaderConfig{
			Headers: map[string]string{
				"X-Custom-Header": "custom-value",
				"Authorization":   "Bearer test-token",
			},
		}),
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	_, err = client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if receivedHeaders["X-Custom-Header"] != "custom-value" {
		t.Errorf("expected X-Custom-Header 'custom-value', got: %s", receivedHeaders["X-Custom-Header"])
	}
	if receivedHeaders["Authorization"] != "Bearer test-token" {
		t.Errorf("expected Authorization 'Bearer test-token', got: %s", receivedHeaders["Authorization"])
	}
}

func TestHeaderMiddleware_InvalidHeader(t *testing.T) {
	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		HeaderMiddleware(&HeaderConfig{
			Headers: map[string]string{
				"X-Invalid": "value\r\nX-Injected: malicious", // CRLF injection attempt
			},
		}),
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Should fail due to invalid header
	_, err = client.Get(ts.URL)
	if err == nil {
		t.Error("expected error for invalid header")
	}
}

func TestDefaultHeaderConfig(t *testing.T) {
	config := DefaultHeaderConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}
	if config.Headers != nil {
		t.Errorf("expected nil Headers, got: %v", config.Headers)
	}
}

func TestMetricsMiddleware(t *testing.T) {
	var metrics struct {
		method     string
		url        string
		statusCode int
		duration   time.Duration
		err        error
		called     bool
	}
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		MetricsMiddleware(&MetricsConfig{
			OnMetrics: func(method, url string, statusCode int, duration time.Duration, err error) {
				mu.Lock()
				defer mu.Unlock()
				metrics.method = method
				metrics.url = url
				metrics.statusCode = statusCode
				metrics.duration = duration
				metrics.err = err
				metrics.called = true
			},
		}),
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	_, err = client.Post(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if !metrics.called {
		t.Error("metrics callback was not called")
	}
	if metrics.method != "POST" {
		t.Errorf("expected method POST, got: %s", metrics.method)
	}
	if metrics.statusCode != http.StatusCreated {
		t.Errorf("expected status code %d, got: %d", http.StatusCreated, metrics.statusCode)
	}
	if metrics.duration < 0 {
		t.Error("expected non-negative duration")
	}
	if metrics.err != nil {
		t.Errorf("expected no error, got: %v", metrics.err)
	}
}

func TestMiddlewareCanModifyRequest(t *testing.T) {
	var receivedValue string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedValue = r.Header.Get("X-Modified-By-Middleware")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		func(next Handler) Handler {
			return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
				req.SetHeader("X-Modified-By-Middleware", "modified-value")
				return next(ctx, req)
			}
		},
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	_, err = client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if receivedValue != "modified-value" {
		t.Errorf("expected 'modified-value', got: %s", receivedValue)
	}
}

func TestMiddlewareCanModifyResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Original", "original-value")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		func(next Handler) Handler {
			return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
				resp, err := next(ctx, req)
				if resp != nil {
					resp.SetHeader("X-Modified", "modified-value")
				}
				return resp, err
			}
		},
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	result, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	modified := result.Response.Headers["X-Modified"]
	if len(modified) == 0 || modified[0] != "modified-value" {
		t.Errorf("expected modified header, got: %v", modified)
	}
}

func BenchmarkMiddlewareOverhead(b *testing.B) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	b.Run("NoMiddleware", func(b *testing.B) {
		cfg := testConfig()
		client, _ := New(cfg)
		defer client.Close()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = client.Get(ts.URL)
		}
	})

	b.Run("WithMiddleware", func(b *testing.B) {
		cfg := testConfig()
		cfg.Middleware.Middlewares = []MiddlewareFunc{
			func(next Handler) Handler {
				return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
					return next(ctx, req)
				}
			},
		}
		client, _ := New(cfg)
		defer client.Close()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = client.Get(ts.URL)
		}
	})

	b.Run("WithThreeMiddlewares", func(b *testing.B) {
		cfg := testConfig()
		cfg.Middleware.Middlewares = []MiddlewareFunc{
			func(next Handler) Handler {
				return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
					return next(ctx, req)
				}
			},
			func(next Handler) Handler {
				return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
					return next(ctx, req)
				}
			},
			func(next Handler) Handler {
				return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
					return next(ctx, req)
				}
			},
		}
		client, _ := New(cfg)
		defer client.Close()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = client.Get(ts.URL)
		}
	})
}

// mockRequest implements RequestMutator for testing
type mockRequest struct {
	method          string
	url             string
	headers         map[string]string
	queryParams     map[string]any
	body            any
	timeout         time.Duration
	maxRetries      int
	ctx             context.Context
	cookies         []http.Cookie
	followRedirects *bool
	maxRedirects    *int
}

func (m *mockRequest) Method() string                 { return m.method }
func (m *mockRequest) URL() string                    { return m.url }
func (m *mockRequest) Headers() map[string]string     { return m.headers }
func (m *mockRequest) QueryParams() map[string]any    { return m.queryParams }
func (m *mockRequest) Body() any                      { return m.body }
func (m *mockRequest) Timeout() time.Duration         { return m.timeout }
func (m *mockRequest) MaxRetries() int                { return m.maxRetries }
func (m *mockRequest) Context() context.Context       { return m.ctx }
func (m *mockRequest) Cookies() []http.Cookie         { return m.cookies }
func (m *mockRequest) FollowRedirects() *bool         { return m.followRedirects }
func (m *mockRequest) MaxRedirects() *int             { return m.maxRedirects }
func (m *mockRequest) SetMethod(v string)             { m.method = v }
func (m *mockRequest) SetURL(v string)                { m.url = v }
func (m *mockRequest) SetHeaders(v map[string]string) { m.headers = v }
func (m *mockRequest) SetHeader(k, v string) {
	if m.headers == nil {
		m.headers = make(map[string]string)
	}
	m.headers[k] = v
}
func (m *mockRequest) SetQueryParams(v map[string]any) { m.queryParams = v }
func (m *mockRequest) SetBody(v any)                   { m.body = v }
func (m *mockRequest) SetTimeout(v time.Duration)      { m.timeout = v }
func (m *mockRequest) SetMaxRetries(v int)             { m.maxRetries = v }
func (m *mockRequest) SetContext(v context.Context)    { m.ctx = v }
func (m *mockRequest) SetCookies(v []http.Cookie)      { m.cookies = v }
func (m *mockRequest) SetFollowRedirects(v *bool)      { m.followRedirects = v }
func (m *mockRequest) SetMaxRedirects(v *int)          { m.maxRedirects = v }
func (m *mockRequest) StreamBody() bool                { return false }
func (m *mockRequest) SetStreamBody(v bool)            {}

// mockResponse implements ResponseMutator for testing
type mockResponse struct {
	statusCode     int
	status         string
	proto          string
	headers        http.Header
	body           string
	rawBody        []byte
	contentLength  int64
	duration       time.Duration
	attempts       int
	cookies        []*http.Cookie
	redirectChain  []string
	redirectCount  int
	requestHeaders http.Header
	requestURL     string
	requestMethod  string
}

func (m *mockResponse) StatusCode() int             { return m.statusCode }
func (m *mockResponse) Status() string              { return m.status }
func (m *mockResponse) Proto() string               { return m.proto }
func (m *mockResponse) Headers() http.Header        { return m.headers }
func (m *mockResponse) Body() string                { return m.body }
func (m *mockResponse) RawBody() []byte             { return m.rawBody }
func (m *mockResponse) ContentLength() int64        { return m.contentLength }
func (m *mockResponse) Duration() time.Duration     { return m.duration }
func (m *mockResponse) Attempts() int               { return m.attempts }
func (m *mockResponse) Cookies() []*http.Cookie     { return m.cookies }
func (m *mockResponse) RedirectChain() []string     { return m.redirectChain }
func (m *mockResponse) RedirectCount() int          { return m.redirectCount }
func (m *mockResponse) RequestHeaders() http.Header { return m.requestHeaders }
func (m *mockResponse) RequestURL() string          { return m.requestURL }
func (m *mockResponse) RequestMethod() string       { return m.requestMethod }
func (m *mockResponse) SetStatusCode(v int)         { m.statusCode = v }
func (m *mockResponse) SetStatus(v string)          { m.status = v }
func (m *mockResponse) SetProto(v string)           { m.proto = v }
func (m *mockResponse) SetHeaders(v http.Header)    { m.headers = v }
func (m *mockResponse) SetHeader(k string, v ...string) {
	if m.headers == nil {
		m.headers = make(http.Header)
	}
	m.headers[k] = v
}
func (m *mockResponse) SetBody(v string)                { m.body = v }
func (m *mockResponse) SetRawBody(v []byte)             { m.rawBody = v }
func (m *mockResponse) SetContentLength(v int64)        { m.contentLength = v }
func (m *mockResponse) SetDuration(v time.Duration)     { m.duration = v }
func (m *mockResponse) SetAttempts(v int)               { m.attempts = v }
func (m *mockResponse) SetCookies(v []*http.Cookie)     { m.cookies = v }
func (m *mockResponse) SetRedirectChain(v []string)     { m.redirectChain = v }
func (m *mockResponse) SetRedirectCount(v int)          { m.redirectCount = v }
func (m *mockResponse) SetRequestHeaders(v http.Header) { m.requestHeaders = v }
func (m *mockResponse) SetRequestURL(v string)          { m.requestURL = v }
func (m *mockResponse) SetRequestMethod(v string)       { m.requestMethod = v }

// ============================================================================
// Audit Middleware Tests
// ============================================================================

func TestAuditMiddleware(t *testing.T) {
	var capturedEvent AuditEvent
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response")) // best-effort test response
	}))
	defer ts.Close()

	cfg := testConfig()
	auditCfg := DefaultAuditConfig()
	auditCfg.OnAudit = func(event AuditEvent) {
		mu.Lock()
		defer mu.Unlock()
		capturedEvent = event
	}
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		AuditMiddleware(auditCfg),
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	_, err = client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if capturedEvent.Method != "GET" {
		t.Errorf("expected method GET, got: %s", capturedEvent.Method)
	}
	if capturedEvent.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got: %d", http.StatusOK, capturedEvent.StatusCode)
	}
	if capturedEvent.Duration < 0 {
		t.Error("expected non-negative duration")
	}
}

func TestAuditMiddlewareWithContextValues(t *testing.T) {
	var capturedEvent AuditEvent
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	auditCfg := DefaultAuditConfig()
	auditCfg.OnAudit = func(event AuditEvent) {
		mu.Lock()
		defer mu.Unlock()
		capturedEvent = event
	}
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		AuditMiddleware(auditCfg),
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Create context with audit values
	ctx := context.WithValue(context.Background(), SourceIPKey, "192.168.1.100")
	ctx = context.WithValue(ctx, UserIDKey, "user-123")

	_, err = client.Request(ctx, "GET", ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if capturedEvent.SourceIP != "192.168.1.100" {
		t.Errorf("expected source IP '192.168.1.100', got: %s", capturedEvent.SourceIP)
	}
	if capturedEvent.UserID != "user-123" {
		t.Errorf("expected user ID 'user-123', got: %s", capturedEvent.UserID)
	}
}

func TestAuditMiddleware_ConfigVariants(t *testing.T) {
	tests := []struct {
		name           string
		config         *AuditConfig
		serverStatus   int
		expectedMethod string
		expectedStatus int
	}{
		{
			name: "JSON format with headers",
			config: &AuditConfig{
				Format:         "json",
				IncludeHeaders: true,
				SanitizeError:  true,
			},
			serverStatus:   http.StatusInternalServerError,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "JSON format with default config",
			config: func() *AuditConfig {
				c := DefaultAuditConfig()
				c.Format = "json"
				return c
			}(),
			serverStatus:   http.StatusOK,
			expectedMethod: "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Text format",
			config: &AuditConfig{
				Format: "text",
			},
			serverStatus:   http.StatusOK,
			expectedMethod: "GET",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedEvent AuditEvent
			var mu sync.Mutex

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.serverStatus)
			}))
			defer ts.Close()

			auditCfg := tt.config
			if auditCfg == nil {
				auditCfg = DefaultAuditConfig()
			}
			auditCfg.OnAudit = func(event AuditEvent) {
				mu.Lock()
				defer mu.Unlock()
				capturedEvent = event
			}
			cfg := testConfig()
			cfg.Middleware.Middlewares = []MiddlewareFunc{
				AuditMiddleware(auditCfg),
			}

			client, err := New(cfg)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}
			defer client.Close()

			_, err = client.Get(ts.URL)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}

			mu.Lock()
			defer mu.Unlock()

			if capturedEvent.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got: %d", tt.expectedStatus, capturedEvent.StatusCode)
			}
			if tt.expectedMethod != "" && capturedEvent.Method != tt.expectedMethod {
				t.Errorf("expected method %s, got: %s", tt.expectedMethod, capturedEvent.Method)
			}
		})
	}
}

func TestAuditMiddlewareNoCallbackIsNoOp(t *testing.T) {
	// No OnAudit callback set: the middleware is a no-op (unwrapped handler)
	// and must not panic when a request runs through it.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		AuditMiddleware(&AuditConfig{Format: "text"}),
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	if _, err := client.Get(ts.URL); err != nil {
		t.Fatalf("no-op audit middleware caused request failure: %v", err)
	}
}

func TestAuditMiddlewareWithError(t *testing.T) {
	var capturedEvent AuditEvent
	var mu sync.Mutex

	cfg := testConfig()
	auditCfg := DefaultAuditConfig()
	auditCfg.OnAudit = func(event AuditEvent) {
		mu.Lock()
		defer mu.Unlock()
		capturedEvent = event
	}
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		AuditMiddleware(auditCfg),
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Request to invalid URL should error
	_, _ = client.Get("http://invalid.invalid.unreachable/test")

	mu.Lock()
	defer mu.Unlock()

	if capturedEvent.Error == nil {
		t.Error("expected error to be captured")
	}
}

func TestDefaultAuditConfig(t *testing.T) {
	config := DefaultAuditConfig()

	if config == nil {
		t.Fatal("expected non-nil config")
	}
	if config.Format != "text" {
		t.Errorf("expected format 'text', got: %s", config.Format)
	}
	if config.IncludeHeaders {
		t.Error("expected IncludeHeaders to be false")
	}
	if len(config.MaskHeaders) == 0 {
		t.Error("expected MaskHeaders to have values")
	}
	if !config.SanitizeError {
		t.Error("expected SanitizeError to be true")
	}
}

func TestRequestIDMiddleware_ExistingHeader(t *testing.T) {
	var receivedID string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		RequestIDMiddleware(&RequestIDConfig{
			HeaderName: "X-Request-ID",
			Generator:  func() string { return "generated-id" },
		}),
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Set header explicitly - middleware should not overwrite
	_, err = client.Get(ts.URL, WithHeader("X-Request-ID", "explicit-id"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if receivedID != "explicit-id" {
		t.Errorf("expected 'explicit-id', got: %s", receivedID)
	}
}

func TestAuditEventMarshalJSON(t *testing.T) {
	event := AuditEvent{
		Timestamp:  time.Now(),
		Method:     "GET",
		URL:        "https://example.com/test",
		StatusCode: 200,
		Duration:   100 * time.Millisecond,
		Attempts:   1,
		Error:      fmt.Errorf("test error"),
		SourceIP:   "192.168.1.1",
		UserID:     "user-123",
	}

	data, err := event.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Verify the JSON contains expected fields
	jsonStr := string(data)
	if !strings.Contains(jsonStr, "GET") {
		t.Error("expected JSON to contain method")
	}
	if !strings.Contains(jsonStr, "durationMs") {
		t.Error("expected JSON to contain durationMs")
	}
	if !strings.Contains(jsonStr, "test error") {
		t.Error("expected JSON to contain error")
	}
}

func TestMaskStringHeaders(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		maskList   []string
		wantMasked []string
		wantPlain  []string
	}{
		{
			name:     "nil headers returns nil",
			headers:  nil,
			maskList: []string{"Authorization"},
		},
		{
			name:     "empty headers returns nil",
			headers:  map[string]string{},
			maskList: []string{"Authorization"},
		},
		{
			name:       "mask authorization",
			headers:    map[string]string{"Authorization": "Bearer secret"},
			maskList:   []string{"Authorization"},
			wantMasked: []string{"Authorization"},
		},
		{
			name:       "mask multiple headers",
			headers:    map[string]string{"Authorization": "Bearer token", "X-Custom": "visible"},
			maskList:   []string{"Authorization", "Cookie"},
			wantMasked: []string{"Authorization"},
			wantPlain:  []string{"X-Custom"},
		},
		{
			name:       "case insensitive mask match",
			headers:    map[string]string{"authorization": "Bearer token"},
			maskList:   []string{"Authorization"},
			wantMasked: []string{"authorization"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskStringHeaders(tt.headers, buildMaskSet(tt.maskList))
			if len(tt.headers) == 0 {
				if result != nil {
					t.Error("expected nil for empty/nil headers")
				}
				return
			}
			for _, k := range tt.wantMasked {
				if v, ok := result[k]; !ok || len(v) != 1 || v[0] != "[REDACTED]" {
					t.Errorf("header %q should be masked, got %v", k, v)
				}
			}
			for _, k := range tt.wantPlain {
				if v, ok := result[k]; !ok || len(v) != 1 || v[0] == "[REDACTED]" {
					t.Errorf("header %q should be plain, got %v", k, v)
				}
			}
		})
	}
}

func TestSanitizeCallbackError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		err          error
		rawURL       string
		sanitizedURL string
		wantContains string // substring expected in result error
		wantNil      bool
	}{
		{"nil error returns nil", nil, "http://user:pass@host", "http://user:***@host", "", true},
		{"empty rawURL returns err unchanged", fmt.Errorf("some error"), "", "http://host", "some error", false},
		{"identical URLs returns err unchanged", fmt.Errorf("fail: http://host/path"), "http://host/path", "http://host/path", "http://host/path", false},
		{"error containing raw URL gets sanitized", fmt.Errorf("connection to http://user:pass@host/path failed"), "http://user:pass@host/path", "http://user:***@host/path", "http://user:***@host/path", false},
		{"error not containing raw URL passes through", fmt.Errorf("network timeout"), "http://user:pass@host/path", "http://user:***@host/path", "network timeout", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeCallbackError(tt.err, tt.rawURL, tt.sanitizedURL)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil error")
			}
			if !strings.Contains(result.Error(), tt.wantContains) {
				t.Errorf("sanitizeCallbackError() = %q, want to contain %q", result.Error(), tt.wantContains)
			}
		})
	}
}

func TestMiddleware_BoundaryConditions(t *testing.T) {
	t.Parallel()

	t.Run("Chain with nil middleware slice", func(t *testing.T) {
		handler := Chain()
		if handler == nil {
			t.Error("Chain() with no args should return non-nil handler")
		}
	})

	// Nil-config middleware constructors are covered table-driven in
	// TestMiddleware_NilConfig.
}

// TestTimeoutMiddleware_RejectsStreaming verifies the middleware refuses
// streaming requests up front instead of letting the deferred cancel() abort
// the body stream mid-read with a misleading "context canceled" error.
func TestTimeoutMiddleware_RejectsStreaming(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		TimeoutMiddleware(&TimeoutMiddlewareConfig{Duration: 5 * time.Second}),
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	_, err = client.Get(ts.URL, WithStreamBody(true))
	if err == nil {
		t.Fatal("expected error for streaming request through TimeoutMiddleware, got nil")
	}
	if !strings.Contains(err.Error(), "incompatible with streaming") {
		t.Errorf("error should explain the incompatibility, got: %v", err)
	}
}

// TestSanitizeCallbackError_PreservesChain verifies the sanitized error keeps
// errors.Is/Unwrap access to the original while its message is redacted.
func TestSanitizeCallbackError_PreservesChain(t *testing.T) {
	raw := "https://user:secretpw@example.com/path"
	sanitized := "https://user:xxxxx@example.com/path"
	inner := fmt.Errorf("request to %s failed: %w", raw, context.DeadlineExceeded)

	got := sanitizeCallbackError(inner, raw, sanitized)
	if got == nil {
		t.Fatal("expected sanitized error, got nil")
	}
	if msg := got.Error(); strings.Contains(msg, "secretpw") {
		t.Errorf("message still contains credentials: %q", msg)
	}
	if !errors.Is(got, context.DeadlineExceeded) {
		t.Errorf("errors.Is must reach the original sentinel through the sanitized wrapper, got: %v", got)
	}

	// Passthrough cases: nil error, identical URLs, or no URL in message.
	if err := sanitizeCallbackError(nil, raw, sanitized); err != nil {
		t.Errorf("nil error should pass through, got %v", err)
	}
	plain := errors.New("unrelated failure")
	if err := sanitizeCallbackError(plain, raw, sanitized); !errors.Is(err, plain) {
		t.Errorf("message without raw URL should pass through unchanged, got %v", err)
	}
}

// TestBuildMiddlewareChain_RequestReplacement covers the facade's fallback
// path for a middleware that replaces the request with a non-*engine.Request
// RequestMutator: every accessor-visible field (method, URL, headers, query,
// body) must still be forwarded to the engine, and a nil request context must
// fall back to the call context.
func TestBuildMiddlewareChain_RequestReplacement(t *testing.T) {
	var gotMethod, gotHeader, gotQuery, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotHeader = r.Header.Get("X-Replaced")
		gotQuery = r.URL.Query().Get("q")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	replaced := &mockRequest{
		method:      "POST",
		url:         server.URL,
		headers:     map[string]string{"X-Replaced": "yes"},
		queryParams: map[string]any{"q": "replaced"},
		body:        "raw-body", // string body: forwarded verbatim, no codec ambiguity
		// ctx intentionally nil: exercises the reqCtx = ctx fallback
	}

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		func(next Handler) Handler {
			return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
				return next(ctx, replaced)
			}
		},
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer client.Close()

	if _, err := client.Get(server.URL); err != nil {
		t.Fatalf("request through replaced mutator failed: %v", err)
	}

	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST (replacement ignored)", gotMethod)
	}
	if gotHeader != "yes" {
		t.Errorf("X-Replaced header not forwarded: %q", gotHeader)
	}
	if gotQuery != "replaced" {
		t.Errorf("query param not forwarded: %q", gotQuery)
	}
	if gotBody != "raw-body" {
		t.Errorf("body not forwarded: %q, want raw-body", gotBody)
	}
}

// wrapperMutator wraps a RequestMutator by embedding it: every method
// delegates to the original request, but the wrapper itself is not a
// *engine.Request — the shape a request-replacing middleware produces.
type wrapperMutator struct {
	RequestMutator
}

// TestMiddlewareChain_RequestReplacement_ConcurrentHeaders is the concurrency
// regression test for the request-replacement fallback path. A delegating
// wrapper's Headers() returns the original engineReq's POOLED map; before the
// fallback switched to copying, the engine's putRequest and the facade's
// deferred ReleaseRequest both returned that same map to headersMapPool, so
// two concurrent requests could acquire the identical map — concurrent map
// writes plus header cross-talk. Each worker must observe only its own
// echoed X-Worker value; run with -race.
func TestMiddlewareChain_RequestReplacement_ConcurrentHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("X-Worker")))
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		func(next Handler) Handler {
			return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
				return next(ctx, &wrapperMutator{RequestMutator: req})
			}
		},
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer client.Close()

	const workers = 8
	const iterations = 50

	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			want := strconv.Itoa(id)
			for i := 0; i < iterations; i++ {
				res, err := client.Get(server.URL, WithHeader("X-Worker", want))
				if err != nil {
					errCh <- fmt.Errorf("worker %d: %w", id, err)
					return
				}
				if got := res.Body(); got != want {
					errCh <- fmt.Errorf("worker %d iter %d: echoed header %q, want %q (pooled map cross-talk)", id, i, got, want)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
