package httpc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
		LoggingMiddleware(logger),
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
		RequestIDMiddleware("X-Request-ID", func() string {
			return "test-request-id-123"
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
		TimeoutMiddleware(10 * time.Millisecond),
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
		HeaderMiddleware(map[string]string{
			"X-Custom-Header": "custom-value",
			"Authorization":   "Bearer test-token",
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
		MetricsMiddleware(func(method, url string, statusCode int, duration time.Duration, err error) {
			mu.Lock()
			defer mu.Unlock()
			metrics.method = method
			metrics.url = url
			metrics.statusCode = statusCode
			metrics.duration = duration
			metrics.err = err
			metrics.called = true
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
	if metrics.duration <= 0 {
		t.Error("expected positive duration")
	}
	if metrics.err != nil {
		t.Errorf("expected no error, got: %v", metrics.err)
	}
}

func TestClient_NoMiddleware_Succeeds(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Client without middlewares
	cfg := testConfig()
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Should work normally
	_, err = client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
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
		w.Write([]byte("response"))
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		AuditMiddleware(func(event AuditEvent) {
			mu.Lock()
			defer mu.Unlock()
			capturedEvent = event
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

	mu.Lock()
	defer mu.Unlock()

	if capturedEvent.Method != "GET" {
		t.Errorf("expected method GET, got: %s", capturedEvent.Method)
	}
	if capturedEvent.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got: %d", http.StatusOK, capturedEvent.StatusCode)
	}
	if capturedEvent.Duration <= 0 {
		t.Error("expected positive duration")
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
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		AuditMiddleware(func(event AuditEvent) {
			mu.Lock()
			defer mu.Unlock()
			capturedEvent = event
		}),
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

func TestAuditMiddlewareWithConfig(t *testing.T) {
	var capturedEvent AuditEvent
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		AuditMiddlewareWithConfig(func(event AuditEvent) {
			mu.Lock()
			defer mu.Unlock()
			capturedEvent = event
		}, &AuditMiddlewareConfig{
			Format:         "json",
			IncludeHeaders: true,
			SanitizeError:  true,
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

	mu.Lock()
	defer mu.Unlock()

	if capturedEvent.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status %d, got: %d", http.StatusInternalServerError, capturedEvent.StatusCode)
	}
}

func TestAuditMiddlewareWithConfigJSON(t *testing.T) {
	var capturedEvent AuditEvent
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	auditCfg := DefaultAuditMiddlewareConfig()
	auditCfg.Format = "json"

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		AuditMiddlewareWithConfig(func(event AuditEvent) {
			mu.Lock()
			defer mu.Unlock()
			capturedEvent = event
		}, auditCfg),
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
}

func TestAuditMiddlewareWithError(t *testing.T) {
	var capturedEvent AuditEvent
	var mu sync.Mutex

	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		AuditMiddleware(func(event AuditEvent) {
			mu.Lock()
			defer mu.Unlock()
			capturedEvent = event
		}),
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

func TestDefaultAuditMiddlewareConfig(t *testing.T) {
	config := DefaultAuditMiddlewareConfig()

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
}

func TestRequestIDMiddleware_NilGenerator(t *testing.T) {
	var receivedID string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	// Pass nil generator - should use default
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		RequestIDMiddleware("X-Request-ID", nil),
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

	if receivedID == "" {
		t.Error("expected request ID to be set")
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
		RequestIDMiddleware("X-Request-ID", func() string { return "generated-id" }),
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

func TestHeaderMiddleware_InvalidHeader(t *testing.T) {
	cfg := testConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{
		HeaderMiddleware(map[string]string{
			"X-Invalid": "value\r\nX-Injected: malicious", // CRLF injection attempt
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
