package httpc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// BASELINE BENCHMARKS - Measure current performance
// ============================================================================

func BenchmarkClient_SimpleGET(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer func() { _ = client.Close() }()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Get(server.URL)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClient_POST_JSON(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer func() { _ = client.Close() }()

	payload := map[string]interface{}{
		"name":  "test",
		"value": 123,
		"tags":  []string{"a", "b", "c"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Post(server.URL, WithJSON(payload))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClient_Concurrent_Requests(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer func() { _ = client.Close() }()

	concurrency := []int{1, 10, 50, 100}

	for _, c := range concurrency {
		b.Run(fmt.Sprintf("Concurrency_%d", c), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_, err := client.Get(server.URL)
					if err != nil {
						b.Error(err)
					}
				}
			})
		})
	}
}

// ============================================================================
// MICRO-BENCHMARKS - Isolate internal hot-path operations
// ============================================================================

func BenchmarkMicro_Headers(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Get(server.URL,
			WithHeader("X-Request-Id", "abc-123-def"),
			WithHeader("X-Custom-1", "value1"),
			WithHeader("X-Custom-2", "value2"),
			WithHeader("Accept", "application/json"),
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMicro_ManyQueryParams(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Get(server.URL,
			WithQuery("page", 1),
			WithQuery("limit", 50),
			WithQuery("sort", "name"),
			WithQuery("order", "asc"),
			WithQuery("filter[status]", "active"),
			WithQuery("filter[type]", "premium"),
			WithQuery("search", "hello world"),
			WithQuery("fields", "id,name,email"),
			WithQuery("embed", "profile,settings"),
			WithQuery("locale", "en_US"),
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMicro_ResultReuse(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","data":[1,2,3]}`))
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := client.Get(server.URL)
		if err != nil {
			b.Fatal(err)
		}
		_ = result.Body() // consume result
	}
}

// ============================================================================
// MEMORY ALLOCATION BENCHMARKS
// ============================================================================

func BenchmarkClient_MemoryAllocation_SmallResponse(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Small response"))
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resp, err := client.Get(server.URL)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body
	}
}

func BenchmarkClient_MemoryAllocation_LargeResponse(b *testing.B) {
	largeBody := strings.Repeat("x", 64*1024) // 64KB

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(largeBody))
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resp, err := client.Get(server.URL)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.RawBody
	}
}

// ============================================================================
// RETRY AND TIMEOUT BENCHMARKS
// ============================================================================

func BenchmarkClient_WithRetry(b *testing.B) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts%3 != 0 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Retry.MaxRetries = 3
	config.Retry.Delay = 1 * time.Millisecond
	config.Security.AllowPrivateIPs = true

	client, _ := New(config)
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = client.Get(server.URL)
	}
}

func BenchmarkClient_WithTimeout(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Get(server.URL, WithTimeout(100*time.Millisecond))
		if err != nil {
			b.Error(err)
		}
	}
}

// ============================================================================
// CONTEXT CANCELLATION BENCHMARKS
// ============================================================================

func BenchmarkClient_ContextCancellation(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		_, _ = client.Request(ctx, "GET", server.URL)
		cancel()
	}
}

// ============================================================================
// DEFAULT CLIENT BENCHMARKS
// ============================================================================

func BenchmarkDefaultClient_Get(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	// Ensure default client is initialized
	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	_ = SetDefaultClient(client)
	defer func() { _ = CloseDefaultClient() }()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := Get(server.URL)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ============================================================================
// HEADER MANIPULATION BENCHMARKS
// ============================================================================

func BenchmarkClient_WithHeaders(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	headers := map[string]string{
		"X-Custom-1": "value1",
		"X-Custom-2": "value2",
		"X-Custom-3": "value3",
		"X-Custom-4": "value4",
		"X-Custom-5": "value5",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Get(server.URL, WithHeaderMap(headers))
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ============================================================================
// RESULT OBJECT BENCHMARKS
// ============================================================================

func BenchmarkResult_ConvenienceMethods(b *testing.B) {
	result := &Result{
		Request: &RequestInfo{
			Cookies: []*http.Cookie{
				{Name: "session", Value: "abc123"},
				{Name: "token", Value: "xyz789"},
			},
		},
		Response: &ResponseInfo{
			StatusCode: 200,
			Body:       "test body content",
			RawBody:    []byte("test body content"),
			Cookies: []*http.Cookie{
				{Name: "resp1", Value: "val1"},
				{Name: "resp2", Value: "val2"},
			},
		},
		Meta: &RequestMeta{
			Duration: 100 * time.Millisecond,
			Attempts: 1,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = result.Body()
		_ = result.StatusCode()
		_ = result.RequestCookies()
		_ = result.ResponseCookies()
		_ = result.IsSuccess()
	}
}

func BenchmarkResult_CookieAccess(b *testing.B) {
	result := &Result{
		Response: &ResponseInfo{
			Cookies: []*http.Cookie{
				{Name: "cookie1", Value: "value1"},
				{Name: "cookie2", Value: "value2"},
				{Name: "cookie3", Value: "value3"},
				{Name: "session", Value: "abc123"},
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = result.GetCookie("session")
		_ = result.HasCookie("session")
	}
}

func BenchmarkResult_Unmarshal(b *testing.B) {
	result := &Result{
		Response: &ResponseInfo{
			RawBody: []byte(`{"name":"John","age":30,"email":"john@example.com"}`),
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var data map[string]interface{}
		_ = result.Unmarshal(&data)
	}
}

func BenchmarkResult_String(b *testing.B) {
	result := &Result{
		Response: &ResponseInfo{
			StatusCode:    200,
			Status:        "200 OK",
			ContentLength: 1024,
			Body:          "test response body",
		},
		Meta: &RequestMeta{
			Duration: 50 * time.Millisecond,
			Attempts: 1,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = result.String()
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func newBenchmarkClient() (Client, error) {
	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	config.Retry.MaxRetries = 0
	return New(config)
}

// ============================================================================
// MULTIPART FORM BENCHMARKS
// ============================================================================

func BenchmarkClient_MultipartForm(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		form := &FormData{
			Fields: map[string]string{
				"username": "testuser",
				"email":    "test@example.com",
				"message":  "This is a test message for benchmarking",
			},
			Files: map[string]*FileData{
				"document": {
					Filename:    "test.txt",
					Content:     []byte("Test file content for benchmarking purposes"),
					ContentType: "text/plain",
				},
			},
		}
		_, err := client.Post(server.URL, WithFormData(form))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClient_MultipartForm_LargeFiles(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	// Create 50KB file content
	largeContent := make([]byte, 50*1024)
	for i := range largeContent {
		largeContent[i] = byte('A' + (i % 26))
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		form := &FormData{
			Files: map[string]*FileData{
				"file": {
					Filename:    "largefile.bin",
					Content:     largeContent,
					ContentType: "application/octet-stream",
				},
			},
		}
		_, err := client.Post(server.URL, WithFormData(form))
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ============================================================================
// QUERY PARAMS BENCHMARKS
// ============================================================================

func BenchmarkClient_QueryParams(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Get(server.URL,
			WithQuery("page", "1"),
			WithQuery("limit", "100"),
			WithQuery("sort", "created_at"),
			WithQuery("order", "desc"),
			WithQuery("filter", "active"),
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClient_QueryParams_Typed(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Get(server.URL,
			WithQuery("page", 1),
			WithQuery("limit", 100),
			WithQuery("active", true),
			WithQuery("price", 99.99),
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ============================================================================
// COMPONENT-LEVEL BENCHMARKS - Isolate specific operations
// ============================================================================

func BenchmarkQueryEncode(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Get(server.URL,
			WithQuery("page", 1),
			WithQuery("limit", 100),
			WithQuery("sort", "created_at"),
			WithQuery("search", "hello world"),
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMultipartBuild(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		form := &FormData{
			Fields: map[string]string{
				"username": "testuser",
				"email":    "test@example.com",
			},
			Files: map[string]*FileData{
				"avatar": {
					Filename:    "avatar.png",
					Content:     []byte(strings.Repeat("x", 1024)),
					ContentType: "image/png",
				},
			},
		}
		_, err := client.Post(server.URL, WithFormData(form))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResult_Unmarshal_Opt(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"test","value":123,"nested":{"key":"value"},"items":[1,2,3,4,5]}`))
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	type TestResponse struct {
		Name   string               `json:"name"`
		Value  int                  `json:"value"`
		Nested struct{ Key string } `json:"nested"`
		Items  []int                `json:"items"`
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := client.Get(server.URL)
		if err != nil {
			b.Fatal(err)
		}
		var resp TestResponse
		if err := result.Unmarshal(&resp); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConcurrent_SameURL(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := client.Get(server.URL)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func BenchmarkConcurrent_DifferentURLs(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer client.Close()

	b.ResetTimer()
	b.ReportAllocs()

	var counter int64

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			url := fmt.Sprintf("%s?req=%d", server.URL, i)
			_, err := client.Get(url)
			if err != nil {
				b.Error(err)
			}
			i++
		}
		_ = counter
	})
}

// BenchmarkClient_WithConfigHeaders measures end-to-end performance when the
// client has default headers in its config (exercises pre-canonicalization).
func BenchmarkClient_WithConfigHeaders(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	config.Retry.MaxRetries = 0
	config.Defaults.Headers = map[string]string{
		"X-Custom-Header-1": "value1",
		"X-Custom-Header-2": "value2",
		"Accept":            "application/json",
	}
	client, _ := New(config)
	defer func() { _ = client.Close() }()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Get(server.URL)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkClient_WithCookies measures end-to-end performance with per-request
// cookies (exercises the batch cookie header builder).
func BenchmarkClient_WithCookies(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, _ := newBenchmarkClient()
	defer func() { _ = client.Close() }()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Get(server.URL,
			WithCookie(http.Cookie{Name: "session_id", Value: "abc123def456"}),
			WithCookie(http.Cookie{Name: "csrf_token", Value: "xyz789"}),
			WithCookie(http.Cookie{Name: "user_pref", Value: "dark_mode"}),
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}
