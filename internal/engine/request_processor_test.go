package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// REQUEST BUILDER TEST HELPERS
// ============================================================================

// testRequestBuilder creates a Request with the given parameters using setters.
// This helper function is used because Request fields are now private.
func testRequestBuilder() *testRequest {
	return &testRequest{}
}

type testRequest struct {
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

func (tr *testRequest) Method(v string) *testRequest              { tr.method = v; return tr }
func (tr *testRequest) URL(v string) *testRequest                 { tr.url = v; return tr }
func (tr *testRequest) Headers(v map[string]string) *testRequest  { tr.headers = v; return tr }
func (tr *testRequest) QueryParams(v map[string]any) *testRequest { tr.queryParams = v; return tr }
func (tr *testRequest) Body(v any) *testRequest                   { tr.body = v; return tr }
func (tr *testRequest) Timeout(v time.Duration) *testRequest      { tr.timeout = v; return tr }
func (tr *testRequest) MaxRetries(v int) *testRequest             { tr.maxRetries = v; return tr }
func (tr *testRequest) Context(v context.Context) *testRequest    { tr.ctx = v; return tr }
func (tr *testRequest) Cookies(v []http.Cookie) *testRequest      { tr.cookies = v; return tr }
func (tr *testRequest) FollowRedirects(v *bool) *testRequest      { tr.followRedirects = v; return tr }
func (tr *testRequest) MaxRedirects(v *int) *testRequest          { tr.maxRedirects = v; return tr }

func (tr *testRequest) Build() *Request {
	req := &Request{}
	req.SetMethod(tr.method)
	req.SetURL(tr.url)
	if tr.headers != nil {
		req.SetHeaders(tr.headers)
	}
	if tr.queryParams != nil {
		req.SetQueryParams(tr.queryParams)
	}
	req.SetBody(tr.body)
	req.SetTimeout(tr.timeout)
	req.SetMaxRetries(tr.maxRetries)
	req.SetContext(tr.ctx)
	req.SetCookies(tr.cookies)
	req.SetFollowRedirects(tr.followRedirects)
	req.SetMaxRedirects(tr.maxRedirects)
	return req
}

// ============================================================================
// REQUEST PROCESSOR TESTS
// ============================================================================

func TestRequestProcessor_Build(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:     true,
		ValidateHeaders: true,
		UserAgent:       "TestClient/1.0",
	}

	processor := newRequestProcessor(config)

	tests := []struct {
		name     string
		request  *Request
		validate func(*testing.T, *http.Request)
	}{
		{
			name: "Simple GET request",
			request: testRequestBuilder().
				Method("GET").
				URL("https://api.example.com/users").
				Context(context.Background()).
				Headers(map[string]string{
					"Accept": "application/json",
				}).
				Build(),
			validate: func(t *testing.T, req *http.Request) {
				if req.Method != "GET" {
					t.Errorf("Expected method GET, got %s", req.Method)
				}
				if req.URL.String() != "https://api.example.com/users" {
					t.Errorf("Expected URL https://api.example.com/users, got %s", req.URL.String())
				}
				if req.Header.Get("Accept") != "application/json" {
					t.Errorf("Expected Accept header application/json, got %s", req.Header.Get("Accept"))
				}
			},
		},
		{
			name: "POST with JSON body",
			request: testRequestBuilder().
				Method("POST").
				URL("https://api.example.com/users").
				Context(context.Background()).
				Headers(map[string]string{
					"Content-Type": "application/json",
				}).
				Body(map[string]interface{}{
					"name":  "John Doe",
					"email": "john@example.com",
				}).
				Build(),
			validate: func(t *testing.T, req *http.Request) {
				if req.Method != "POST" {
					t.Errorf("Expected method POST, got %s", req.Method)
				}
				if req.Header.Get("Content-Type") != "application/json" {
					t.Errorf("Expected Content-Type application/json, got %s", req.Header.Get("Content-Type"))
				}
				if req.Body == nil {
					t.Error("Expected request body, got nil")
				}

				// Read and validate body
				bodyBytes, err := io.ReadAll(req.Body)
				if err != nil {
					t.Errorf("Failed to read body: %v", err)
				}

				var data map[string]interface{}
				if err := json.Unmarshal(bodyBytes, &data); err != nil {
					t.Errorf("Failed to unmarshal JSON body: %v", err)
				}

				if data["name"] != "John Doe" {
					t.Errorf("Expected name 'John Doe', got %v", data["name"])
				}
			},
		},
		{
			name: "Request with query parameters",
			request: testRequestBuilder().
				Method("GET").
				URL("https://api.example.com/users").
				Context(context.Background()).
				QueryParams(map[string]any{
					"page":   1,
					"limit":  10,
					"filter": "active",
				}).
				Build(),
			validate: func(t *testing.T, req *http.Request) {
				query := req.URL.Query()
				if query.Get("page") != "1" {
					t.Errorf("Expected page=1, got %s", query.Get("page"))
				}
				if query.Get("limit") != "10" {
					t.Errorf("Expected limit=10, got %s", query.Get("limit"))
				}
				if query.Get("filter") != "active" {
					t.Errorf("Expected filter=active, got %s", query.Get("filter"))
				}
			},
		},
		{
			name: "Request with cookies",
			request: testRequestBuilder().
				Method("GET").
				URL("https://api.example.com/users").
				Context(context.Background()).
				Cookies([]http.Cookie{
					{Name: "session_id", Value: "abc123"},
					{Name: "user_pref", Value: "dark_mode"},
				}).
				Build(),
			validate: func(t *testing.T, req *http.Request) {
				cookies := req.Cookies()
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
		{
			name: "Request with timeout",
			request: testRequestBuilder().
				Method("GET").
				URL("https://api.example.com/users").
				Context(context.Background()).
				Timeout(15 * time.Second).
				Build(),
			validate: func(t *testing.T, req *http.Request) {
				if req.Context() == nil {
					t.Error("Expected context to be set")
				}
			},
		},
		{
			name: "Request with string body",
			request: testRequestBuilder().
				Method("POST").
				URL("https://api.example.com/data").
				Context(context.Background()).
				Headers(map[string]string{
					"Content-Type": "text/plain",
				}).
				Body("Hello, World!").
				Build(),
			validate: func(t *testing.T, req *http.Request) {
				if req.Body == nil {
					t.Error("Expected request body, got nil")
				}

				bodyBytes, err := io.ReadAll(req.Body)
				if err != nil {
					t.Errorf("Failed to read body: %v", err)
				}

				if string(bodyBytes) != "Hello, World!" {
					t.Errorf("Expected body 'Hello, World!', got '%s'", string(bodyBytes))
				}
			},
		},
		{
			name: "Request with byte array body",
			request: testRequestBuilder().
				Method("POST").
				URL("https://api.example.com/data").
				Context(context.Background()).
				Headers(map[string]string{
					"Content-Type": "application/octet-stream",
				}).
				Body([]byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}). // "Hello"
				Build(),
			validate: func(t *testing.T, req *http.Request) {
				if req.Body == nil {
					t.Error("Expected request body, got nil")
				}

				bodyBytes, err := io.ReadAll(req.Body)
				if err != nil {
					t.Errorf("Failed to read body: %v", err)
				}

				expected := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}
				if !bytes.Equal(bodyBytes, expected) {
					t.Errorf("Expected body %v, got %v", expected, bodyBytes)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpReq, err := processor.Build(tt.request)
			if err != nil {
				t.Fatalf("Failed to build request: %v", err)
			}

			tt.validate(t, httpReq)
		})
	}
}

func TestRequestProcessor_BuildErrors(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:     true,
		ValidateHeaders: true,
	}

	processor := newRequestProcessor(config)

	tests := []struct {
		name        string
		request     *Request
		expectError bool
		wantMethod  string // if set, assert the built request's method (post-normalization)
		wantCtxSet  bool   // if true, assert the built request has a non-nil context
	}{
		{
			name: "Invalid URL",
			request: testRequestBuilder().
				Method("GET").
				URL("://invalid-url").
				Context(context.Background()).
				Build(),
			expectError: true,
		},
		{
			// Build normalizes an empty method to "GET" (request.go:633-635) —
			// this is intentional defaulting, not a validation gap.
			name: "Empty method defaults to GET",
			request: testRequestBuilder().
				Method("").
				URL("https://api.example.com/users").
				Context(context.Background()).
				Build(),
			expectError: false,
			wantMethod:  "GET",
		},
		{
			// Build defaults a nil context to context.Background (request.go:637-639).
			name: "Nil context defaults to background",
			request: testRequestBuilder().
				Method("GET").
				URL("https://api.example.com/users").
				Build(),
			expectError: false,
			wantCtxSet:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpReq, err := processor.Build(tt.request)

			if tt.expectError && err == nil {
				t.Error("Expected error, got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Verify the documented defaulting behavior when Build succeeds.
			if err == nil && httpReq != nil {
				if tt.wantMethod != "" && httpReq.Method != tt.wantMethod {
					t.Errorf("Method = %q, want %q", httpReq.Method, tt.wantMethod)
				}
				if tt.wantCtxSet && httpReq.Context() == nil {
					t.Error("Expected non-nil context after defaulting")
				}
			}
		})
	}
}

func TestRequestProcessor_BodySerialization(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:     true,
		ValidateHeaders: true,
	}

	processor := newRequestProcessor(config)

	tests := []struct {
		name         string
		body         interface{}
		expectedType string
		validate     func(*testing.T, io.Reader)
	}{
		{
			name:         "JSON object",
			body:         map[string]interface{}{"key": "value"},
			expectedType: "application/json",
			validate: func(t *testing.T, reader io.Reader) {
				bodyBytes, err := io.ReadAll(reader)
				if err != nil {
					t.Errorf("Failed to read body: %v", err)
				}

				var data map[string]interface{}
				if err := json.Unmarshal(bodyBytes, &data); err != nil {
					t.Errorf("Failed to unmarshal JSON: %v", err)
				}

				if data["key"] != "value" {
					t.Errorf("Expected key=value, got %v", data["key"])
				}
			},
		},
		{
			name:         "String body",
			body:         "test string",
			expectedType: "text/plain",
			validate: func(t *testing.T, reader io.Reader) {
				bodyBytes, err := io.ReadAll(reader)
				if err != nil {
					t.Errorf("Failed to read body: %v", err)
				}

				if string(bodyBytes) != "test string" {
					t.Errorf("Expected 'test string', got '%s'", string(bodyBytes))
				}
			},
		},
		{
			name:         "Byte array body",
			body:         []byte("test bytes"),
			expectedType: "application/octet-stream",
			validate: func(t *testing.T, reader io.Reader) {
				bodyBytes, err := io.ReadAll(reader)
				if err != nil {
					t.Errorf("Failed to read body: %v", err)
				}

				if string(bodyBytes) != "test bytes" {
					t.Errorf("Expected 'test bytes', got '%s'", string(bodyBytes))
				}
			},
		},
		{
			name:         "URL values (form)",
			body:         url.Values{"key": []string{"value1", "value2"}},
			expectedType: "application/x-www-form-urlencoded",
			validate: func(t *testing.T, reader io.Reader) {
				bodyBytes, err := io.ReadAll(reader)
				if err != nil {
					t.Errorf("Failed to read body: %v", err)
				}

				bodyStr := string(bodyBytes)
				// URL values will be serialized as JSON, not form format
				if !strings.Contains(bodyStr, "key") {
					t.Errorf("Expected body to contain 'key', got '%s'", bodyStr)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := testRequestBuilder().
				Method("POST").
				URL("https://api.example.com/data").
				Context(context.Background()).
				Body(tt.body).
				Build()

			httpReq, err := processor.Build(request)
			if err != nil {
				t.Fatalf("Failed to build request: %v", err)
			}

			if httpReq.Body != nil {
				tt.validate(t, httpReq.Body)
			}
		})
	}
}

func TestRequestProcessor_HeaderHandling(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:     true,
		ValidateHeaders: true,
		UserAgent:       "TestClient/1.0",
		Headers: map[string]string{
			"X-Default-Header": "default-value",
		},
	}

	processor := newRequestProcessor(config)

	request := testRequestBuilder().
		Method("GET").
		URL("https://api.example.com/users").
		Context(context.Background()).
		Headers(map[string]string{
			"Accept":          "application/json",
			"X-Custom-Header": "custom-value",
		}).
		Build()

	httpReq, err := processor.Build(request)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}

	// Check default headers
	if httpReq.Header.Get("X-Default-Header") != "default-value" {
		t.Errorf("Expected X-Default-Header 'default-value', got '%s'", httpReq.Header.Get("X-Default-Header"))
	}

	// Check custom headers
	if httpReq.Header.Get("Accept") != "application/json" {
		t.Errorf("Expected Accept 'application/json', got '%s'", httpReq.Header.Get("Accept"))
	}

	if httpReq.Header.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("Expected X-Custom-Header 'custom-value', got '%s'", httpReq.Header.Get("X-Custom-Header"))
	}

	// Check User-Agent
	if httpReq.Header.Get("User-Agent") != "TestClient/1.0" {
		t.Errorf("Expected User-Agent 'TestClient/1.0', got '%s'", httpReq.Header.Get("User-Agent"))
	}
}

func TestRequestProcessor_QueryParameterHandling(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		ValidateURL:     true,
		ValidateHeaders: true,
	}

	processor := newRequestProcessor(config)

	tests := []struct {
		name        string
		baseURL     string
		queryParams map[string]any
		expected    string
	}{
		{
			name:    "URL without existing query",
			baseURL: "https://api.example.com/users",
			queryParams: map[string]any{
				"page":  1,
				"limit": 10,
			},
			expected: "https://api.example.com/users?limit=10&page=1",
		},
		{
			name:    "URL with existing query",
			baseURL: "https://api.example.com/users?sort=name",
			queryParams: map[string]any{
				"page":  1,
				"limit": 10,
			},
			expected: "https://api.example.com/users?sort=name&limit=10&page=1",
		},
		{
			name:    "Mixed parameter types",
			baseURL: "https://api.example.com/search",
			queryParams: map[string]any{
				"q":      "golang",
				"count":  100,
				"active": true,
			},
			expected: "https://api.example.com/search?active=true&count=100&q=golang",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := testRequestBuilder().
				Method("GET").
				URL(tt.baseURL).
				Context(context.Background()).
				QueryParams(tt.queryParams).
				Build()

			httpReq, err := processor.Build(request)
			if err != nil {
				t.Fatalf("Failed to build request: %v", err)
			}

			// Parse expected URL and actual URL for comparison
			expectedURL, err := url.Parse(tt.expected)
			if err != nil {
				t.Fatalf("Failed to parse expected URL: %v", err)
			}

			expectedQuery := expectedURL.Query()
			actualQuery := httpReq.URL.Query()

			for key, expectedValues := range expectedQuery {
				actualValues := actualQuery[key]
				if len(actualValues) != len(expectedValues) {
					t.Errorf("Query param %s: expected %v, got %v", key, expectedValues, actualValues)
					continue
				}

				for i, expectedValue := range expectedValues {
					if actualValues[i] != expectedValue {
						t.Errorf("Query param %s[%d]: expected %s, got %s", key, i, expectedValue, actualValues[i])
					}
				}
			}
		})
	}
}

// ============================================================================
// REQUEST PROCESSOR EDGE CASE TESTS
// ============================================================================

func TestRequestProcessor_EdgeCases(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		MaxResponseBodySize: 50 * 1024 * 1024,
	}

	processor := newRequestProcessor(config)

	t.Run("Very long URL", func(t *testing.T) {
		longPath := strings.Repeat("a", 2000)
		request := testRequestBuilder().
			Method("GET").
			URL("https://api.example.com/" + longPath).
			Context(context.Background()).
			Build()

		_, err := processor.Build(request)
		// Should be able to handle long URLs (within reasonable limits)
		if err != nil {
			t.Errorf("Unexpected error for long URL: %v", err)
		}
	})

	t.Run("Many query parameters", func(t *testing.T) {
		params := make(map[string]any)
		for i := 0; i < 100; i++ {
			params[fmt.Sprintf("param%d", i)] = fmt.Sprintf("value%d", i)
		}

		request := testRequestBuilder().
			Method("GET").
			URL("https://api.example.com/test").
			Context(context.Background()).
			QueryParams(params).
			Build()

		httpReq, err := processor.Build(request)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		query := httpReq.URL.Query()
		if len(query) != 100 {
			t.Errorf("Expected 100 query parameters, got %d", len(query))
		}
	})

	t.Run("Many headers", func(t *testing.T) {
		headers := make(map[string]string)
		for i := 0; i < 50; i++ {
			headers[fmt.Sprintf("X-Header-%d", i)] = fmt.Sprintf("value-%d", i)
		}

		request := testRequestBuilder().
			Method("GET").
			URL("https://api.example.com/test").
			Context(context.Background()).
			Headers(headers).
			Build()

		httpReq, err := processor.Build(request)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Check that all headers are set
		for key, expectedValue := range headers {
			actualValue := httpReq.Header.Get(key)
			if actualValue != expectedValue {
				t.Errorf("Expected header %s=%s, got %s", key, expectedValue, actualValue)
			}
		}
	})
}
