package httpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cybergodev/httpc/internal/engine"
	"github.com/cybergodev/httpc/internal/validation"
)

// ============================================================================
// REQUEST TESTS - Headers, cookies, query params, body, options
// Consolidates: options_test.go, cookie_*.go, request_headers_test.go
// ============================================================================

// ----------------------------------------------------------------------------
// Headers
// ----------------------------------------------------------------------------

func TestRequest_Headers(t *testing.T) {
	t.Run("SingleHeaders", func(t *testing.T) {
		tests := []struct {
			name       string
			key        string
			value      string
			optionFunc func(string, string) RequestOption
		}{
			{"WithHeader", "X-Custom-Header", "custom-value", WithHeader},
			{"AcceptJSON", "Accept", "application/json", WithHeader},
			{"AcceptXML", "Accept", "application/xml", WithHeader},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var gotKey, gotVal string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					gotKey = tt.key
					gotVal = r.Header.Get(tt.key)
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				client, _ := newTestClient()
				defer func() { _ = client.Close() }()

				_, err := client.Get(server.URL, tt.optionFunc(tt.key, tt.value))
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}
				if gotVal != tt.value {
					t.Errorf("Expected %s: %s, got %s", gotKey, tt.value, gotVal)
				}
			})
		}
	})

	t.Run("WithHeaderMap", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Header-1") != "value1" {
				t.Error("Expected X-Header-1: value1")
			}
			if r.Header.Get("X-Header-2") != "value2" {
				t.Error("Expected X-Header-2: value2")
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		_, err := client.Get(server.URL, WithHeaderMap(map[string]string{
			"X-Header-1": "value1",
			"X-Header-2": "value2",
		}))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithUserAgent", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("User-Agent") != "custom-agent/1.0" {
				t.Errorf("Expected User-Agent: custom-agent/1.0, got %s", r.Header.Get("User-Agent"))
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		_, err := client.Get(server.URL, WithUserAgent("custom-agent/1.0"))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("RequestHeadersInspection", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		resp, err := client.Get(server.URL,
			WithHeader("X-Custom", "test-value"),
			WithHeader("X-Another", "another-value"),
		)
		if err != nil {
			t.Fatal(err)
		}

		if resp.Request == nil || resp.Request.Headers == nil {
			t.Fatal("Request headers not captured")
		}
		if resp.Request.Headers.Get("X-Custom") != "test-value" {
			t.Error("X-Custom header not captured correctly")
		}
		if resp.Request.Headers.Get("X-Another") != "another-value" {
			t.Error("X-Another header not captured correctly")
		}
	})
}

// ----------------------------------------------------------------------------
// Authentication
// ----------------------------------------------------------------------------

func TestRequest_Authentication(t *testing.T) {
	t.Run("WithBasicAuth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			if !ok || username != "user" || password != "pass" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		resp, err := client.Get(server.URL, WithBasicAuth("user", "pass"))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		if resp.StatusCode() != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode())
		}
	})

	authErrorCases := []struct {
		name string
		opt  RequestOption
	}{
		{"EmptyUsername", WithBasicAuth("", "pass")},
		{"EmptyBearerToken", WithBearerToken("")},
		{"EmptyHeaderKey", WithHeader("", "value")},
		{"EmptyHeaderKeyWithControlChars", WithHeader("X-Bad\r\n", "value")},
	}

	for _, tt := range authErrorCases {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client, _ := newTestClient()
			defer func() { _ = client.Close() }()

			_, err := client.Get(server.URL, tt.opt)
			if err == nil {
				t.Error("Expected error")
			}
		})
	}

	t.Run("WithBearerToken", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-token-123" {
				t.Errorf("Expected Bearer token, got %s", auth)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		_, err := client.Get(server.URL, WithBearerToken("test-token-123"))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})
}

// ----------------------------------------------------------------------------
// Query Parameters
// ----------------------------------------------------------------------------

func TestRequest_QueryParameters(t *testing.T) {
	t.Run("WithQueryMap", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("key1") != "value1" {
				t.Error("Expected key1=value1")
			}
			if r.URL.Query().Get("key2") != "value2" {
				t.Error("Expected key2=value2")
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		params := map[string]any{
			"key1": "value1",
			"key2": "value2",
		}
		_, err := client.Get(server.URL, WithQueryMap(params))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithQuery", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("search") != "test query" {
				t.Error("Expected search=test query")
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		_, err := client.Get(server.URL, WithQuery("search", "test query"))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithQueryMap nil", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		_, err := client.Get(server.URL, WithQueryMap(nil))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithQueryMap empty", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		_, err := client.Get(server.URL, WithQueryMap(map[string]any{}))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithQuery nil value", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		_, err := client.Get(server.URL, WithQuery("key", nil))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})
}

// ----------------------------------------------------------------------------
// WithBody - Auto-detection and explicit body kinds
// ----------------------------------------------------------------------------

func TestRequest_WithBody(t *testing.T) {
	t.Parallel()

	type TestData struct {
		Message string `json:"message" xml:"message"`
		Code    int    `json:"code" xml:"code"`
	}

	// untaggedRaw is used for the AutoDetect_UntaggedStruct test case.
	type untaggedRaw struct {
		Name string
		Age  int
	}

	// bodyOption returns the RequestOption for each test case. This helper
	// is needed because the table cannot store variadic BodyKind arguments
	// directly alongside interface{} bodies without losing type information.
	bodyOption := func(body interface{}, kinds []BodyKind) RequestOption {
		switch len(kinds) {
		case 0:
			return WithBody(body)
		case 1:
			return WithBody(body, kinds[0])
		default:
			return WithBody(body, kinds[0])
		}
	}

	tests := []struct {
		name         string
		body         interface{}
		kinds        []BodyKind // empty = auto-detect; 1 element = explicit kind
		needsServer  bool       // true = spin up httptest.Server and check Content-Type
		expectedType string     // exact Content-Type expected (used when usePrefix=false)
		usePrefix    bool       // true = check strings.HasPrefix instead of exact match
		expectError  bool       // true = expect non-nil error, no server needed
	}{
		// --- Auto-detect cases ---
		{
			name:         "AutoDetect_JSON",
			body:         TestData{Message: "test", Code: 200},
			needsServer:  true,
			expectedType: "application/json",
		},
		{
			name:         "AutoDetect_String",
			body:         "plain text body",
			needsServer:  true,
			expectedType: "text/plain; charset=utf-8",
		},
		{
			name:         "AutoDetect_ByteArray",
			body:         []byte("binary data"),
			needsServer:  true,
			expectedType: "application/octet-stream",
		},
		{
			name:         "AutoDetect_FormMap",
			body:         map[string]string{"key": "value"},
			needsServer:  true,
			expectedType: "application/x-www-form-urlencoded",
		},
		{
			name:         "AutoDetect_FormData",
			body:         &FormData{Fields: map[string]string{"field1": "value1"}},
			needsServer:  true,
			expectedType: "multipart/form-data",
			usePrefix:    true,
		},
		{
			name:         "AutoDetect_Reader",
			body:         strings.NewReader("reader content"),
			needsServer:  true,
			expectedType: "", // io.Reader should NOT set Content-Type
		},
		{
			name:         "AutoDetect_UntaggedStruct",
			body:         untaggedRaw{Name: "test", Age: 30},
			needsServer:  true,
			expectedType: "application/json",
		},

		// --- Explicit body-kind cases ---
		{
			name:         "Explicit_JSON",
			body:         "string as json",
			kinds:        []BodyKind{BodyJSON},
			needsServer:  true,
			expectedType: "application/json",
		},
		{
			name:         "Explicit_XML",
			body:         TestData{Message: "test", Code: 200},
			kinds:        []BodyKind{BodyXML},
			needsServer:  true,
			expectedType: "application/xml",
		},
		{
			name:         "Explicit_Form",
			body:         map[string]string{"key": "value"},
			kinds:        []BodyKind{BodyForm},
			needsServer:  true,
			expectedType: "application/x-www-form-urlencoded",
		},
		{
			name:         "Explicit_Binary",
			body:         []byte("binary"),
			kinds:        []BodyKind{BodyBinary},
			needsServer:  true,
			expectedType: "application/octet-stream",
		},
		{
			name:         "Explicit_Multipart",
			body:         &FormData{Fields: map[string]string{"field1": "value1"}},
			kinds:        []BodyKind{BodyMultipart},
			needsServer:  true,
			expectedType: "multipart/form-data",
			usePrefix:    true,
		},

		// --- Error cases (no server needed) ---
		{
			name:        "Error_NilBody",
			body:        nil,
			expectError: true,
		},
		{
			name:        "Error_FormWrongType",
			body:        "not a map",
			kinds:       []BodyKind{BodyForm},
			expectError: true,
		},
		{
			name:        "Error_BinaryWrongType",
			body:        123,
			kinds:       []BodyKind{BodyBinary},
			expectError: true,
		},
		{
			name:        "Error_MultipartWrongType",
			body:        map[string]string{"key": "value"},
			kinds:       []BodyKind{BodyMultipart},
			expectError: true,
		},
		{
			name:        "AutoDetect_NilByteArray",
			body:        []byte(nil),
			expectError: true,
		},
		{
			name:        "AutoDetect_NilFormData",
			body:        (*FormData)(nil),
			expectError: true,
		},
		{
			name:        "AutoDetect_NilFormMap",
			body:        map[string]string(nil),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := newTestClient()
			defer func() { _ = client.Close() }()

			opt := bodyOption(tt.body, tt.kinds)

			if tt.needsServer {
				expectedType := tt.expectedType
				usePrefix := tt.usePrefix

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					got := r.Header.Get("Content-Type")
					if usePrefix {
						if !strings.HasPrefix(got, expectedType) {
							t.Errorf("Expected Content-Type prefix %q, got %q", expectedType, got)
						}
					} else {
						if got != expectedType {
							t.Errorf("Expected Content-Type %q, got %q", expectedType, got)
						}
					}
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				_, err := client.Post(server.URL, opt)
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}
			} else {
				// Error-only cases: no server needed
				_, err := client.Post("http://example.com", opt)
				if tt.expectError && err == nil {
					t.Error("Expected error but got nil")
				}
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Note: Cookie tests have been moved to cookie_test.go for better organization
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Timeout & Retry Options
// ----------------------------------------------------------------------------

// TestRequest_TimeoutAndRetry was moved to retry_test.go as
// TestRetry_PerRequestMaxRetriesOption — retry behavior belongs with the
// other retry tests; only the knob is option-layer.

// ----------------------------------------------------------------------------
// Combined Options
// ----------------------------------------------------------------------------

func TestRequest_CombinedOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify all options applied
		if r.Header.Get("X-Custom") != "value" {
			t.Error("Header not set")
		}
		if r.URL.Query().Get("param") != "test" {
			t.Error("Query param not set")
		}
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value != "abc123" {
			t.Error("Cookie not set")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer func() { _ = client.Close() }()

	_, err := client.Get(server.URL,
		WithHeader("X-Custom", "value"),
		WithQuery("param", "test"),
		WithCookies([]http.Cookie{{Name: "session", Value: "abc123"}}),
	)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
}

// ----------------------------------------------------------------------------
// WithFile
// ----------------------------------------------------------------------------

func TestWithFile(t *testing.T) {
	t.Parallel()

	t.Run("empty field name", func(t *testing.T) {
		opt := WithFile("", "test.txt", []byte("data"))
		err := opt(nil)
		if err == nil {
			t.Error("expected error for empty field name")
		}
	})

	t.Run("empty filename", func(t *testing.T) {
		opt := WithFile("file", "", []byte("data"))
		err := opt(nil)
		if err == nil {
			t.Error("expected error for empty filename")
		}
	})

	t.Run("path traversal rejected", func(t *testing.T) {
		// Filename with path traversal should be rejected by validation
		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		_, err := client.Post("http://example.com", WithFile("file", "../etc/passwd", []byte("data")))
		if err == nil {
			t.Error("expected error for path traversal filename")
		}
	})

	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
				t.Error("expected multipart content type")
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		_, err := client.Post(server.URL, WithFile("upload", "test.txt", []byte("file content")))
		if err != nil {
			t.Fatalf("WithFile failed: %v", err)
		}
	})
}

// ----------------------------------------------------------------------------
// WithContext
// ----------------------------------------------------------------------------

func TestWithContext(t *testing.T) {
	t.Parallel()

	t.Run("nil context error", func(t *testing.T) {
		var nilCtx context.Context // intentionally nil: exercises the guard
		opt := WithContext(nilCtx)
		err := opt(nil)
		if err == nil {
			t.Error("expected error for nil context")
		}
	})

	t.Run("valid context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		ctx := context.Background()
		_, err := client.Get(server.URL, WithContext(ctx))
		if err != nil {
			t.Fatalf("Request with context failed: %v", err)
		}
	})
}

// ----------------------------------------------------------------------------
// WithSecureCookie
// ----------------------------------------------------------------------------

func TestWithSecureCookie(t *testing.T) {
	t.Parallel()

	t.Run("nil config", func(t *testing.T) {
		opt := WithSecureCookie(nil)
		err := opt(nil)
		if err == nil {
			t.Error("expected error for nil config")
		}
	})

	t.Run("insecure cookie rejected", func(t *testing.T) {
		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		securityConfig := &validation.CookieSecurityConfig{
			RequireSecure: true,
		}

		_, err := client.Get("http://example.com",
			WithCookies([]http.Cookie{{Name: "test", Value: "val"}}),
			WithSecureCookie(securityConfig),
		)
		if err == nil {
			t.Error("expected error for insecure cookie with strict config")
		}
	})
}

// ----------------------------------------------------------------------------
// WithTimeout Boundaries
// ----------------------------------------------------------------------------

func TestWithTimeout_Boundaries(t *testing.T) {
	t.Parallel()

	t.Run("negative timeout", func(t *testing.T) {
		opt := WithTimeout(-1 * time.Second)
		err := opt(nil)
		if err == nil {
			t.Error("expected error for negative timeout")
		}
	})

	t.Run("exceeds max timeout", func(t *testing.T) {
		opt := WithTimeout(31 * time.Minute)
		err := opt(nil)
		if err == nil {
			t.Error("expected error for exceeding max timeout")
		}
	})

	t.Run("valid timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer func() { _ = client.Close() }()

		_, err := client.Get(server.URL, WithTimeout(5*time.Second))
		if err != nil {
			t.Fatalf("valid timeout should work: %v", err)
		}
	})
}

// ----------------------------------------------------------------------------
// queryValueLength type coverage
// ----------------------------------------------------------------------------

func TestQueryValueLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		value  any
		minLen int
	}{
		{"string", "hello", 5},
		{"int", 42, 2},
		{"int64", int64(42), 2},
		{"int32", int32(42), 2},
		{"uint", uint(42), 2},
		{"uint64", uint64(42), 2},
		{"uint32", uint32(42), 2},
		{"float64", 3.14, 1},
		{"float32", float32(3.14), 1},
		{"bool true", true, 4},
		{"bool false", false, 5},
		{"negative int64", int64(-42), 3},
		{"default type", struct{}{}, 2},
		{"url.Values formatted as k=v pairs", url.Values{"k": {"v"}}, 3},
		{"nil is zero-length", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := queryValueLength(tt.value)
			if got < tt.minLen {
				t.Errorf("queryValueLength(%v) = %d, expected >= %d", tt.value, got, tt.minLen)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// convertToBinary edge cases
// ----------------------------------------------------------------------------

func TestConvertToBinary(t *testing.T) {
	t.Parallel()

	t.Run("nil byte slice", func(t *testing.T) {
		_, err := convertToBinary([]byte(nil))
		if err == nil {
			t.Error("expected error for nil byte slice")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := convertToBinary("")
		if err == nil {
			t.Error("expected error for empty string")
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		_, err := convertToBinary(42)
		if err == nil {
			t.Error("expected error for wrong type")
		}
	})

	t.Run("valid bytes", func(t *testing.T) {
		got, err := convertToBinary([]byte("data"))
		if err != nil || string(got) != "data" {
			t.Errorf("expected 'data', got %q, err=%v", got, err)
		}
	})

	t.Run("valid string", func(t *testing.T) {
		got, err := convertToBinary("hello")
		if err != nil || string(got) != "hello" {
			t.Errorf("expected 'hello', got %q, err=%v", got, err)
		}
	})
}

// ----------------------------------------------------------------------------
// convertToForm edge cases
// ----------------------------------------------------------------------------

func TestConvertToForm(t *testing.T) {
	t.Parallel()

	t.Run("nil url.Values", func(t *testing.T) {
		_, err := convertToForm(url.Values(nil))
		if err == nil {
			t.Error("expected error for nil url.Values")
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		_, err := convertToForm(42)
		if err == nil {
			t.Error("expected error for wrong type")
		}
	})

	t.Run("valid url.Values", func(t *testing.T) {
		v := url.Values{"k": {"v"}}
		got, err := convertToForm(v)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "k=v" {
			t.Errorf("expected 'k=v', got %q", got)
		}
	})
}

// TestWithFile_MultipleFilesMerge verifies consecutive WithFile options
// upload as one multipart body instead of silently dropping all but the last
// file.
func TestWithFile_MultipleFilesMerge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			http.Error(w, "not multipart: "+err.Error(), http.StatusBadRequest)
			return
		}
		fileA, _, errA := r.FormFile("fileA")
		fileB, _, errB := r.FormFile("fileB")
		if errA != nil || errB != nil {
			http.Error(w, fmt.Sprintf("missing file: %v / %v", errA, errB), http.StatusBadRequest)
			return
		}
		defer func() { _ = fileA.Close() }() // best-effort; test server lifetime
		defer func() { _ = fileB.Close() }() // best-effort; test server lifetime
		contentA, _ := io.ReadAll(fileA)
		contentB, _ := io.ReadAll(fileB)
		_, _ = fmt.Fprintf(w, "%s|%s", contentA, contentB)
	}))
	defer server.Close()

	client, err := newTestClient()
	if err != nil {
		t.Fatalf("newTestClient() error: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Post(server.URL,
		WithFile("fileA", "a.txt", []byte("content-A")),
		WithFile("fileB", "b.txt", []byte("content-B")),
	)
	if err != nil {
		t.Fatalf("Post with two files failed: %v", err)
	}
	if got := result.Body(); got != "content-A|content-B" {
		t.Errorf("multipart merge mismatch: got %q, want %q", got, "content-A|content-B")
	}
}

// TestWithHeader_ErrorsWrapSentinel verifies invalid-header errors from both
// WithHeader and WithHeaderMap satisfy errors.Is(err, ErrInvalidHeader), as
// documented.
func TestWithHeader_ErrorsWrapSentinel(t *testing.T) {
	client, err := newTestClient()
	if err != nil {
		t.Fatalf("newTestClient() error: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Get("http://example.com/x", WithHeader("Bad\r\nKey", "v"))
	if !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("WithHeader error should wrap ErrInvalidHeader, got: %v", err)
	}

	_, err = client.Get("http://example.com/x", WithHeaderMap(map[string]string{"K": "v\r\n"}))
	if !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("WithHeaderMap error should wrap ErrInvalidHeader, got: %v", err)
	}
}

// ----------------------------------------------------------------------------
// Public option error paths — table-driven
// (moved from boundary_test.go)
// ----------------------------------------------------------------------------

func TestOptions_ErrorPaths(t *testing.T) {
	t.Run("WithBasicAuth", func(t *testing.T) {
		tests := []struct {
			name     string
			username string
			password string
			wantErr  bool
		}{
			{"empty username", "", "pass", true},
			{"username with control char", "user\x00name", "pass", true},
			{"password with control char", "user", "pass\x01word", true},
			{"valid credentials", "user", "pass", false},
			{"empty password rejected", "user", "", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := engine.AcquireRequest()
				err := WithBasicAuth(tt.username, tt.password)(req)
				if tt.wantErr && err == nil {
					t.Error("expected error, got nil")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			})
		}
	})

	t.Run("WithBearerToken", func(t *testing.T) {
		tests := []struct {
			name    string
			token   string
			wantErr bool
		}{
			{"empty token", "", true},
			{"token with control char", "tok\x01en", true},
			{"valid token", "Bearer123", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := engine.AcquireRequest()
				err := WithBearerToken(tt.token)(req)
				if tt.wantErr && err == nil {
					t.Error("expected error, got nil")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			})
		}
	})

	t.Run("WithQuery", func(t *testing.T) {
		tests := []struct {
			name    string
			key     string
			value   any
			wantErr bool
		}{
			{"empty key", "", "val", true},
			{"key too long", strings.Repeat("k", validation.MaxHeaderKeyLen+1), "val", true},
			{"nil value skipped", "key", nil, false},
			{"valid int value", "count", 42, false},
			{"valid string value", "name", "test", false},
			{"valid bool value", "enabled", true, false},
			{"value too long", "data", strings.Repeat("x", validation.MaxValueLen+1), true},
			{"unicode value round-trips", "q", "日本語-ünïcödé", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := engine.AcquireRequest()
				err := WithQuery(tt.key, tt.value)(req)
				if tt.wantErr && err == nil {
					t.Error("expected error, got nil")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			})
		}
	})

	t.Run("WithQueryMap", func(t *testing.T) {
		tests := []struct {
			name    string
			params  map[string]any
			wantErr bool
		}{
			{"empty key in map", map[string]any{"": "val"}, true},
			{"nil value skipped", map[string]any{"key": nil}, false},
			{"valid map", map[string]any{"a": "1", "b": 2}, false},
			{"value too long", map[string]any{"key": strings.Repeat("x", validation.MaxValueLen+1)}, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := engine.AcquireRequest()
				err := WithQueryMap(tt.params)(req)
				if tt.wantErr && err == nil {
					t.Error("expected error, got nil")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			})
		}
	})

	t.Run("WithHeaderMap", func(t *testing.T) {
		tests := []struct {
			name    string
			headers map[string]string
			wantErr bool
		}{
			{"empty key", map[string]string{"": "val"}, true},
			{"control char in value", map[string]string{"X-Key": "bad\x01val"}, true},
			{"valid single header", map[string]string{"X-Custom": "value"}, false},
			{"valid multiple headers", map[string]string{"X-A": "1", "X-B": "2"}, false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := engine.AcquireRequest()
				err := WithHeaderMap(tt.headers)(req)
				if tt.wantErr && err == nil {
					t.Error("expected error, got nil")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			})
		}
	})

	t.Run("WithForm nil data", func(t *testing.T) {
		req := engine.AcquireRequest()
		err := WithForm(nil)(req)
		if err == nil {
			t.Error("expected error for nil form data")
		}
	})

	t.Run("WithMaxRetries", func(t *testing.T) {
		tests := []struct {
			name    string
			n       int
			wantErr bool
		}{
			{"zero", 0, false},
			{"positive", 3, false},
			{"negative", -1, true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := engine.AcquireRequest()
				err := WithMaxRetries(tt.n)(req)
				if tt.wantErr && err == nil {
					t.Error("expected error, got nil")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			})
		}
	})
}

// ----------------------------------------------------------------------------
// Binary / form-data option boundary conditions
// (moved from boundary_test.go)
// ----------------------------------------------------------------------------

func TestWithBinary_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"nil data", nil, true},
		{"empty data", []byte{}, true},
		{"valid binary data", []byte{0x00, 0x01, 0xFF}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := engine.AcquireRequest()
			err := WithBinary(tt.data)(req)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

func TestWithFormData_BoundaryConditions(t *testing.T) {
	t.Run("nil form data", func(t *testing.T) {
		req := engine.AcquireRequest()
		err := WithFormData(nil)(req)
		if err == nil {
			t.Error("expected error for nil form data")
		}
	})

	t.Run("empty form data", func(t *testing.T) {
		req := engine.AcquireRequest()
		err := WithFormData(&FormData{})(req)
		// empty form data should be valid (no fields, no files)
		if err != nil {
			t.Errorf("expected no error for empty form data, got: %v", err)
		}
	})
}

// Moved from quality_regression_test.go (dissolved grab-bag file):
// TestQueryValueLengthParity pins the documented invariant of queryValueLength:
// it must return exactly len(FormatQueryParam(v)) for every supported type.
// The MAINTENANCE note in public_options.go requires new types to be added to
// all three formatting sites; this covers the public-package side.
func TestQueryValueLengthParity(t *testing.T) {
	type stringer string
	cases := []any{
		nil, "", "hello", true, false,
		0, 42, -7, int64(1 << 40), int32(-5), uint(9), uint64(1 << 41), uint32(77),
		2.5, float32(1.5), stringer("custom"), struct{ X int }{X: 1},
	}
	for _, v := range cases {
		if got, want := queryValueLength(v), len(engine.FormatQueryParam(v)); got != want {
			t.Errorf("queryValueLength(%#v) = %d, want %d", v, got, want)
		}
	}
}

// TestBuildXMLWithCharsetContentType guards parameter-tolerant XML
// Content-Type detection: a struct body with an explicit
// "application/xml; charset=utf-8" header must be XML-marshaled, not
// JSON-marshaled under an XML header.
func TestBuildXMLWithCharsetContentType(t *testing.T) {
	var gotContentType string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		buf := make([]byte, 128)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
	}))
	defer srv.Close()

	type payload struct {
		XMLName struct{} `xml:"root"`
		Name    string   `xml:"name"`
	}

	client, err := New(TestingConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Post(srv.URL,
		WithBody(payload{Name: "x"}, BodyXML),
		WithHeader("Content-Type", "application/xml; charset=utf-8"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := "application/xml; charset=utf-8"; gotContentType != want {
		t.Fatalf("Content-Type = %q, want %q", gotContentType, want)
	}
	// XML marshal produces "<root><name>x</name></root>" (plus the standard
	// xml header); JSON would produce {"name":"x"}.
	if !strings.Contains(gotBody, "<root>") || !strings.Contains(gotBody, "<name>x</name>") {
		t.Fatalf("body = %q, want XML-marshaled payload", gotBody)
	}
}
