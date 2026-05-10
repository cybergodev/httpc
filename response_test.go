package httpc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// RESPONSE TESTS - Result object, response parsing, formats, cookies
// Consolidates: result_test.go, response_format_test.go
// ============================================================================

// ----------------------------------------------------------------------------
// Basic Result Usage
// ----------------------------------------------------------------------------

func TestResult_BasicUsage(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Header", "custom-value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"success","code":200}`))
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	result, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Test status code
	if result.StatusCode() != http.StatusOK {
		t.Errorf("Expected status 200, got %d", result.StatusCode())
	}

	// Test body
	body := result.Body()
	if body == "" {
		t.Error("Body should not be empty")
	}

	// Test response info
	if result.Response == nil {
		t.Fatal("Response info should not be nil")
	}
	if result.Response.StatusCode != http.StatusOK {
		t.Error("Response status code mismatch")
	}
	if result.Response.Headers.Get("Content-Type") != "application/json" {
		t.Error("Content-Type header not found")
	}
	if result.Response.Headers.Get("X-Custom-Header") != "custom-value" {
		t.Error("Custom header not found")
	}
}

// ----------------------------------------------------------------------------
// Convenience Methods
// ----------------------------------------------------------------------------

func TestResult_ConvenienceMethods(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Header-1", "value1")
		w.Header().Set("X-Header-2", "value2")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response body"))
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	result, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Test Body()
	if result.Body() != "response body" {
		t.Errorf("Expected 'response body', got %s", result.Body())
	}

	// Test RawBody()
	bytes := result.RawBody()
	if string(bytes) != "response body" {
		t.Error("RawBody() mismatch")
	}

	// Test StatusCode()
	if result.StatusCode() != http.StatusOK {
		t.Errorf("Expected 200, got %d", result.StatusCode())
	}

	// Test Response headers
	if result.Response.Headers.Get("Content-Type") != "text/plain" {
		t.Error("Header failed for Content-Type")
	}
	if result.Response.Headers.Get("X-Header-1") != "value1" {
		t.Error("Header failed for X-Header-1")
	}
	if result.Response.Headers.Get("X-Header-2") != "value2" {
		t.Error("Header failed for X-Header-2")
	}
}

// ----------------------------------------------------------------------------
// Status Checks
// ----------------------------------------------------------------------------

func TestResult_StatusChecks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		statusCode    int
		isSuccess     bool
		isClientError bool
		isServerError bool
	}{
		{"200 OK", http.StatusOK, true, false, false},
		{"201 Created", http.StatusCreated, true, false, false},
		{"204 No Content", http.StatusNoContent, true, false, false},
		{"400 Bad Request", http.StatusBadRequest, false, true, false},
		{"404 Not Found", http.StatusNotFound, false, true, false},
		{"500 Internal Error", http.StatusInternalServerError, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			client, _ := newTestClient()
			defer client.Close()

			result, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}

			if result.IsSuccess() != tt.isSuccess {
				t.Errorf("IsSuccess() = %v, want %v", result.IsSuccess(), tt.isSuccess)
			}
			if result.IsClientError() != tt.isClientError {
				t.Errorf("IsClientError() = %v, want %v", result.IsClientError(), tt.isClientError)
			}
			if result.IsServerError() != tt.isServerError {
				t.Errorf("IsServerError() = %v, want %v", result.IsServerError(), tt.isServerError)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// JSON Parsing
// ----------------------------------------------------------------------------

func TestResult_Unmarshal(t *testing.T) {
	t.Parallel()

	t.Run("Valid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "success",
				"code":    200,
			})
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		result, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		var data map[string]interface{}
		if err := result.Unmarshal(&data); err != nil {
			t.Fatalf("JSON parsing failed: %v", err)
		}

		if data["message"] != "success" {
			t.Error("JSON data mismatch")
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		result, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		var data map[string]interface{}
		err = result.Unmarshal(&data)
		if err == nil {
			t.Error("Expected JSON parsing error")
		}
	})
}

// ----------------------------------------------------------------------------
// Note: Cookie tests have been moved to cookie_test.go for better organization
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Nil Safety
// ----------------------------------------------------------------------------

func TestResult_NilSafety(t *testing.T) {
	t.Parallel()

	var result *Result

	// All methods should handle nil gracefully
	if result.StatusCode() != 0 {
		t.Error("Nil result StatusCode should be 0")
	}
	if result.Body() != "" {
		t.Error("Nil result Body should be empty")
	}
	if result.RawBody() != nil {
		t.Error("Nil result RawBody should be nil")
	}
	if result.IsSuccess() {
		t.Error("Nil result IsSuccess should be false")
	}
	if result.IsClientError() {
		t.Error("Nil result IsClientError should be false")
	}
	if result.IsServerError() {
		t.Error("Nil result IsServerError should be false")
	}

	var data map[string]interface{}
	if err := result.Unmarshal(&data); err == nil {
		t.Error("Nil result Unmarshal should return error")
	}
}

// ----------------------------------------------------------------------------
// Proto
// ----------------------------------------------------------------------------

func TestResult_Proto(t *testing.T) {
	t.Parallel()

	t.Run("nil Result", func(t *testing.T) {
		var r *Result
		if r.Proto() != "" {
			t.Error("nil Result Proto should return empty string")
		}
	})

	t.Run("nil Response", func(t *testing.T) {
		r := &Result{}
		if r.Proto() != "" {
			t.Error("nil Response Proto should return empty string")
		}
	})

	t.Run("normal", func(t *testing.T) {
		r := &Result{Response: &ResponseInfo{Proto: "HTTP/2.0"}}
		if r.Proto() != "HTTP/2.0" {
			t.Errorf("Expected HTTP/2.0, got %s", r.Proto())
		}
	})
}

// ----------------------------------------------------------------------------
// RequestCookies / ResponseCookies
// ----------------------------------------------------------------------------

func TestResult_RequestCookies(t *testing.T) {
	t.Parallel()

	t.Run("nil Result", func(t *testing.T) {
		var r *Result
		if r.RequestCookies() != nil {
			t.Error("nil Result should return nil")
		}
	})

	t.Run("nil Request", func(t *testing.T) {
		r := &Result{}
		if r.RequestCookies() != nil {
			t.Error("nil Request should return nil")
		}
	})

	t.Run("with cookies", func(t *testing.T) {
		cookies := []*http.Cookie{{Name: "session", Value: "abc"}}
		r := &Result{Request: &RequestInfo{Cookies: cookies}}
		if len(r.RequestCookies()) != 1 || r.RequestCookies()[0].Name != "session" {
			t.Error("Request cookies mismatch")
		}
	})
}

func TestResult_ResponseCookies(t *testing.T) {
	t.Parallel()

	t.Run("nil Result", func(t *testing.T) {
		var r *Result
		if r.ResponseCookies() != nil {
			t.Error("nil Result should return nil")
		}
	})

	t.Run("nil Response", func(t *testing.T) {
		r := &Result{}
		if r.ResponseCookies() != nil {
			t.Error("nil Response should return nil")
		}
	})

	t.Run("with cookies", func(t *testing.T) {
		cookies := []*http.Cookie{{Name: "token", Value: "xyz"}}
		r := &Result{Response: &ResponseInfo{Cookies: cookies}}
		if len(r.ResponseCookies()) != 1 || r.ResponseCookies()[0].Name != "token" {
			t.Error("Response cookies mismatch")
		}
	})
}

// ----------------------------------------------------------------------------
// IsRedirect
// ----------------------------------------------------------------------------

func TestResult_IsRedirect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		result     *Result
		isRedirect bool
	}{
		{"nil Result", nil, false},
		{"nil Response", &Result{}, false},
		{"200 OK", &Result{Response: &ResponseInfo{StatusCode: 200}}, false},
		{"301 Moved", &Result{Response: &ResponseInfo{StatusCode: 301}}, true},
		{"302 Found", &Result{Response: &ResponseInfo{StatusCode: 302}}, true},
		{"307 Temp", &Result{Response: &ResponseInfo{StatusCode: 307}}, true},
		{"308 Permanent", &Result{Response: &ResponseInfo{StatusCode: 308}}, true},
		{"399 edge", &Result{Response: &ResponseInfo{StatusCode: 399}}, true},
		{"400 Bad", &Result{Response: &ResponseInfo{StatusCode: 400}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.result.IsRedirect() != tt.isRedirect {
				t.Errorf("IsRedirect() = %v, want %v", tt.result.IsRedirect(), tt.isRedirect)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// GetRequestCookie / HasRequestCookie
// ----------------------------------------------------------------------------

func TestResult_GetRequestCookie(t *testing.T) {
	t.Parallel()

	t.Run("nil Result", func(t *testing.T) {
		var r *Result
		if r.GetRequestCookie("test") != nil {
			t.Error("nil Result should return nil")
		}
	})

	t.Run("nil Request", func(t *testing.T) {
		r := &Result{}
		if r.GetRequestCookie("test") != nil {
			t.Error("nil Request should return nil")
		}
	})

	t.Run("found", func(t *testing.T) {
		r := &Result{Request: &RequestInfo{Cookies: []*http.Cookie{
			{Name: "session", Value: "abc"},
			{Name: "user", Value: "bob"},
		}}}
		c := r.GetRequestCookie("user")
		if c == nil || c.Value != "bob" {
			t.Error("expected to find cookie 'user'")
		}
	})

	t.Run("not found", func(t *testing.T) {
		r := &Result{Request: &RequestInfo{Cookies: []*http.Cookie{
			{Name: "session", Value: "abc"},
		}}}
		if r.GetRequestCookie("missing") != nil {
			t.Error("expected nil for missing cookie")
		}
	})
}

func TestResult_HasRequestCookie(t *testing.T) {
	t.Parallel()

	r := &Result{Request: &RequestInfo{Cookies: []*http.Cookie{
		{Name: "session", Value: "abc"},
	}}}

	t.Run("existing", func(t *testing.T) {
		if !r.HasRequestCookie("session") {
			t.Error("expected HasRequestCookie to return true")
		}
	})

	t.Run("missing", func(t *testing.T) {
		if r.HasRequestCookie("missing") {
			t.Error("expected HasRequestCookie to return false")
		}
	})

	t.Run("nil Result", func(t *testing.T) {
		var r2 *Result
		if r2.HasRequestCookie("any") {
			t.Error("nil Result should return false")
		}
	})
}

// ----------------------------------------------------------------------------
// GetCookie Nil Safety
// ----------------------------------------------------------------------------

func TestResult_GetCookie_NilSafety(t *testing.T) {
	t.Parallel()

	t.Run("nil Result", func(t *testing.T) {
		var r *Result
		if r.GetCookie("test") != nil {
			t.Error("nil Result should return nil")
		}
	})

	t.Run("nil Response", func(t *testing.T) {
		r := &Result{}
		if r.GetCookie("test") != nil {
			t.Error("nil Response should return nil")
		}
	})

	t.Run("not found", func(t *testing.T) {
		r := &Result{Response: &ResponseInfo{Cookies: []*http.Cookie{
			{Name: "other", Value: "val"},
		}}}
		if r.GetCookie("missing") != nil {
			t.Error("expected nil for missing cookie")
		}
	})
}

// ----------------------------------------------------------------------------
// Unmarshal Boundaries
// ----------------------------------------------------------------------------

func TestResult_Unmarshal_Boundaries(t *testing.T) {
	t.Parallel()

	t.Run("empty body", func(t *testing.T) {
		r := &Result{Response: &ResponseInfo{RawBody: []byte{}}}
		var v map[string]interface{}
		if err := r.Unmarshal(&v); err == nil {
			t.Error("expected error for empty body")
		}
	})

	t.Run("nil RawBody", func(t *testing.T) {
		r := &Result{Response: &ResponseInfo{RawBody: nil}}
		var v map[string]interface{}
		if err := r.Unmarshal(&v); err == nil {
			t.Error("expected error for nil body")
		}
	})

	t.Run("oversized body", func(t *testing.T) {
		r := &Result{Response: &ResponseInfo{RawBody: make([]byte, 50*1024*1024+1)}}
		var v map[string]interface{}
		if err := r.Unmarshal(&v); err == nil {
			t.Error("expected error for oversized body")
		}
	})
}

// ----------------------------------------------------------------------------
// String Comprehensive
// ----------------------------------------------------------------------------

func TestResult_String_Comprehensive(t *testing.T) {
	t.Parallel()

	t.Run("nil Result", func(t *testing.T) {
		var r *Result
		if r.String() != "Result{}" {
			t.Errorf("Expected 'Result{}', got %q", r.String())
		}
	})

	t.Run("nil Response", func(t *testing.T) {
		r := &Result{}
		if r.String() != "Result{}" {
			t.Errorf("Expected 'Result{}', got %q", r.String())
		}
	})

	t.Run("with Meta", func(t *testing.T) {
		r := &Result{
			Response: &ResponseInfo{StatusCode: 200, Status: "OK", ContentLength: 42},
			Meta:     &RequestMeta{Duration: 100 * time.Millisecond, Attempts: 2},
		}
		s := r.String()
		if !strings.Contains(s, "Duration:") || !strings.Contains(s, "Attempts:") {
			t.Errorf("String should contain Duration and Attempts, got: %s", s)
		}
	})

	t.Run("with sensitive headers", func(t *testing.T) {
		r := &Result{
			Response: &ResponseInfo{
				StatusCode:    200,
				Status:        "OK",
				ContentLength: 0,
				Headers: http.Header{
					"Authorization": []string{"Bearer secret"},
					"X-Custom":      []string{"visible"},
				},
			},
		}
		s := r.String()
		if !strings.Contains(s, "Authorization: ***") {
			t.Errorf("Authorization should be masked, got: %s", s)
		}
		if !strings.Contains(s, "X-Custom") {
			t.Errorf("X-Custom should be visible, got: %s", s)
		}
	})

	t.Run("with cookies", func(t *testing.T) {
		r := &Result{
			Response: &ResponseInfo{
				StatusCode:    200,
				Status:        "OK",
				ContentLength: 0,
				Cookies:       []*http.Cookie{{Name: "session", Value: "abc"}},
			},
		}
		s := r.String()
		if !strings.Contains(s, "Cookies: 1") {
			t.Errorf("Should show cookie count, got: %s", s)
		}
	})

	t.Run("body truncation", func(t *testing.T) {
		longBody := strings.Repeat("x", 201)
		r := &Result{
			Response: &ResponseInfo{
				StatusCode:    200,
				Status:        "OK",
				ContentLength: 201,
				Body:          longBody,
			},
		}
		s := r.String()
		if !strings.Contains(s, "...[truncated]") {
			t.Error("Body should be truncated")
		}
	})

	t.Run("body no truncation at 200 chars", func(t *testing.T) {
		body := strings.Repeat("x", 200)
		r := &Result{
			Response: &ResponseInfo{
				StatusCode:    200,
				Status:        "OK",
				ContentLength: 200,
				Body:          body,
			},
		}
		s := r.String()
		if strings.Contains(s, "...[truncated]") {
			t.Error("Body should NOT be truncated at exactly 200 chars")
		}
	})
}

// ----------------------------------------------------------------------------
// SaveToFile Boundaries
// ----------------------------------------------------------------------------

func TestResult_SaveToFile_Boundaries(t *testing.T) {
	t.Parallel()

	t.Run("nil Result", func(t *testing.T) {
		var r *Result
		if err := r.SaveToFile("test.txt"); err == nil {
			t.Error("expected error for nil Result")
		}
	})

	t.Run("nil RawBody", func(t *testing.T) {
		r := &Result{Response: &ResponseInfo{}}
		if err := r.SaveToFile("test.txt"); err == nil {
			t.Error("expected error for nil RawBody")
		}
	})

	t.Run("path traversal", func(t *testing.T) {
		r := &Result{Response: &ResponseInfo{RawBody: []byte("data")}}
		if err := r.SaveToFile("../../../etc/passwd"); err == nil {
			t.Error("expected error for path traversal")
		}
	})
}
