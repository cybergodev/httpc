package httpc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ----------------------------------------------------------------------------
// Cookie Tests - Unified
// ----------------------------------------------------------------------------
// This file consolidates all cookie-related tests from request_test.go,
// data_test.go, and response_test.go for better organization and maintainability.

// ----------------------------------------------------------------------------
// Request Cookies - Basic Operations
// ----------------------------------------------------------------------------

func TestCookie_RequestBasicOperations(t *testing.T) {
	t.Run("WithCookie", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("test-cookie")
			if err != nil || cookie.Value != "test-value" {
				t.Error("Cookie not found or incorrect")
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get(server.URL, WithCookie(http.Cookie{
			Name:  "test-cookie",
			Value: "test-value",
		}))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithCookies", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie1, _ := r.Cookie("cookie1")
			cookie2, _ := r.Cookie("cookie2")
			if cookie1 == nil || cookie2 == nil {
				t.Error("Cookies not found")
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get(server.URL,
			WithCookie(http.Cookie{Name: "cookie1", Value: "value1"}),
			WithCookie(http.Cookie{Name: "cookie2", Value: "value2"}),
		)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithCookies_batch", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie1, _ := r.Cookie("cookie1")
			cookie2, _ := r.Cookie("cookie2")
			cookie3, _ := r.Cookie("cookie3")
			if cookie1 == nil || cookie2 == nil || cookie3 == nil {
				t.Error("Cookies not found")
			}
			if cookie1 != nil && cookie1.Value != "value1" {
				t.Errorf("cookie1: expected value1, got %s", cookie1.Value)
			}
			if cookie2 != nil && cookie2.Value != "value2" {
				t.Errorf("cookie2: expected value2, got %s", cookie2.Value)
			}
			if cookie3 != nil && cookie3.Value != "value3" {
				t.Errorf("cookie3: expected value3, got %s", cookie3.Value)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get(server.URL, WithCookies([]http.Cookie{
			{Name: "cookie1", Value: "value1"},
			{Name: "cookie2", Value: "value2"},
			{Name: "cookie3", Value: "value3"},
		}))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithCookies_empty_slice", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := r.Cookies()
			if len(cookies) != 0 {
				t.Errorf("Expected 0 cookies, got %d", len(cookies))
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get(server.URL, WithCookies([]http.Cookie{}))
		if err != nil {
			t.Fatalf("Request with empty slice should not fail: %v", err)
		}
	})

	t.Run("WithCookies_nil_slice", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get(server.URL, WithCookies(nil))
		if err != nil {
			t.Fatalf("Request with nil slice should not fail: %v", err)
		}
	})

	t.Run("WithCookies_invalid_cookie", func(t *testing.T) {
		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get("http://localhost",
			WithCookies([]http.Cookie{
				{Name: "valid", Value: "ok"},
				{Name: "", Value: "empty-name"},
			}),
		)
		if err == nil {
			t.Fatal("Expected error for invalid cookie name")
		}
	})

	t.Run("WithCookies_combined_with_WithCookie", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := r.Cookies()
			if len(cookies) != 3 {
				t.Errorf("Expected 3 cookies, got %d", len(cookies))
			}

			expected := map[string]string{
				"cookie1": "value1",
				"cookie2": "value2",
				"cookie3": "value3",
			}

			for name, expectedValue := range expected {
				cookie, err := r.Cookie(name)
				if err != nil {
					t.Errorf("Cookie %s not found", name)
					continue
				}
				if cookie.Value != expectedValue {
					t.Errorf("Cookie %s: expected %s, got %s", name, expectedValue, cookie.Value)
				}
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get(server.URL,
			WithCookie(http.Cookie{Name: "cookie1", Value: "value1"}),
			WithCookies([]http.Cookie{
				{Name: "cookie2", Value: "value2"},
				{Name: "cookie3", Value: "value3"},
			}),
		)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithCookieValue", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("simple")
			if err != nil || cookie.Value != "value" {
				t.Error("Cookie not found or incorrect")
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get(server.URL, WithCookie(http.Cookie{Name: "simple", Value: "value"}))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})
}

// ----------------------------------------------------------------------------
// Cookie String Parsing
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Cookie Map Operations
// ----------------------------------------------------------------------------

func TestCookie_MapOperations(t *testing.T) {
	t.Run("WithCookieMap basic", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := r.Cookies()
			if len(cookies) != 3 {
				t.Errorf("Expected 3 cookies, got %d", len(cookies))
			}

			expected := map[string]string{
				"session_id": "abc123",
				"user_pref":  "dark_mode",
				"lang":       "en",
			}

			for name, expectedValue := range expected {
				cookie, err := r.Cookie(name)
				if err != nil {
					t.Errorf("Cookie %s not found", name)
					continue
				}
				if cookie.Value != expectedValue {
					t.Errorf("Cookie %s: expected %s, got %s", name, expectedValue, cookie.Value)
				}
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		cookies := map[string]string{
			"session_id": "abc123",
			"user_pref":  "dark_mode",
			"lang":       "en",
		}

		_, err := client.Get(server.URL, WithCookieMap(cookies))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithCookieMap empty map", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := r.Cookies()
			if len(cookies) != 0 {
				t.Errorf("Expected 0 cookies, got %d", len(cookies))
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get(server.URL, WithCookieMap(map[string]string{}))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithCookieMap nil map", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get(server.URL, WithCookieMap(nil))
		if err != nil {
			t.Fatalf("Request with nil map should not fail: %v", err)
		}
	})

	t.Run("WithCookieMap combined with WithCookie", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := r.Cookies()
			if len(cookies) != 3 {
				t.Errorf("Expected 3 cookies, got %d", len(cookies))
			}

			// Verify all cookies are present
			expected := map[string]string{
				"cookie1": "value1",
				"cookie2": "value2",
				"cookie3": "value3",
			}

			for name, expectedValue := range expected {
				cookie, err := r.Cookie(name)
				if err != nil {
					t.Errorf("Cookie %s not found", name)
					continue
				}
				if cookie.Value != expectedValue {
					t.Errorf("Cookie %s: expected %s, got %s", name, expectedValue, cookie.Value)
				}
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get(server.URL,
			WithCookie(http.Cookie{Name: "cookie1", Value: "value1"}),
			WithCookieMap(map[string]string{
				"cookie2": "value2",
				"cookie3": "value3",
			}),
		)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithCookieMap with special characters", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("token")
			if err != nil {
				t.Errorf("Cookie token not found")
				return
			}
			if cookie.Value != "xyz-789_ABC" {
				t.Errorf("Expected 'xyz-789_ABC', got '%s'", cookie.Value)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Get(server.URL, WithCookieMap(map[string]string{
			"token": "xyz-789_ABC",
		}))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("WithCookieMap invalid cookie name", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		// Cookie name with invalid character (semicolon)
		_, err := client.Get(server.URL, WithCookieMap(map[string]string{
			"invalid;name": "value",
		}))
		if err == nil {
			t.Error("Expected error for invalid cookie name")
		}
	})
}

func TestCookie_StringParsing(t *testing.T) {
	tests := []struct {
		name            string
		cookieString    string
		expectedCount   int
		expectedCookies map[string]string
	}{
		{
			name:            "empty string",
			cookieString:    "",
			expectedCount:   0,
			expectedCookies: map[string]string{},
		},
		{
			name:          "single cookie",
			cookieString:  "name=value",
			expectedCount: 1,
			expectedCookies: map[string]string{
				"name": "value",
			},
		},
		{
			name:          "multiple cookies",
			cookieString:  "cookie1=value1; cookie2=value2; cookie3=value3",
			expectedCount: 3,
			expectedCookies: map[string]string{
				"cookie1": "value1",
				"cookie2": "value2",
				"cookie3": "value3",
			},
		},
		{
			name:          "complex with special chars",
			cookieString:  "session=abc123; token=xyz-789_ABC; user=john@example.com",
			expectedCount: 3,
			expectedCookies: map[string]string{
				"session": "abc123",
				"token":   "xyz-789_ABC",
				"user":    "john@example.com",
			},
		},
		{
			name:          "with spaces",
			cookieString:  "name1 = value1 ; name2 = value2",
			expectedCount: 2,
			expectedCookies: map[string]string{
				"name1": "value1",
				"name2": "value2",
			},
		},
		{
			name:          "empty value",
			cookieString:  "empty=",
			expectedCount: 1,
			expectedCookies: map[string]string{
				"empty": "",
			},
		},
		{
			name:          "duplicate names",
			cookieString:  "name=val1; name=val2",
			expectedCount: 1,
			expectedCookies: map[string]string{
				"name": "val2",
			},
		},
		{
			name:          "long value",
			cookieString:  "data=" + strings.Repeat("x", 1024),
			expectedCount: 1,
			expectedCookies: map[string]string{
				"data": strings.Repeat("x", 1024),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cookies := r.Cookies()
				if len(cookies) != tt.expectedCount {
					t.Errorf("Expected %d cookies, got %d", tt.expectedCount, len(cookies))
				}

				for name, expectedValue := range tt.expectedCookies {
					cookie, err := r.Cookie(name)
					if err != nil {
						t.Errorf("Cookie %s not found", name)
						continue
					}
					if cookie.Value != expectedValue {
						t.Errorf("Cookie %s: expected value %s, got %s", name, expectedValue, cookie.Value)
					}
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client, _ := newTestClient()
			defer client.Close()

			_, err := client.Get(server.URL, WithCookieString(tt.cookieString))
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Cookie String Parsing - Error Cases
// ----------------------------------------------------------------------------

func TestCookie_StringParsingErrors(t *testing.T) {
	tests := []struct {
		name         string
		cookieString string
		expectError  bool
	}{
		{
			name:         "malformed without equals",
			cookieString: "invalid",
			expectError:  true,
		},
		{
			name:         "empty name",
			cookieString: "=value",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client, _ := newTestClient()
			defer client.Close()

			_, err := client.Get(server.URL, WithCookieString(tt.cookieString))
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Cookie Auto-Domain Extraction
// ----------------------------------------------------------------------------

func TestCookie_AutoDomain(t *testing.T) {
	t.Parallel()

	cookieReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("test")
		if err == nil && c.Value == "value" {
			cookieReceived = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	// Create cookie without domain - should auto-extract from URL
	cookie := http.Cookie{
		Name:  "test",
		Value: "value",
	}

	_, err := client.Get(server.URL, WithCookie(cookie))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if !cookieReceived {
		t.Error("Cookie was not received by server")
	}
}

// ----------------------------------------------------------------------------
// Cookie Persistence (Jar)
// ----------------------------------------------------------------------------

func TestCookie_Persistence(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
			w.WriteHeader(http.StatusOK)
		} else {
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != "abc123" {
				t.Error("Session cookie not persisted")
			}
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	// First request - server sets cookie
	_, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}

	// Second request - cookie should be sent automatically
	_, err = client.Get(server.URL)
	if err != nil {
		t.Fatalf("Second request failed: %v", err)
	}
}

// ----------------------------------------------------------------------------
// Response Cookies
// ----------------------------------------------------------------------------

func TestCookie_ResponseOperations(t *testing.T) {
	t.Run("GetCookie", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
			http.SetCookie(w, &http.Cookie{Name: "token", Value: "xyz789"})
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		sessionCookie := resp.GetCookie("session")
		if sessionCookie == nil || sessionCookie.Value != "abc123" {
			t.Error("Session cookie not found or incorrect")
		}

		tokenCookie := resp.GetCookie("token")
		if tokenCookie == nil || tokenCookie.Value != "xyz789" {
			t.Error("Token cookie not found or incorrect")
		}
	})

	t.Run("HasCookie", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "exists", Value: "yes"})
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if !resp.HasCookie("exists") {
			t.Error("Expected cookie 'exists' to be present")
		}

		if resp.HasCookie("nonexistent") {
			t.Error("Expected cookie 'nonexistent' to be absent")
		}
	})

	t.Run("ResponseCookies", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "cookie1", Value: "value1"})
			http.SetCookie(w, &http.Cookie{Name: "cookie2", Value: "value2"})
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		cookies := resp.Response.Cookies
		if len(cookies) != 2 {
			t.Errorf("Expected 2 cookies, got %d", len(cookies))
		}
	})
}

// ----------------------------------------------------------------------------
// Cookie Inspection
// ----------------------------------------------------------------------------

func TestCookie_Inspection(t *testing.T) {
	t.Parallel()

	var receivedCookies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, c := range r.Cookies() {
			receivedCookies = append(receivedCookies, c.Name+"="+c.Value)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	_, err := client.Get(server.URL,
		WithCookie(http.Cookie{Name: "cookie1", Value: "value1"}),
		WithCookie(http.Cookie{Name: "cookie2", Value: "value2"}),
	)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if len(receivedCookies) != 2 {
		t.Fatalf("Expected 2 cookies, got %d", len(receivedCookies))
	}
	found1, found2 := false, false
	for _, c := range receivedCookies {
		if c == "cookie1=value1" {
			found1 = true
		}
		if c == "cookie2=value2" {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Errorf("Missing cookies: cookie1=%v cookie2=%v, received=%v", found1, found2, receivedCookies)
	}
}

// ============================================================================
// Cookie pool and parseCookieHeader boundary tests
// ============================================================================

func TestCookieSlicePool_BoundaryConditions(t *testing.T) {
	t.Run("get and return normal slice", func(t *testing.T) {
		slice := getCookiesSlice()
		if slice == nil {
			t.Fatal("expected non-nil slice")
		}
		if len(*slice) != 0 {
			t.Error("expected empty slice from pool")
		}
		*slice = append(*slice, &http.Cookie{Name: "test", Value: "val"})
		putCookiesSlice(slice)
	})

	t.Run("oversized slice not pooled", func(t *testing.T) {
		s := make([]*http.Cookie, 0, 128)
		slice := &s
		for i := range 100 {
			*slice = append(*slice, &http.Cookie{Name: "c" + strings.Repeat("x", 1), Value: strings.Repeat("v", 1)})
			_ = i
		}
		// cap > 64, should not be pooled
		preCap := cap(*slice)
		if preCap <= 64 {
			t.Skip("slice cap too small to test oversized path")
		}
		putCookiesSlice(slice)
		// No panic = success
	})
}

func TestParseCookieHeader_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name  string
		input string
		wantN int
	}{
		{"empty string", "", 0},
		{"just semicolons", ";;;", 0},
		{"whitespace only", "   ", 0},
		{"single pair no value", "name", 0},
		{"single pair with equals", "name=value", 1},
		{"leading whitespace", "  name=value", 1},
		{"trailing whitespace", "name=value  ", 1},
		{"multiple pairs", "a=1; b=2; c=3", 3},
		{"tab as whitespace", "name=	val	ue", 1},
		{"empty name", "=value", 0},
		{"pair with spaces around equals", "name = value", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cookies := parseCookieHeader(tt.input)
			if len(cookies) != tt.wantN {
				t.Errorf("parseCookieHeader(%q) returned %d cookies, want %d", tt.input, len(cookies), tt.wantN)
			}
		})
	}
}
