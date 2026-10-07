package engine

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// RESPONSE PROCESSOR TESTS
// ============================================================================

func TestResponseProcessor_Process(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		MaxResponseBodySize: 50 * 1024 * 1024, // 50MB
	}

	processor := newResponseProcessor(config)

	tests := []struct {
		name         string
		httpResponse *http.Response
		validate     func(*testing.T, *Response)
	}{
		{
			name: "Simple JSON response",
			httpResponse: &http.Response{
				StatusCode:    200,
				Status:        "200 OK",
				ContentLength: 32, // Correct length for the JSON string
				Header: http.Header{
					"Content-Type":   []string{"application/json"},
					"Content-Length": []string{"32"},
				},
				Body:    io.NopCloser(strings.NewReader(`{"message":"success","code":200}`)),
				Request: &http.Request{}, // Add Request to avoid nil pointer
			},
			validate: func(t *testing.T, resp *Response) {
				if resp.StatusCode() != 200 {
					t.Errorf("Expected status code 200, got %d", resp.StatusCode())
				}
				if resp.Status() != "200 OK" {
					t.Errorf("Expected status '200 OK', got '%s'", resp.Status())
				}
				if resp.Body() != `{"message":"success","code":200}` {
					t.Errorf("Expected body '..success..', got '%s'", resp.Body())
				}
				if len(resp.RawBody()) == 0 {
					t.Error("RawBody should not be empty")
				}
				if resp.ContentLength() != 32 {
					t.Errorf("Expected content length 32, got %d", resp.ContentLength())
				}
			},
		},
		{
			name: "Error response",
			httpResponse: &http.Response{
				StatusCode: 404,
				Status:     "404 Not Found",
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body:    io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
				Request: &http.Request{}, // Add Request to avoid nil pointer
			},
			validate: func(t *testing.T, resp *Response) {
				if resp.StatusCode() != 404 {
					t.Errorf("Expected status code 404, got %d", resp.StatusCode())
				}
				if resp.Status() != "404 Not Found" {
					t.Errorf("Expected status '404 Not Found', got '%s'", resp.Status())
				}
				if !strings.Contains(resp.Body(), "not found") {
					t.Error("Response body should contain 'not found'")
				}
			},
		},
		{
			name: "Response with cookies",
			httpResponse: &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header: http.Header{
					"Set-Cookie": []string{
						"session_id=abc123; Path=/; HttpOnly",
						"user_pref=dark_mode; Path=/",
					},
				},
				Body:    io.NopCloser(strings.NewReader("OK")),
				Request: &http.Request{}, // Add Request to avoid nil pointer
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
		{
			name: "Empty response body",
			httpResponse: &http.Response{
				StatusCode: 204,
				Status:     "204 No Content",
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    &http.Request{}, // Add Request to avoid nil pointer
			},
			validate: func(t *testing.T, resp *Response) {
				if resp.StatusCode() != 204 {
					t.Errorf("Expected status code 204, got %d", resp.StatusCode())
				}
				if resp.Body() != "" {
					t.Errorf("Expected empty body, got '%s'", resp.Body())
				}
				if len(resp.RawBody()) != 0 {
					t.Errorf("Expected empty RawBody, got %d bytes", len(resp.RawBody()))
				}
			},
		},
		{
			name: "Binary response",
			httpResponse: &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header: http.Header{
					"Content-Type": []string{"application/octet-stream"},
				},
				Body:    io.NopCloser(bytes.NewReader([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})), // PNG header
				Request: &http.Request{},                                                                       // Add Request to avoid nil pointer
			},
			validate: func(t *testing.T, resp *Response) {
				if resp.StatusCode() != 200 {
					t.Errorf("Expected status code 200, got %d", resp.StatusCode())
				}

				expectedBytes := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
				if !bytes.Equal(resp.RawBody(), expectedBytes) {
					t.Errorf("Expected binary data %v, got %v", expectedBytes, resp.RawBody())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := processor.Process(tt.httpResponse)
			if err != nil {
				t.Fatalf("Failed to process response: %v", err)
			}

			tt.validate(t, resp)
		})
	}
}

func TestResponseProcessor_LargeResponse(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		MaxResponseBodySize: 1024, // 1KB limit for testing
	}

	processor := newResponseProcessor(config)

	// Create response exceeding the limit
	largeData := strings.Repeat("A", 2048) // 2KB data
	httpResponse := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
		},
		Body:    io.NopCloser(strings.NewReader(largeData)),
		Request: &http.Request{}, // Add Request to avoid nil pointer
	}

	_, err := processor.Process(httpResponse)
	if err == nil {
		t.Error("Expected error for large response, got nil")
	}

	if !strings.Contains(err.Error(), "response body exceeds limit") && !strings.Contains(err.Error(), "response body too large") {
		t.Errorf("Expected response body size error, got: %v", err)
	}
}

// TestResponseProcessor_BodySizeExactBoundary pins the limit semantics at the
// edge: a body of exactly MaxResponseBodySize bytes must be accepted, and one
// byte over must be rejected.
func TestResponseProcessor_BodySizeExactBoundary(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"exactly at limit succeeds", 1024, false},
		{"one byte over limit fails", 1025, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Timeout:             30 * time.Second,
				MaxResponseBodySize: 1024,
			}
			processor := newResponseProcessor(config)

			httpResponse := &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header: http.Header{
					"Content-Type": []string{"text/plain"},
				},
				Body:    io.NopCloser(strings.NewReader(strings.Repeat("A", tt.size))),
				Request: &http.Request{},
			}

			resp, err := processor.Process(httpResponse)
			if tt.wantErr && err == nil {
				t.Error("expected size-limit error, got nil")
			}
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(resp.Body()) != tt.size {
					t.Errorf("body length = %d, want %d", len(resp.Body()), tt.size)
				}
				ReleaseResponse(resp)
			}
		})
	}
}

func TestResponseProcessor_HeaderProcessing(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		MaxResponseBodySize: 50 * 1024 * 1024,
	}

	processor := newResponseProcessor(config)

	httpResponse := &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		ContentLength: 13, // Set ContentLength field directly
		Header: http.Header{
			"Content-Type":    []string{"application/json"},
			"Content-Length":  []string{"13"},
			"X-Custom-Header": []string{"custom-value"},
			"Cache-Control":   []string{"no-cache, no-store"},
			"Set-Cookie":      []string{"session=abc123"},
		},
		Body:    io.NopCloser(strings.NewReader(`{"test":true}`)),
		Request: &http.Request{}, // Add Request to avoid nil pointer
	}

	resp, err := processor.Process(httpResponse)
	if err != nil {
		t.Fatalf("Failed to process response: %v", err)
	}

	// Check if headers are correctly copied
	headers := resp.Headers()
	if len(headers["Content-Type"]) == 0 || headers["Content-Type"][0] != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got %v", headers["Content-Type"])
	}

	if len(headers["X-Custom-Header"]) == 0 || headers["X-Custom-Header"][0] != "custom-value" {
		t.Errorf("Expected X-Custom-Header 'custom-value', got %v", headers["X-Custom-Header"])
	}

	if len(headers["Cache-Control"]) == 0 || headers["Cache-Control"][0] != "no-cache, no-store" {
		t.Errorf("Expected Cache-Control 'no-cache, no-store', got %v", headers["Cache-Control"])
	}

	// Check if Content-Length is correctly set
	if resp.ContentLength() != 13 {
		t.Errorf("Expected content length 13, got %d", resp.ContentLength())
	}
}

func TestResponseProcessor_CookieProcessing(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		MaxResponseBodySize: 50 * 1024 * 1024,
	}

	processor := newResponseProcessor(config)

	tests := []struct {
		name       string
		setCookies []string
		validate   func(*testing.T, []*http.Cookie)
	}{
		{
			name: "Simple cookie",
			setCookies: []string{
				"session_id=abc123",
			},
			validate: func(t *testing.T, cookies []*http.Cookie) {
				if len(cookies) != 1 {
					t.Errorf("Expected 1 cookie, got %d", len(cookies))
					return
				}

				cookie := cookies[0]
				if cookie.Name != "session_id" {
					t.Errorf("Expected cookie name 'session_id', got '%s'", cookie.Name)
				}
				if cookie.Value != "abc123" {
					t.Errorf("Expected cookie value 'abc123', got '%s'", cookie.Value)
				}
			},
		},
		{
			name: "Cookie with attributes",
			setCookies: []string{
				"session_id=abc123; Path=/; HttpOnly; Secure",
			},
			validate: func(t *testing.T, cookies []*http.Cookie) {
				if len(cookies) != 1 {
					t.Errorf("Expected 1 cookie, got %d", len(cookies))
					return
				}

				cookie := cookies[0]
				if cookie.Name != "session_id" {
					t.Errorf("Expected cookie name 'session_id', got '%s'", cookie.Name)
				}
				if cookie.Value != "abc123" {
					t.Errorf("Expected cookie value 'abc123', got '%s'", cookie.Value)
				}
				if cookie.Path != "/" {
					t.Errorf("Expected cookie path '/', got '%s'", cookie.Path)
				}
				if !cookie.HttpOnly {
					t.Error("Expected HttpOnly cookie")
				}
				if !cookie.Secure {
					t.Error("Expected Secure cookie")
				}
			},
		},
		{
			name: "Multiple cookies",
			setCookies: []string{
				"session_id=abc123; Path=/",
				"user_pref=dark_mode; Path=/settings",
				"lang=en; Domain=.example.com",
			},
			validate: func(t *testing.T, cookies []*http.Cookie) {
				if len(cookies) != 3 {
					t.Errorf("Expected 3 cookies, got %d", len(cookies))
					return
				}

				cookieMap := make(map[string]*http.Cookie)
				for _, cookie := range cookies {
					cookieMap[cookie.Name] = cookie
				}

				if session, ok := cookieMap["session_id"]; ok {
					if session.Value != "abc123" {
						t.Errorf("Expected session_id value 'abc123', got '%s'", session.Value)
					}
					if session.Path != "/" {
						t.Errorf("Expected session_id path '/', got '%s'", session.Path)
					}
				} else {
					t.Error("session_id cookie not found")
				}

				if pref, ok := cookieMap["user_pref"]; ok {
					if pref.Value != "dark_mode" {
						t.Errorf("Expected user_pref value 'dark_mode', got '%s'", pref.Value)
					}
					if pref.Path != "/settings" {
						t.Errorf("Expected user_pref path '/settings', got '%s'", pref.Path)
					}
				} else {
					t.Error("user_pref cookie not found")
				}

				if lang, ok := cookieMap["lang"]; ok {
					if lang.Value != "en" {
						t.Errorf("Expected lang value 'en', got '%s'", lang.Value)
					}
					if lang.Domain != ".example.com" {
						t.Errorf("Expected lang domain '.example.com', got '%s'", lang.Domain)
					}
				} else {
					t.Error("lang cookie not found")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpResponse := &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header: http.Header{
					"Set-Cookie": tt.setCookies,
				},
				Body:    io.NopCloser(strings.NewReader("OK")),
				Request: &http.Request{}, // Add Request to avoid nil pointer
			}

			resp, err := processor.Process(httpResponse)
			if err != nil {
				t.Fatalf("Failed to process response: %v", err)
			}

			tt.validate(t, resp.Cookies())
		})
	}
}

func TestResponseProcessor_ErrorHandling(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		MaxResponseBodySize: 50 * 1024 * 1024,
	}

	processor := newResponseProcessor(config)

	tests := []struct {
		name         string
		httpResponse *http.Response
		expectError  bool
	}{
		{
			name:         "Nil response",
			httpResponse: nil,
			expectError:  true,
		},
		{
			name: "Response with nil body",
			httpResponse: &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     http.Header{},
				Body:       nil,
				Request:    &http.Request{}, // Add Request to avoid nil pointer
			},
			expectError: false, // Should handle gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := processor.Process(tt.httpResponse)

			if tt.expectError && err == nil {
				t.Error("Expected error, got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestResponseProcessor_ContentLengthHandling(t *testing.T) {
	config := &Config{
		Timeout: 30 * time.Second,

		MaxResponseBodySize: 50 * 1024 * 1024,
	}

	processor := newResponseProcessor(config)

	tests := []struct {
		name           string
		contentLength  string
		body           string
		expectedLength int64
	}{
		{
			name:           "Correct content length",
			contentLength:  "13",
			body:           "Hello, World!",
			expectedLength: 13,
		},
		{
			name:           "No content length header",
			contentLength:  "",
			body:           "Hello, World!",
			expectedLength: 0, // Should be 0 when header is missing
		},
		{
			name:           "Invalid content length",
			contentLength:  "invalid",
			body:           "Hello, World!",
			expectedLength: 0, // Should be 0 when header is invalid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			var contentLength int64 = 0
			if tt.contentLength != "" {
				headers.Set("Content-Length", tt.contentLength)
				// Parse content length for the ContentLength field
				if parsed, err := strconv.ParseInt(tt.contentLength, 10, 64); err == nil {
					contentLength = parsed
				}
			}

			httpResponse := &http.Response{
				StatusCode:    200,
				Status:        "200 OK",
				ContentLength: contentLength,
				Header:        headers,
				Body:          io.NopCloser(strings.NewReader(tt.body)),
			}

			resp, err := processor.Process(httpResponse)
			if err != nil {
				t.Fatalf("Failed to process response: %v", err)
			}

			if resp.ContentLength() != tt.expectedLength {
				t.Errorf("Expected content length %d, got %d", tt.expectedLength, resp.ContentLength())
			}
		})
	}
}

// countingReadCloser tracks how many times Close is invoked.
type countingReadCloser struct {
	inner  io.Reader
	closes int
}

func (c *countingReadCloser) Read(p []byte) (int, error) { return c.inner.Read(p) }
func (c *countingReadCloser) Close() error {
	c.closes++
	return nil
}

// TestStreamBodyReader_CloseIdempotent verifies Close is safe to call twice:
// the caller may close the body and ReleaseResponse will close it again via
// rawBodyReader. Without the guard the same *pooledLimitReader would be
// returned to the pool twice, handing one object to two concurrent requests.
func TestStreamBodyReader_CloseIdempotent(t *testing.T) {
	source := &countingReadCloser{inner: strings.NewReader("stream body")}
	s := &streamBodyReader{reader: getLimitReader(source, 1024), source: source}

	if err := s.Close(); err != nil {
		t.Fatalf("first Close() error: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close() error: %v", err)
	}
	if source.closes != 1 {
		t.Errorf("source.Close called %d times, want exactly 1", source.closes)
	}
}

// TestStreamBodyReader_OversizeError verifies the limit-enforcement contract
// at the unit level: a body larger than the configured limit must surface as
// a Read error (not a synthetic EOF, which io.Copy would treat as success and
// silently truncate), while a body of exactly the limit must read cleanly.
// The underlying reader's budget is limit+1 (see executeRequest), which is
// what lets Read distinguish the two cases.
func TestStreamBodyReader_OversizeError(t *testing.T) {
	t.Run("body exactly at limit reads cleanly", func(t *testing.T) {
		const limit = 8
		s := &streamBodyReader{
			reader: getLimitReader(io.NopCloser(strings.NewReader("12345678")), limit+1),
			source: io.NopCloser(strings.NewReader("")),
			limit:  limit,
		}
		data, err := io.ReadAll(s)
		if err != nil {
			t.Fatalf("ReadAll at exact limit: unexpected error %v", err)
		}
		if string(data) != "12345678" {
			t.Errorf("ReadAll at exact limit: got %q, want %q", data, "12345678")
		}
	})

	t.Run("body over limit errors instead of truncating", func(t *testing.T) {
		const limit = 8
		s := &streamBodyReader{
			reader: getLimitReader(io.NopCloser(strings.NewReader("12345678901")), limit+1),
			source: io.NopCloser(strings.NewReader("")),
			limit:  limit,
		}
		_, err := io.ReadAll(s)
		if err == nil {
			t.Fatal("ReadAll over limit: expected error, got success (silent truncation)")
		}
		if !strings.Contains(err.Error(), "exceeds size limit") {
			t.Errorf("ReadAll over limit: unexpected error %v", err)
		}
	})

	t.Run("final chunk crossing limit with EOF errors", func(t *testing.T) {
		// An io.Reader may legally return its last bytes together with io.EOF.
		// A body of exactly limit+1 bytes delivered that way must still report
		// the oversize error — returning the raw EOF would let io.Copy treat
		// the truncated read as a clean success.
		const limit = 8
		s := &streamBodyReader{
			reader: getLimitReader(&eofOnLastReader{data: "123456789"}, limit+1),
			source: io.NopCloser(strings.NewReader("")),
			limit:  limit,
		}
		_, err := io.ReadAll(s)
		if err == nil {
			t.Fatal("expected oversize error when final chunk crosses limit with EOF, got clean EOF")
		}
		if !strings.Contains(err.Error(), "exceeds size limit") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("read after close errors instead of panicking", func(t *testing.T) {
		// Close returns the pooled limit reader to the pool (nil'ing its
		// underlying reader); a subsequent Read must surface an error rather
		// than dereferencing the recycled reader.
		s := &streamBodyReader{
			reader: getLimitReader(io.NopCloser(strings.NewReader("body")), 1024),
			source: io.NopCloser(strings.NewReader("")),
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		buf := make([]byte, 4)
		if _, err := s.Read(buf); err == nil {
			t.Error("expected error reading after Close, got success")
		} else if !strings.Contains(err.Error(), "closed") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// eofOnLastReader returns (n, io.EOF) from the Read that delivers its final
// byte — a legal io.Reader behavior that strings/bytes.Reader never exercise.
type eofOnLastReader struct {
	data string
	off  int
}

func (r *eofOnLastReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	if r.off == len(r.data) {
		return n, io.EOF
	}
	return n, nil
}

// TestStreamBodyReader_ConcurrentClose is the concurrent variant of
// TestStreamBodyReader_CloseIdempotent: the user's Close and ReleaseResponse's
// Close may race from different goroutines, so the guard must be an atomic
// CAS — run with -race, which flags the unsynchronized closed-flag write this
// test provokes when the guard is a plain bool.
func TestStreamBodyReader_ConcurrentClose(t *testing.T) {
	const rounds = 200
	for i := 0; i < rounds; i++ {
		source := &countingReadCloser{inner: strings.NewReader("x")}
		s := &streamBodyReader{reader: getLimitReader(source, 1024), source: source}

		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = s.Close()
			}()
		}
		wg.Wait()

		if source.closes != 1 {
			t.Fatalf("round %d: source.Close called %d times, want exactly 1", i, source.closes)
		}
	}
}

// ---------------------------------------------------------------------------
// TestResponseConcurrentBodyAccess verifies that the Response body accessors
// are safe to call concurrently with the body mutators. RawBody and
// RawBodyReader take bodyMu for read specifically so that middleware or user
// goroutines reading a response never race with a concurrent SetRawBody /
// SetRawBodyReader / SetBody write; run with -race to catch a regression.
func TestResponseConcurrentBodyAccess(t *testing.T) {
	resp := getResponse()
	defer ReleaseResponse(resp)
	resp.SetRawBody([]byte("initial body content"))

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		// Reader goroutine: mixes locked and previously-unlocked accessors.
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 300; j++ {
				_ = resp.RawBody()
				_ = resp.Body()
				_ = resp.RawBodyReader()
			}
		}()

		// Writer goroutine: mutates every body-related field under bodyMu.
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 300; j++ {
				resp.SetRawBody([]byte("writer payload"))
				resp.SetBody("direct body")
				resp.SetRawBodyReader(io.NopCloser(bytes.NewReader(nil)))
			}
		}()
	}
	wg.Wait()
}

// TestResponseProcessor_LargeChunkedBody pins the slow path for bodies with
// unknown length (ContentLength -1, chunked semantics) spanning several
// buffer growth steps: content must round-trip exactly at sizes well beyond
// the initial pooled buffer capacity.
func TestResponseProcessor_LargeChunkedBody(t *testing.T) {
	config := &Config{Timeout: 30 * time.Second, MaxResponseBodySize: 50 * 1024 * 1024}
	processor := newResponseProcessor(config)

	for _, size := range []int{33 * 1024, 64 * 1024, 100 * 1024} {
		want := bytes.Repeat([]byte{0x7f}, size)
		httpResp := &http.Response{
			StatusCode:    200,
			Status:        "200 OK",
			Header:        http.Header{},
			Body:          io.NopCloser(bytes.NewReader(want)),
			Request:       &http.Request{},
			ContentLength: -1, // unknown length -> slow path
		}
		resp, err := processor.Process(httpResp)
		if err != nil {
			t.Fatalf("Process(%d bytes): %v", size, err)
		}
		if !bytes.Equal(resp.RawBody(), want) {
			t.Fatalf("body of %d bytes mismatched", size)
		}
	}
}
