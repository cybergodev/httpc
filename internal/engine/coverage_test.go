package engine

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybergodev/httpc/internal/types"
)

// fileDataHelper is a test helper for creating file data.
type fileDataHelper struct {
	Filename    string
	Content     []byte
	ContentType string
}

// formDataHelper creates a *types.FormData for testing.
func formDataHelper(fields map[string]string, files map[string]*fileDataHelper) *types.FormData {
	fd := &types.FormData{
		Fields: fields,
		Files:  make(map[string]*types.FileData),
	}
	for key, fh := range files {
		if fh == nil {
			fd.Files[key] = nil
			continue
		}
		fd.Files[key] = &types.FileData{
			Filename:    fh.Filename,
			Content:     fh.Content,
			ContentType: fh.ContentType,
		}
	}
	return fd
}

// ============================================================================
// URL CACHE TESTS
// ============================================================================

// TestURLCache_SanitizedKey validates that URLs differing only in sensitive query params
// share a single cache entry (sanitized key deduplication), while URLs with different
// non-sensitive params are cached separately.
func TestURLCache_SanitizedKey(t *testing.T) {
	clearURLCache()

	// These URLs differ only in the sensitive "token" param — should map to one cache entry
	url1 := "https://api.example.com/data?token=secretA&page=1"
	url2 := "https://api.example.com/data?token=secretB&page=1"

	parsed1, err := globalURLCache.Get(url1)
	if err != nil {
		t.Fatalf("Failed to parse URL1: %v", err)
	}
	parsed2, err := globalURLCache.Get(url2)
	if err != nil {
		t.Fatalf("Failed to parse URL2: %v", err)
	}

	// Both URLs should share a single sanitized cache entry
	if getURLCacheSize() != 1 {
		t.Errorf("Expected 1 cache entry (sanitized key dedup), got %d", getURLCacheSize())
	}

	// Both lookups return the first cached entry's token value (dedup by sanitized key)
	q1 := parsed1.Query()
	q2 := parsed2.Query()
	if q1.Get("token") != "secretA" {
		t.Errorf("URL1 token = %q, want %q", q1.Get("token"), "secretA")
	}
	if q2.Get("token") != "secretA" {
		t.Errorf("URL2 token = %q, want %q (dedup: shares first entry's value)", q2.Get("token"), "secretA")
	}

	// URLs with different non-sensitive params should be cached separately
	url3 := "https://api.example.com/data?page=2"
	_, err = globalURLCache.Get(url3)
	if err != nil {
		t.Fatalf("Failed to parse URL3: %v", err)
	}
	if getURLCacheSize() != 2 {
		t.Errorf("Expected 2 cache entries after adding non-sensitive variant, got %d", getURLCacheSize())
	}
}

// TestURLCache_Operations was removed: populate/size/clear behavior is a
// strict subset of TestURLCache_Get below.

// TestCloneURL validates deep copying of URL structures.
func TestCloneURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Nil input", "", ""},
		{"URL with user stripped", "https://user:pass@example.com/path?q=1#frag", "https://example.com/path?q=1#frag"},
		{"URL without user", "https://example.com/path", "https://example.com/path"},
		{"URL with query and fragment", "https://example.com/search?q=golang#results", "https://example.com/search?q=golang#results"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.input == "" {
				result := cloneURL(nil)
				if result != nil {
					t.Error("cloneURL(nil) should return nil")
				}
				return
			}

			parsed, err := url.Parse(tt.input)
			if err != nil {
				t.Fatalf("Failed to parse URL: %v", err)
			}

			cloned := cloneURL(parsed)

			if cloned.String() != tt.expected {
				t.Errorf("Clone String() = %q, want %q", cloned.String(), tt.expected)
			}

			// Verify credentials are stripped
			if cloned.User != nil {
				t.Error("cloneURL should not preserve credentials (User field)")
			}

			// Verify independence: modify clone should not affect original
			cloned.Path = "/modified"
			if parsed.Path == "/modified" {
				t.Error("Modifying clone affected original")
			}
		})
	}
}

// ============================================================================
// ESCAPE QUOTES TESTS
// ============================================================================

// TestEscapeQuotes validates backslash and quote escaping per RFC 7578.
func TestEscapeQuotes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"No escaping needed", "hello", "hello"},
		{"Double quotes", `say "hello"`, `say \"hello\"`},
		{"Backslashes", `path\to\file`, `path\\to\\file`},
		{"Mixed escapes", `mix\"ed`, `mix\\\"ed`},
		{"Empty string", "", ""},
		{"Only backslash", `\`, `\\`},
		{"Only quote", `"`, `\"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapeQuotes(tt.input)
			if result != tt.expected {
				t.Errorf("escapeQuotes(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// ============================================================================
// FORMAT QUERY PARAM TESTS
// ============================================================================

// TestFormatQueryParam validates type-specific formatting of query parameter values.
func TestFormatQueryParam(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{"Nil", nil, ""},
		{"String", "hello", "hello"},
		{"Int", 42, "42"},
		{"Int64", int64(100), "100"},
		{"Int32", int32(7), "7"},
		{"Uint", uint(5), "5"},
		{"Uint64", uint64(200), "200"},
		{"Uint32", uint32(15), "15"},
		{"Float64", float64(3.14), "3.14"},
		{"Float32", float32(2.5), "2.5"},
		{"Bool true", true, "true"},
		{"Bool false", false, "false"},
		{"Other type", []int{1, 2, 3}, "[1 2 3]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatQueryParam(tt.input)
			if result != tt.expected {
				t.Errorf("FormatQueryParam(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// ============================================================================
// POOL BUFFER READ TESTS
// ============================================================================

// TestPooledMultipartBuffer_Read validates multipart buffer pool read behavior.
func TestPooledMultipartBuffer_Read(t *testing.T) {
	t.Run("Normal read", func(t *testing.T) {
		buf := bytes.NewBufferString("multipart data")
		reader := &pooledMultipartBuffer{buf: buf, owned: false}

		p := make([]byte, 32)
		n, err := reader.Read(p)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if n == 0 {
			t.Error("Expected to read some bytes")
		}
	})

	t.Run("Read from nil buffer", func(t *testing.T) {
		reader := &pooledMultipartBuffer{buf: nil, owned: false}
		p := make([]byte, 10)
		_, err := reader.Read(p)
		if err != io.EOF {
			t.Errorf("Expected io.EOF for nil buffer, got %v", err)
		}
	})

	t.Run("Read until EOF defers pool return to Close", func(t *testing.T) {
		buf := getMultipartBuffer()
		buf.WriteString("data")
		reader := &pooledMultipartBuffer{buf: buf, owned: true}

		// Read everything
		_, _ = io.ReadAll(reader)

		// EOF must NOT release: net/http closes the body after reading it
		// (later, and on HTTP/2 from another goroutine). Releasing at EOF
		// would recycle the wrapper while a delayed Close can still arrive
		// and release a wrapper already reused by another request.
		if reader.buf == nil {
			t.Error("buf must stay owned after EOF read — release belongs to Close")
		}
		if !reader.owned {
			t.Error("owned must stay true after EOF read — release belongs to Close")
		}

		_ = reader.Close()

		if reader.buf != nil {
			t.Error("Expected buf to be nil after Close")
		}
		if reader.owned {
			t.Error("Expected owned to be false after Close")
		}
	})
}

// TestPooledJSONBuffer_Read validates JSON buffer pool read behavior.
func TestPooledJSONBuffer_Read(t *testing.T) {
	t.Run("Normal read", func(t *testing.T) {
		buf := bytes.NewBufferString(`{"key":"value"}`)
		reader := &pooledJSONBuffer{buf: buf, owned: false}

		p := make([]byte, 64)
		n, err := reader.Read(p)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if n == 0 {
			t.Error("Expected to read some bytes")
		}
	})

	t.Run("Read from nil buffer", func(t *testing.T) {
		reader := &pooledJSONBuffer{buf: nil, owned: false}
		p := make([]byte, 10)
		_, err := reader.Read(p)
		if err != io.EOF {
			t.Errorf("Expected io.EOF for nil buffer, got %v", err)
		}
	})

	t.Run("Read until EOF defers pool return to Close", func(t *testing.T) {
		buf := getJSONBuffer()
		buf.WriteString(`{"test":true}`)
		reader := &pooledJSONBuffer{buf: buf, owned: true}

		// Read everything
		_, _ = io.ReadAll(reader)

		// EOF must NOT release — see the matching pooledMultipartBuffer
		// subtest for the net/http close-after-EOF rationale.
		if reader.buf == nil {
			t.Error("buf must stay owned after EOF read — release belongs to Close")
		}
		if !reader.owned {
			t.Error("owned must stay true after EOF read — release belongs to Close")
		}

		_ = reader.Close()

		if reader.buf != nil {
			t.Error("Expected buf to be nil after Close")
		}
		if reader.owned {
			t.Error("Expected owned to be false after Close")
		}
	})
}

// ============================================================================
// RESPONSE ACCESSOR/MUTATOR TESTS
// ============================================================================

// TestResponse_Accessors_TableDriven validates that each Response getter returns the set value.
func TestResponse_Accessors_TableDriven(t *testing.T) {
	cookies := []*http.Cookie{{Name: "session", Value: "abc"}}
	redirectChain := []string{"https://a.com", "https://b.com"}
	reqHeaders := http.Header{"X-Test": {"value"}}

	tests := []struct {
		name    string
		setFunc func(*Response)
		getFunc func(*Response) any
		want    any
	}{
		{
			name:    "StatusCode",
			setFunc: func(r *Response) { r.SetStatusCode(201) },
			getFunc: func(r *Response) any { return r.StatusCode() },
			want:    201,
		},
		{
			name:    "Status",
			setFunc: func(r *Response) { r.SetStatus("201 Created") },
			getFunc: func(r *Response) any { return r.Status() },
			want:    "201 Created",
		},
		{
			name:    "Headers",
			setFunc: func(r *Response) { r.SetHeaders(http.Header{"X-Custom": {"val"}}) },
			getFunc: func(r *Response) any { return r.Headers().Get("X-Custom") },
			want:    "val",
		},
		{
			name:    "Body",
			setFunc: func(r *Response) { r.SetBody("response body") },
			getFunc: func(r *Response) any { return r.Body() },
			want:    "response body",
		},
		{
			name:    "RawBody",
			setFunc: func(r *Response) { r.SetRawBody([]byte("raw")) },
			getFunc: func(r *Response) any { return string(r.RawBody()) },
			want:    "raw",
		},
		{
			name:    "ContentLength",
			setFunc: func(r *Response) { r.SetContentLength(1234) },
			getFunc: func(r *Response) any { return r.ContentLength() },
			want:    int64(1234),
		},
		{
			name:    "Proto",
			setFunc: func(r *Response) { r.SetProto("HTTP/2.0") },
			getFunc: func(r *Response) any { return r.Proto() },
			want:    "HTTP/2.0",
		},
		{
			name:    "Duration",
			setFunc: func(r *Response) { r.SetDuration(5 * time.Second) },
			getFunc: func(r *Response) any { return r.Duration() },
			want:    5 * time.Second,
		},
		{
			name:    "Attempts",
			setFunc: func(r *Response) { r.SetAttempts(3) },
			getFunc: func(r *Response) any { return r.Attempts() },
			want:    3,
		},
		{
			name:    "Cookies count",
			setFunc: func(r *Response) { r.SetCookies(cookies) },
			getFunc: func(r *Response) any { return len(r.Cookies()) },
			want:    1,
		},
		{
			name:    "RedirectChain length",
			setFunc: func(r *Response) { r.SetRedirectChain(redirectChain) },
			getFunc: func(r *Response) any { return len(r.RedirectChain()) },
			want:    2,
		},
		{
			name:    "RedirectCount",
			setFunc: func(r *Response) { r.SetRedirectCount(2) },
			getFunc: func(r *Response) any { return r.RedirectCount() },
			want:    2,
		},
		{
			name:    "ProxyURL",
			setFunc: func(r *Response) { r.SetProxyURL("http://proxy.example.com:8080") },
			getFunc: func(r *Response) any { return r.ProxyURL() },
			want:    "http://proxy.example.com:8080",
		},
		{
			name:    "RequestHeaders",
			setFunc: func(r *Response) { r.SetRequestHeaders(reqHeaders) },
			getFunc: func(r *Response) any { return r.RequestHeaders().Get("X-Test") },
			want:    "value",
		},
		{
			name:    "RequestURL",
			setFunc: func(r *Response) { r.SetRequestURL("https://example.com/api") },
			getFunc: func(r *Response) any { return r.RequestURL() },
			want:    "https://example.com/api",
		},
		{
			name:    "RequestMethod",
			setFunc: func(r *Response) { r.SetRequestMethod("PUT") },
			getFunc: func(r *Response) any { return r.RequestMethod() },
			want:    "PUT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{}
			tt.setFunc(resp)
			got := tt.getFunc(resp)
			if got != tt.want {
				t.Errorf("Accessor mismatch: got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestResponse_SetHeader validates SetHeader behavior with nil map and multiple values.
func TestResponse_SetHeader(t *testing.T) {
	t.Run("Nil headers auto-init", func(t *testing.T) {
		resp := &Response{}
		if resp.Headers() != nil {
			t.Error("Expected nil headers initially")
		}
		resp.SetHeader("X-Test", "value1")
		if resp.Headers() == nil {
			t.Error("Expected headers to be auto-initialized")
		}
		if resp.Headers().Get("X-Test") != "value1" {
			t.Errorf("Expected X-Test=value1, got %s", resp.Headers().Get("X-Test"))
		}
	})

	t.Run("Multiple values for same key", func(t *testing.T) {
		resp := &Response{}
		resp.SetHeader("Accept", "text/html", "application/json")
		vals := resp.Headers()["Accept"]
		if len(vals) != 2 {
			t.Errorf("Expected 2 values, got %d", len(vals))
		}
		if vals[0] != "text/html" || vals[1] != "application/json" {
			t.Errorf("Expected [text/html, application/json], got %v", vals)
		}
	})
}

// ============================================================================
// REQUEST SETHEADER NIL-MAP BRANCH
// ============================================================================

// TestRequest_SetHeader_NilMap validates that SetHeader auto-creates the headers map.
func TestRequest_SetHeader_NilMap(t *testing.T) {
	req := &Request{}
	if req.Headers() != nil {
		t.Error("Expected nil headers initially")
	}

	req.SetHeader("Authorization", "Bearer token")

	if req.Headers() == nil {
		t.Error("Expected headers map to be auto-created")
	}
	if req.Headers()["Authorization"] != "Bearer token" {
		t.Errorf("Expected Authorization=Bearer token, got %s", req.Headers()["Authorization"])
	}
}

// ============================================================================
// CLIENT POOL OPERATIONS TESTS
// ============================================================================

// TestClient_PoolOperations validates get/put operations for internal request pools.
func TestClient_PoolOperations(t *testing.T) {
	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	t.Run("Request pool get/put", func(t *testing.T) {
		req := client.getRequest()
		if req == nil {
			t.Error("getRequest returned nil")
		}
		req.SetMethod("GET")
		req.SetURL("https://example.com")

		client.putRequest(req)
		// Should not panic
	})

	t.Run("Security request pool get/put", func(t *testing.T) {
		secReq := client.getSecurityRequest()
		if secReq == nil {
			t.Fatal("getSecurityRequest returned nil")
		}
		secReq.Method = "GET"
		secReq.URL = "https://example.com"

		client.putSecurityRequest(secReq)
	})

	t.Run("Exec request pool get/put", func(t *testing.T) {
		execReq := client.getExecRequest()
		if execReq == nil {
			t.Error("getExecRequest returned nil")
		}
		execReq.SetMethod("POST")

		client.putExecRequest(execReq)
	})

	t.Run("Put nil security request", func(t *testing.T) {
		client.putSecurityRequest(nil) // should not panic
	})
}

// ============================================================================
// ADDITIONAL COVERAGE TESTS
// ============================================================================

// TestReleaseResponse was removed: nil/double-release and zeroed-after-release
// are asserted together in TestReleaseResponseNilSafe (resource_leak_test.go).

// TestClearResponsePools validates that clearResponsePools does not panic.
func TestClearResponsePools(t *testing.T) {
	clearResponsePools()

	// Verify pools still work after clearing
	buf := getBuffer()
	if buf == nil {
		t.Error("getBuffer returned nil after clearResponsePools")
	}
	putBuffer(buf)
}

// testBufferPoolLifecycle exercises the get/write/put/nil/oversize cycle for
// a *bytes.Buffer-based sync.Pool. Collapses the identical three-subtest
// pattern previously duplicated across multipart and JSON buffer pools.
func testBufferPoolLifecycle(t *testing.T, get func() *bytes.Buffer, put func(*bytes.Buffer), maxSize int) {
	t.Helper()

	t.Run("get and put", func(t *testing.T) {
		buf := get()
		if buf == nil {
			t.Fatal("get returned nil")
		}
		buf.WriteString("test data")
		put(buf)
	})

	t.Run("put nil", func(t *testing.T) {
		put(nil) // should not panic
	})

	t.Run("oversize discarded", func(t *testing.T) {
		buf := get()
		buf.Grow(maxSize + 1)
		put(buf) // should be discarded, not pooled
	})
}

// TestPoolLifecycle validates get/put/nil/oversize behavior for all internal
// pools via a single table-driven entry point, replacing three previously
// duplicated test functions.
func TestPoolLifecycle(t *testing.T) {
	t.Run("MultipartBuffer", func(t *testing.T) {
		testBufferPoolLifecycle(t, getMultipartBuffer, putMultipartBuffer, maxMultipartBufferSize)
	})
	t.Run("JSONBuffer", func(t *testing.T) {
		testBufferPoolLifecycle(t, getJSONBuffer, putJSONBuffer, maxJSONBufferSize)
	})
	// The MIMEHeader subtests were removed with the pool itself: Build's
	// multipart encoding now writes part headers directly into the pooled
	// buffer (see TestMultipartWireParity in pools_test.go).
}

// TestClient_IsClosed validates IsClosed reporting.
func TestClient_IsClosed(t *testing.T) {
	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client.IsClosed() {
		t.Error("New client should not be closed")
	}

	if err := client.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	if !client.IsClosed() {
		t.Error("Client should be closed after Close()")
	}
}

// TestClient_ClosedRequest validates that requests fail after client is closed.
func TestClient_ClosedRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Close before making request
	_ = client.Close()

	_, err = client.Request(backgroundCtx, "GET", server.URL)
	if err == nil {
		t.Error("Expected error when using closed client")
	}
}

// TestPooledReaders_ReadEOF consolidates the former TestPooledStringsReader
// and TestPooledBytesReader: normal reads deliver the full payload, and a
// read after EOF returns io.EOF. The strings reader's release discipline
// (pool return only in Close, never at EOF) is pinned separately by
// TestPooledStringsReader_NoReleaseOnEOF in request_test.go.
func TestPooledReaders_ReadEOF(t *testing.T) {
	tests := []struct {
		name   string
		reader io.Reader
		want   string
	}{
		{"strings reader", getPooledStringsReader("hello world"), "hello world"},
		{"bytes reader", getPooledBytesReader([]byte("byte data")), "byte data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := io.ReadAll(tt.reader)
			if err != nil {
				t.Fatalf("ReadAll error: %v", err)
			}
			if string(data) != tt.want {
				t.Errorf("read %q, want %q", data, tt.want)
			}
			// Second read must return EOF (inner reader is nil after EOF).
			p := make([]byte, 10)
			if _, err := tt.reader.Read(p); err != io.EOF {
				t.Errorf("read after EOF: got %v, want io.EOF", err)
			}
		})
	}
}

// TestBuild_NilBody validates that nil body is handled without error.
func TestBuild_NilBody(t *testing.T) {
	config := &Config{Timeout: 30 * time.Second}
	processor := newRequestProcessor(config)

	req := testRequestBuilder().
		Method("GET").
		URL("https://api.example.com/test").
		Context(context.Background()).
		Build()

	httpReq, err := processor.Build(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if httpReq == nil {
		t.Fatal("Expected HTTP request, got nil")
	}
}

// TestBuild_IOReaderBody validates that io.Reader body passes through directly.
func TestBuild_IOReaderBody(t *testing.T) {
	config := &Config{Timeout: 30 * time.Second}
	processor := newRequestProcessor(config)

	req := testRequestBuilder().
		Method("POST").
		URL("https://api.example.com/upload").
		Context(context.Background()).
		Body(bytes.NewBufferString("raw reader data")).
		Headers(map[string]string{"Content-Type": "application/octet-stream"}).
		Build()

	httpReq, err := processor.Build(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if httpReq.Body == nil {
		t.Error("Expected body, got nil")
	}
}

// TestBuild_XMLBody validates XML body serialization.
func TestBuild_XMLBody(t *testing.T) {
	config := &Config{Timeout: 30 * time.Second}
	processor := newRequestProcessor(config)

	type xmlRequest struct {
		XMLName struct{} `xml:"request"`
		Key     string   `xml:"key"`
	}

	req := testRequestBuilder().
		Method("POST").
		URL("https://api.example.com/data").
		Context(context.Background()).
		Headers(map[string]string{"Content-Type": "application/xml"}).
		Body(&xmlRequest{Key: "value"}).
		Build()

	httpReq, err := processor.Build(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if httpReq.Header.Get("Content-Type") != "application/xml" {
		t.Errorf("Expected Content-Type application/xml, got %s", httpReq.Header.Get("Content-Type"))
	}
}

// TestRequest_OnRequestOnResponse tests callback accessors.
func TestRequest_OnRequestOnResponse(t *testing.T) {
	req := &Request{}

	if req.OnRequest() != nil {
		t.Error("Expected nil OnRequest initially")
	}
	if req.OnResponse() != nil {
		t.Error("Expected nil OnResponse initially")
	}

	req.SetOnRequest(func(r *Request) error {
		return nil
	})
	if req.OnRequest() == nil {
		t.Error("Expected OnRequest to be set")
	}

	req.SetOnResponse(func(r *Response) error {
		return nil
	})
	if req.OnResponse() == nil {
		t.Error("Expected OnResponse to be set")
	}
}

// TestGetBuffer validates buffer pool get/put behavior.
func TestGetBuffer(t *testing.T) {
	buf := getBuffer()
	if buf == nil {
		t.Fatal("getBuffer returned nil")
	}
	buf.WriteString("test data")
	putBuffer(buf)

	// Get again should return a reset buffer
	buf2 := getBuffer()
	if buf2.Len() != 0 {
		t.Error("Expected empty buffer from pool")
	}
	putBuffer(buf2)
}

// TestPooledLimitReader validates the limit reader behavior.
func TestPooledLimitReader(t *testing.T) {
	t.Run("Limit enforcement", func(t *testing.T) {
		src := bytes.NewBufferString("hello world")
		lr := getLimitReader(src, 5)
		defer putLimitReader(lr)

		data, err := io.ReadAll(lr)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if len(data) > 5 {
			t.Errorf("Expected at most 5 bytes, got %d", len(data))
		}
	})

	t.Run("Nil reader", func(t *testing.T) {
		putLimitReader(nil) // should not panic
	})
}

// TestResponseProcessor_NilResponse was removed: the nil-response row of
// TestResponseProcessor_ErrorHandling (response_processor_test.go) asserts
// the same Process(nil) -> error contract.

// ============================================================================
// MULTIPART FORM DATA TESTS
// ============================================================================

// TestBuild_MultipartFormData validates multipart form data with fields and files.
func TestBuild_MultipartFormData(t *testing.T) {
	config := &Config{Timeout: 30 * time.Second}
	processor := newRequestProcessor(config)

	t.Run("Fields only", func(t *testing.T) {
		formData := formDataHelper(map[string]string{"username": "john"}, nil)
		req := testRequestBuilder().
			Method("POST").
			URL("https://api.example.com/upload").
			Context(context.Background()).
			Body(formData).
			Build()

		httpReq, err := processor.Build(req)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		ct := httpReq.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "multipart/form-data") {
			t.Errorf("Expected multipart content-type, got %s", ct)
		}
	})

	t.Run("Fields and files without content type", func(t *testing.T) {
		files := map[string]*fileDataHelper{
			"file1": {Filename: "test.txt", Content: []byte("file content")},
		}
		formData := formDataHelper(map[string]string{"field1": "value1"}, files)
		req := testRequestBuilder().
			Method("POST").
			URL("https://api.example.com/upload").
			Context(context.Background()).
			Body(formData).
			Build()

		httpReq, err := processor.Build(req)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		ct := httpReq.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "multipart/form-data") {
			t.Errorf("Expected multipart content-type, got %s", ct)
		}
	})

	t.Run("Files with content type", func(t *testing.T) {
		files := map[string]*fileDataHelper{
			"file1": {Filename: "test.png", Content: []byte("png data"), ContentType: "image/png"},
		}
		formData := formDataHelper(nil, files)
		req := testRequestBuilder().
			Method("POST").
			URL("https://api.example.com/upload").
			Context(context.Background()).
			Body(formData).
			Build()

		httpReq, err := processor.Build(req)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		ct := httpReq.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "multipart/form-data") {
			t.Errorf("Expected multipart content-type, got %s", ct)
		}
	})

	t.Run("Nil file entry errors", func(t *testing.T) {
		// A nil *FileData map entry means the caller's upload is missing a
		// file. Silently dropping it (the old behavior) loses data without
		// notice — Build must fail loudly instead.
		files := map[string]*fileDataHelper{
			"nil_file": nil,
		}
		formData := formDataHelper(nil, files)
		req := testRequestBuilder().
			Method("POST").
			URL("https://api.example.com/upload").
			Context(context.Background()).
			Body(formData).
			Build()

		httpReq, err := processor.Build(req)
		if err == nil {
			t.Fatal("Expected error for nil FileData entry, got nil")
		}
		if httpReq != nil {
			t.Errorf("Expected nil request on error, got %v", httpReq)
		}
	})
}

// ============================================================================
// CLIENT ERROR WITH TYPE TEST
// ============================================================================

// TestClientError_WithType validates the WithType method returns a copy.
func TestClientError_WithType(t *testing.T) {
	err := &ClientError{Type: ErrorTypeNetwork}
	result := err.WithType(ErrorTypeTimeout)
	if result == err {
		t.Error("WithType should return a new copy, not the same pointer")
	}
	if err.Type != ErrorTypeNetwork {
		t.Errorf("Original should be unmodified, got %v", err.Type)
	}
	if result.Type != ErrorTypeTimeout {
		t.Errorf("Expected ErrorTypeTimeout, got %v", result.Type)
	}
}

// ============================================================================
// RELEASE LAST RESP TEST
// ============================================================================

// TestReleaseLastResp validates releasing intermediate response objects.
func TestReleaseLastResp(t *testing.T) {
	t.Run("Non-nil response", func(t *testing.T) {
		resp := getResponse()
		resp.SetStatusCode(200)
		var lastResp = resp
		releaseLastResp(&lastResp)
		if lastResp != nil {
			t.Error("Expected pointer to be nil after release")
		}
	})

	t.Run("Nil response", func(t *testing.T) {
		var lastResp *Response
		releaseLastResp(&lastResp)
		if lastResp != nil {
			t.Error("Expected pointer to remain nil")
		}
	})
}

// ============================================================================
// URL CACHE GET TESTS
// ============================================================================

// TestURLCache_Get validates cache hit/miss and eviction behavior.
func TestURLCache_Get(t *testing.T) {
	clearURLCache()

	// Cache miss -> parse and store
	u, err := globalURLCache.Get("https://example.com/page1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if u == nil {
		t.Fatal("Expected URL, got nil")
	}

	// Cache hit
	u2, err := globalURLCache.Get("https://example.com/page1")
	if err != nil {
		t.Fatalf("Unexpected error on cache hit: %v", err)
	}
	if u2.String() != u.String() {
		t.Errorf("Cache hit returned different URL: %s vs %s", u2.String(), u.String())
	}

	// Invalid URL
	_, err = globalURLCache.Get("://invalid")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}

	clearURLCache()
}

// ============================================================================
// RETRY SCENARIO TESTS
// ============================================================================

// TestClient_RetryOnServerErrors validates retry behavior on server errors.
func TestClient_RetryOnServerErrors(t *testing.T) {
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      3,
		RetryDelay:      50 * time.Millisecond,
		BackoffFactor:   2.0,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Request(backgroundCtx, "GET", server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}
	if resp.Attempts() < 3 {
		t.Errorf("Expected at least 3 attempts, got %d", resp.Attempts())
	}
}

// TestClient_RetryExhausted was removed: TestClient_ExecuteRetry_MaxReached
// covers the same always-5xx exhaustion scenario and additionally counts
// actual server hits.

// TestClient_OverrideMaxRetries validates per-request retry override.
func TestClient_OverrideMaxRetries(t *testing.T) {
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      0,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	retryOption := func(req *Request) error {
		req.SetMaxRetries(2)
		return nil
	}

	resp, err := client.Request(backgroundCtx, "GET", server.URL, retryOption)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}
}

// ============================================================================
// REDIRECT TESTS
// ============================================================================

// TestClient_Redirects is the consolidated redirect behavior table (formerly
// six standalone tests: RedirectFollowing, NoRedirectFollowing,
// MultipleRedirects, MaxRedirectLimit, CircularRedirect, SSRSRedirectBlocked —
// identical scaffolds differing only in handler, config, and expectation).
func TestClient_Redirects(t *testing.T) {
	tests := []struct {
		name          string
		handler       http.HandlerFunc
		follow        bool
		maxRedirects  int
		blockPrivate  bool // SSRF protection on: redirect targets are validated
		path          string
		wantStatus    int    // asserted when wantErr is false
		wantBody      string // asserted when non-empty
		wantRedirects int    // asserted when wantErr is false
		wantErr       bool
		errContains   string // asserted when wantErr is true
	}{
		{
			name: "single redirect is followed",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/redirect":
					http.Redirect(w, r, "/final", http.StatusFound)
				case "/final":
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("final destination"))
				}
			},
			follow: true, path: "/redirect",
			wantStatus: 200, wantBody: "final destination", wantRedirects: 1,
		},
		{
			name: "following disabled returns 302 as-is",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/final", http.StatusFound)
			},
			follow: false, path: "/redirect",
			wantStatus: http.StatusFound,
		},
		{
			name: "multi-hop chain with mixed statuses",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/start":
					http.Redirect(w, r, "/r1", http.StatusMovedPermanently)
				case "/r1":
					http.Redirect(w, r, "/r2", http.StatusFound)
				case "/r2":
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("final"))
				}
			},
			follow: true, path: "/start",
			wantStatus: 200, wantBody: "final", wantRedirects: 2,
		},
		{
			name: "max redirect limit exceeded errors",
			handler: func() http.HandlerFunc {
				count := 0
				return func(w http.ResponseWriter, r *http.Request) {
					count++
					if count <= 15 {
						http.Redirect(w, r, fmt.Sprintf("/redirect/%d", count), http.StatusFound)
						return
					}
					w.WriteHeader(http.StatusOK)
				}
			}(),
			follow: true, maxRedirects: 3, path: "/start",
			wantErr: true, errContains: "redirect",
		},
		{
			name: "circular redirect is detected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/a":
					http.Redirect(w, r, "/b", http.StatusFound)
				case "/b":
					http.Redirect(w, r, "/a", http.StatusFound)
				default:
					w.WriteHeader(http.StatusOK)
				}
			},
			follow: true, path: "/a", // maxRedirects 0 = default limit
			wantErr: true, errContains: "circular",
		},
		{
			name: "redirect to private IP blocked under SSRF protection",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirect-to-localhost" {
					http.Redirect(w, r, "http://127.0.0.1:1/blocked", http.StatusFound)
					return
				}
				w.WriteHeader(http.StatusOK)
			},
			follow: true, blockPrivate: true, path: "/redirect-to-localhost",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			config := &Config{
				Timeout:         30 * time.Second,
				AllowPrivateIPs: !tt.blockPrivate,
				FollowRedirects: tt.follow,
				MaxRedirects:    tt.maxRedirects,
				MaxRetries:      0,
				UserAgent:       "test/1.0",
			}

			client, err := NewClient(config)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}
			defer func() { _ = client.Close() }()

			resp, err := client.Request(backgroundCtx, "GET", server.URL+tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err, tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			defer ReleaseResponse(resp)
			if resp.StatusCode() != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode(), tt.wantStatus)
			}
			if tt.wantBody != "" && resp.Body() != tt.wantBody {
				t.Errorf("body = %q, want %q", resp.Body(), tt.wantBody)
			}
			if resp.RedirectCount() != tt.wantRedirects {
				t.Errorf("redirect count = %d, want %d", resp.RedirectCount(), tt.wantRedirects)
			}
		})
	}
}

// ============================================================================
// QUERY ESCAPE LARGE INPUT TEST
// ============================================================================

// TestAppendQueryEscape_LargeInput validates the large input fast path.
func TestAppendQueryEscape_LargeInput(t *testing.T) {
	// Create a string larger than maxQueryEscapeSize with no special chars
	largeInput := strings.Repeat("a", maxQueryEscapeSize+1)

	var b strings.Builder
	AppendQueryEscape(&b, largeInput)
	if b.String() != largeInput {
		t.Error("Expected identity for large string without special chars")
	}

	// Large string with special char near the beginning to trigger escaping
	largeWithSpecial := "hello world" + strings.Repeat("a", maxQueryEscapeSize)
	b.Reset()
	AppendQueryEscape(&b, largeWithSpecial)
	// url.QueryEscape encodes space as +
	result := b.String()
	if !strings.Contains(result, "+") && !strings.Contains(result, "%20") {
		t.Errorf("Expected space encoding in large string, got %q", result[:min(50, len(result))])
	}
}

// ============================================================================
// REQUEST CALLBACK ERROR TEST
// ============================================================================

// TestClient_OnRequestError validates that OnRequest callback errors propagate.
func TestClient_OnRequestError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      0,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	errOption := func(req *Request) error {
		req.SetOnRequest(func(r *Request) error {
			return fmt.Errorf("callback error")
		})
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.Request(ctx, "GET", server.URL, errOption)
	if err == nil {
		t.Error("Expected error from OnRequest callback")
	}
}

// ============================================================================
// ZERO TIMEOUT CONTEXT TEST
// ============================================================================

// TestClient_ZeroTimeout validates behavior with zero timeout (no deadline).
func TestClient_ZeroTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &Config{
		Timeout:         0, // Zero timeout - no deadline
		AllowPrivateIPs: true,
		MaxRetries:      0,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Request(backgroundCtx, "GET", server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}
}

// ============================================================================
// MULTIPART WITH SPECIAL CHARACTERS TEST
// ============================================================================

// TestBuild_MultipartSpecialChars validates multipart with filenames needing escaping.
func TestBuild_MultipartSpecialChars(t *testing.T) {
	config := &Config{Timeout: 30 * time.Second}
	processor := newRequestProcessor(config)

	files := map[string]*fileDataHelper{
		"file": {Filename: `test "file".txt`, Content: []byte("data"), ContentType: "text/plain"},
	}
	formData := formDataHelper(nil, files)
	req := testRequestBuilder().
		Method("POST").
		URL("https://api.example.com/upload").
		Context(context.Background()).
		Body(formData).
		Build()

	httpReq, err := processor.Build(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	ct := httpReq.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/form-data") {
		t.Errorf("Expected multipart content-type, got %s", ct)
	}
}

// ============================================================================
// COOKIE JAR TESTS
// ============================================================================

// TestClient_WithCookieJar validates cookie jar integration.
func TestClient_WithCookieJar(t *testing.T) {
	jar := newTestCookieJar()

	var mu sync.Mutex            // protects receivedCookies (written in handler goroutine)
	var receivedCookies []string // cookie names seen by the server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		for _, c := range r.Cookies() {
			receivedCookies = append(receivedCookies, c.Name)
		}
		mu.Unlock()
		// Set a cookie on every response
		http.SetCookie(w, &http.Cookie{
			Name:  "server-cookie",
			Value: "server-value",
			Path:  "/",
		})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      0,
		UserAgent:       "test/1.0",
		EnableCookies:   true,
		CookieJar:       jar,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	// First request: send a manual cookie, server sets server-cookie via jar.
	cookieOption := func(req *Request) error {
		req.SetCookies([]http.Cookie{
			{Name: "manual-cookie", Value: "manual-value"},
		})
		return nil
	}

	resp, err := client.Request(backgroundCtx, "GET", server.URL, cookieOption)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}

	// Second request: jar should replay server-cookie from the first response.
	resp2, err := client.Request(backgroundCtx, "GET", server.URL)
	if err != nil {
		t.Fatalf("Second request failed: %v", err)
	}
	if resp2.StatusCode() != 200 {
		t.Errorf("Expected status 200 on second request, got %d", resp2.StatusCode())
	}

	mu.Lock()
	defer mu.Unlock()

	// The manual cookie from the first request must have been received.
	foundManual := false
	for _, name := range receivedCookies {
		if name == "manual-cookie" {
			foundManual = true
		}
	}
	if !foundManual {
		t.Error("server never received manual-cookie from first request")
	}

	// The server-cookie set on the first response must be replayed by the jar
	// on the second request (proves cookie jar persistence).
	serverCookieCount := 0
	for _, name := range receivedCookies {
		if name == "server-cookie" {
			serverCookieCount++
		}
	}
	// First request: manual-cookie sent. Second request: server-cookie replayed.
	// So server-cookie should appear at least once (on the second request).
	if serverCookieCount == 0 {
		t.Error("cookie jar did not replay server-cookie on second request")
	}
}

// testCookieJar is a minimal in-memory cookie jar for testing.
type testCookieJar struct {
	cookies map[string][]*http.Cookie
}

func newTestCookieJar() *testCookieJar {
	return &testCookieJar{
		cookies: make(map[string][]*http.Cookie),
	}
}

func (j *testCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.cookies[u.Host] = append(j.cookies[u.Host], cookies...)
}

func (j *testCookieJar) Cookies(u *url.URL) []*http.Cookie {
	return j.cookies[u.Host]
}

// ============================================================================
// GZIP DECOMPRESSOR CLOSE TEST
// ============================================================================

// TestPooledGzipReader_Close validates the pooled gzip reader close behavior.
func TestPooledGzipReader_Close(t *testing.T) {
	t.Run("Nil reader", func(t *testing.T) {
		r := &pooledGzipReader{}
		err := r.Close()
		if err != nil {
			t.Errorf("Expected nil error for nil reader, got %v", err)
		}
	})

	t.Run("Normal close", func(t *testing.T) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		_, _ = gw.Write([]byte("test"))
		_ = gw.Close()

		gr, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("Failed to create gzip reader: %v", err)
		}

		r := &pooledGzipReader{Reader: gr}
		err = r.Close()
		if err != nil {
			t.Errorf("Unexpected error on close: %v", err)
		}
		if r.Reader != nil {
			t.Error("Expected reader to be nil after close")
		}
	})
}

// TestPooledFlateReader validates the pooled flate reader behavior.
func TestPooledFlateReader(t *testing.T) {
	t.Run("Nil reader Read", func(t *testing.T) {
		r := &pooledFlateReader{reader: nil}
		p := make([]byte, 10)
		_, err := r.Read(p)
		if err != io.EOF {
			t.Errorf("Expected io.EOF, got %v", err)
		}
	})

	t.Run("Nil reader Close", func(t *testing.T) {
		r := &pooledFlateReader{reader: nil}
		err := r.Close()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

// ============================================================================
// CONTEXT CANCELLATION WITH SLEEP TEST
// ============================================================================

// TestClient_SleepWithContext was removed: it never touched its first test
// server (dead code) and only asserted err != nil. The sleep branches are
// unit-covered by TestSleepWithContext (retry_test.go) and integration-covered
// by TestClient_ContextCancellation (client_test.go).

// ============================================================================
// EXECUTE WITH RETRY - MAX RETRIES REACHED TEST
// ============================================================================

// TestClient_ExecuteRetry_MaxReached validates the full retry exhaustion path.
func TestClient_ExecuteRetry_MaxReached(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	config := &Config{
		Timeout:         5 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      2,
		RetryDelay:      10 * time.Millisecond,
		BackoffFactor:   1.5,
		Jitter:          false,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Request(backgroundCtx, "GET", server.URL)
	// After retries are exhausted, the server must have been hit exactly
	// 1 + MaxRetries times and the last (503) response is returned.
	_ = err
	if wantHits := 3; attempts != wantHits { // 1 initial + 2 retries
		t.Errorf("Expected server to be hit %d times, got %d", wantHits, attempts)
	}
	if resp == nil {
		t.Fatal("expected non-nil response after exhausted retries")
	}
	if resp.StatusCode() != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d after exhausted retries, got %d", http.StatusServiceUnavailable, resp.StatusCode())
	}
}

// ============================================================================
// MULTIPLE REDIRECT TEST
// ============================================================================

// TestClient_MultipleRedirects was folded into TestClient_Redirects above.

// ============================================================================
// REQUEST TIMEOUT OVERRIDE TEST
// ============================================================================

// TestClient_RequestTimeoutOverride validates per-request timeout via RequestOption.
func TestClient_RequestTimeoutOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      0,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	timeoutOption := func(req *Request) error {
		req.SetTimeout(5 * time.Second)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Request(ctx, "GET", server.URL, timeoutOption)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}
}

// ============================================================================
// MAX REDIRECT LIMIT TEST
// ============================================================================

// TestClient_MaxRedirectLimit was folded into TestClient_Redirects above.

// ============================================================================
// URL CACHE EVICTION TEST
// ============================================================================

// TestURLCache_Eviction was removed: bounded-eviction is asserted (stronger,
// including the evicted key and refill) by TestURLCache_EvictOldest
// (request_test.go) and TestURLCacheRawEviction (resource_leak_test.go).

// ============================================================================
// NIL OPTION TEST
// ============================================================================

// TestClient_NilOption validates that nil options are skipped gracefully.
func TestClient_NilOption(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      0,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var nilOption RequestOption = nil
	resp, err := client.Request(ctx, "GET", server.URL, nilOption)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}
}

// ============================================================================
// CUSTOM RETRY POLICY TEST
// ============================================================================

// TestClient_CustomRetryPolicy validates custom retry policy integration.
func TestClient_CustomRetryPolicy(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	config := &Config{
		Timeout:           30 * time.Second,
		AllowPrivateIPs:   true,
		MaxRetries:        0, // Let custom policy decide
		RetryDelay:        10 * time.Millisecond,
		BackoffFactor:     1.0,
		UserAgent:         "test/1.0",
		CustomRetryPolicy: &testRetryPolicy{maxRetries: 3, delay: 10 * time.Millisecond},
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Request(backgroundCtx, "GET", server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}
}

// testRetryPolicy is a simple retry policy for testing.
type testRetryPolicy struct {
	maxRetries int
	delay      time.Duration
}

func (p *testRetryPolicy) MaxRetries() int                    { return p.maxRetries }
func (p *testRetryPolicy) GetDelay(attempt int) time.Duration { return p.delay }
func (p *testRetryPolicy) ShouldRetry(resp types.ResponseReader, err error, attempt int) bool {
	if err != nil {
		return attempt < p.maxRetries
	}
	if resp != nil && resp.StatusCode() >= 500 {
		return attempt < p.maxRetries
	}
	return false
}

// TestClient_CustomRetryPolicy_NegativeMaxRetries verifies that a custom
// policy violating the RetryPolicy contract (MaxRetries < 0) still results in
// the request being executed exactly once. Before the clamp in
// executeWithRetry, a negative value skipped the no-retry fast path and fell
// into a never-entered retry loop, returning "request failed after -4
// attempts" without the request ever being sent.
func TestClient_CustomRetryPolicy_NegativeMaxRetries(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	config := &Config{
		Timeout:           30 * time.Second,
		AllowPrivateIPs:   true,
		UserAgent:         "test/1.0",
		CustomRetryPolicy: &testRetryPolicy{maxRetries: -5, delay: time.Millisecond},
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Request(backgroundCtx, "GET", server.URL)
	if err != nil {
		t.Fatalf("Request must still execute with a contract-violating policy, got: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}
	if resp.Attempts() != 1 {
		t.Errorf("Expected exactly 1 attempt, got %d", resp.Attempts())
	}
	if attempts != 1 {
		t.Errorf("Server saw %d requests, want 1", attempts)
	}
}

// ============================================================================
// CLOSE MULTIPLE RESOURCES TEST
// ============================================================================

// TestClient_CloseWithConnectionPool validates Close with active connection pool.
func TestClient_CloseWithConnectionPool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      0,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make a request first to establish connections
	_, _ = client.Request(backgroundCtx, "GET", server.URL)

	// Close should clean up transport and connection pool
	err = client.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// ============================================================================
// OPTION ERROR TEST
// ============================================================================

// TestClient_OptionError validates that option errors propagate.
func TestClient_OptionError(t *testing.T) {
	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      0,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	failOption := func(req *Request) error {
		return fmt.Errorf("option failed")
	}

	_, err = client.Request(ctx, "GET", "https://example.com", failOption)
	if err == nil {
		t.Error("Expected error from failed option")
	}
}

// ============================================================================
// PUT REQUEST WITH BODY TEST
// ============================================================================

// TestClient_PutWithBody validates PUT request with body.
func TestClient_PutWithBody(t *testing.T) {
	var gotMethod string
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		bodyBytes, _ := io.ReadAll(r.Body)
		gotBody = string(bodyBytes)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      0,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	bodyOption := func(req *Request) error {
		req.SetBody(map[string]string{"key": "value"})
		return nil
	}

	resp, err := client.Request(backgroundCtx, "PUT", server.URL, bodyOption)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}
	if gotMethod != "PUT" {
		t.Errorf("Expected PUT, got %s", gotMethod)
	}
	if gotBody == "" {
		t.Error("Expected body to be sent")
	}
}

// ============================================================================
// CIRCULAR REDIRECT TEST
// ============================================================================

// TestClient_CircularRedirect and TestClient_SSRSRedirectBlocked were folded
// into TestClient_Redirects (see the REDIRECT TESTS section above).

// ============================================================================
// MOCK TRANSPORT RETRY TESTS
// ============================================================================

// TestClient_MockTransportRetry validates retry behavior with mock transport.
func TestClient_MockTransportRetry(t *testing.T) {
	t.Run("Error then success", func(t *testing.T) {
		mock := newMockTransport(200, "OK")
		mock.failFirst = 1 // first attempt fails, second succeeds
		config := &Config{
			Timeout:         30 * time.Second,
			AllowPrivateIPs: true,
			MaxRetries:      2,
			RetryDelay:      10 * time.Millisecond,
			BackoffFactor:   1.0,
			UserAgent:       "test/1.0",
		}

		client, err := NewClient(config, func(opts *clientOptions) {
			opts.customTransport = mock
		})
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer func() { _ = client.Close() }()

		resp, err := client.Request(context.Background(), "GET", "https://example.com")
		if err != nil {
			t.Fatalf("expected success after retry, got: %v", err)
		}
		if resp.StatusCode() != 200 {
			t.Errorf("status = %d, want 200", resp.StatusCode())
		}
		if resp.Attempts() != 2 {
			t.Errorf("attempts = %d, want 2 (1 failure + 1 success)", resp.Attempts())
		}
	})

	t.Run("Non-retryable error", func(t *testing.T) {
		mock := newMockTransport(200, "OK")
		config := &Config{
			Timeout:         30 * time.Second,
			AllowPrivateIPs: true,
			MaxRetries:      3,
			RetryDelay:      10 * time.Millisecond,
			BackoffFactor:   1.0,
			UserAgent:       "test/1.0",
		}

		client, err := NewClient(config, func(opts *clientOptions) {
			opts.customTransport = mock
		})
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer func() { _ = client.Close() }()

		// Context canceled is non-retryable
		mock.SetError(context.Canceled)
		ctx := context.Background()

		_, err = client.Request(ctx, "GET", "https://example.com")
		if err == nil {
			t.Error("Expected error for canceled context")
		}
	})

	t.Run("Success without retries", func(t *testing.T) {
		mock := newMockTransport(200, "success")
		config := &Config{
			Timeout:         30 * time.Second,
			AllowPrivateIPs: true,
			MaxRetries:      3,
			RetryDelay:      10 * time.Millisecond,
			BackoffFactor:   1.0,
			UserAgent:       "test/1.0",
		}

		client, err := NewClient(config, func(opts *clientOptions) {
			opts.customTransport = mock
		})
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer func() { _ = client.Close() }()

		ctx := context.Background()
		resp, err := client.Request(ctx, "GET", "https://example.com")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if resp.StatusCode() != 200 {
			t.Errorf("Expected status 200, got %d", resp.StatusCode())
		}
		if resp.Attempts() != 1 {
			t.Errorf("Expected 1 attempt, got %d", resp.Attempts())
		}
	})
}

// === Merged from coverage_gap_test.go ===

// TestIsRetryableWrappedError was removed: its message-cause and nil-cause
// rows are rows of TestClientError_IsRetryable (errors_test.go), which now
// also carries the wrapped-ClientError (unwrap depth) rows.

// ============================================================================
// Task 1b/1c: isRetryableSyscallError / isRetryableDNSError
// ============================================================================

// TestIsRetryableSyscallError was removed: its POSIX-constant rows are
// unreliable on Go 1.25+ Windows (see the comment on
// TestIsRetryableSyscallError_WSAErrno in errors_test.go, which carries the
// platform-correct superset, including the non-retryable negative row).
//
// TestIsRetryableDNSError_NonDNSCause was removed: the same contract
// (ErrorTypeDNS + non-DNSError cause → not retryable) is the
// "DNS permanent is not retryable" row of TestClientError_IsRetryable
// (errors_test.go).

// ============================================================================
// Task 2: Streaming body tests (0% coverage)
// ============================================================================

func TestStreamingBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("streaming body content"))
	}))
	defer server.Close()

	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
		MaxRetries:      0,
		UserAgent:       "test/1.0",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	t.Run("SetStreamBody true returns raw body reader", func(t *testing.T) {
		streamOption := func(req *Request) error {
			req.SetStreamBody(true)
			return nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.Request(ctx, "GET", server.URL, streamOption)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer ReleaseResponse(resp)

		if resp.StatusCode() != 200 {
			t.Errorf("Expected status 200, got %d", resp.StatusCode())
		}

		reader := resp.RawBodyReader()
		if reader == nil {
			t.Fatal("Expected non-nil RawBodyReader for streaming request")
		}

		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("Failed to read from RawBodyReader: %v", err)
		}

		if string(data) != "streaming body content" {
			t.Errorf("Expected 'streaming body content', got %q", string(data))
		}

		_ = reader.Close()
	})

	t.Run("Non-streaming request returns nil RawBodyReader", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.Request(ctx, "GET", server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer ReleaseResponse(resp)

		if resp.RawBodyReader() != nil {
			t.Error("Expected nil RawBodyReader for non-streaming request")
		}

		if resp.Body() != "streaming body content" {
			t.Errorf("Expected 'streaming body content', got %q", resp.Body())
		}
	})

	t.Run("StreamBody accessor round-trip", func(t *testing.T) {
		req := &Request{}
		if req.StreamBody() {
			t.Error("Expected StreamBody=false by default")
		}
		req.SetStreamBody(true)
		if !req.StreamBody() {
			t.Error("Expected StreamBody=true after SetStreamBody(true)")
		}
	})
}

// TestStreamingBody_ExceedsLimit verifies that a streamed body larger than
// MaxResponseBodySize surfaces as a Read error instead of a synthetic EOF.
// Before this regression guard, the pooled limit reader returned io.EOF when
// its budget ran out, so io.Copy-based consumers (Download) silently truncated
// the body to the limit and reported success.
func TestStreamingBody_ExceedsLimit(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 2000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	config := &Config{
		Timeout:             30 * time.Second,
		AllowPrivateIPs:     true,
		MaxRetries:          0,
		MaxResponseBodySize: 1000,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Request(ctx, "GET", server.URL, func(req *Request) error {
		req.SetStreamBody(true)
		return nil
	})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer ReleaseResponse(resp)

	reader := resp.RawBodyReader()
	if reader == nil {
		t.Fatal("Expected non-nil RawBodyReader for streaming request")
	}

	read, readErr := io.ReadAll(reader)
	if readErr == nil {
		t.Fatalf("Expected error reading oversize streamed body, got success (%d bytes)", len(read))
	}
	if !strings.Contains(readErr.Error(), "exceeds size limit") {
		t.Errorf("Expected size-limit error, got: %v", readErr)
	}
	if len(read) > 1001 { // limit + the one over-read byte
		t.Errorf("Read %d bytes, want at most limit+1", len(read))
	}
}

// ============================================================================
// Task 3: Close method tests for pooled readers (0% coverage)
// ============================================================================

// io.Closer is tested for all pooled reader/buffer types via table-driven test.
func TestPooledReaders_Close(t *testing.T) {
	t.Run("StringsReader close before reading", func(t *testing.T) {
		reader := getPooledStringsReader("hello").(*pooledStringsReader)
		if err := reader.Close(); err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if reader.reader != nil {
			t.Error("Expected reader to be nil after Close")
		}
	})

	t.Run("StringsReader double close", func(t *testing.T) {
		reader := getPooledStringsReader("hello").(*pooledStringsReader)
		_ = reader.Close()
		if err := reader.Close(); err != nil {
			t.Errorf("Unexpected error on double close: %v", err)
		}
	})

	t.Run("BytesReader close before reading", func(t *testing.T) {
		reader := getPooledBytesReader([]byte("hello")).(*pooledBytesReader)
		if err := reader.Close(); err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if reader.reader != nil {
			t.Error("Expected reader to be nil after Close")
		}
	})

	t.Run("BytesReader double close", func(t *testing.T) {
		reader := getPooledBytesReader([]byte("hello")).(*pooledBytesReader)
		_ = reader.Close()
		if err := reader.Close(); err != nil {
			t.Errorf("Unexpected error on double close: %v", err)
		}
	})

	t.Run("MultipartBuffer close owned", func(t *testing.T) {
		buf := getMultipartBuffer()
		buf.WriteString("multipart data")
		reader := &pooledMultipartBuffer{buf: buf, owned: true}
		if err := reader.Close(); err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if reader.buf != nil {
			t.Error("Expected buf to be nil after Close")
		}
	})

	t.Run("MultipartBuffer close nil", func(t *testing.T) {
		reader := &pooledMultipartBuffer{buf: nil, owned: false}
		if err := reader.Close(); err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("MultipartBuffer close not-owned", func(t *testing.T) {
		buf := bytes.NewBufferString("data")
		reader := &pooledMultipartBuffer{buf: buf, owned: false}
		if err := reader.Close(); err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("MultipartBuffer double close", func(t *testing.T) {
		buf := getMultipartBuffer()
		buf.WriteString("data")
		reader := &pooledMultipartBuffer{buf: buf, owned: true}
		_ = reader.Close()
		if err := reader.Close(); err != nil {
			t.Errorf("Unexpected error on double close: %v", err)
		}
	})

	t.Run("JSONBuffer close owned", func(t *testing.T) {
		buf := getJSONBuffer()
		buf.WriteString(`{"test": true}`)
		reader := &pooledJSONBuffer{buf: buf, owned: true}
		if err := reader.Close(); err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if reader.buf != nil {
			t.Error("Expected buf to be nil after Close")
		}
	})

	t.Run("JSONBuffer close nil", func(t *testing.T) {
		reader := &pooledJSONBuffer{buf: nil, owned: false}
		if err := reader.Close(); err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("JSONBuffer close not-owned", func(t *testing.T) {
		buf := bytes.NewBufferString(`{"data":1}`)
		reader := &pooledJSONBuffer{buf: buf, owned: false}
		if err := reader.Close(); err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("JSONBuffer double close", func(t *testing.T) {
		buf := getJSONBuffer()
		buf.WriteString(`{"test": true}`)
		reader := &pooledJSONBuffer{buf: buf, owned: true}
		_ = reader.Close()
		if err := reader.Close(); err != nil {
			t.Errorf("Unexpected error on double close: %v", err)
		}
	})
}

// ============================================================================
// Task 4: createDecompressor edge cases (68.8% -> higher)
// ============================================================================

func TestCreateDecompressor_FlateNonResetter(t *testing.T) {
	// Clear pools to ensure clean state
	clearResponsePools()

	config := &Config{Timeout: 30 * time.Second}
	processor := newResponseProcessor(config)

	// Put a non-Resetter io.ReadCloser into the flate pool
	flateReaderPool.Put(io.NopCloser(bytes.NewReader([]byte("dummy"))))

	// When createDecompressor gets this non-Resetter, it should fall through
	// to creating a new flate.NewReader
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = fw.Write([]byte("flate test"))
	_ = fw.Close()

	decompressor, err := processor.createDecompressor(bytes.NewReader(buf.Bytes()), "deflate")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	data, err := io.ReadAll(decompressor)
	if err != nil {
		t.Fatalf("Failed to read decompressed data: %v", err)
	}

	if string(data) != "flate test" {
		t.Errorf("Expected 'flate test', got %q", string(data))
	}
	_ = decompressor.Close()
}

func TestCreateDecompressor_GzipDirectNewReader(t *testing.T) {
	// Test the fallback path where pool returns a wrong type.
	// Clear the pool and put a non-*gzip.Reader value in it.
	clearResponsePools()
	gzipReaderPool.Put("not a gzip reader") //nolint:staticcheck // intentional wrong-type poisoning // wrong type

	config := &Config{Timeout: 30 * time.Second}
	processor := newResponseProcessor(config)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte("direct gzip"))
	_ = gw.Close()

	decompressor, err := processor.createDecompressor(bytes.NewReader(buf.Bytes()), "gzip")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	data, err := io.ReadAll(decompressor)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if string(data) != "direct gzip" {
		t.Errorf("Expected 'direct gzip', got %q", string(data))
	}
	_ = decompressor.Close()
}

// ============================================================================
// Pool type-assertion fallback tests
// ============================================================================

// TestPoolGet_TypeAssertionFallback exercises the defensive fallback branch in
// each pool's Get wrapper: when sync.Pool returns a value of the wrong type
// (which can happen if the pool is corrupted), the wrapper must return a fresh
// zero-value instead of panicking.
func TestPoolGet_TypeAssertionFallback(t *testing.T) {
	t.Run("getHeadersMap", func(t *testing.T) {
		headersMapPool.Put("wrong type") //nolint:staticcheck // intentional wrong-type poisoning // poison the pool
		m := getHeadersMap()
		if m == nil {
			t.Fatal("expected non-nil map from fallback")
		}
		if len(m) != 0 {
			t.Errorf("expected empty map, got %d entries", len(m))
		}
	})

	t.Run("getQueryParamsMap", func(t *testing.T) {
		queryParamsPool.Put(new(int)) // poison with a different wrong type (pointer-like to satisfy SA6002)
		m := getQueryParamsMap()
		if m == nil {
			t.Fatal("expected non-nil map from fallback")
		}
		if len(m) != 0 {
			t.Errorf("expected empty map, got %d entries", len(m))
		}
	})

	t.Run("getQueryParamsMap typed-nil map", func(t *testing.T) {
		// A typed-nil map passes the type assertion (ok=true) but must still
		// hit the fresh-map fallback.
		queryParamsPool.Put(map[string]any(nil))
		m := getQueryParamsMap()
		if m == nil {
			t.Fatal("expected fresh map for typed-nil pooled value")
		}
	})

	t.Run("requestPool get", func(t *testing.T) {
		rp := newRequestPool()
		rp.pool.Put(new(int)) // poison the pool with a wrong pointer-like type
		req := rp.get()
		if req == nil {
			t.Fatal("expected non-nil Request from fallback")
		}
	})
}
