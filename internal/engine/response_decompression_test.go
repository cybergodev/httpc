package engine

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"

	"time"
)

// ============================================================================
// RESPONSE DECOMPRESSION TESTS
// ============================================================================

func TestResponseProcessor_Decompression(t *testing.T) {
	config := &Config{
		Timeout:             30 * time.Second,
		MaxResponseBodySize: 50 * 1024 * 1024,
	}

	processor := newResponseProcessor(config)

	tests := []struct {
		name        string
		encoding    string
		content     string
		wantBody    string
		wantErr     bool
		errContains string
	}{
		// Gzip cases
		{
			name:     "Gzip simple compressed text",
			encoding: "gzip",
			content:  "Hello, World! This is a test of gzip compression.",
			wantBody: "Hello, World! This is a test of gzip compression.",
			wantErr:  false,
		},
		{
			name:     "Gzip compressed JSON",
			encoding: "gzip",
			content:  `{"message":"success","data":{"id":123,"name":"test user","active":true}}`,
			wantBody: `{"message":"success","data":{"id":123,"name":"test user","active":true}}`,
			wantErr:  false,
		},
		{
			name:     "Gzip large compressed data",
			encoding: "gzip",
			content:  strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 100),
			wantBody: strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 100),
			wantErr:  false,
		},
		{
			name:     "Gzip empty compressed data",
			encoding: "gzip",
			content:  "",
			wantBody: "",
			wantErr:  false,
		},
		// Deflate cases
		{
			name:     "Deflate simple compressed text",
			encoding: "deflate",
			content:  "Hello, World! This is a test of deflate compression.",
			wantBody: "Hello, World! This is a test of deflate compression.",
			wantErr:  false,
		},
		{
			name:     "Deflate compressed JSON",
			encoding: "deflate",
			content:  `{"status":"ok","count":42,"items":["a","b","c"]}`,
			wantBody: `{"status":"ok","count":42,"items":["a","b","c"]}`,
			wantErr:  false,
		},
		{
			name:     "Deflate large compressed data",
			encoding: "deflate",
			content:  strings.Repeat("The quick brown fox jumps over the lazy dog. ", 50),
			wantBody: strings.Repeat("The quick brown fox jumps over the lazy dog. ", 50),
			wantErr:  false,
		},

		// No encoding / identity / unknown cases
		{
			name:     "No Content-Encoding header",
			encoding: "",
			content:  "Plain text without compression",
			wantBody: "Plain text without compression",
			wantErr:  false,
		},
		{
			name:        "Unknown encoding",
			encoding:    "unknown-encoding",
			content:     "Data with unknown encoding",
			wantBody:    "",
			wantErr:     true,
			errContains: "unsupported Content-Encoding",
		},
		{
			// TrimSpace in createDecompressor tolerates padded header values.
			name:        "Padded gzip header value",
			encoding:    " gzip ",
			content:     "Data behind a space-padded Content-Encoding",
			wantBody:    "Data behind a space-padded Content-Encoding",
			wantErr:     false,
			errContains: "",
		},
		{
			name:     "Identity encoding",
			encoding: "identity",
			content:  "Data with identity encoding",
			wantBody: "Data with identity encoding",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bodyReader io.Reader
			bodyReader = strings.NewReader(tt.content)

			// Compress content if encoding requires it
			switch tt.encoding {
			case "gzip", " gzip ":
				var buf bytes.Buffer
				gzipWriter := gzip.NewWriter(&buf)
				_, err := gzipWriter.Write([]byte(tt.content))
				if err != nil {
					t.Fatalf("Failed to write gzip data: %v", err)
				}
				if err := gzipWriter.Close(); err != nil {
					t.Fatalf("Failed to close gzip writer: %v", err)
				}
				bodyReader = &buf
			case "deflate":
				var buf bytes.Buffer
				deflateWriter, err := flate.NewWriter(&buf, flate.DefaultCompression)
				if err != nil {
					t.Fatalf("Failed to create deflate writer: %v", err)
				}
				_, err = deflateWriter.Write([]byte(tt.content))
				if err != nil {
					t.Fatalf("Failed to write deflate data: %v", err)
				}
				if err := deflateWriter.Close(); err != nil {
					t.Fatalf("Failed to close deflate writer: %v", err)
				}
				bodyReader = &buf
			}

			headers := http.Header{
				"Content-Type": []string{"text/plain"},
			}
			if tt.encoding != "" {
				headers.Set("Content-Encoding", tt.encoding)
			}

			httpResponse := &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     headers,
				Body:       io.NopCloser(bodyReader),
				Request:    &http.Request{},
			}

			resp, err := processor.Process(httpResponse)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errContains, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Failed to process response: %v", err)
			}

			// Special validation for gzip simple text: also check RawBody
			if tt.encoding == "gzip" && tt.name == "Gzip simple compressed text" {
				if string(resp.RawBody()) != tt.wantBody {
					t.Errorf("Expected RawBody '%s', got '%s'", tt.wantBody, string(resp.RawBody()))
				}
			}

			if resp.Body() != tt.wantBody {
				bodyLen := len(resp.Body())
				wantLen := len(tt.wantBody)
				if bodyLen != wantLen {
					t.Errorf("Body length mismatch: expected %d, got %d", wantLen, bodyLen)
				} else {
					t.Errorf("Expected body '%s', got '%s'", tt.wantBody, resp.Body())
				}
			}
		})
	}
}

func TestResponseProcessor_InvalidCompressedData(t *testing.T) {
	config := &Config{
		Timeout:             30 * time.Second,
		MaxResponseBodySize: 50 * 1024 * 1024,
	}

	processor := newResponseProcessor(config)

	tests := []struct {
		name     string
		encoding string
		rawData  string
	}{
		{
			name:     "Invalid gzip data",
			encoding: "gzip",
			rawData:  "This is not valid gzip data",
		},
		{
			name:     "Invalid deflate data",
			encoding: "deflate",
			rawData:  "This is not valid deflate data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpResponse := &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header: http.Header{
					"Content-Type":     []string{"text/plain"},
					"Content-Encoding": []string{tt.encoding},
				},
				Body:    io.NopCloser(strings.NewReader(tt.rawData)),
				Request: &http.Request{},
			}

			_, err := processor.Process(httpResponse)
			if err == nil {
				t.Error("Expected error for invalid compressed data, got nil")
			}
		})
	}
}

func TestResponseProcessor_DecompressionWithSizeLimit(t *testing.T) {
	config := &Config{
		Timeout:             30 * time.Second,
		MaxResponseBodySize: 100, // Small limit for testing
	}

	processor := newResponseProcessor(config)

	// Create data that will exceed limit after decompression
	largeData := strings.Repeat("A", 200) // 200 bytes uncompressed

	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	_, err := gzipWriter.Write([]byte(largeData))
	if err != nil {
		t.Fatalf("Failed to write gzip data: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("Failed to close gzip writer: %v", err)
	}

	httpResponse := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header: http.Header{
			"Content-Type":     []string{"text/plain"},
			"Content-Encoding": []string{"gzip"},
		},
		Body:    io.NopCloser(&buf),
		Request: &http.Request{},
	}

	_, err = processor.Process(httpResponse)
	if err == nil {
		t.Error("Expected error for decompressed data exceeding limit, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("Expected size limit error, got: %v", err)
	}
}

// TestResponseProcessor_MultipleEncodings was removed: despite the name it
// used a single "gzip" Content-Encoding — the identical round-trip is the
// "Gzip simple compressed text" case of TestResponseProcessor_Decompression.

func TestResponseProcessor_CaseInsensitiveEncoding(t *testing.T) {
	config := &Config{
		Timeout:             30 * time.Second,
		MaxResponseBodySize: 50 * 1024 * 1024,
	}

	processor := newResponseProcessor(config)

	originalData := "Test case insensitive encoding"

	tests := []struct {
		name     string
		encoding string
	}{
		{"Uppercase GZIP", "GZIP"},
		{"Mixed case GZip", "GZip"},
		{"Uppercase DEFLATE", "DEFLATE"},
		{"Mixed case Deflate", "Deflate"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			var writer io.WriteCloser

			// Create appropriate compressor based on encoding type
			if strings.ToLower(tt.encoding) == "gzip" {
				writer = gzip.NewWriter(&buf)
			} else {
				w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
				writer = w
			}

			_, err := writer.Write([]byte(originalData))
			if err != nil {
				t.Fatalf("Failed to write compressed data: %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("Failed to close writer: %v", err)
			}

			httpResponse := &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header: http.Header{
					"Content-Type":     []string{"text/plain"},
					"Content-Encoding": []string{tt.encoding},
				},
				Body:    io.NopCloser(&buf),
				Request: &http.Request{},
			}

			// RFC 7231 Section 3.1.2.1: content-coding tokens are case-insensitive
			resp, err := processor.Process(httpResponse)
			if err != nil {
				t.Fatalf("Failed to process response with encoding %q: %v", tt.encoding, err)
			}
			if resp.Body() != originalData {
				t.Errorf("Expected decompressed body %q, got %q", originalData, resp.Body())
			}
		})
	}
}

// BenchmarkResponseProcessor_GzipDecompression benchmarks gzip decompression
func BenchmarkResponseProcessor_GzipDecompression(b *testing.B) {
	config := &Config{
		Timeout:             30 * time.Second,
		MaxResponseBodySize: 50 * 1024 * 1024,
	}

	processor := newResponseProcessor(config)

	// Prepare compressed data
	originalData := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 100)
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	_, _ = gzipWriter.Write([]byte(originalData)) // fixed test input
	gzipWriter.Close()
	compressedData := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		httpResponse := &http.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Header: http.Header{
				"Content-Type":     []string{"text/plain"},
				"Content-Encoding": []string{"gzip"},
			},
			Body:    io.NopCloser(bytes.NewReader(compressedData)),
			Request: &http.Request{},
		}

		_, err := processor.Process(httpResponse)
		if err != nil {
			b.Fatalf("Failed to process response: %v", err)
		}
	}
}

// BenchmarkResponseProcessor_DeflateDecompression benchmarks deflate decompression
func BenchmarkResponseProcessor_DeflateDecompression(b *testing.B) {
	config := &Config{
		Timeout:             30 * time.Second,
		MaxResponseBodySize: 50 * 1024 * 1024,
	}

	processor := newResponseProcessor(config)

	// Prepare compressed data
	originalData := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 100)
	var buf bytes.Buffer
	deflateWriter, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = deflateWriter.Write([]byte(originalData)) // fixed test input
	deflateWriter.Close()
	compressedData := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		httpResponse := &http.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Header: http.Header{
				"Content-Type":     []string{"text/plain"},
				"Content-Encoding": []string{"deflate"},
			},
			Body:    io.NopCloser(bytes.NewReader(compressedData)),
			Request: &http.Request{},
		}

		_, err := processor.Process(httpResponse)
		if err != nil {
			b.Fatalf("Failed to process response: %v", err)
		}
	}
}

func TestCreateDecompressor_UnsupportedEncodings(t *testing.T) {
	t.Parallel()
	config := &Config{
		Timeout:             30 * time.Second,
		MaxResponseBodySize: 50 * 1024 * 1024,
	}
	proc := newResponseProcessor(config)

	tests := []struct {
		name        string
		encoding    string
		wantErr     bool
		errContains string
	}{
		{"brotli unsupported", "br", true, "brotli"},
		{"compress rejected", "compress", true, "LZW"},
		{"x-compress rejected", "x-compress", true, "LZW"},
		{"identity pass-through", "identity", false, ""},
		{"empty encoding pass-through", "", false, ""},
		{"unknown encoding rejected", "zstd", true, `unsupported Content-Encoding "zstd"`},
		{"multi-token encoding rejected", "gzip, br", true, `unsupported Content-Encoding "gzip, br"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader("test data")
			rc, err := proc.createDecompressor(reader, tt.encoding)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				} else if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if rc == nil {
					t.Error("expected non-nil ReadCloser")
				} else {
					rc.Close()
				}
			}
		})
	}
}

// ============================================================================
// POOL REGRESSION TESTS (P-001)
// ============================================================================

// TestGzipReaderPoolNewUsable pins the gzipReaderPool.New contract: it must
// return a non-nil *gzip.Reader that Reset can (re)initialize. The original
// implementation built it via gzip.NewReader(bytes.NewReader(nil)), which
// fails header parsing on the empty stream and returns (nil, io.EOF) — the
// discarded error silently produced a nil New that disabled the pool, so
// every compressed response allocated a fresh decompressor stack. A plain
// functional test cannot catch this regression (the fallback path is
// behaviorally identical, only slower), so the pool object is asserted
// directly.
func TestGzipReaderPoolNewUsable(t *testing.T) {
	raw, ok := gzipReaderPool.New().(*gzip.Reader)
	if !ok || raw == nil {
		t.Fatalf("gzipReaderPool.New must return a non-nil *gzip.Reader, got %T (%v)", raw, raw)
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte("pool reuse payload")); err != nil {
		t.Fatalf("seed gzip data: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close seed writer: %v", err)
	}

	if err := raw.Reset(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("Reset on a pool-fresh reader must succeed on valid gzip data: %v", err)
	}
	body, err := io.ReadAll(raw)
	if err != nil {
		t.Fatalf("read through pool-fresh reader: %v", err)
	}
	if string(body) != "pool reuse payload" {
		t.Fatalf("unexpected decompressed body %q", body)
	}
}

// TestBufioReaderPoolRoundtrip verifies that a recycled *bufio.Reader reads
// only from its new source: stale buffered bytes from the previous response
// must be unreachable after putBufioReader's Reset.
func TestBufioReaderPoolRoundtrip(t *testing.T) {
	br := getBufioReader(strings.NewReader("first-response-bytes"))
	if _, err := io.ReadAll(br); err != nil {
		t.Fatalf("drain first reader: %v", err)
	}
	putBufioReader(br)

	// Whether the pool hands back the same object or a fresh one, the next
	// reader must expose only the new source's bytes.
	br2 := getBufioReader(strings.NewReader("second"))
	got, err := io.ReadAll(br2)
	if err != nil {
		t.Fatalf("read recycled reader: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("recycled bufio leaked stale bytes: got %q, want %q", got, "second")
	}
	putBufioReader(br2)
}
