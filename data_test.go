package httpc

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ============================================================================
// DATA HANDLING TESTS - JSON, XML, multipart, form data
// Consolidates: data_handling_test.go
// ============================================================================

type TestData struct {
	Message string `json:"message" xml:"message"`
	Code    int    `json:"code" xml:"code"`
}

// ----------------------------------------------------------------------------
// JSON Handling
// ----------------------------------------------------------------------------

func TestData_JSON(t *testing.T) {
	t.Run("SendReceiveJSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Content-Type") != "application/json" {
				t.Error("Expected Content-Type: application/json")
			}
			body, _ := io.ReadAll(r.Body)
			var data TestData
			if err := json.Unmarshal(body, &data); err != nil {
				t.Errorf("Failed to unmarshal JSON: %v", err)
			}
			if data.Message != "test" {
				t.Errorf("Expected message=test, got %s", data.Message)
			}
			// Echo back
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(TestData{Message: "response", Code: 200})
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		data := TestData{Message: "test", Code: 200}
		resp, err := client.Post(server.URL, WithJSON(data))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		var respData TestData
		if err := resp.Unmarshal(&respData); err != nil {
			t.Fatalf("Failed to parse response JSON: %v", err)
		}
		if respData.Message != "response" {
			t.Errorf("Expected message=response, got %s", respData.Message)
		}
	})

	t.Run("EmptyJSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if string(body) != "{}" {
				t.Errorf("Expected empty JSON object, got: %s", string(body))
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		_, err := client.Post(server.URL, WithJSON(map[string]interface{}{}))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})
}

// ----------------------------------------------------------------------------
// XML Handling
// ----------------------------------------------------------------------------

func TestData_XML(t *testing.T) {
	t.Run("SendXML", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Content-Type") != "application/xml" {
				t.Error("Expected Content-Type: application/xml")
			}
			body, _ := io.ReadAll(r.Body)
			var data TestData
			if err := xml.Unmarshal(body, &data); err != nil {
				t.Errorf("Failed to unmarshal XML: %v", err)
			}
			if data.Message != "test" {
				t.Errorf("Expected message=test, got %s", data.Message)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		data := TestData{Message: "test", Code: 200}
		_, err := client.Post(server.URL, WithXML(data))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("EmptyXML", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Content-Type") != "application/xml" {
				t.Error("Expected Content-Type: application/xml")
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		data := TestData{}
		_, err := client.Post(server.URL, WithXML(data))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("ReceiveXML", func(t *testing.T) {
		xmlData := `<?xml version="1.0" encoding="UTF-8"?><TestData><message>hello</message><code>200</code></TestData>`
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(xmlData))
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		var received TestData
		if err := xml.Unmarshal(resp.RawBody(), &received); err != nil {
			t.Fatalf("Failed to unmarshal XML response: %v", err)
		}
		if received.Message != "hello" {
			t.Errorf("Expected message=hello, got %s", received.Message)
		}
		if received.Code != 200 {
			t.Errorf("Expected code=200, got %d", received.Code)
		}
	})
}

// ----------------------------------------------------------------------------
// Multipart Form Data
// ----------------------------------------------------------------------------

func TestData_Multipart(t *testing.T) {
	t.Run("SingleFile", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
				t.Error("Expected Content-Type: multipart/form-data")
			}
			if err := r.ParseMultipartForm(10 << 20); err != nil {
				t.Errorf("Failed to parse multipart form: %v", err)
			}
			file, header, err := r.FormFile("file")
			if err != nil {
				t.Errorf("Failed to get file: %v", err)
			}
			defer func() { _ = file.Close() }()
			if header.Filename != "test.txt" {
				t.Errorf("Expected filename test.txt, got %s", header.Filename)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		formData := &FormData{
			Files: map[string]*FileData{
				"file": {
					Filename: "test.txt",
					Content:  []byte("test content"),
				},
			},
		}
		_, err := client.Post(server.URL, WithFormData(formData))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("MultipleFiles", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseMultipartForm(10 << 20); err != nil {
				t.Errorf("Failed to parse multipart form: %v", err)
			}
			if len(r.MultipartForm.File) != 2 {
				t.Errorf("Expected 2 files, got %d", len(r.MultipartForm.File))
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		formData := &FormData{
			Files: map[string]*FileData{
				"file1": {Filename: "test1.txt", Content: []byte("content1")},
				"file2": {Filename: "test2.txt", Content: []byte("content2")},
			},
		}
		_, err := client.Post(server.URL, WithFormData(formData))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("MixedFieldsAndFiles", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseMultipartForm(10 << 20); err != nil {
				t.Errorf("Failed to parse multipart form: %v", err)
			}
			if r.FormValue("field1") != "value1" {
				t.Error("Expected field1=value1")
			}
			if len(r.MultipartForm.File) != 1 {
				t.Errorf("Expected 1 file, got %d", len(r.MultipartForm.File))
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		formData := &FormData{
			Fields: map[string]string{"field1": "value1"},
			Files: map[string]*FileData{
				"file": {Filename: "test.txt", Content: []byte("content")},
			},
		}
		_, err := client.Post(server.URL, WithFormData(formData))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})

	t.Run("ContentTypes", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseMultipartForm(10 << 20); err != nil {
				t.Errorf("Failed to parse multipart form: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := newTestClient()
		defer client.Close()

		formData := &FormData{
			Files: map[string]*FileData{
				"image": {
					Filename:    "test.png",
					Content:     []byte("fake image data"),
					ContentType: "image/png",
				},
				"doc": {
					Filename:    "test.pdf",
					Content:     []byte("fake pdf data"),
					ContentType: "application/pdf",
				},
			},
		}
		_, err := client.Post(server.URL, WithFormData(formData))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
	})
}

// ----------------------------------------------------------------------------
// Note: Cookie tests have been moved to cookie_test.go for better organization
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Form URL Encoded
// ----------------------------------------------------------------------------

func TestData_FormURLEncoded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("Expected Content-Type: application/x-www-form-urlencoded")
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("Failed to parse form: %v", err)
		}
		if r.FormValue("field1") != "value1" {
			t.Error("Expected field1=value1")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := newTestClient()
	defer client.Close()

	_, err := client.Post(server.URL, WithForm(map[string]string{
		"field1": "value1",
		"field2": "value2",
	}))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
}

// ----------------------------------------------------------------------------
// Compression Handling
// ----------------------------------------------------------------------------

func TestData_Compression(t *testing.T) {
	tests := []struct {
		name            string
		contentEncoding string
		compress        func([]byte) []byte
		content         string
	}{
		{
			name:            "GzipResponse",
			contentEncoding: "gzip",
			compress: func(data []byte) []byte {
				var buf bytes.Buffer
				gw := gzip.NewWriter(&buf)
				_, _ = gw.Write(data)
				_ = gw.Close()
				return buf.Bytes()
			},
			content: "This is compressed content",
		},
		{
			name:            "DeflateResponse",
			contentEncoding: "deflate",
			compress: func(data []byte) []byte {
				var buf bytes.Buffer
				fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
				_, _ = fw.Write(data)
				_ = fw.Close()
				return buf.Bytes()
			},
			content: "This is deflate compressed content",
		},
		{
			name:            "NoCompression",
			contentEncoding: "",
			compress:        nil,
			content:         "This is uncompressed content",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.contentEncoding != "" {
					w.Header().Set("Content-Encoding", tt.contentEncoding)
				}
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)

				if tt.compress != nil {
					_, _ = w.Write(tt.compress([]byte(tt.content)))
				} else {
					_, _ = w.Write([]byte(tt.content))
				}
			}))
			defer server.Close()

			client, _ := newTestClient()
			defer client.Close()

			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}

			if resp.Body() != tt.content {
				t.Errorf("Expected content %q, got %q", tt.content, resp.Body())
			}
		})
	}
}

// TestData_Compression_Concurrent exercises the pooled gzip/deflate/bufio
// machinery under concurrent load: since the P-001 pool fix, compressed
// responses share pooled decompressor stacks and buffered readers across
// goroutines, so cross-request data bleed or double-recycling would only
// surface under parallelism. Run with -race.
func TestData_Compression_Concurrent(t *testing.T) {
	const payload = "concurrent compressed payload 0123456789"
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write([]byte(payload)); err != nil {
		t.Fatalf("seed gzip data: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close seed writer: %v", err)
	}
	gzipped := compressed.Bytes()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(gzipped)
	}))
	defer server.Close()

	client, err := newTestClient()
	if err != nil {
		t.Fatalf("newTestClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 15; j++ {
				resp, err := client.Get(server.URL)
				if err != nil {
					errs <- err
					return
				}
				if got := resp.Body(); got != payload {
					errs <- fmt.Errorf("body corruption: got %d bytes %q, want %q", len(got), got, payload)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
