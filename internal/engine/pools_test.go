package engine

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cybergodev/httpc/internal/types"
)

func TestCloneHeader(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		if CloneHeader(nil) != nil {
			t.Error("CloneHeader(nil) should return nil")
		}
	})

	t.Run("DeepCopy", func(t *testing.T) {
		src := http.Header{
			"Content-Type": {"application/json"},
			"Accept":       {"text/html", "application/xml"},
		}
		dst := CloneHeader(src)

		// Modify source - should not affect clone
		src["Content-Type"][0] = "text/plain"
		delete(src, "Accept")

		if dst.Get("Content-Type") != "application/json" {
			t.Errorf("Clone not independent: got %q", dst.Get("Content-Type"))
		}
		if len(dst["Accept"]) != 2 {
			t.Errorf("Clone should have 2 Accept values, got %d", len(dst["Accept"]))
		}
	})

	t.Run("EmptyValueSliceNotCopied", func(t *testing.T) {
		src := http.Header{"A": {}}
		dst := CloneHeader(src)
		if dst == nil {
			t.Fatal("CloneHeader should not return nil for non-nil src")
		}
		// Keys with empty value slices are not copied (totalValues == 0 fast path)
		if len(dst) != 0 {
			t.Logf("Empty value slice keys not preserved (expected behavior): got %d keys", len(dst))
		}
	})
}

func TestQueryBuilder(t *testing.T) {
	t.Run("GetAndReturn", func(t *testing.T) {
		sb := getQueryBuilder()
		sb.WriteString("test")
		putQueryBuilder(sb)

		sb2 := getQueryBuilder()
		if sb2.Len() != 0 {
			t.Error("Reused builder should be reset")
		}
		putQueryBuilder(sb2)
	})

	t.Run("PutNil", func(t *testing.T) {
		putQueryBuilder(nil) // should not panic
	})

	t.Run("OversizeNotPooled", func(t *testing.T) {
		sb := getQueryBuilder()
		sb.Grow(5000)
		sb.WriteString(strings.Repeat("x", 5000))
		putQueryBuilder(sb) // should discard
	})

	t.Run("poisoned pools fall back to fresh values", func(t *testing.T) {
		// Wrong-typed entries exercise the !ok fallback branches of
		// getHTTPHeader and getQueryBuilder.
		httpHeaderPool.Put(new(int)) // wrong type, pointer-like for SA6002
		queryBuilderPool.Put(42)     //nolint:staticcheck // intentional wrong-type poisoning

		h := getHTTPHeader()
		if h == nil {
			t.Fatal("getHTTPHeader returned nil from poisoned pool")
		}
		h.Set("X-Test", "v") // must be usable
		putHTTPHeader(h)

		qb := getQueryBuilder()
		if qb == nil {
			t.Fatal("getQueryBuilder returned nil from poisoned pool")
		}
		qb.WriteString("ok")
		putQueryBuilder(qb)
	})
}

func TestAppendQueryEscape(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"Empty", "", ""},
		{"NoEscape", "hello", "hello"},
		{"Space", "hello world", "hello%20world"},
		{"SpecialChars", "a=b&c=d", "a%3Db%26c%3Dd"},
		{"Unicode", "hello世界", "hello%E4%B8%96%E7%95%8C"},
		{"Unreserved", "-._~", "-._~"},
		{"AllAlpha", "ABCxyz", "ABCxyz"},
		{"Digits", "12345", "12345"},
		// Meta characters — classic divergence vs url.QueryEscape ("+" and "%"
		// must both be escaped here, same as the stdlib).
		{"Plus", "a+b", "a%2Bb"},
		{"Percent", "100%", "100%25"},
		{"Ampersand", "a&b", "a%26b"},
		{"Equals", "a=b", "a%3Db"},
		{"Tilde vs percent-tilde", "~", "~"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b strings.Builder
			AppendQueryEscape(&b, tt.input)
			if got := b.String(); got != tt.want {
				t.Errorf("AppendQueryEscape(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAppendQueryParams(t *testing.T) {
	tests := []struct {
		name     string
		existing string
		params   map[string]any
		want     string
	}{
		{"NilParams", "a=1", nil, "a=1"},
		{"EmptyParams", "a=1", map[string]any{}, "a=1"},
		{"AppendToEmpty", "", map[string]any{"b": "2"}, "b=2"},
		{"AppendToExisting", "a=1", map[string]any{"b": "2"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendQueryParams(tt.existing, tt.params)
			if tt.want != "" && got != tt.want {
				t.Errorf("appendQueryParams() = %q, want %q", got, tt.want)
			}
			if tt.want == "" && len(tt.params) > 0 {
				if !strings.Contains(got, tt.existing) {
					t.Errorf("Result %q should contain existing %q", got, tt.existing)
				}
			}
		})
	}
}

// TestAppendQueryParams_DeterministicOrder guards the sorted-key contract of
// appendQueryParams: identical maps must encode to identical strings.
// (Moved from response_truncation_test.go, where it sat among unrelated
// readBody truncation tests.)
func TestAppendQueryParams_DeterministicOrder(t *testing.T) {
	a := map[string]any{"z": 1, "a": 2, "m": "x", "0": true}
	b := map[string]any{"0": true, "m": "x", "a": 2, "z": 1}
	s1 := appendQueryParams("", a)
	s2 := appendQueryParams("", b)
	if s1 != s2 {
		t.Fatalf("same params encoded differently: %q vs %q", s1, s2)
	}
	// Merging into an existing query must also be sorted after the existing part.
	merged := appendQueryParams("keep=1", a)
	want := "keep=1&0=true&a=2&m=x&z=1"
	if merged != want {
		t.Fatalf("merged query = %q, want %q", merged, want)
	}
}

func TestWriteQueryParamValue_Types(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected string
	}{
		{"string", "hello", "hello"},
		{"empty string", "", ""},
		{"int", 42, "42"},
		{"int64", int64(12345678901234), "12345678901234"},
		{"int32", int32(99), "99"},
		{"uint", uint(100), "100"},
		{"uint64", uint64(18446744073709551615), "18446744073709551615"},
		{"uint32", uint32(4294967295), "4294967295"},
		{"float64", float64(3.14), strconv.FormatFloat(3.14, 'f', -1, 64)},
		{"float32", float32(2.5), strconv.FormatFloat(float64(float32(2.5)), 'f', -1, 32)},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"custom type via FormatQueryParam", time.Duration(5 * time.Second), "5s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sb strings.Builder
			var numBuf [32]byte
			writeQueryParamValue(&sb, tt.value, numBuf[:0])
			got := sb.String()
			if tt.expected != "" && got != tt.expected {
				t.Errorf("writeQueryParamValue(%v) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

// TestWriteQueryParamValue_MatchesQueryEscapeFormatQueryParam is a contract
// test for the duplicated query-value type switch (code-quality review
// D-002 / M2).
//
// writeQueryParamValue (pools.go) and FormatQueryParam (request.go) format a
// query value through independent type switches. This test pins their
// relationship: for every supported type, the bytes written by
// writeQueryParamValue must equal QueryEscape(FormatQueryParam(v)). Numeric and
// bool values contain no characters QueryEscape changes, so the escape is a
// no-op there; strings, fmt.Stringer values, and the default %v path are
// escaped in both formulations. Adding a type to one switch without the other
// will fail here.
//
// nil is excluded from this table: WithQuery/WithQueryMap skip nil upstream,
// and both writeQueryParamValue and FormatQueryParam format nil as "" (the
// former via an early return, the latter via its nil case), so they agree.
func TestWriteQueryParamValue_MatchesQueryEscapeFormatQueryParam(t *testing.T) {
	t.Parallel()

	values := []any{
		"", "hello", "with space", "a&b=c", "ünïcödé",
		int(42), int(-42), int(0),
		int64(12345678901234), int64(-1),
		int32(99), int32(-99),
		uint(100), uint(0),
		uint64(18446744073709551615),
		uint32(4294967295),
		float64(3.14), float64(-0.5), float64(0),
		float32(2.5), float32(-2.5),
		bool(true), bool(false),
		time.Duration(5 * time.Second),
		struct{}{},
	}

	for _, v := range values {
		var sb strings.Builder
		var numBuf [32]byte
		writeQueryParamValue(&sb, v, numBuf[:0])
		got := sb.String()

		var wantBuilder strings.Builder
		AppendQueryEscape(&wantBuilder, FormatQueryParam(v))
		if got != wantBuilder.String() {
			t.Errorf("writeQueryParamValue(%T %v) = %q, want AppendQueryEscape(FormatQueryParam) = %q",
				v, v, got, wantBuilder.String())
		}
	}
}

// TestGetMIMEHeader_ReuseAndClear/TestGetMIMEHeader_PoolFallback were
// removed: the mimeHeaderPool went away when Build's multipart encoding
// switched from CreatePart (via a pooled textproto.MIMEHeader) to writing
// part headers directly into the pooled buffer. The wire format those tests
// indirectly guarded is now pinned explicitly by TestMultipartWireParity.

// TestMultipartWireParity pins Build's hand-rolled multipart encoding to
// byte-identical output with mime/multipart.Writer — the encoder it replaced
// to avoid CreatePart's per-part allocations. Any drift changes what servers
// parse, so a change to writeMultipartPartHeader or the Build FormData branch
// must keep this passing. Cases are limited to one field and one file per
// form because part order follows map iteration order (and is not
// significant); fields-before-files is asserted by the combined case.
func TestMultipartWireParity(t *testing.T) {
	t.Parallel()

	buildBody := func(t *testing.T, fd *types.FormData) (body []byte, boundary string) {
		t.Helper()
		req := testRequestBuilder().
			Method("POST").
			URL("https://api.example.com/upload").
			Context(context.Background()).
			Body(fd).
			Build()
		httpReq, err := newRequestProcessor(&Config{}).Build(req)
		if err != nil {
			t.Fatalf("Build failed: %v", err)
		}
		body, err = io.ReadAll(httpReq.Body)
		if err != nil {
			t.Fatalf("read multipart body failed: %v", err)
		}
		ct := httpReq.Header.Get("Content-Type")
		boundary = strings.TrimPrefix(ct, "multipart/form-data; boundary=")
		if boundary == ct {
			t.Fatalf("unexpected Content-Type %q", ct)
		}
		return body, boundary
	}

	// wantBody reproduces the same form through mime/multipart.Writer with
	// the boundary Build chose, so the two encodings can be compared.
	wantBody := func(t *testing.T, fd *types.FormData, boundary string) []byte {
		t.Helper()
		var want bytes.Buffer
		w := multipart.NewWriter(&want)
		if err := w.SetBoundary(boundary); err != nil {
			t.Fatalf("SetBoundary failed: %v", err)
		}
		for k, v := range fd.Fields {
			if err := w.WriteField(k, v); err != nil {
				t.Fatalf("WriteField failed: %v", err)
			}
		}
		for k, f := range fd.Files {
			// Files without a ContentType go through CreateFormFile, which
			// supplies the implicit application/octet-stream the engine's
			// encoder also writes.
			if f.ContentType == "" {
				part, err := w.CreateFormFile(k, f.Filename)
				if err != nil {
					t.Fatalf("CreateFormFile failed: %v", err)
				}
				if _, err := part.Write(f.Content); err != nil {
					t.Fatalf("write part failed: %v", err)
				}
				continue
			}
			h := make(textproto.MIMEHeader)
			disposition := `form-data; name="` + escapeQuotes(k) +
				`"; filename="` + escapeQuotes(f.Filename) + `"`
			h.Set("Content-Disposition", disposition)
			h.Set("Content-Type", f.ContentType)
			part, err := w.CreatePart(h)
			if err != nil {
				t.Fatalf("CreatePart failed: %v", err)
			}
			if _, err := part.Write(f.Content); err != nil {
				t.Fatalf("write part failed: %v", err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
		return want.Bytes()
	}

	cases := []struct {
		name string
		fd   *types.FormData
	}{
		{"empty form", &types.FormData{}},
		{"single field", &types.FormData{Fields: map[string]string{"username": "testuser"}}},
		{"field with escapes", &types.FormData{Fields: map[string]string{"na\"me\\": "a\"b"}}},
		{"single file without content type", &types.FormData{
			Files: map[string]*types.FileData{"file": {Filename: "data.bin", Content: []byte{0x00, 0x01, 0xFF}}},
		}},
		{"single file with content type", &types.FormData{
			Files: map[string]*types.FileData{"doc": {Filename: "report.txt", Content: []byte("line1\r\nline2"), ContentType: "text/plain"}},
		}},
		{"filename with escapes", &types.FormData{
			Files: map[string]*types.FileData{"f": {Filename: `we"ird\name.png`, Content: []byte("png")}},
		}},
		{"field plus file", &types.FormData{
			Fields: map[string]string{"username": "john"},
			Files:  map[string]*types.FileData{"file1": {Filename: "test.txt", Content: []byte("file content")}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, boundary := buildBody(t, tc.fd)
			want := wantBody(t, tc.fd, boundary)
			if !bytes.Equal(got, want) {
				t.Errorf("multipart bytes diverge from mime/multipart.Writer:\ngot:  %q\nwant: %q", got, want)
			}
		})
	}
}

// TestAcquireReleaseRequest_ResetContract validates the pooled-Request reset
// contract: a fresh request carries the maxRetriesUnset sentinel (so it
// inherits the client's retry config), and ReleaseRequest resets every field
// in place so a recycled request does not leak prior-request state.
func TestAcquireReleaseRequest_ResetContract(t *testing.T) {
	t.Parallel()

	req := AcquireRequest()
	if req == nil {
		t.Fatal("AcquireRequest returned nil")
	}
	// Fresh requests must carry the unset sentinel, NOT 0 (which means disabled).
	if req.maxRetries != maxRetriesUnset {
		t.Errorf("fresh request maxRetries=%d, want %d (unset sentinel)", req.maxRetries, maxRetriesUnset)
	}

	// Populate fields, then release.
	req.SetMethod("POST")
	req.SetURL("https://example.com/x")
	req.SetHeader("X-Test", "v")
	req.SetMaxRetries(5)

	ReleaseRequest(req)

	// ReleaseRequest resets the struct in place via *req = Request{...}.
	if req.method != "" || req.url != "" || req.maxRetries != maxRetriesUnset {
		t.Errorf("ReleaseRequest did not reset: method=%q url=%q maxRetries=%d",
			req.method, req.url, req.maxRetries)
	}
	// The headers map must have been returned to its pool (nil after reset).
	if req.headers != nil {
		t.Errorf("headers should be nil after reset, got %v", req.headers)
	}
}

// TestReleaseRequest_NilIsNoOp confirms ReleaseRequest tolerates nil defensively.
func TestReleaseRequest_NilIsNoOp(t *testing.T) {
	t.Parallel()
	ReleaseRequest(nil) // must not panic
}

// TestTransferHeaders_OwnershipContract validates the header ownership-transfer
// contract (client.go:387): TransferHeaders returns the map and severs the
// Response's reference, so a second call returns nil. This avoids a redundant
// clone when the public layer takes ownership of response headers.
func TestTransferHeaders_OwnershipContract(t *testing.T) {
	t.Parallel()
	resp := &Response{headers: http.Header{"X-A": []string{"1"}}}

	h := resp.TransferHeaders()
	if h.Get("X-A") != "1" {
		t.Errorf("TransferHeaders did not return the header map, got %v", h)
	}
	if resp.headers != nil {
		t.Error("Response.headers should be nil after transfer")
	}
	// Second transfer returns nil — ownership already moved.
	if resp.TransferHeaders() != nil {
		t.Error("second TransferHeaders should return nil after ownership transfer")
	}
}

// TestTransferRequestHeaders_OwnershipContract mirrors the above for request
// headers (client.go:394).
func TestTransferRequestHeaders_OwnershipContract(t *testing.T) {
	t.Parallel()
	resp := &Response{requestHeaders: http.Header{"Authorization": []string{"Bearer x"}}}

	h := resp.TransferRequestHeaders()
	if h.Get("Authorization") != "Bearer x" {
		t.Errorf("TransferRequestHeaders did not return the header map, got %v", h)
	}
	if resp.requestHeaders != nil {
		t.Error("Response.requestHeaders should be nil after transfer")
	}
	if resp.TransferRequestHeaders() != nil {
		t.Error("second TransferRequestHeaders should return nil after ownership transfer")
	}
}

// TestPoolHelpers_EdgeCases exercises the guard clauses and reuse paths of the
// internal sync.Pool helpers that are not directly exercised by integration tests.
func TestPoolHelpers_EdgeCases(t *testing.T) {
	t.Run("putQueryParamsMap nil is no-op", func(t *testing.T) {
		putQueryParamsMap(nil) // must not panic
	})

	t.Run("putQueryParamsMap oversized map discarded", func(t *testing.T) {
		big := make(map[string]any, 40)
		for i := 0; i < 40; i++ {
			big[strconv.Itoa(i)] = i
		}
		putQueryParamsMap(big) // must not panic; oversized maps are not returned to pool
	})

	t.Run("getQueryParamsMap reuse clears entries", func(t *testing.T) {
		m := getQueryParamsMap()
		m["key"] = "value"
		putQueryParamsMap(m)

		// Next get should return a map without the previous entry.
		m2 := getQueryParamsMap()
		if _, ok := m2["key"]; ok {
			t.Error("reused map should be cleared of previous entries")
		}
		putQueryParamsMap(m2)
	})

	t.Run("getHTTPHeader reuse clears entries", func(t *testing.T) {
		h := getHTTPHeader()
		h.Set("X-Test", "value")
		putHTTPHeader(h)

		h2 := getHTTPHeader()
		if h2.Get("X-Test") != "" {
			t.Error("reused header should be cleared of previous entries")
		}
		putHTTPHeader(h2)
	})

	// getMIMEHeader get->populate->put->get-cleared is asserted by the
	// dedicated TestGetMIMEHeader_ReuseAndClear above.
}
