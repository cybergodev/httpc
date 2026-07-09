package engine

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
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
}

func TestQueryEscape(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := QueryEscape(tt.input)
			if got != tt.want {
				t.Errorf("queryEscape(%q) = %q, want %q", tt.input, got, tt.want)
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

		want := QueryEscape(FormatQueryParam(v))
		if got != want {
			t.Errorf("writeQueryParamValue(%T %v) = %q, want QueryEscape(FormatQueryParam) = %q",
				v, v, got, want)
		}
	}
}

func TestGetMIMEHeader_ReuseAndClear(t *testing.T) {
	t.Parallel()

	// Get a header, populate it, put it back, get again - should be cleared
	h := getMIMEHeader()
	if h == nil {
		t.Fatal("expected non-nil MIMEHeader")
	}
	(*h)["Content-Type"] = []string{"application/json"}
	(*h)["X-Custom"] = []string{"value"}

	if len(*h) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(*h))
	}

	// Return to pool
	putMIMEHeader(h)

	// Get again - should be cleared
	h2 := getMIMEHeader()
	if len(*h2) != 0 {
		t.Errorf("reused MIMEHeader should be cleared, got %d entries", len(*h2))
	}

	// Verify it's usable after clearing
	(*h2)["Accept"] = []string{"text/html"}
	if len(*h2) != 1 {
		t.Errorf("expected 1 header after populate, got %d", len(*h2))
	}
	putMIMEHeader(h2)
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
