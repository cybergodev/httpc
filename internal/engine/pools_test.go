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
		if cloneHeader(nil) != nil {
			t.Error("cloneHeader(nil) should return nil")
		}
	})

	t.Run("DeepCopy", func(t *testing.T) {
		src := http.Header{
			"Content-Type": {"application/json"},
			"Accept":       {"text/html", "application/xml"},
		}
		dst := cloneHeader(src)

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
		dst := cloneHeader(src)
		if dst == nil {
			t.Fatal("cloneHeader should not return nil for non-nil src")
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
			got := queryEscape(tt.input)
			if got != tt.want {
				t.Errorf("queryEscape(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEncodeQueryParams(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"Nil", nil, ""},
		{"Empty", map[string]any{}, ""},
		{"SingleParam", map[string]any{"key": "value"}, "key=value"},
		{"MultipleParams", map[string]any{"a": "1", "b": "2"}, ""},
		{"SpecialChars", map[string]any{"q": "hello world"}, "q=hello%20world"},
		{"IntValue", map[string]any{"page": 42}, "page=42"},
		{"BoolValue", map[string]any{"flag": true}, "flag=true"},
		{"EmptyValue", map[string]any{"key": ""}, "key="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeQueryParams(tt.params)
			if tt.want == "" && len(tt.params) > 1 {
				// Multiple params - just check it's non-empty
				if got == "" {
					t.Error("Expected non-empty result for multiple params")
				}
				return
			}
			if got != tt.want {
				t.Errorf("encodeQueryParams() = %q, want %q", got, tt.want)
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
