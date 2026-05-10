package engine

import (
	"errors"
	"net/http"
	"testing"
)

func BenchmarkClassifyError(b *testing.B) {
	err := errors.New("connection refused by server")
	url := "https://api.example.com/v1/users?page=1&token=secret123"
	method := "GET"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = classifyError(err, url, method, 1)
	}
}

func BenchmarkClassifyError_ContextCanceled(b *testing.B) {
	err := errors.New("context canceled")
	url := "https://api.example.com/v1/users"
	method := "GET"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = classifyError(err, url, method, 1)
	}
}

func BenchmarkClassifyErrorWithSanitizedURL(b *testing.B) {
	err := errors.New("connection refused by server")
	sanitizedURL := "https://api.example.com/v1/users"
	method := "GET"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = classifyErrorWithSanitizedURL(err, sanitizedURL, method, 1)
	}
}

func BenchmarkCloneHeader_Small(b *testing.B) {
	src := http.Header{
		"Content-Type": {"application/json"},
		"Accept":       {"application/json"},
		"User-Agent":   {"httpc/1.0"},
		"X-Request-Id": {"abc-123"},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = cloneHeader(src)
	}
}

func BenchmarkCloneHeader_Large(b *testing.B) {
	src := make(http.Header, 20)
	for i := 0; i < 20; i++ {
		src.Set(http.CanonicalHeaderKey("X-Custom-"+string(rune('A'+i%26))), "value")
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = cloneHeader(src)
	}
}

func BenchmarkQueryEscape_NoEscape(b *testing.B) {
	inputs := []string{"hello", "value123", "abc_def-ghi", "test~value"}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, s := range inputs {
			_ = queryEscape(s)
		}
	}
}

func BenchmarkQueryEscape_NeedsEscape(b *testing.B) {
	inputs := []string{"hello world", "a=b&c=d", "special chars!", "/path?q=1"}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, s := range inputs {
			_ = queryEscape(s)
		}
	}
}

func BenchmarkFormatQueryParam(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = FormatQueryParam("hello")
		_ = FormatQueryParam(42)
		_ = FormatQueryParam(int64(999))
		_ = FormatQueryParam(3.14)
		_ = FormatQueryParam(true)
		_ = FormatQueryParam(nil)
	}
}

func BenchmarkContainsFold(b *testing.B) {
	s := "connection reset by peer: network error occurred after timeout"
	substrs := []string{"connection reset", "eof", "timeout", "broken pipe", "not found"}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, sub := range substrs {
			containsFold(s, sub)
		}
	}
}

func BenchmarkAppendQueryParams_Typed(b *testing.B) {
	params := map[string]any{
		"page":   1,
		"limit":  100,
		"active": true,
		"price":  99.99,
		"sort":   "created_at",
		"q":      "hello world",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = appendQueryParams("", params)
	}
}

func BenchmarkAppendQueryParams_Strings(b *testing.B) {
	params := map[string]any{
		"page":   "1",
		"limit":  "100",
		"sort":   "created_at",
		"order":  "desc",
		"filter": "active",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = appendQueryParams("", params)
	}
}

func BenchmarkClientError_Error(b *testing.B) {
	err := &ClientError{
		Type:     ErrorTypeNetwork,
		Message:  "connection refused by server",
		URL:      "https://api.example.com/v1/users?page=1",
		Method:   "GET",
		Attempts: 3,
		Cause:    errors.New("dial tcp 192.168.1.1:443: connect: connection refused"),
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = err.Error()
	}
}

func BenchmarkHasSensitiveContent_NoQuery(b *testing.B) {
	url := "https://api.example.com/v1/users/123/profile"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = hasSensitiveContent(url)
	}
}

func BenchmarkHasSensitiveContent_WithQuery(b *testing.B) {
	url := "https://api.example.com/v1/users?page=1&limit=10&sort=name"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = hasSensitiveContent(url)
	}
}

func BenchmarkHasSensitiveContent_WithSensitiveQuery(b *testing.B) {
	url := "https://api.example.com/v1/users?page=1&token=secret123&api_key=mykey"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = hasSensitiveContent(url)
	}
}

func BenchmarkHasSensitiveContent_WithCredentials(b *testing.B) {
	url := "https://user:pass@api.example.com/v1/users?page=1"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = hasSensitiveContent(url)
	}
}
