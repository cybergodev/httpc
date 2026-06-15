package security

import (
	"testing"
)

func BenchmarkValidateURL_Valid(b *testing.B) {
	v := NewValidator()
	url := "https://api.example.com/v1/users?page=1&limit=10"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = v.validateURL(url, nil)
	}
}

func BenchmarkValidateURL_Invalid(b *testing.B) {
	v := NewValidator()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = v.validateURL("", nil)
		_ = v.validateURL("not-a-url", nil)
	}
}

func BenchmarkValidateRequest_Minimal(b *testing.B) {
	v := NewValidator()
	req := &Request{
		Method: "GET",
		URL:    "https://api.example.com/v1/users",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = v.ValidateRequest(req)
	}
}

func BenchmarkValidateRequest_WithHeaders(b *testing.B) {
	v := NewValidator()
	req := &Request{
		Method: "POST",
		URL:    "https://api.example.com/v1/users",
		Headers: map[string]string{
			"Content-Type":      "application/json",
			"Authorization":     "Bearer token123",
			"X-Request-Id":      "abc-123",
			"Accept":            "application/json",
			"Connection":        "keep-alive",
			"Transfer-Encoding": "chunked",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = v.ValidateRequest(req)
	}
}
