package engine

import (
	"fmt"
	"strings"
	"testing"
)

// TestQueryParamWireEncoding pins the wire-encoding contract of
// writeQueryParamValue: numeric, bool, and nil values are written verbatim
// (their formatting never contains escapable bytes), while strings,
// Stringers, and the default fmt branch are URL-escaped. The three
// formatting sites (queryValueLength in the public package, FormatQueryParam,
// writeQueryParamValue) must keep this categorization in sync — their
// MAINTENANCE notes require adding new types to all three.
func TestQueryParamWireEncoding(t *testing.T) {
	stringerVal := stringerQueryValue("custom value")

	verbatim := []struct {
		name  string
		value any
	}{
		{"nil", nil},
		{"bool true", true},
		{"bool false", false},
		{"int", 42},
		{"int64", int64(-7)},
		{"int32", int32(300)},
		{"uint", uint(9)},
		{"uint64", uint64(1 << 40)},
		{"uint32", uint32(77)},
		{"float64", 2.5},
		{"float32", float32(1.5)},
	}
	for _, tc := range verbatim {
		t.Run("verbatim/"+tc.name, func(t *testing.T) {
			var sb strings.Builder
			writeQueryParamValue(&sb, tc.value, nil)
			if got, want := sb.String(), FormatQueryParam(tc.value); got != want {
				t.Fatalf("wire = %q, FormatQueryParam = %q", got, want)
			}
		})
	}

	escaped := []struct {
		name  string
		value any
	}{
		{"string", "hello world"},
		{"empty string", ""},
		{"stringer", stringerVal},
		{"default", struct{ X int }{X: 1}},
	}
	for _, tc := range escaped {
		t.Run("escaped/"+tc.name, func(t *testing.T) {
			var got, want strings.Builder
			writeQueryParamValue(&got, tc.value, nil)
			if f := FormatQueryParam(tc.value); f != "" {
				AppendQueryEscape(&want, f)
			}
			if got.String() != want.String() {
				t.Fatalf("wire = %q, AppendQueryEscape(FormatQueryParam(v)) = %q", got.String(), want.String())
			}
		})
	}
}

type stringerQueryValue string

func (s stringerQueryValue) String() string { return string(s) }

var _ = fmt.Sprintf // keep fmt referenced if the table above changes

// TestIsXMLContentType covers parameter-tolerant, case-insensitive XML
// Content-Type detection used by requestProcessor.Build.
func TestIsXMLContentType(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"application/xml", true},
		{"application/xml; charset=utf-8", true},
		{"APPLICATION/XML", true},
		{"text/xml", true},
		{" text/xml ; charset=iso-8859-1 ", true},
		{"application/json", false},
		{"", false},
		{"application/xmlx", false},
		{"text/xml-ish", false},
	}
	for _, tc := range cases {
		if got := isXMLContentType(tc.in); got != tc.want {
			t.Errorf("isXMLContentType(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
