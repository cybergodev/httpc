package engine

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// httpHeaderPool reduces allocations for http.Header maps used in request building.
// Header maps are allocated per-request and can be reused after clearing.
//
// Stores the map value directly rather than *http.Header: boxing a map into any
// is allocation-free (a map value is a single-word pointer to its hmap), whereas
// httpHeaderPool.Put(&h) would force the parameter h to escape to the heap on
// every return, allocating a pointer box.
var httpHeaderPool = sync.Pool{
	New: func() any {
		return make(http.Header, 8)
	},
}

// getHTTPHeader retrieves a cleared http.Header from the pool.
func getHTTPHeader() http.Header {
	h, ok := httpHeaderPool.Get().(http.Header)
	if !ok || h == nil {
		return make(http.Header, 8)
	}
	for k := range h {
		delete(h, k)
	}
	return h
}

// putHTTPHeader returns an http.Header to the pool after clearing all entries.
// Maps with more than 64 entries are discarded to prevent memory bloat.
func putHTTPHeader(h http.Header) {
	if h == nil || len(h) > 64 {
		return
	}
	for k := range h {
		delete(h, k)
	}
	httpHeaderPool.Put(h)
}

// CloneHeader creates a deep copy of headers using batch allocation.
// Returns a newly allocated header map that can be safely modified.
// SECURITY: Always allocates new slices to prevent data leakage between requests.
// OPTIMIZATION: Uses batch allocation to reduce N allocations (one per header) to 1 allocation.
// For single-value headers (the common case), uses a shared backing array to reduce
// slice header overhead.
func CloneHeader(src http.Header) http.Header {
	if src == nil {
		return nil
	}

	n := len(src)
	dst := make(http.Header, n)

	if n == 0 {
		return dst
	}

	// Fast path: count total values.
	totalValues := 0
	for _, v := range src {
		totalValues += len(v)
	}

	if totalValues == 0 {
		return dst
	}

	// Batch allocate all string values in one slice
	allValues := make([]string, totalValues)
	valueIdx := 0

	for k, v := range src {
		switch len(v) {
		case 0:
			dst[k] = zeroStringSlice
		case 1:
			allValues[valueIdx] = v[0]
			dst[k] = allValues[valueIdx : valueIdx+1]
			valueIdx++
		default:
			endIdx := valueIdx + len(v)
			newVals := allValues[valueIdx:endIdx]
			copy(newVals, v)
			dst[k] = newVals
			valueIdx = endIdx
		}
	}
	return dst
}

// zeroStringSlice is a reusable empty slice for headers with no values.
// Read-only: never appended to or mutated.
var zeroStringSlice = []string{}

// queryBuilderPool reduces allocations for building query strings
var queryBuilderPool = sync.Pool{
	New: func() any {
		sb := &strings.Builder{}
		return sb
	},
}

// getQueryBuilder retrieves a strings.Builder from the pool for query building.
func getQueryBuilder() *strings.Builder {
	sb, ok := queryBuilderPool.Get().(*strings.Builder)
	if !ok || sb == nil {
		return &strings.Builder{}
	}
	sb.Reset()
	return sb
}

// putQueryBuilder returns a strings.Builder to the pool.
// Builders with large capacity are discarded to prevent memory bloat.
func putQueryBuilder(sb *strings.Builder) {
	if sb == nil || sb.Cap() > 4096 {
		return
	}
	sb.Reset()
	queryBuilderPool.Put(sb)
}

// shouldEscape reports whether the byte needs escaping for URL query encoding.
// Fast path: only check for characters that actually need escaping.
func shouldEscape(c byte) bool {
	// RFC 3986: unreserved characters are A-Z, a-z, 0-9, '-', '.', '_', '~'
	// These are the only characters that DON'T need escaping
	return (c < 'A' || c > 'Z') &&
		(c < 'a' || c > 'z') &&
		(c < '0' || c > '9') &&
		c != '-' && c != '.' && c != '_' && c != '~'
}

// queryEscapePool pools byte slices for query escaping.
var queryEscapePool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 64)
		return &b
	},
}

// maxQueryEscapeSize limits the maximum input size for optimized query escaping.
// Inputs larger than this will use the standard library to avoid integer overflow
// in capacity calculation (len(s)*3) and excessive memory allocation.
const maxQueryEscapeSize = 10 * 1024 * 1024 // 10MB

// QueryEscape performs URL query escaping with minimal allocations.
// Returns the original string if no escaping is needed (zero allocation).
func QueryEscape(s string) string {
	// SECURITY: For very large inputs, use standard library to avoid:
	// 1. Integer overflow in len(s)*3 capacity calculation (32-bit systems)
	// 2. Excessive memory allocation
	if len(s) > maxQueryEscapeSize {
		// Count escapes to determine if we can return original
		for i := 0; i < len(s); i++ {
			if shouldEscape(s[i]) {
				// Use standard library for large inputs that need escaping
				return url.QueryEscape(s)
			}
		}
		return s // No escaping needed
	}

	// Fast path: scan for characters that need escaping
	var needsEscape bool
	for i := 0; i < len(s); i++ {
		if shouldEscape(s[i]) {
			needsEscape = true
			break
		}
	}
	if !needsEscape {
		return s // Zero allocation for strings that don't need escaping
	}

	// Slow path: escape using pooled buffer
	// Safe from overflow: len(s) <= maxQueryEscapeSize (10MB), so len(s)*3 <= 30MB
	bufPtr, ok := queryEscapePool.Get().(*[]byte)
	origPtr := bufPtr
	if !ok || bufPtr == nil || cap(*bufPtr) < len(s)*3 {
		tmp := make([]byte, 0, len(s)*3)
		bufPtr = &tmp
	}
	buf := (*bufPtr)[:0]

	for i := 0; i < len(s); i++ {
		c := s[i]
		if !shouldEscape(c) {
			buf = append(buf, c)
		} else {
			buf = append(buf, '%')
			buf = append(buf, "0123456789ABCDEF"[c>>4])
			buf = append(buf, "0123456789ABCDEF"[c&0x0F])
		}
	}

	result := string(buf)
	if cap(buf) <= 1024 {
		*bufPtr = buf
		queryEscapePool.Put(bufPtr)
	} else if origPtr != bufPtr && origPtr != nil {
		*origPtr = (*origPtr)[:0]
		queryEscapePool.Put(origPtr)
	}
	return result
}

// AppendQueryEscape appends the URL-query-escaped form of s directly to b.
// Writing straight into the builder avoids the intermediate escaped string
// allocation that b.WriteString(QueryEscape(s)) would incur whenever s
// contains characters that need escaping. Inputs with no escapable bytes are
// written verbatim after a single scan. Mirrors QueryEscape's semantics
// (RFC 3986 unreserved set) and large-input safety fallback.
func AppendQueryEscape(b *strings.Builder, s string) {
	// SECURITY: delegate very large inputs to the standard library to avoid the
	// per-byte loop cost and keep parity with QueryEscape's overflow guard.
	if len(s) > maxQueryEscapeSize {
		b.WriteString(url.QueryEscape(s))
		return
	}

	// Fast scan: locate the first byte that needs escaping.
	firstEscape := -1
	for i := 0; i < len(s); i++ {
		if shouldEscape(s[i]) {
			firstEscape = i
			break
		}
	}
	if firstEscape < 0 {
		b.WriteString(s) // nothing to escape — single bulk write
		return
	}

	// Slow path: write the leading verbatim run, then escape the remainder.
	b.WriteString(s[:firstEscape])
	const hex = "0123456789ABCDEF"
	for i := firstEscape; i < len(s); i++ {
		c := s[i]
		if !shouldEscape(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0F])
	}
}

// appendQueryParams appends query parameters to an existing raw query string.
// This is more efficient than creating url.Values when you have an existing query.
// Optimized to write numeric values directly via strconv.Append* and to escape
// string keys/values straight into the builder (appendQueryEscape), avoiding the
// intermediate string allocations that QueryEscape would incur.
func appendQueryParams(existingQuery string, params map[string]any) string {
	if len(params) == 0 {
		return existingQuery
	}

	sb := getQueryBuilder()

	// Pre-calculate size
	estimatedSize := len(existingQuery) + len(params)*32
	sb.Grow(estimatedSize)

	// Write existing query first
	if existingQuery != "" {
		sb.WriteString(existingQuery)
	}

	var numBuf [32]byte // stack-allocated buffer for numeric formatting

	first := existingQuery == ""
	for key, value := range params {
		if first {
			first = false
		} else {
			sb.WriteByte('&')
		}
		AppendQueryEscape(sb, key)
		sb.WriteByte('=')

		writeQueryParamValue(sb, value, numBuf[:0])
	}

	result := sb.String()
	putQueryBuilder(sb)
	return result
}

// writeQueryParamValue appends a query parameter value to sb.
// Numeric and bool values are written directly via strconv.Append*
// to avoid intermediate string allocations. Strings are URL-escaped straight
// into the builder via appendQueryEscape.
// nil emits nothing, matching FormatQueryParam (which formats nil as "");
// without this guard the default %v branch would render the literal "<nil>".
func writeQueryParamValue(sb *strings.Builder, value any, numBuf []byte) {
	if value == nil {
		return
	}
	switch v := value.(type) {
	case string:
		if v != "" {
			AppendQueryEscape(sb, v)
		}
	case int:
		sb.Write(strconv.AppendInt(numBuf, int64(v), 10))
	case int64:
		sb.Write(strconv.AppendInt(numBuf, v, 10))
	case int32:
		sb.Write(strconv.AppendInt(numBuf, int64(v), 10))
	case uint:
		sb.Write(strconv.AppendUint(numBuf, uint64(v), 10))
	case uint64:
		sb.Write(strconv.AppendUint(numBuf, v, 10))
	case uint32:
		sb.Write(strconv.AppendUint(numBuf, uint64(v), 10))
	case float64:
		sb.Write(strconv.AppendFloat(numBuf, v, 'f', -1, 64))
	case float32:
		sb.Write(strconv.AppendFloat(numBuf, float64(v), 'f', -1, 32))
	case bool:
		if v {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	default:
		if s, ok := value.(fmt.Stringer); ok {
			if strValue := s.String(); strValue != "" {
				AppendQueryEscape(sb, strValue)
			}
		} else if strValue := fmt.Sprintf("%v", value); strValue != "" {
			AppendQueryEscape(sb, strValue)
		}
	}
}
