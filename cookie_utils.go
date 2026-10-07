package httpc

import (
	"net/http"
	"strings"
)

// parseCookieHeader parses a Cookie header value into http.Cookie slice.
// Optimized to minimize allocations by using index-based trimming and a single
// contiguous backing array for all cookie structs (capacity sized by a
// semicolon count, mirroring SessionManager.GetCookies) instead of one heap
// object per cookie.
// SECURITY: Returns newly allocated slices — never backed by shared or pooled
// memory — so the result cannot alias another request's cookies.
func parseCookieHeader(cookieHeader string) []*http.Cookie {
	if cookieHeader == "" {
		return nil
	}

	// One allocation holds every parsed cookie. The semicolon count sizes the
	// capacity exactly for well-formed headers, clamped so a hostile header of
	// pure separators (legal within the 8KB value limit) cannot amplify into a
	// ~1MB allocation — headers with more than 16 real cookies grow via append.
	capHint := min(strings.Count(cookieHeader, ";")+1, 16)
	backing := make([]http.Cookie, 0, capHint)

	headerLen := len(cookieHeader)
	start := 0

	for i := 0; i <= headerLen; i++ {
		if i == headerLen || cookieHeader[i] == ';' {
			if i > start {
				// Trim whitespace from the pair using indices (no allocation)
				pairStart, pairEnd := trimSpaceIndices(cookieHeader, start, i)
				if pairStart < pairEnd {
					pair := cookieHeader[pairStart:pairEnd]
					if idx := strings.IndexByte(pair, '='); idx > 0 {
						// Trim whitespace from name
						nameStart, nameEnd := trimSpaceIndices(pair, 0, idx)
						// Trim whitespace from value
						valueStart, valueEnd := trimSpaceIndices(pair, idx+1, len(pair))

						if nameStart < nameEnd {
							backing = append(backing, http.Cookie{
								Name:  pair[nameStart:nameEnd],
								Value: pair[valueStart:valueEnd],
							})
						}
					}
				}
			}
			start = i + 1
		}
	}

	if len(backing) == 0 {
		return nil
	}

	result := make([]*http.Cookie, len(backing))
	for i := range backing {
		result[i] = &backing[i]
	}
	return result
}

// trimSpaceIndices returns the start and end indices of s[low:high] after trimming whitespace.
// This avoids allocating a new string.
func trimSpaceIndices(s string, low, high int) (int, int) {
	// Trim leading whitespace
	for low < high && isWhitespace(s[low]) {
		low++
	}
	// Trim trailing whitespace
	for high > low && isWhitespace(s[high-1]) {
		high--
	}
	return low, high
}

// isWhitespace reports whether byte c is a cookie OWS (optional whitespace).
// RFC 6265 Section 4.1.1 only permits SP and HTAB as OWS.
func isWhitespace(c byte) bool {
	return c == ' ' || c == '\t'
}
