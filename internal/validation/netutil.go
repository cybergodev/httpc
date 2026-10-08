package validation

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// isPrivateOrReservedIP checks if an IP address is private, reserved, or
// otherwise not suitable for public internet communication.
// This is used for SSRF (Server-Side Request Forgery) protection.
//
// SECURITY: This function handles IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
// to prevent bypass attempts using mixed notation.
func isPrivateOrReservedIP(ip net.IP) bool {
	// Normalize: handle IPv4-mapped IPv6 addresses (::ffff:127.0.0.1)
	// This prevents SSRF bypass using mixed IPv4/IPv6 notation
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}

	// IPv4 specific checks
	if ip4 := ip.To4(); ip4 != nil {
		// Check for reserved IP ranges
		if ip4[0] >= 240 || // Class E (240.0.0.0/4) - Reserved
			ip4[0] == 0 || // "This" Network (0.0.0.0/8)
			(ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127) || // Carrier-Grade NAT (RFC 6598) 100.64.0.0/10
			(ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0) || // IETF Protocol Assignments (192.0.0.0/24)
			(ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2) || // Documentation TEST-NET-1 (192.0.2.0/24)
			(ip4[0] == 192 && ip4[1] == 88 && ip4[2] == 99) || // 6to4 Relay Anycast (192.88.99.0/24)
			(ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100) || // Documentation TEST-NET-2 (198.51.100.0/24)
			(ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113) { // Documentation TEST-NET-3 (203.0.113.0/24)
			return true
		}
		// NOTE: 198.18.0.0/15 (RFC 2544 benchmarking) is deliberately allowed:
		// Clash/Surge-style proxy tools allocate their fake-IP pool there, and
		// blocking it would break those setups (see netutil_test).
		return false
	}

	// IPv6 specific checks (only for true IPv6 addresses, not mapped IPv4)
	if len(ip) == 16 {
		// Documentation prefix 2001:db8::/32 (RFC 3849)
		if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
			return true
		}
		// Teredo 2001::/32 (RFC 4380): the last 4 bytes carry the client's
		// IPv4 address in obfuscated (complemented) form, so ANY target —
		// including 127.0.0.1 — can be hidden there. Checking the embedded
		// address is unreliable (the complement of an arbitrary public IP
		// quasi-randomly lands in reserved space), so the whole prefix is
		// blocked, matching common SSRF filter practice. Teredo is obsolete
		// (removed from Windows 10+), making the false-positive cost negligible.
		if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00 {
			return true
		}
		// Site-local fec0::/10 (deprecated but still routable in some nets)
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0xc0 {
			return true
		}
		// NAT64 well-known prefix 64:ff9b::/96 (RFC 6052)
		// Validates embedded IPv4 to prevent SSRF bypass via IPv6.
		if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
			ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
			ip[8] == 0 && ip[9] == 0 && ip[10] == 0 && ip[11] == 0 {
			embeddedIP := net.IPv4(ip[12], ip[13], ip[14], ip[15])
			return isPrivateOrReservedIP(embeddedIP)
		}
		// 6to4 2002::/16 (RFC 7526, deprecated): bytes 2-5 embed the public
		// IPv4 target of the relay, so a private target (e.g. 2002:7f00:1::
		// = 127.0.0.1) hides inside a globally-routed prefix. Validate the
		// embedded address, mirroring the NAT64 handling above — the same
		// embedded-IPv4 SSRF bypass the Teredo/NAT64 comments describe.
		if ip[0] == 0x20 && ip[1] == 0x02 {
			embeddedIP := net.IPv4(ip[2], ip[3], ip[4], ip[5])
			return isPrivateOrReservedIP(embeddedIP)
		}
	}

	return false
}

// isIPExempted checks if an IP address matches any of the exempt CIDR ranges.
func isIPExempted(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateIPWithExemptions checks if an IP is allowed, considering exempt CIDR ranges.
// IPs that are private/reserved but match an exempt CIDR are allowed.
func ValidateIPWithExemptions(ip net.IP, exemptNets []*net.IPNet) error {
	if isPrivateOrReservedIP(ip) && !isIPExempted(ip, exemptNets) {
		return fmt.Errorf("blocked IP address")
	}
	return nil
}

// FilterAllowedIPs filters a list of IPs to only those allowed under SSRF rules.
// Private/reserved IPs are excluded unless they match an exempt CIDR range.
// Returns nil slice when no IPs are allowed.
// This supports Split-Horizon DNS environments where a domain may resolve to
// both public and private IPs — only public (or exempted) IPs are used for dialing.
func FilterAllowedIPs(ips []net.IP, exemptNets []*net.IPNet) []net.IP {
	allowed := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if !isPrivateOrReservedIP(ip) || isIPExempted(ip, exemptNets) {
			allowed = append(allowed, ip)
		}
	}
	return allowed
}

// isLocalhost detects localhost variations by hostname string:
//   - "localhost" (case-insensitive)
//   - 127.0.0.1, ::1, 0.0.0.0, ::
//   - full dotted-quad 127.x.x.x loopback addresses (but NOT domains that
//     merely start with "127." — 127.net and 127.com are real public domains)
//   - "localhost.localdomain" and "localhost.localdomain." (case-insensitive)
//
// Arbitrary localhost.* subdomains are intentionally NOT matched here: names
// such as localhost.example.com may be legitimate public domains. Hosts that
// resolve to loopback IPs are still blocked at the dialer layer (see
// ValidateSSRFHost and isPrivateOrReservedIP), so excluding them here only
// affects this early hostname-string fast path, not overall SSRF protection.
//
// Optimized to avoid repeated string allocations from strings.ToLower.
func isLocalhost(hostname string) bool {
	// Fast path: check length before any string operations
	hlen := len(hostname)
	if hlen == 0 {
		return false
	}

	// Check for dotted-quad 127.x.x.x loopback forms first (most common
	// localhost pattern). The bare "127." prefix check this replaces
	// misclassified legitimate public domains such as 127.net / 127.com as
	// localhost; the remainder must now parse as a full dotted-quad IPv4
	// loopback address. Legacy short forms that net.ParseIP rejects (127.1,
	// 127.0.0.1.2) are still blocked by looksLikeLegacyIPLiteral in
	// ValidateSSRFHost.
	if hlen >= 4 && hostname[0] == '1' && hostname[1] == '2' && hostname[2] == '7' && hostname[3] == '.' {
		if ip := net.ParseIP(hostname); ip != nil && ip.IsLoopback() {
			return true
		}
	}

	// Check exact matches - handle both cases for "localhost"
	switch hostname {
	case "localhost", "LOCALHOST", "127.0.0.1", "::1", "0.0.0.0", "::":
		return true
	}

	// Check for "Localhost" and other case variations without allocation
	// Only do case-insensitive check if first char is 'l' or 'L'
	if hlen == 9 && (hostname[0] == 'l' || hostname[0] == 'L') {
		// Check "localhost" case-insensitively
		if EqualFold(hostname, "localhost") {
			return true
		}
	}

	// Check for known local DNS names derived from localhost
	// Only match specific local DNS suffixes, not arbitrary localhost.* subdomains
	// which may be legitimate public domains (e.g., localhost.example.com).
	// Domains resolving to loopback IPs are still blocked at the dialer layer.
	if hlen == 21 && (hostname[0] == 'l' || hostname[0] == 'L') {
		if EqualFold(hostname, "localhost.localdomain") {
			return true
		}
	}
	if hlen == 22 && (hostname[0] == 'l' || hostname[0] == 'L') {
		if EqualFold(hostname, "localhost.localdomain.") {
			return true
		}
	}

	return false
}

// EqualFold checks if s equals t case-insensitively (ASCII only).
// Avoids allocation from strings.ToLower.
func EqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c1 := s[i]
		c2 := t[i]
		if c1 == c2 {
			continue
		}
		// Convert to lowercase for comparison
		if c1 >= 'A' && c1 <= 'Z' {
			c1 += 'a' - 'A'
		}
		if c2 >= 'A' && c2 <= 'Z' {
			c2 += 'a' - 'A'
		}
		if c1 != c2 {
			return false
		}
	}
	return true
}

// ContainsFold reports whether substr is contained within s, ASCII case-insensitively.
// Zero-allocation alternative to strings.Contains(strings.ToLower(s), substr).
func ContainsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	end := len(s) - len(substr)
	for i := 0; i <= end; i++ {
		if EqualFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

// ValidateAndParseURL validates a URL and returns the parsed result.
// This avoids callers needing to parse the URL again after validation.
func ValidateAndParseURL(urlStr string) (*url.URL, error) {
	if urlStr == "" {
		return nil, fmt.Errorf("URL cannot be empty")
	}
	if len(urlStr) > maxURLLen {
		return nil, fmt.Errorf("URL too long (max %d)", maxURLLen)
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsedURL.Scheme == "" {
		return nil, fmt.Errorf("URL scheme is required")
	}
	if parsedURL.Host == "" {
		return nil, fmt.Errorf("URL host is required")
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme: %s", parsedURL.Scheme)
	}
	return parsedURL, nil
}

// ValidateProxyURL parses and validates a proxy URL string, returning the parsed
// URL so callers do not need to re-parse.
//
// Accepted schemes: http, https, socks5, socks5h. The socks5 schemes are
// supported natively by net/http.Transport when set via transport.Proxy =
// http.ProxyURL(u), so they must not be rejected here.
//
// This is the single source of truth for proxy URL validation, shared by the
// public Config validator (ValidateConfig) and the internal connection pool
// (NewPoolManager). Centralizing it prevents the two layers from drifting —
// which is what previously let the public layer accept socks5 while the pool
// rejected it with a different error.
func ValidateProxyURL(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, fmt.Errorf("proxy URL cannot be empty")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		// SECURITY: url.Parse errors embed the raw input verbatim
		// (`parse "…": …`), which may contain proxy credentials. Redact both
		// the echoed URL and the wrapped error text so the password cannot
		// reach application logs through the error chain.
		return nil, fmt.Errorf("invalid proxy URL %q: %w", SanitizeURL(rawURL), redactErrorURL(err, rawURL))
	}

	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		if u.Scheme == "" {
			return nil, fmt.Errorf("invalid proxy URL %q: missing scheme", SanitizeURL(rawURL))
		}
		return nil, fmt.Errorf("unsupported proxy URL scheme %q (want http, https, socks5, or socks5h)", u.Scheme)
	}

	if u.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL %q: missing host", SanitizeURL(rawURL))
	}

	return u, nil
}

// redactErrorURL replaces any occurrence of rawURL inside err's message with
// its sanitized form, so a wrapped url.Parse error ("parse \"raw\": …") does
// not carry credentials up the error chain. When rawURL has nothing to
// sanitize the original error is returned unchanged, preserving its type for
// errors.Is/As; otherwise a new error is built from the scrubbed message.
func redactErrorURL(err error, rawURL string) error {
	sanitized := SanitizeURL(rawURL)
	if sanitized == rawURL || !strings.Contains(err.Error(), rawURL) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), rawURL, sanitized))
}

// schemeDefaultPorts maps proxy URL schemes to the port net/http appends when
// the proxy URL omits one (mirrors net/http transport.schemePort, which drives
// the address the transport actually dials).
var schemeDefaultPorts = map[string]string{
	"http":    "80",
	"https":   "443",
	"socks5":  "1080",
	"socks5h": "1080",
}

// CanonicalProxyAddr returns the host:port form of a proxy URL as net/http
// will actually DIAL it. net/http's transport dials canonicalAddr(proxyURL) —
// the URL hostname with the scheme's default port appended when the URL omits
// one — so any comparison against the dial address (proxy SSRF exemptions,
// proxypool health-report keys) must use this canonical form, not url.Host.
// Before this existed, a portless entry like "socks5://internal-proxy" was
// keyed as "internal-proxy" while the dialer saw "internal-proxy:1080": the
// proxy SSRF exemption silently never applied and circuit-breaking failure
// counts never incremented.
//
// LIMITATION: internationalized (non-ASCII) hostnames are not punycoded here
// (net/http applies IDNA at dial time); an IDN proxy URL without an explicit
// port still will not match. Explicit-port IDN proxies match — the port is
// never rewritten.
func CanonicalProxyAddr(u *url.URL) string {
	if u == nil {
		return ""
	}
	// Mirror stdlib exactly: canonicalAddr uses url.Port() — which returns ""
	// both for a missing port AND for a syntactically present but EMPTY port
	// ("http://proxy:" → Host "proxy:", Port() "") — and then appends the
	// scheme default. Testing SplitHostPort instead would keep the literal
	// "proxy:" and never match the dialed "proxy:80".
	if u.Port() != "" {
		return u.Host // already carries a real port
	}
	return net.JoinHostPort(u.Hostname(), schemeDefaultPorts[u.Scheme])
}

// ValidateSSRFHost checks whether a hostname (which may include a port) should be
// blocked under SSRF protection rules. It checks localhost, direct IP addresses,
// and legacy IP-literal notation.
// Returns nil if the host is allowed, or an error describing why it was blocked.
//
// DNS resolution of hostnames is deliberately NOT performed here: the
// connection pool dialer (internal/connection) resolves once, validates every
// IP, and dials the validated IP directly, which also prevents DNS-rebinding
// TOCTOU attacks a pre-check could not.
func ValidateSSRFHost(host string, exemptNets []*net.IPNet) error {
	// Extract hostname from host:port format
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	// Normalize the fully-qualified trailing dot ("localhost." is a legal FQDN
	// spelling of "localhost") so hostname checks cannot be bypassed by it.
	hostname = strings.TrimSuffix(hostname, ".")

	if isLocalhost(hostname) {
		return fmt.Errorf("localhost access blocked for security")
	}

	if ip := net.ParseIP(hostname); ip != nil {
		if err := ValidateIPWithExemptions(ip, exemptNets); err != nil {
			return fmt.Errorf("private/reserved IP address blocked")
		}
		return nil
	}

	// Block legacy integer/hex/octal IPv4 notation (e.g. "2130706433",
	// "0x7f000001", "0177.0.0.1", "10.1"). net.ParseIP rejects these, so
	// without this guard they fall through to the dialer, where libc-family
	// resolvers (directly or via proxies) may map them to private IPs
	// (e.g. 127.0.0.1), bypassing SSRF protection.
	if looksLikeLegacyIPLiteral(hostname) {
		return fmt.Errorf("legacy IP literal notation blocked for security: %s", hostname)
	}

	return nil
}

// looksLikeLegacyIPLiteral reports whether s uses a legacy integer, hex, or octal
// IPv4 notation that net.ParseIP does not recognize but some platform resolvers
// (cgo getaddrinfo) accept. Used to defensively block SSRF bypass attempts.
//
// Recognized legacy forms:
//   - Pure decimal integer without dots: "2130706433"
//   - Hex with 0x prefix (dotted or not): "0x7f000001", "0x7f.0.0.1"
//   - Octal via leading-zero octets: "0177.0.0.1"
func looksLikeLegacyIPLiteral(s string) bool {
	if s == "" {
		return false
	}

	// Hex form (whole or per-octet): 0x7f000001, 0x7f.0.0.1
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return true
	}

	if !strings.Contains(s, ".") {
		// Pure decimal integer host (no dots): 2130706433. A bare all-numeric
		// label is not a legitimate DNS hostname.
		return isAllDigits(s)
	}

	// Dotted form: flag leading-zero octets (octal) or hex octets.
	for part := range strings.SplitSeq(s, ".") {
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") {
			return true
		}
		// Leading zero on a multi-char octet => octal (e.g. "0177"). "0" is fine.
		if len(part) > 1 && part[0] == '0' {
			return true
		}
	}

	// Short-form inet_aton literals ("10.1" → 10.0.0.1, "192.168.1" →
	// 192.168.0.1) and out-of-range octets ("1.2.3.256"): net.ParseIP has
	// already rejected this string, and a legal DNS hostname cannot have an
	// all-numeric final label (RFC 1123 §2.1), so treat it as a legacy IP
	// literal. Proxied requests resolve the host remotely, where libc-family
	// resolvers still accept these forms — this pre-check is then the only
	// line of SSRF defense. Full dotted quads with every octet in range are
	// excluded: net.ParseIP accepts those before this helper is consulted.
	parts := strings.Split(s, ".")
	if last := parts[len(parts)-1]; isAllDigits(last) {
		if len(parts) != 4 {
			return true
		}
		for _, part := range parts {
			if !isAllDigits(part) {
				// A non-numeric label (e.g. "a.1.2.3") makes this a hostname,
				// not an IP literal.
				return false
			}
			if v := octetValue(part); v < 0 || v > 255 {
				return true
			}
		}
	}
	return false
}

// octetValue parses a digits-only label into its decimal value. Returns -1
// for labels longer than 3 digits, which no valid octet can be.
func octetValue(s string) int {
	if len(s) > 3 {
		return -1
	}
	v := 0
	for i := 0; i < len(s); i++ {
		v = v*10 + int(s[i]-'0')
	}
	return v
}

// isAllDigits reports whether s is non-empty and consists only of ASCII digits.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
