package validation

import (
	"fmt"
	"net"
	"net/url"
)

// IsPrivateOrReservedIP checks if an IP address is private, reserved, or
// otherwise not suitable for public internet communication.
// This is used for SSRF (Server-Side Request Forgery) protection.
//
// SECURITY: This function handles IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
// to prevent bypass attempts using mixed notation.
func IsPrivateOrReservedIP(ip net.IP) bool {
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
			(ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0) || // IETF Protocol Assignments (192.0.0.0/24)
			(ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2) || // Documentation TEST-NET-1 (192.0.2.0/24)
			(ip4[0] == 192 && ip4[1] == 88 && ip4[2] == 99) || // 6to4 Relay Anycast (192.88.99.0/24)
			(ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100) || // Documentation TEST-NET-2 (198.51.100.0/24)
			(ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113) { // Documentation TEST-NET-3 (203.0.113.0/24)
			return true
		}
		return false
	}

	// IPv6 specific checks (only for true IPv6 addresses, not mapped IPv4)
	if len(ip) == 16 {
		// Documentation prefix 2001:db8::/32 (RFC 3849)
		if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
			return true
		}
		// NAT64 well-known prefix 64:ff9b::/96 (RFC 6052)
		// Validates embedded IPv4 to prevent SSRF bypass via IPv6.
		if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
			ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
			ip[8] == 0 && ip[9] == 0 && ip[10] == 0 && ip[11] == 0 {
			embeddedIP := net.IPv4(ip[12], ip[13], ip[14], ip[15])
			return IsPrivateOrReservedIP(embeddedIP)
		}
	}

	return false
}

// ValidateIP checks if an IP is allowed for outbound requests.
// Returns an error if the IP is blocked by security policy.
func ValidateIP(ip net.IP) error {
	if IsPrivateOrReservedIP(ip) {
		return fmt.Errorf("blocked IP address")
	}
	return nil
}

// ParseExemptCIDRs parses a list of CIDR strings into net.IPNet slices.
// Returns nil, nil for empty input.
func ParseExemptCIDRs(cidrs []string) ([]*net.IPNet, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}

// IsIPExempted checks if an IP address matches any of the exempt CIDR ranges.
func IsIPExempted(ip net.IP, nets []*net.IPNet) bool {
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
	if IsPrivateOrReservedIP(ip) && !IsIPExempted(ip, exemptNets) {
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
		if !IsPrivateOrReservedIP(ip) || IsIPExempted(ip, exemptNets) {
			allowed = append(allowed, ip)
		}
	}
	return allowed
}

// IsLocalhost detects localhost variations including:
// - "localhost" (case-insensitive)
// - 127.0.0.1
// - ::1
// - 0.0.0.0
// - ::
// - 127.x.x.x range
// - localhost.* subdomains (case-insensitive)
//
// Optimized to avoid repeated string allocations from strings.ToLower.
func IsLocalhost(hostname string) bool {
	// Fast path: check length before any string operations
	hlen := len(hostname)
	if hlen == 0 {
		return false
	}

	// Check for 127.x.x.x range first (most common localhost pattern)
	// Use direct byte comparison to avoid string allocation
	// SECURITY: Must check hlen >= 4 to safely access hostname[3]
	// "127." prefix indicates 127.x.x.x range (loopback network)
	if hlen >= 4 && hostname[0] == '1' && hostname[1] == '2' && hostname[2] == '7' && hostname[3] == '.' {
		return true
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
		if equalFold(hostname, "localhost") {
			return true
		}
	}

	// Check for known local DNS names derived from localhost
	// Only match specific local DNS suffixes, not arbitrary localhost.* subdomains
	// which may be legitimate public domains (e.g., localhost.example.com).
	// Domains resolving to loopback IPs are still blocked at the dialer layer.
	if hlen == 21 && (hostname[0] == 'l' || hostname[0] == 'L') {
		if equalFold(hostname, "localhost.localdomain") {
			return true
		}
	}
	if hlen == 22 && (hostname[0] == 'l' || hostname[0] == 'L') {
		if equalFold(hostname, "localhost.localdomain.") {
			return true
		}
	}

	return false
}

// equalFold checks if s equals t case-insensitively (ASCII only)
// Avoids allocation from strings.ToLower
func equalFold(s, t string) bool {
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

// ValidateSSRFHost checks whether a hostname (which may include a port) should be
// blocked under SSRF protection rules. It checks localhost, direct IP addresses,
// and optionally resolves DNS for domain names.
// Returns nil if the host is allowed, or an error describing why it was blocked.
func ValidateSSRFHost(host string, exemptNets []*net.IPNet, resolveDNS bool) error {
	// Extract hostname from host:port format
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	if IsLocalhost(hostname) {
		return fmt.Errorf("localhost access blocked for security")
	}

	if ip := net.ParseIP(hostname); ip != nil {
		if err := ValidateIPWithExemptions(ip, exemptNets); err != nil {
			return fmt.Errorf("private/reserved IP address blocked")
		}
		return nil
	}

	if resolveDNS {
		ips, err := net.LookupIP(hostname)
		if err != nil {
			return fmt.Errorf("DNS resolution failed: %w", err)
		}
		for _, ip := range ips {
			if err := ValidateIPWithExemptions(ip, exemptNets); err != nil {
				return fmt.Errorf("domain resolves to blocked address")
			}
		}
	}

	return nil
}
