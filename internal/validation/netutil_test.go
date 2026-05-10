package validation

import (
	"net"
	"strings"
	"testing"
)

// BenchmarkIsLocalhost benchmarks the IsLocalhost function
func BenchmarkIsLocalhost(b *testing.B) {
	benchmarks := []struct {
		name     string
		hostname string
	}{
		{"localhost", "localhost"},
		{"LOCALHOST", "LOCALHOST"},
		{"LocalHost", "LocalHost"},
		{"127.0.0.1", "127.0.0.1"},
		{"127.1.1.1", "127.1.1.1"},
		{"localhost.local", "localhost.local"},
		{"example.com", "example.com"},
		{"notlocalhost.com", "notlocalhost.com"},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = IsLocalhost(bm.hostname)
			}
		})
	}
}

func TestIsPrivateOrReservedIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// IPv4 private addresses
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv4 private A", "10.0.0.1", true},
		{"IPv4 private B", "172.16.0.1", true},
		{"IPv4 private C", "192.168.1.1", true},
		{"IPv4 link-local", "169.254.1.1", true},
		{"IPv4 multicast", "224.0.0.1", true},
		{"IPv4 unspecified", "0.0.0.0", true},

		// IPv4 reserved ranges
		{"IPv4 Class E", "240.0.0.1", true},
		{"IPv4 This network", "0.1.2.3", true},
		{"IPv4 CGNAT (allowed - Tailscale/WireGuard)", "100.64.0.1", false},
		{"IPv4 Benchmarking (allowed - Clash/Surge fake-IP)", "198.18.0.1", false},

		// IPv4 public addresses
		{"IPv4 public Google DNS", "8.8.8.8", false},
		{"IPv4 public Cloudflare", "1.1.1.1", false},
		{"IPv4 public", "93.184.216.34", false},

		// IPv6 addresses
		{"IPv6 loopback", "::1", true},
		{"IPv6 unspecified", "::", true},
		{"IPv6 private fc00", "fc00::1", true},
		{"IPv6 private fd00", "fd00::1", true},
		{"IPv6 link-local", "fe80::1", true},
		{"IPv6 documentation", "2001:db8::1", true},

		// IPv6 public addresses
		{"IPv6 public Google", "2001:4860:4860::8888", false},
		{"IPv6 public Cloudflare", "2606:4700:4700::1111", false},

		// IPv4-mapped IPv6 addresses (SSRF bypass prevention)
		{"IPv4-mapped loopback", "::ffff:127.0.0.1", true},
		{"IPv4-mapped private A", "::ffff:10.0.0.1", true},
		{"IPv4-mapped private B", "::ffff:172.16.0.1", true},
		{"IPv4-mapped private C", "::ffff:192.168.1.1", true},
		{"IPv4-mapped public", "::ffff:8.8.8.8", false},
		{"IPv4-mapped link-local", "::ffff:169.254.1.1", true},
		{"IPv4-mapped CGNAT (allowed - Tailscale/WireGuard)", "::ffff:100.64.0.1", false},

		// NAT64 well-known prefix (RFC 6052)
		{"NAT64 mapped loopback", "64:ff9b::7f00:1", true},
		{"NAT64 mapped metadata", "64:ff9b::a9fe:a9fe", true},
		{"NAT64 mapped private", "64:ff9b::a00:1", true},
		{"NAT64 mapped public", "64:ff9b::808:808", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			result := IsPrivateOrReservedIP(ip)
			if result != tt.expected {
				t.Errorf("IsPrivateOrReservedIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"public IP no error", "8.8.8.8", false},
		{"private IP error", "192.168.1.1", true},
		{"loopback error", "127.0.0.1", true},
		{"IPv4-mapped private error", "::ffff:192.168.1.1", true},
		{"IPv6 private error", "fc00::1", true},
		{"IPv6 link-local error", "fe80::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			err := ValidateIP(ip)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateIP(%s) expected error, got nil", tt.ip)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateIP(%s) unexpected error: %v", tt.ip, err)
			}
		})
	}
}

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		expected bool
	}{
		// Standard localhost
		{"localhost lowercase", "localhost", true},
		{"localhost uppercase", "LOCALHOST", true},
		{"localhost mixed case", "LocalHost", true},

		// IP addresses
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.2", "127.0.0.2", true},
		{"127.1.1.1", "127.1.1.1", true},
		{"::1", "::1", true},
		{"0.0.0.0", "0.0.0.0", true},
		{"::", "::", true},

		// Known local DNS names (still blocked)
		{"localhost.localdomain", "localhost.localdomain", true},
		{"LOCALHOST.LOCALDOMAIN", "LOCALHOST.LOCALDOMAIN", true},
		{"localhost.localdomain.", "localhost.localdomain.", true},
		{"LOCALHOST.LOCALDOMAIN.", "LOCALHOST.LOCALDOMAIN.", true},

		// Legitimate localhost.* public domains (no longer blocked at this layer;
		// if they resolve to loopback IPs, the dialer will still block them)
		{"localhost.local", "localhost.local", false},
		{"localhost.example.com", "localhost.example.com", false},
		{"localhost.dev.mycompany.com", "localhost.dev.mycompany.com", false},

		// Non-localhost
		{"example.com", "example.com", false},
		{"192.168.1.1", "192.168.1.1", false},
		{"mylocalhost.com", "mylocalhost.com", false}, // "localhost" not at start
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsLocalhost(tt.hostname)
			if result != tt.expected {
				t.Errorf("IsLocalhost(%s) = %v, want %v", tt.hostname, result, tt.expected)
			}
		})
	}
}

func TestSSRFBypassPrevention(t *testing.T) {
	// This test specifically validates SSRF bypass prevention techniques
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// Common SSRF bypass attempts
		{"IPv4-mapped IPv6 localhost", "::ffff:127.0.0.1", true},
		{"IPv4-mapped IPv6 private", "::ffff:10.0.0.1", true},
		{"IPv4-mapped IPv6 loopback variant", "::ffff:127.0.0.2", true},
		{"IPv4-mapped IPv6 0.0.0.0", "::ffff:0.0.0.0", true},
		{"IPv4-mapped IPv6 169.254", "::ffff:169.254.1.1", true},

		// IPv6 local ranges
		{"IPv6 link-local fe80", "fe80::1", true},
		{"IPv6 unique local fc00", "fc00::1", true},
		{"IPv6 unique local fd00", "fdff:ffff:ffff:ffff::1", true},

		// Should NOT be blocked
		{"IPv4-mapped public", "::ffff:1.1.1.1", false},
		{"IPv6 public", "2606:4700:4700::1111", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}

			blocked := IsPrivateOrReservedIP(ip)
			if blocked != tt.blocked {
				t.Errorf("SSRF bypass check for %s: blocked=%v, want=%v", tt.ip, blocked, tt.blocked)
			}
		})
	}
}

func TestParseExemptCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		wantLen int
		wantErr bool
	}{
		{"nil input", nil, 0, false},
		{"empty input", []string{}, 0, false},
		{"single valid", []string{"10.0.0.0/8"}, 1, false},
		{"multiple valid", []string{"10.0.0.0/8", "172.16.0.0/12"}, 2, false},
		{"invalid CIDR", []string{"not-a-cidr"}, 0, true},
		{"mixed valid and invalid", []string{"10.0.0.0/8", "bad"}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets, err := ParseExemptCIDRs(tt.cidrs)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if len(nets) != tt.wantLen {
				t.Errorf("got %d nets, want %d", len(nets), tt.wantLen)
			}
		})
	}
}

func TestIsIPExempted(t *testing.T) {
	nets, err := ParseExemptCIDRs([]string{"10.0.0.0/8", "100.64.0.0/10"})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"exempt 10.x", "10.0.0.1", true},
		{"exempt 10.255.255.255", "10.255.255.255", true},
		{"exempt CGNAT", "100.64.0.1", true},
		{"not exempt 192.168", "192.168.1.1", false},
		{"not exempt public", "8.8.8.8", false},
		{"not exempt 127", "127.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			result := IsIPExempted(ip, nets)
			if result != tt.expected {
				t.Errorf("IsIPExempted(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestValidateIPWithExemptions(t *testing.T) {
	nets, err := ParseExemptCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"public IP no error", "8.8.8.8", false},
		{"exempt private IP no error", "10.0.0.1", false},
		{"non-exempt private IP error", "192.168.1.1", true},
		{"loopback error", "127.0.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			err := ValidateIPWithExemptions(ip, nets)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateIPWithExemptions(%s) expected error, got nil", tt.ip)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateIPWithExemptions(%s) unexpected error: %v", tt.ip, err)
			}
		})
	}
}

func TestValidateSSRFHost(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		exemptNets []string
		resolveDNS bool
		wantErr    bool
		errContain string
	}{
		{"localhost blocked", "localhost", nil, false, true, "localhost"},
		{"localhost with port blocked", "localhost:8080", nil, false, true, "localhost"},
		{"127.0.0.1 blocked", "127.0.0.1", nil, false, true, "localhost"},
		{"private IP blocked", "192.168.1.1", nil, false, true, "private/reserved"},
		{"public IP allowed", "8.8.8.8", nil, false, false, ""},
		{"public IP with port allowed", "8.8.8.8:443", nil, false, false, ""},
		{"exempt private IP allowed", "10.0.0.1", []string{"10.0.0.0/8"}, false, false, ""},
		{"non-exempt private IP blocked", "192.168.1.1", []string{"10.0.0.0/8"}, false, true, "private/reserved"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nets []*net.IPNet
			if len(tt.exemptNets) > 0 {
				var err error
				nets, err = ParseExemptCIDRs(tt.exemptNets)
				if err != nil {
					t.Fatalf("ParseExemptCIDRs error: %v", err)
				}
			}
			err := ValidateSSRFHost(tt.host, nets, tt.resolveDNS)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateSSRFHost(%q) expected error, got nil", tt.host)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateSSRFHost(%q) unexpected error: %v", tt.host, err)
			}
			if tt.wantErr && err != nil && tt.errContain != "" {
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("ValidateSSRFHost(%q) error %q should contain %q", tt.host, err.Error(), tt.errContain)
				}
			}
		})
	}
}

func TestIsPrivateOrReservedIP_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// IPv4 boundary addresses
		{"IPv4 broadcast 255.255.255.255", "255.255.255.255", true},
		{"IPv4 private A network boundary", "10.0.0.0", true},
		{"IPv4 private A network end", "10.255.255.255", true},
		{"IPv4 private B start", "172.16.0.0", true},
		{"IPv4 private B end", "172.31.255.255", true},
		{"IPv4 private B just before", "172.15.255.255", false},
		{"IPv4 private B just after", "172.32.0.0", false},
		{"IPv4 private C start", "192.168.0.0", true},
		{"IPv4 private C end", "192.168.255.255", true},
		{"IPv4 link-local start", "169.254.0.0", true},
		{"IPv4 link-local end", "169.254.255.255", true},

		// IPv6 boundary
		{"IPv6 multicast", "ff00::1", true},
		{"IPv6 documentation end", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"IPv6 public just past documentation", "2001:db9::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			result := IsPrivateOrReservedIP(ip)
			if result != tt.expected {
				t.Errorf("IsPrivateOrReservedIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestFilterAllowedIPs(t *testing.T) {
	exemptNets, _ := ParseExemptCIDRs([]string{"10.0.0.0/8"})

	tests := []struct {
		name     string
		ips      []string
		exempt   []*net.IPNet
		expected int
	}{
		{
			name:     "All public IPs",
			ips:      []string{"8.8.8.8", "1.1.1.1"},
			exempt:   nil,
			expected: 2,
		},
		{
			name:     "All private IPs no exemption",
			ips:      []string{"192.168.1.1", "10.0.0.1"},
			exempt:   nil,
			expected: 0,
		},
		{
			name:     "Mixed public and private - filters to public only",
			ips:      []string{"10.0.0.1", "8.8.8.8", "192.168.1.1"},
			exempt:   nil,
			expected: 1,
		},
		{
			name:     "Private IPs with exemption - exempted ones pass",
			ips:      []string{"10.0.0.1", "192.168.1.1"},
			exempt:   exemptNets,
			expected: 1,
		},
		{
			name:     "Split-Horizon DNS: private and public",
			ips:      []string{"10.0.0.5", "93.184.216.34", "192.168.1.1"},
			exempt:   nil,
			expected: 1,
		},
		{
			name:     "Empty input",
			ips:      []string{},
			exempt:   nil,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := make([]net.IP, 0, len(tt.ips))
			for _, s := range tt.ips {
				ip := net.ParseIP(s)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", s)
				}
				ips = append(ips, ip)
			}

			result := FilterAllowedIPs(ips, tt.exempt)
			if len(result) != tt.expected {
				t.Errorf("FilterAllowedIPs returned %d IPs, want %d", len(result), tt.expected)
			}
		})
	}
}

func TestValidateAndParseURL_BoundaryConditions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		url         string
		wantErr     bool
		errContains string
	}{
		{"empty URL", "", true, "cannot be empty"},
		{"URL too long", "https://example.com/" + strings.Repeat("a", 30000), true, "too long"},
		{"invalid URL parse", "http://[::1:bad", true, "invalid URL"},
		{"missing scheme", "example.com/path", true, "scheme is required"},
		{"missing host", "http://", true, "host is required"},
		{"unsupported scheme ftp", "ftp://example.com/file", true, "unsupported URL scheme"},
		{"valid HTTP", "http://example.com/path", false, ""},
		{"valid HTTPS", "https://example.com/path?q=1", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ValidateAndParseURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				} else if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if u == nil {
					t.Error("expected non-nil URL")
				}
			}
		})
	}
}

func TestValidateSSRFHost_BoundaryConditions(t *testing.T) {
	t.Parallel()
	t.Run("host with port", func(t *testing.T) {
		err := ValidateSSRFHost("example.com:8080", nil, false)
		if err != nil {
			t.Errorf("public host with port should pass: %v", err)
		}
	})
	t.Run("domain without DNS resolution", func(t *testing.T) {
		err := ValidateSSRFHost("example.com", nil, false)
		if err != nil {
			t.Errorf("domain with resolveDNS=false should pass: %v", err)
		}
	})
	t.Run("DNS resolution failure", func(t *testing.T) {
		// Use a domain under .test (RFC 2606 reserved) with random suffix
		// to avoid DNS cache/proxy interference
		err := ValidateSSRFHost("nonexistent-dns-test-xyz123.test", nil, true)
		if err == nil {
			t.Skip("DNS resolved unexpectedly; skipping DNS failure test")
		}
		if !strings.Contains(err.Error(), "DNS") {
			t.Errorf("error should mention DNS, got: %v", err)
		}
	})
}
