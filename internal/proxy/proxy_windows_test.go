package proxy

import (
	"net/url"
	"testing"
)

// TestParseWindowsProxyString verifies parsing of Windows proxy server strings
// in both simple host:port and per-protocol formats, including protocol priority
// and URL verification.
func TestParseWindowsProxyString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		wantHost string // expected hostname (checked when wantErr is false and non-empty)
		wantURL  string // expected full URL string (checked when non-empty)
	}{
		// Basic parsing cases
		{
			name:     "Simple host:port",
			input:    "proxy:8080",
			wantHost: "proxy",
			wantErr:  false,
		},
		{
			name:     "Host without port",
			input:    "proxy",
			wantHost: "proxy",
			wantErr:  false,
		},
		{
			name:     "IP address with port",
			input:    "192.168.1.1:3128",
			wantHost: "192.168.1.1",
			wantErr:  false,
		},
		{
			name:    "Empty string returns error",
			input:   "",
			wantErr: true,
		},
		{
			name:    "Whitespace-only string returns error",
			input:   "   ",
			wantErr: true,
		},
		// Per-protocol parsing
		{
			name:     "Per-protocol returns first matching protocol",
			input:    "http=proxy-http:8080;https=proxy-https:8443",
			wantHost: "proxy-http",
			wantErr:  false,
		},
		{
			name:     "Per-protocol HTTP only",
			input:    "http=proxy-http:8080",
			wantHost: "proxy-http",
			wantErr:  false,
		},
		// Protocol priority: first matching protocol (http or https) is returned
		{
			name:     "Per-protocol https first has priority",
			input:    "https=https-proxy:8443;http=http-proxy:8080",
			wantHost: "https-proxy",
			wantErr:  false,
		},
		// Full URL prefixes
		{
			name:     "Full URL with http prefix",
			input:    "http://proxy.example.com:8080",
			wantHost: "proxy.example.com",
			wantErr:  false,
		},
		{
			name:     "Full URL with https prefix",
			input:    "https://proxy.example.com:8443",
			wantHost: "proxy.example.com",
			wantErr:  false,
		},
		{
			name:     "SOCKS5 URL",
			input:    "socks5://proxy.example.com:1080",
			wantHost: "proxy.example.com",
			wantErr:  false,
		},
		{
			name:     "Per-protocol with FTP fallback to HTTP",
			input:    "ftp=ftp-proxy:2121;http=http-proxy:8888",
			wantHost: "http-proxy",
			wantErr:  false,
		},
		// URL verification: ensure returned URL is valid and usable
		{
			name:    "Simple proxy gets http scheme prepended",
			input:   "proxy:8080",
			wantURL: "http://proxy:8080",
		},
		{
			name:    "http:// prefix preserved",
			input:   "http://proxy:8080",
			wantURL: "http://proxy:8080",
		},
		{
			name:    "Per-protocol result has http scheme",
			input:   "https=secure-proxy:8443",
			wantURL: "http://secure-proxy:8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseWindowsProxyString(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("expected non-nil URL, got nil")
			}

			// Verify the host part of the resulting URL
			if tt.wantHost != "" {
				host := result.Hostname()
				if host != tt.wantHost {
					t.Errorf("host = %q, want %q (full URL: %s)", host, tt.wantHost, result.String())
				}
			}

			// Verify the full URL string
			if tt.wantURL != "" {
				got := result.String()
				if got != tt.wantURL {
					// url.URL.String() may add trailing slash for empty path
					wantURL, _ := url.Parse(tt.wantURL)
					if got != wantURL.String() {
						t.Errorf("URL = %q, want %q", got, wantURL.String())
					}
				}
			}
		})
	}
}
