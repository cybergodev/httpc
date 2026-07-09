package engine

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cybergodev/httpc/internal/connection"
	"github.com/cybergodev/httpc/internal/security"
)

func TestCheckRedirect_CrossOriginHeaderStripping(t *testing.T) {
	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	trans, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = trans.Close() }()

	tests := []struct {
		name                 string
		originalHost         string
		redirectHost         string
		expectAuthStripped   bool
		expectCookieStripped bool
	}{
		{
			name:                 "different hosts strips sensitive headers",
			originalHost:         "api.example.com",
			redirectHost:         "evil.com",
			expectAuthStripped:   true,
			expectCookieStripped: true,
		},
		{
			name:                 "same host preserves headers",
			originalHost:         "example.com",
			redirectHost:         "example.com",
			expectAuthStripped:   false,
			expectCookieStripped: false,
		},
		{
			name:                 "different subdomain strips headers",
			originalHost:         "api.example.com",
			redirectHost:         "www.example.com",
			expectAuthStripped:   true,
			expectCookieStripped: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redirectURL, _ := url.Parse("https://" + tt.redirectHost + "/redirected")
			redirectReq, _ := http.NewRequest("GET", redirectURL.String(), nil)
			redirectReq.Header.Set("Authorization", "Bearer secret-token")
			redirectReq.Header.Set("Proxy-Authorization", "Basic creds")
			redirectReq.Header.Set("Cookie", "session=abc")
			redirectReq.Header.Set("X-Custom", "visible")

			originalURL, _ := url.Parse("https://" + tt.originalHost + "/original")
			originalReq, _ := http.NewRequest("GET", originalURL.String(), nil)

			settings := getRedirectSettings()
			settings.followRedirects = true
			settings.maxRedirects = 5
			ctx := context.WithValue(redirectReq.Context(), redirectContextKey{}, settings)
			redirectReq = redirectReq.WithContext(ctx)

			via := []*http.Request{originalReq}
			err := trans.checkRedirect(redirectReq, via)
			if err != nil {
				t.Fatalf("checkRedirect returned error: %v", err)
			}

			authStripped := redirectReq.Header.Get("Authorization") == ""
			cookieStripped := redirectReq.Header.Get("Cookie") == ""

			if authStripped != tt.expectAuthStripped {
				t.Errorf("Authorization stripped=%v, want=%v", authStripped, tt.expectAuthStripped)
			}
			if cookieStripped != tt.expectCookieStripped {
				t.Errorf("Cookie stripped=%v, want=%v", cookieStripped, tt.expectCookieStripped)
			}

			if redirectReq.Header.Get("X-Custom") != "visible" {
				t.Error("X-Custom header should never be stripped")
			}

			putRedirectSettings(settings)
		})
	}
}

func TestCheckRedirect_SameOriginHeadersPreserved(t *testing.T) {
	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	trans, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = trans.Close() }()

	redirectURL, _ := url.Parse("https://example.com/new-path")
	redirectReq, _ := http.NewRequest("GET", redirectURL.String(), nil)
	redirectReq.Header.Set("Authorization", "Bearer secret-token")

	originalURL, _ := url.Parse("https://example.com/old-path")
	originalReq, _ := http.NewRequest("GET", originalURL.String(), nil)

	settings := getRedirectSettings()
	settings.followRedirects = true
	settings.maxRedirects = 5
	ctx := context.WithValue(redirectReq.Context(), redirectContextKey{}, settings)
	redirectReq = redirectReq.WithContext(ctx)

	err = trans.checkRedirect(redirectReq, []*http.Request{originalReq})
	if err != nil {
		t.Fatalf("checkRedirect returned error: %v", err)
	}

	if redirectReq.Header.Get("Authorization") != "Bearer secret-token" {
		t.Error("Authorization should be preserved on same-origin redirect")
	}
	putRedirectSettings(settings)
}

func TestClearPools(t *testing.T) {
	// Populate pools
	settings := getRedirectSettings()
	if settings == nil {
		t.Fatal("getRedirectSettings returned nil")
	}
	settings.followRedirects = true
	settings.maxRedirects = 5
	settings.addRedirect("https://example.com")
	putRedirectSettings(settings)

	// Clear pools
	clearTransportPools()

	// Verify pools are empty after clear
	cleared := getRedirectSettings()
	if cleared == nil {
		t.Fatal("getRedirectSettings returned nil after clear")
	}
	if cleared.chainLen != 0 {
		t.Errorf("redirect chain should be empty after clear, got %d entries", cleared.chainLen)
	}
}

func TestCrossOriginRedirectHostComparison(t *testing.T) {
	tests := []struct {
		name         string
		originalHost string
		redirectHost string
		shouldStrip  bool
	}{
		{"same host", "example.com", "example.com", false},
		{"different host", "example.com", "evil.com", true},
		{"same host different port", "example.com:8080", "example.com:9090", false},
		{"different subdomain", "api.example.com", "www.example.com", true},
		{"ip vs hostname", "example.com", "127.0.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original, _ := url.Parse("http://" + tt.originalHost + "/path")
			redirect, _ := url.Parse("http://" + tt.redirectHost + "/path")

			stripNeeded := original.Hostname() != redirect.Hostname()
			if stripNeeded != tt.shouldStrip {
				t.Errorf("hostname comparison: %q vs %q, stripNeeded=%v, want=%v",
					original.Hostname(), redirect.Hostname(), stripNeeded, tt.shouldStrip)
			}
		})
	}
}

// TestCheckRedirect_WhitelistBlock covers the redirect-whitelist branch
// (transport.go:195-198): when a whitelist is configured, redirects to
// non-whitelisted hosts are blocked, while whitelisted hosts pass.
// AllowPrivateIPs=true disables the SSRF check so the whitelist is the only gate.
func TestCheckRedirect_WhitelistBlock(t *testing.T) {
	config := &Config{
		Timeout:           30 * time.Second,
		AllowPrivateIPs:   true,
		RedirectWhitelist: security.NewDomainWhitelist("allowed.example.com"),
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	trans, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = trans.Close() }()

	tests := []struct {
		name         string
		redirectHost string
		wantErr      string // empty = expect nil (redirect allowed)
	}{
		{"whitelisted host allowed", "allowed.example.com", ""},
		{"non-whitelisted host blocked", "evil.example.com", "redirect blocked by whitelist"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redirectReq, _ := http.NewRequest("GET", "https://"+tt.redirectHost+"/path", nil)
			settings := getRedirectSettings()
			settings.followRedirects = true
			ctx := context.WithValue(redirectReq.Context(), redirectContextKey{}, settings)
			redirectReq = redirectReq.WithContext(ctx)
			defer putRedirectSettings(settings)

			err := trans.checkRedirect(redirectReq, nil)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil error for %s, got %v", tt.redirectHost, err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

// TestCheckRedirect_SSRFPrivateIPBlocked covers the SSRF branch
// (transport.go:210-214): with AllowPrivateIPs=false, redirects to
// private/loopback addresses and unsupported schemes are blocked.
func TestCheckRedirect_SSRFPrivateIPBlocked(t *testing.T) {
	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: false, // SSRF protection active
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	trans, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = trans.Close() }()

	tests := []struct {
		name        string
		redirectURL string
		wantErr     string // empty = expect nil (redirect allowed)
	}{
		{"public host allowed", "https://example.com/path", ""},
		{"private IP blocked", "https://192.168.1.1/path", "redirect blocked"},
		{"loopback blocked", "https://127.0.0.1/path", "redirect blocked"},
		{"unsupported scheme blocked", "ftp://example.com/x", "redirect blocked"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redirectReq, _ := http.NewRequest("GET", tt.redirectURL, nil)
			settings := getRedirectSettings()
			settings.followRedirects = true
			ctx := context.WithValue(redirectReq.Context(), redirectContextKey{}, settings)
			redirectReq = redirectReq.WithContext(ctx)
			defer putRedirectSettings(settings)

			err := trans.checkRedirect(redirectReq, nil)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil error for %s, got %v", tt.redirectURL, err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

// TestCheckRedirect_PolicyArms covers the remaining redirect-policy branches:
// the disabled-redirect arm (transport.go:190-192 → http.ErrUseLastResponse),
// the no-settings default arm (:184-186 → nil), and the max-redirects arm
// (:255-257 → "stopped after N redirects").
func TestCheckRedirect_PolicyArms(t *testing.T) {
	config := &Config{
		Timeout:         30 * time.Second,
		AllowPrivateIPs: true,
	}

	connConfig := testConnectionConfig()
	poolManager, err := connection.NewPoolManager(connConfig)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer func() { _ = poolManager.Close() }()

	trans, err := newTransport(config, poolManager)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	defer func() { _ = trans.Close() }()

	t.Run("disabled redirects return ErrUseLastResponse", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/x", nil)
		settings := getRedirectSettings()
		settings.followRedirects = false
		ctx := context.WithValue(req.Context(), redirectContextKey{}, settings)
		req = req.WithContext(ctx)
		defer putRedirectSettings(settings)

		if err := trans.checkRedirect(req, nil); err != http.ErrUseLastResponse {
			t.Errorf("expected http.ErrUseLastResponse, got %v", err)
		}
	})

	t.Run("no settings in context defaults to allow", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/x", nil)
		if err := trans.checkRedirect(req, nil); err != nil {
			t.Errorf("expected nil when no redirect settings present, got %v", err)
		}
	})

	t.Run("max redirects exceeded is blocked", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/x", nil)
		settings := getRedirectSettings()
		settings.followRedirects = true
		settings.maxRedirects = 2
		ctx := context.WithValue(req.Context(), redirectContextKey{}, settings)
		req = req.WithContext(ctx)
		defer putRedirectSettings(settings)

		// Two prior hops → len(via)==2 == maxRedirects → blocked.
		via1, _ := http.NewRequest("GET", "https://example.com/1", nil)
		via2, _ := http.NewRequest("GET", "https://example.com/2", nil)
		err := trans.checkRedirect(req, []*http.Request{via1, via2})
		if err == nil || !strings.Contains(err.Error(), "stopped after 2 redirects") {
			t.Errorf("expected 'stopped after 2 redirects', got %v", err)
		}
	})
}
