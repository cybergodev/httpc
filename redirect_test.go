package httpc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cybergodev/httpc/internal/engine"
)

func TestRedirect_AutoFollow(t *testing.T) {
	t.Parallel()

	redirectCount := 0
	finalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Final destination")) // best-effort test response
	}))
	defer finalServer.Close()

	var redirectServer *httptest.Server
	redirectServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		if redirectCount < 3 {
			http.Redirect(w, r, redirectServer.URL, http.StatusFound)
		} else {
			http.Redirect(w, r, finalServer.URL, http.StatusFound)
		}
	}))
	defer redirectServer.Close()

	config := testConfig()
	config.Defaults.FollowRedirects = true
	config.Defaults.MaxRedirects = 10
	client, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Get(redirectServer.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode() != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode())
	}

	if resp.Body() != "Final destination" {
		t.Errorf("Expected 'Final destination', got '%s'", resp.Body())
	}

	if resp.Meta.RedirectCount != 3 {
		t.Errorf("Expected 3 redirects, got %d", resp.Meta.RedirectCount)
	}

	if len(resp.Meta.RedirectChain) != 3 {
		t.Errorf("Expected redirect chain length 3, got %d", len(resp.Meta.RedirectChain))
	}
}

// TestRedirect_NoFollow was removed: the unfollowed-302 contract is covered
// by TestRedirect_PerRequestOverride below (same assertions via the
// per-request option), which now also carries this test's Location-header
// check. Config-level FollowRedirects=false is exercised by the
// non-following rows of TestRedirect_NonFollowingModes above.

func TestRedirect_MaxRedirectsLimit(t *testing.T) {
	t.Parallel()

	var redirectServer *httptest.Server
	redirectServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectServer.URL, http.StatusFound)
	}))
	defer redirectServer.Close()

	config := testConfig()
	config.Defaults.FollowRedirects = true
	config.Defaults.MaxRedirects = 3
	client, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Get(redirectServer.URL)
	if err == nil {
		t.Error("Expected error for too many redirects, got nil")
	}
}

func TestRedirect_PerRequestOverride(t *testing.T) {
	t.Parallel()

	finalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Final destination")) // best-effort test response
	}))
	defer finalServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, finalServer.URL, http.StatusFound)
	}))
	defer redirectServer.Close()

	// Client configured to follow redirects
	config := testConfig()
	config.Defaults.FollowRedirects = true
	client, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Override to not follow redirects for this request
	resp, err := client.Get(redirectServer.URL, WithFollowRedirects(false))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode() != http.StatusFound {
		t.Errorf("Expected status 302, got %d", resp.StatusCode())
	}

	// (Location-header assertion folded in from the retired TestRedirect_NoFollow.)
	location := resp.Response.Headers.Get("Location")
	if location != finalServer.URL {
		t.Errorf("Expected Location header '%s', got '%s'", finalServer.URL, location)
	}

	if resp.Meta.RedirectCount != 0 {
		t.Errorf("Expected 0 redirects, got %d", resp.Meta.RedirectCount)
	}
}

func TestRedirect_MaxRedirectsPerRequest(t *testing.T) {
	t.Parallel()

	redirectCount := 0
	var redirectServer *httptest.Server
	redirectServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		http.Redirect(w, r, redirectServer.URL, http.StatusFound)
	}))
	defer redirectServer.Close()

	config := testConfig()
	config.Defaults.FollowRedirects = true
	config.Defaults.MaxRedirects = 10
	client, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Override max redirects to 2 for this request
	_, err = client.Get(redirectServer.URL, WithMaxRedirects(2))
	if err == nil {
		t.Error("Expected error for too many redirects, got nil")
	}

	if redirectCount > 3 {
		t.Errorf("Expected at most 3 redirect attempts, got %d", redirectCount)
	}
}

func TestRedirect_DifferentStatusCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		shouldWork bool
	}{
		{"301 Moved Permanently", http.StatusMovedPermanently, true},
		{"302 Found", http.StatusFound, true},
		{"303 See Other", http.StatusSeeOther, true},
		{"307 Temporary Redirect", http.StatusTemporaryRedirect, true},
		{"308 Permanent Redirect", http.StatusPermanentRedirect, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Success")) // best-effort test response
			}))
			defer finalServer.Close()

			redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", finalServer.URL)
				w.WriteHeader(tt.statusCode)
			}))
			defer redirectServer.Close()

			config := testConfig()
			config.Defaults.FollowRedirects = true
			client, err := New(config)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}
			defer func() { _ = client.Close() }()

			resp, err := client.Get(redirectServer.URL)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}

			if tt.shouldWork && resp.StatusCode() != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode())
			}

			if tt.shouldWork && resp.Meta.RedirectCount != 1 {
				t.Errorf("Expected 1 redirect, got %d", resp.Meta.RedirectCount)
			}
		})
	}
}

func TestRedirect_ChainTracking(t *testing.T) {
	t.Parallel()

	server3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Final")) // best-effort test response
	}))
	defer server3.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server3.URL, http.StatusFound)
	}))
	defer server2.Close()

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server2.URL, http.StatusFound)
	}))
	defer server1.Close()

	config := testConfig()
	config.Defaults.FollowRedirects = true
	client, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Get(server1.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.Meta.RedirectCount != 2 {
		t.Errorf("Expected 2 redirects, got %d", resp.Meta.RedirectCount)
	}

	if len(resp.Meta.RedirectChain) != 2 {
		t.Fatalf("Expected redirect chain length 2, got %d", len(resp.Meta.RedirectChain))
	}

	// Verify the chain contains the intermediate URLs
	if resp.Meta.RedirectChain[0] != server1.URL {
		t.Errorf("Expected first redirect to be %s, got %s", server1.URL, resp.Meta.RedirectChain[0])
	}

	if resp.Meta.RedirectChain[1] != server2.URL {
		t.Errorf("Expected second redirect to be %s, got %s", server2.URL, resp.Meta.RedirectChain[1])
	}
}

var maxRedirectValidationCases = []struct {
	name        string
	maxRedirect int
	wantErr     bool
}{
	{"Valid: 0", 0, false},
	{"Valid: 10", 10, false},
	{"Valid: 50", 50, false},
	{"Invalid: negative", -1, true},
	{"Invalid: too large", 51, true},
}

func TestRedirect_ConfigValidation(t *testing.T) {
	t.Parallel()

	for _, tt := range maxRedirectValidationCases {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.Defaults.MaxRedirects = tt.maxRedirect
			err := ValidateConfig(&config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRedirect_OptionValidation(t *testing.T) {
	t.Parallel()

	for _, tt := range maxRedirectValidationCases {
		t.Run(tt.name, func(t *testing.T) {
			req := &engine.Request{}
			opt := WithMaxRedirects(tt.maxRedirect)
			err := opt(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("WithMaxRedirects() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRedirect_LoopDetection(t *testing.T) {
	t.Parallel()

	var serverB *httptest.Server
	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/to-b" {
			http.Redirect(w, r, serverB.URL+"/to-a", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer serverA.Close()

	serverB = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, serverA.URL+"/to-b", http.StatusFound)
	}))
	defer serverB.Close()

	config := testConfig()
	config.Defaults.FollowRedirects = true
	config.Defaults.MaxRedirects = 10
	client, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Get(serverA.URL + "/to-b")
	if err == nil {
		t.Error("Expected error for circular redirect, got nil")
	}
}

func TestRedirect_QueryParameterPreservation(t *testing.T) {
	t.Parallel()

	var receivedQuery string
	finalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer finalServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, finalServer.URL+"?"+r.URL.RawQuery, http.StatusFound)
	}))
	defer redirectServer.Close()

	config := testConfig()
	config.Defaults.FollowRedirects = true
	client, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Get(redirectServer.URL + "?key=value&foo=bar")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode())
	}
	if receivedQuery != "foo=bar&key=value" && receivedQuery != "key=value&foo=bar" {
		t.Errorf("Expected query params preserved, got %q", receivedQuery)
	}
}

func TestRedirect_BoundaryStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"300 Multiple Choices", 300},
		{"399 edge case", 399},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://example.com/target")
				w.WriteHeader(tt.statusCode)
			}))
			defer source.Close()

			cfg := testConfig()
			cfg.Defaults.FollowRedirects = true

			client, err := New(cfg)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}
			defer func() { _ = client.Close() }()

			resp, err := client.Get(source.URL)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}

			if resp.StatusCode() != tt.statusCode {
				t.Errorf("Expected status %d for non-followed redirect, got %d", tt.statusCode, resp.StatusCode())
			}
		})
	}
}

// TestRedirect_ZeroMaxRedirectsFallsBackToDefault replaces the former
// TestRedirect_FollowWithZeroMaxRedirects (which asserted nothing and
// redirected to an external host). MaxRedirects=0 is the "not set" sentinel:
// following stays enabled with the DEFAULT cap (10), not "never follow" and
// not "unlimited".
func TestRedirect_ZeroMaxRedirectsFallsBackToDefault(t *testing.T) {
	// hopServer redirects to itself the first hops times, then returns 200.
	hopServer := func(hops int) *httptest.Server {
		count := 0
		var s *httptest.Server
		s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count++
			if count <= hops {
				http.Redirect(w, r, s.URL, http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("done")) // best-effort test response
		}))
		return s
	}

	t.Run("chain within default cap succeeds", func(t *testing.T) {
		t.Parallel()
		server := hopServer(5)
		defer server.Close()

		config := testConfig()
		config.Defaults.FollowRedirects = true
		config.Defaults.MaxRedirects = 0 // sentinel: fall back to default cap
		client, err := New(config)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer func() { _ = client.Close() }()

		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		if resp.StatusCode() != http.StatusOK {
			t.Errorf("Expected 200, got %d", resp.StatusCode())
		}
		if resp.Meta.RedirectCount != 5 {
			t.Errorf("Expected 5 followed redirects, got %d", resp.Meta.RedirectCount)
		}
	})

	t.Run("chain exceeding default cap errors", func(t *testing.T) {
		t.Parallel()
		server := hopServer(11) // 11 > default cap of 10
		defer server.Close()

		config := testConfig()
		config.Defaults.FollowRedirects = true
		config.Defaults.MaxRedirects = 0 // sentinel: fall back to default cap
		client, err := New(config)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer func() { _ = client.Close() }()

		if _, err := client.Get(server.URL); err == nil {
			t.Error("Expected error for chain exceeding the default cap with MaxRedirects=0, got nil")
		}
	})
}

// TestRedirect_MixedStatusCodes was removed: the 3-hop chain with RedirectCount
// assertion is covered by TestRedirect_AutoFollow, and each redirect status
// individually by TestRedirect_DifferentStatusCodes.

// ============================================================================
// 307/308 BODY-REPLAY ACROSS REDIRECTS (merged from redirect_body_test.go)
// ============================================================================
//
// net/http only replays a body across a redirect hop when Request.GetBody
// is set, so these tests pin the engine's replay sources: string/[]byte/
// JSON/XML/multipart bodies are replayable; a raw io.Reader is replayable
// only when the retry path has buffered it (MaxRetries > 0).
// newEchoServer returns a server that replies "METHOD|BODY|CONTENT-TYPE".
func newEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body failed", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(r.Method + "|" + string(body) + "|" + r.Header.Get("Content-Type"))) // best-effort test response
	}))
}

// newRedirectServer returns a server that replies with the given status and Location.
func newRedirectServer(t *testing.T, status int, location string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, location, status)
	}))
}

func TestRedirect_307FollowsWithJSONBody(t *testing.T) {
	t.Parallel()

	final := newEchoServer(t)
	defer final.Close()
	redirector := newRedirectServer(t, http.StatusTemporaryRedirect, final.URL)
	defer redirector.Close()

	client, err := newTestClient()
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Post(redirector.URL, WithJSON(map[string]any{"name": "httpc", "version": 2}))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if result.StatusCode() != http.StatusOK {
		t.Fatalf("Expected status 200 after 307, got %d (body: %s)", result.StatusCode(), result.Body())
	}

	want := `POST|{"name":"httpc","version":2}|application/json`
	if result.Body() != want {
		t.Errorf("Body not preserved across 307:\n got: %s\nwant: %s", result.Body(), want)
	}
	if result.Meta.RedirectCount != 1 {
		t.Errorf("Expected 1 redirect, got %d", result.Meta.RedirectCount)
	}
}

func TestRedirect_308FollowsWithStringBody(t *testing.T) {
	t.Parallel()

	final := newEchoServer(t)
	defer final.Close()
	redirector := newRedirectServer(t, http.StatusPermanentRedirect, final.URL)
	defer redirector.Close()

	client, err := newTestClient()
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Put(redirector.URL, WithBody("hello 308"))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if result.StatusCode() != http.StatusOK {
		t.Fatalf("Expected status 200 after 308, got %d", result.StatusCode())
	}

	want := "PUT|hello 308|text/plain; charset=utf-8"
	if result.Body() != want {
		t.Errorf("Body not preserved across 308:\n got: %s\nwant: %s", result.Body(), want)
	}
}

func TestRedirect_307MultipartBodyPreserved(t *testing.T) {
	t.Parallel()

	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			http.Error(w, "parse multipart failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		if r.FormValue("key") != "value" {
			http.Error(w, "missing form field", http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("upload")
		if err != nil {
			http.Error(w, "missing file field: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer func() { _ = file.Close() }() // best-effort cleanup
		content, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "read file failed", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("method=" + r.Method + " file=" + string(content))) // best-effort test response
	}))
	defer final.Close()
	redirector := newRedirectServer(t, http.StatusTemporaryRedirect, final.URL)
	defer redirector.Close()

	client, err := newTestClient()
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Post(redirector.URL,
		WithFormData(&FormData{Fields: map[string]string{"key": "value"}}),
		WithFile("upload", "data.txt", []byte("file-content")),
	)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if result.StatusCode() != http.StatusOK {
		t.Fatalf("Expected status 200 after 307, got %d (body: %s)", result.StatusCode(), result.Body())
	}
	if want := "method=POST file=file-content"; result.Body() != want {
		t.Errorf("Multipart body not preserved across 307:\n got: %s\nwant: %s", result.Body(), want)
	}
}

func TestRedirect_307ChainReplaysBodyEachHop(t *testing.T) {
	t.Parallel()

	final := newEchoServer(t)
	defer final.Close()
	hop2 := newRedirectServer(t, http.StatusTemporaryRedirect, final.URL)
	defer hop2.Close()
	hop1 := newRedirectServer(t, http.StatusTemporaryRedirect, hop2.URL)
	defer hop1.Close()

	client, err := newTestClient()
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Post(hop1.URL, WithBinary([]byte("replay-me")))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if result.StatusCode() != http.StatusOK {
		t.Fatalf("Expected status 200 after two 307 hops, got %d", result.StatusCode())
	}
	want := "POST|replay-me|application/octet-stream"
	if result.Body() != want {
		t.Errorf("Body not replayed on every hop:\n got: %s\nwant: %s", result.Body(), want)
	}
	// RedirectChain records the URL left at each hop: start + hop2, so two
	// hops yield two entries (the final URL is not part of the chain).
	if result.Meta.RedirectCount != 2 || len(result.Meta.RedirectChain) != 2 {
		t.Errorf("Expected 2 redirects and chain length 2, got count=%d chain=%d",
			result.Meta.RedirectCount, len(result.Meta.RedirectChain))
	}
}

func TestRedirect_307RawReaderNotFollowedWithoutRetries(t *testing.T) {
	t.Parallel()

	final := newEchoServer(t)
	defer final.Close()
	redirector := newRedirectServer(t, http.StatusTemporaryRedirect, final.URL)
	defer redirector.Close()

	// testConfig has MaxRetries=0: the fast path passes the io.Reader through
	// unbuffered, so GetBody cannot be set — matching net/http, the 307 is
	// returned unfollowed instead of silently dropping the body.
	client, err := newTestClient()
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Post(redirector.URL, WithBody(strings.NewReader("streaming body")))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if result.StatusCode() != http.StatusTemporaryRedirect {
		t.Fatalf("Expected unfollowed 307 (no replayable body, MaxRetries=0), got %d", result.StatusCode())
	}
	if !result.IsRedirect() {
		t.Error("Expected IsRedirect() to be true for the returned 307")
	}
	if result.Meta.RedirectCount != 0 {
		t.Errorf("Expected 0 followed redirects, got %d", result.Meta.RedirectCount)
	}
}

func TestRedirect_307RawReaderFollowedWhenRetriesBufferBody(t *testing.T) {
	t.Parallel()

	final := newEchoServer(t)
	defer final.Close()
	redirector := newRedirectServer(t, http.StatusTemporaryRedirect, final.URL)
	defer redirector.Close()

	// MaxRetries > 0 makes executeWithRetry buffer io.Reader bodies to []byte
	// for replay across attempts; the same bytes make the body replayable
	// across 307/308 hops. POST is non-idempotent, so buffering only kicks in
	// with retries explicitly enabled for it.
	config := testConfig()
	config.Retry.MaxRetries = 1
	config.Retry.RetryNonIdempotent = true
	client, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Post(redirector.URL, WithBody(strings.NewReader("streaming body")))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if result.StatusCode() != http.StatusOK {
		t.Fatalf("Expected status 200 after 307 (body buffered for retries), got %d (body: %s)",
			result.StatusCode(), result.Body())
	}
	want := "POST|streaming body|application/octet-stream"
	if result.Body() != want {
		t.Errorf("Buffered stream body not preserved across 307:\n got: %s\nwant: %s", result.Body(), want)
	}
}

func TestRedirect_307CrossOriginStripsCredentialsKeepsBody(t *testing.T) {
	t.Parallel()

	// One server, two hostnames: the request targets 127.0.0.1, the redirect
	// target uses "localhost" — a different Host, so the hop is cross-origin.
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) // best-effort test read
		if got := r.Header.Get("Authorization"); got != "" {
			http.Error(w, "Authorization leaked across origins: "+got, http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("body=" + string(body))) // best-effort test response
	}))
	defer final.Close()

	target := strings.Replace(final.URL, "127.0.0.1", "localhost", 1)
	redirector := newRedirectServer(t, http.StatusTemporaryRedirect, target)
	defer redirector.Close()

	client, err := newTestClient()
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Post(redirector.URL,
		WithBearerToken("secret-token"),
		WithJSON(map[string]string{"ping": "pong"}),
	)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if result.StatusCode() != http.StatusOK {
		t.Fatalf("Expected status 200 after cross-origin 307, got %d (body: %s)", result.StatusCode(), result.Body())
	}
	if want := `body={"ping":"pong"}`; result.Body() != want {
		t.Errorf("Body not preserved across cross-origin 307:\n got: %s\nwant: %s", result.Body(), want)
	}
}
