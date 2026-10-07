package httpc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The tests in this file cover 307/308 redirect following for requests that
// carry a body. net/http only replays a body across such a hop when
// Request.GetBody is set, so these tests pin the engine's replay sources:
// string/[]byte/JSON/XML/multipart bodies are replayable; a raw io.Reader is
// replayable only when the retry path has buffered it (MaxRetries > 0).

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
	defer client.Close()

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
	defer client.Close()

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
	defer client.Close()

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
	defer client.Close()

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
	defer client.Close()

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
	defer client.Close()

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
	defer client.Close()

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
