package httpc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cybergodev/httpc/internal/engine"
)

// TestMiddlewareReturningNilNilYieldsError guards the facade's defensive
// fallback: a middleware that returns neither a response nor an error must
// surface as an error, not as a nil Result that nil-safe accessors would
// report as a status-0 "success".
func TestMiddlewareReturningNilNilYieldsError(t *testing.T) {
	broken := MiddlewareFunc(func(next Handler) Handler {
		return func(ctx context.Context, req RequestMutator) (ResponseMutator, error) {
			return nil, nil // contract violation
		}
	})

	cfg := TestingConfig()
	cfg.Middleware.Middlewares = []MiddlewareFunc{broken}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	result, err := client.Get(srv.URL)
	if err == nil {
		t.Fatalf("expected error for (nil, nil) middleware result, got result=%v", result)
	}
	if result != nil {
		t.Fatalf("expected nil result, got %v", result)
	}
}

// TestQueryValueLengthParity pins the documented invariant of queryValueLength:
// it must return exactly len(FormatQueryParam(v)) for every supported type.
// The MAINTENANCE note in public_options.go requires new types to be added to
// all three formatting sites; this covers the public-package side.
func TestQueryValueLengthParity(t *testing.T) {
	type stringer string
	cases := []any{
		nil, "", "hello", true, false,
		0, 42, -7, int64(1 << 40), int32(-5), uint(9), uint64(1 << 41), uint32(77),
		2.5, float32(1.5), stringer("custom"), struct{ X int }{X: 1},
	}
	for _, v := range cases {
		if got, want := queryValueLength(v), len(engine.FormatQueryParam(v)); got != want {
			t.Errorf("queryValueLength(%#v) = %d, want %d", v, got, want)
		}
	}
}

// TestBuildURLCaseInsensitiveScheme guards the case-insensitive absolute-URL
// detection in DomainClient.buildURL: "HTTP://host" is an absolute URL per
// url.Parse (which lowercases schemes), not a relative path to be joined.
func TestBuildURLCaseInsensitiveScheme(t *testing.T) {
	dc, err := NewDomain("https://api.example.com/v1", TestingConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	impl := dc.(*DomainClient)

	for _, abs := range []string{
		"HTTP://other.example.com/x",
		"http://other.example.com/x",
		"https://other.example.com/x",
		"HTTPS://other.example.com/x",
	} {
		got, err := impl.buildURL(abs)
		if err != nil {
			t.Fatalf("buildURL(%q): %v", abs, err)
		}
		if got != abs {
			t.Errorf("buildURL(%q) = %q, want the URL used as-is", abs, got)
		}
	}

	// Relative paths must still join onto the base path.
	got, err := impl.buildURL("users")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://api.example.com/v1/users"; got != want {
		t.Errorf("buildURL(users) = %q, want %q", got, want)
	}
}

// TestAuditMiddlewareContextValueSources covers both context sources for
// SourceIP/UserID: the ctx passed to Client.Request and, since the audit
// context-value fix, the request context set via WithContext.
func TestAuditMiddlewareContextValueSources(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	newAuditedClient := func(t *testing.T) (*clientImpl, *[]AuditEvent) {
		events := []AuditEvent{}
		cfg := TestingConfig()
		cfg.Middleware.Middlewares = []MiddlewareFunc{AuditMiddleware(&AuditConfig{
			OnAudit: func(e AuditEvent) { events = append(events, e) },
		})}
		client, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client.(*clientImpl), &events
	}

	t.Run("request ctx", func(t *testing.T) {
		client, events := newAuditedClient(t)
		ctx := context.WithValue(context.Background(), SourceIPKey, "10.0.0.1")
		if _, err := client.Request(ctx, "GET", srv.URL); err != nil {
			t.Fatal(err)
		}
		if got := (*events)[0].SourceIP; got != "10.0.0.1" {
			t.Fatalf("SourceIP = %q, want 10.0.0.1", got)
		}
	})

	t.Run("WithContext option", func(t *testing.T) {
		client, events := newAuditedClient(t)
		ctx := context.WithValue(context.Background(), UserIDKey, "u-123")
		if _, err := client.Get(srv.URL, WithContext(ctx)); err != nil {
			t.Fatal(err)
		}
		if got := (*events)[0].UserID; got != "u-123" {
			t.Fatalf("UserID = %q, want u-123 (WithContext values must reach audit)", got)
		}
	})
}

// TestCaptureFromOptionsSkipsInvalidCookies guards the ValidateCookie gate in
// captureFromOptions: cookies set by raw options that bypass WithCookie
// validation must not enter the session store.
func TestCaptureFromOptionsSkipsInvalidCookies(t *testing.T) {
	sm, err := NewSessionManagerDefault()
	if err != nil {
		t.Fatal(err)
	}
	raw := RequestOption(func(r *engine.Request) error {
		r.SetCookies([]http.Cookie{
			{Name: "good", Value: "fine"},
			{Name: "bad;name", Value: "invalid"}, // control/separator chars in name
		})
		return nil
	})
	sm.captureFromOptions([]RequestOption{raw})

	if got := sm.GetCookie("good"); got == nil {
		t.Error("valid cookie from option should be captured")
	}
	if got := sm.GetCookie("bad;name"); got != nil {
		t.Errorf("invalid cookie should be rejected, got %v", got)
	}
}

// TestBuildXMLWithCharsetContentType guards parameter-tolerant XML
// Content-Type detection: a struct body with an explicit
// "application/xml; charset=utf-8" header must be XML-marshaled, not
// JSON-marshaled under an XML header.
func TestBuildXMLWithCharsetContentType(t *testing.T) {
	var gotContentType string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		buf := make([]byte, 128)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
	}))
	defer srv.Close()

	type payload struct {
		XMLName struct{} `xml:"root"`
		Name    string   `xml:"name"`
	}

	client, err := New(TestingConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.Post(srv.URL,
		WithBody(payload{Name: "x"}, BodyXML),
		WithHeader("Content-Type", "application/xml; charset=utf-8"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := "application/xml; charset=utf-8"; gotContentType != want {
		t.Fatalf("Content-Type = %q, want %q", gotContentType, want)
	}
	// XML marshal produces "<root><name>x</name></root>" (plus the standard
	// xml header); JSON would produce {"name":"x"}.
	if !strings.Contains(gotBody, "<root>") || !strings.Contains(gotBody, "<name>x</name>") {
		t.Fatalf("body = %q, want XML-marshaled payload", gotBody)
	}
}
