package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestDoHBodyDrain verifies that the DoH resolver drains the response body even
// on error/invalid responses, allowing the HTTP transport to reuse connections.
// This exercises the fix for the body-drain connection-leak issue across two
// failure modes: HTTP error status and malformed JSON body.
func TestDoHBodyDrain(t *testing.T) {
	tests := []struct {
		name             string
		firstStatus      int
		firstBody        string
		firstContentType string
	}{
		{
			name:             "HTTP 500 drains body for connection reuse",
			firstStatus:      http.StatusInternalServerError,
			firstBody:        "internal server error",
			firstContentType: "",
		},
		{
			name:             "invalid JSON drains body for connection reuse",
			firstStatus:      http.StatusOK,
			firstBody:        "not valid json at all",
			firstContentType: "application/dns-json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requestCount atomic.Int32
			firstRequest := atomic.Bool{}
			firstRequest.Store(true)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestCount.Add(1)

				if firstRequest.Load() {
					firstRequest.Store(false)
					if tt.firstContentType != "" {
						w.Header().Set("Content-Type", tt.firstContentType)
					}
					w.WriteHeader(tt.firstStatus)
					_, _ = w.Write([]byte(tt.firstBody)) // best-effort test response
					return
				}

				// Valid JSON response on second request
				w.Header().Set("Content-Type", "application/dns-json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"name":"test.local","type":1,"data":"1.2.3.4"}]}`)) // best-effort test response
			}))
			defer server.Close()

			provider := &dohProvider{
				Name:     "test",
				Template: server.URL + "/dns-query?name={name}&type=A",
				Priority: 1,
			}

			resolver := NewDoHResolver([]*dohProvider{provider}, 5*time.Minute)
			defer resolver.Close()

			// First request fails (error status or invalid JSON) → body must be drained.
			_, _ = resolver.LookupIPAddr(context.Background(), "test.local")

			// Second request should reach the server again and get a valid response.
			ips, err := resolver.LookupIPAddr(context.Background(), "test.local")
			if err != nil {
				t.Fatalf("Second request should succeed: %v", err)
			}
			if len(ips) == 0 {
				t.Fatal("Expected at least one IP address")
			}

			if requestCount.Load() < 2 {
				t.Errorf("Expected at least 2 server requests, got %d", requestCount.Load())
			}
		})
	}
}
