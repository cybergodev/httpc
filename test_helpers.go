package httpc

import (
	"crypto/tls"
	"time"
)

// testConfig returns a configuration suitable for testing with localhost servers.
// SECURITY: This configuration allows private IPs and skips TLS verification.
// DO NOT use in production.
func testConfig() Config {
	return Config{
		Timeouts: TimeoutConfig{
			Request:        60 * time.Second,
			Dial:           10 * time.Second,
			TLSHandshake:   10 * time.Second,
			ResponseHeader: 30 * time.Second,
			IdleConn:       90 * time.Second,
		},
		Connection: ConnectionConfig{
			MaxIdleConns:    200,
			MaxConnsPerHost: 200,
			EnableHTTP2:     false,
			EnableCookies:   true,
		},
		Security: SecurityConfig{
			InsecureSkipVerify:  true,
			MaxResponseBodySize: 10 * 1024 * 1024,
			AllowPrivateIPs:     true,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Retry: RetryConfig{
			MaxRetries:    0,
			Delay:         100 * time.Millisecond,
			BackoffFactor: 2.0,
		},
		Middleware: MiddlewareConfig{},
		Defaults: RequestDefaults{
			UserAgent:       "httpc-test/1.0",
			Headers:         make(map[string]string),
			FollowRedirects: true,
			MaxRedirects:    10,
		},
	}
}

func newTestClient() (Client, error) {
	return New(testConfig())
}
