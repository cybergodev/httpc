package httpc

import (
	"testing"
	"time"
)

func TestCalculateMaxRetries(t *testing.T) {
	tests := []struct {
		name             string
		retryMaxRetries  int
		proxyPool        []string
		rotateOnStatus   []int
		expectedRetries  int
	}{
		{
			name:            "no proxy pool, no rotation",
			retryMaxRetries: 3,
			proxyPool:       nil,
			rotateOnStatus:  nil,
			expectedRetries: 3,
		},
		{
			name:            "proxy pool without rotation — no adjustment",
			retryMaxRetries: 2,
			proxyPool:       []string{"http://p1:8080", "http://p2:8080", "http://p3:8080"},
			rotateOnStatus:  nil,
			expectedRetries: 2,
		},
		{
			name:            "rotation with 2 proxies, MaxRetries=3 — no change needed",
			retryMaxRetries: 3,
			proxyPool:       []string{"http://p1:8080", "http://p2:8080"},
			rotateOnStatus:  []int{403},
			expectedRetries: 3, // 3 >= 2-1=1, no adjustment
		},
		{
			name:            "rotation with 5 proxies, MaxRetries=2 — raised to 4",
			retryMaxRetries: 2,
			proxyPool: []string{
				"http://p1:8080", "http://p2:8080", "http://p3:8080",
				"http://p4:8080", "http://p5:8080",
			},
			rotateOnStatus:  []int{403},
			expectedRetries: 4, // 5-1=4 > 2, raised
		},
		{
			name:            "rotation with 12 proxies — capped at maxRetryAttempts(10)",
			retryMaxRetries: 1,
			proxyPool: []string{
				"http://p1:8080", "http://p2:8080", "http://p3:8080",
				"http://p4:8080", "http://p5:8080", "http://p6:8080",
				"http://p7:8080", "http://p8:8080", "http://p9:8080",
				"http://p10:8080", "http://p11:8080", "http://p12:8080",
			},
			rotateOnStatus:  []int{403},
			expectedRetries: 10, // capped
		},
		{
			name:            "single proxy with rotation — no adjustment",
			retryMaxRetries: 3,
			proxyPool:       []string{"http://p1:8080"},
			rotateOnStatus:  []int{403},
			expectedRetries: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Retry.MaxRetries = tt.retryMaxRetries
			cfg.Retry.Delay = 50 * time.Millisecond
			cfg.Connection.ProxyPool = tt.proxyPool
			cfg.Connection.ProxyRotateOnStatus = tt.rotateOnStatus

			got := calculateMaxRetries(&cfg)
			if got != tt.expectedRetries {
				t.Errorf("calculateMaxRetries() = %d, want %d", got, tt.expectedRetries)
			}
		})
	}
}
