package engine

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMetrics_recordRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		success bool
		latency int64
	}{
		{"SuccessZeroLatency", true, 0},
		{"SuccessNonZeroLatency", true, 1000000}, // 1ms in ns
		{"FailureNonZeroLatency", false, 500000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &metrics{}
			m.recordRequest(tt.latency, tt.success)

			snap := m.snapshot()
			if snap.totalRequests != 1 {
				t.Errorf("totalRequests = %d, want 1", snap.totalRequests)
			}
			if tt.success && snap.successfulRequests != 1 {
				t.Errorf("successfulRequests = %d, want 1", snap.successfulRequests)
			}
			if !tt.success && snap.failedRequests != 1 {
				t.Errorf("failedRequests = %d, want 1", snap.failedRequests)
			}
		})
	}
}

func TestMetrics_snapshot(t *testing.T) {
	m := &metrics{}
	m.recordRequest(100, true)
	m.recordRequest(200, true)
	m.recordRequest(300, false)

	snap := m.snapshot()
	if snap.totalRequests != 3 {
		t.Errorf("totalRequests = %d, want 3", snap.totalRequests)
	}
	if snap.successfulRequests != 2 {
		t.Errorf("successfulRequests = %d, want 2", snap.successfulRequests)
	}
	if snap.failedRequests != 1 {
		t.Errorf("failedRequests = %d, want 1", snap.failedRequests)
	}
	if snap.averageLatency == 0 {
		t.Error("averageLatency should be non-zero after recording requests")
	}
}

func TestMetrics_reset(t *testing.T) {
	m := &metrics{}
	m.recordRequest(100, true)
	m.recordRequest(200, false)

	m.reset()

	snap := m.snapshot()
	if snap.totalRequests != 0 {
		t.Errorf("totalRequests = %d, want 0 after reset", snap.totalRequests)
	}
	if snap.successfulRequests != 0 {
		t.Errorf("successfulRequests = %d, want 0 after reset", snap.successfulRequests)
	}
	if snap.failedRequests != 0 {
		t.Errorf("failedRequests = %d, want 0 after reset", snap.failedRequests)
	}
	if snap.averageLatency != 0 {
		t.Errorf("averageLatency = %v, want 0 after reset", snap.averageLatency)
	}
}

func TestMetrics_getHealthStatus(t *testing.T) {
	tests := []struct {
		name        string
		successes   int64
		failures    int64
		wantHealthy bool
		wantRate    float64
	}{
		{"NoRequests_Healthy", 0, 0, true, 0.0},
		{"AllSuccess_Healthy", 10, 0, true, 0.0},
		{"LowErrorRate_Healthy", 19, 1, true, 0.05},
		{"HighErrorRate_Unhealthy", 5, 50, false, 0.9090909090909091},
		{"AllFailures_Unhealthy", 0, 10, false, 1.0},
		{"Boundary10Pct_Unhealthy", 9, 1, false, 0.1}, // error rate == 0.1 means NOT healthy (< 0.1)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &metrics{}
			for i := int64(0); i < tt.successes; i++ {
				m.recordRequest(100, true)
			}
			for i := int64(0); i < tt.failures; i++ {
				m.recordRequest(100, false)
			}

			status := m.getHealthStatus()
			if status.healthy != tt.wantHealthy {
				t.Errorf("healthy = %v, want %v (error rate = %f)", status.healthy, tt.wantHealthy, status.errorRate)
			}
			total := tt.successes + tt.failures
			if status.totalRequests != total {
				t.Errorf("totalRequests = %d, want %d", status.totalRequests, total)
			}
			if status.successfulRequests != tt.successes {
				t.Errorf("successfulRequests = %d, want %d", status.successfulRequests, tt.successes)
			}
			if status.failedRequests != tt.failures {
				t.Errorf("failedRequests = %d, want %d", status.failedRequests, tt.failures)
			}
		})
	}
}

func TestMetrics_Concurrent(t *testing.T) {
	m := &metrics{}
	var wg sync.WaitGroup
	const goroutines = 100
	const opsPerGoroutine = 100

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(success bool) {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				m.recordRequest(int64(i*100), success)
			}
		}(g%2 == 0)
	}
	wg.Wait()

	snap := m.snapshot()
	expected := int64(goroutines * opsPerGoroutine)
	if snap.totalRequests != expected {
		t.Errorf("totalRequests = %d, want %d", snap.totalRequests, expected)
	}

	// Half the goroutines record success (even-indexed), half record failure (odd-indexed)
	expectedEach := int64(goroutines/2) * opsPerGoroutine
	if snap.successfulRequests != expectedEach {
		t.Errorf("successfulRequests = %d, want %d", snap.successfulRequests, expectedEach)
	}
	if snap.failedRequests != expectedEach {
		t.Errorf("failedRequests = %d, want %d", snap.failedRequests, expectedEach)
	}
}

func TestMetrics_ConcurrentReadAndWrite(t *testing.T) {
	m := &metrics{}
	const duration = 100 * time.Millisecond

	var stop int32
	var wg sync.WaitGroup

	// Writers
	wg.Add(1)
	go func() {
		defer wg.Done()
		for atomic.LoadInt32(&stop) == 0 {
			m.recordRequest(1000, true)
		}
	}()

	// Readers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for atomic.LoadInt32(&stop) == 0 {
				snap := m.snapshot()
				_ = snap.totalRequests
				_ = m.getHealthStatus()
				_ = m.isHealthy()
			}
		}()
	}

	time.Sleep(duration)
	atomic.StoreInt32(&stop, 1)
	wg.Wait()

	// The writer ran for the full duration, so counters must be positive.
	final := m.snapshot()
	if final.totalRequests <= 0 || final.successfulRequests <= 0 {
		t.Errorf("after concurrent load: total=%d success=%d, want both > 0",
			final.totalRequests, final.successfulRequests)
	}
}
