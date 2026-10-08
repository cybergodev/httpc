package engine

import (
	"sync/atomic"
	"time"
)

// metricsSnapshot represents a point-in-time snapshot of client metrics.
type metricsSnapshot struct {
	totalRequests      int64
	successfulRequests int64
	failedRequests     int64
	averageLatency     time.Duration
}

// healthStatus represents basic health metrics for the client.
type healthStatus struct {
	healthy            bool
	totalRequests      int64
	successfulRequests int64
	failedRequests     int64
	averageLatency     time.Duration
	errorRate          float64
}

// metrics collects and tracks HTTP client performance metrics.
// All methods are safe for concurrent use.
type metrics struct {
	totalRequests      atomic.Int64
	successfulRequests atomic.Int64
	failedRequests     atomic.Int64
	averageLatency     atomic.Int64 // stored as nanoseconds
}

// recordRequest records the result of a single request.
// It updates the request counters and rolling average latency.
func (m *metrics) recordRequest(latencyNs int64, success bool) {
	m.totalRequests.Add(1)
	if success {
		m.successfulRequests.Add(1)
	} else {
		m.failedRequests.Add(1)
	}
	m.updateLatency(latencyNs)
}

// updateLatency updates the rolling average latency using CAS for lock-free updates.
func (m *metrics) updateLatency(latency int64) {
	for {
		current := m.averageLatency.Load()
		newVal := latency
		if current != 0 {
			newVal = (current*9 + latency) / 10
		}
		if m.averageLatency.CompareAndSwap(current, newVal) {
			break
		}
	}
}

// snapshot returns a point-in-time copy of the current metrics.
// Each field is individually atomic, but the snapshot is not transactionally
// consistent — concurrent calls may cause total != success + failed.
func (m *metrics) snapshot() metricsSnapshot {
	return metricsSnapshot{
		totalRequests:      m.totalRequests.Load(),
		successfulRequests: m.successfulRequests.Load(),
		failedRequests:     m.failedRequests.Load(),
		averageLatency:     time.Duration(m.averageLatency.Load()),
	}
}

// reset resets all metrics to zero.
// Currently exercised only by tests.
func (m *metrics) reset() {
	m.totalRequests.Store(0)
	m.successfulRequests.Store(0)
	m.failedRequests.Store(0)
	m.averageLatency.Store(0)
}

// getHealthStatus returns the current health status of the client.
// A client is considered healthy if its error rate is below 10%.
func (m *metrics) getHealthStatus() healthStatus {
	total := m.totalRequests.Load()
	failed := m.failedRequests.Load()
	success := m.successfulRequests.Load()
	avgLatNs := m.averageLatency.Load()

	var errorRate float64
	if total > 0 {
		errorRate = float64(failed) / float64(total)
	}

	healthy := errorRate < 0.1

	return healthStatus{
		healthy:            healthy,
		totalRequests:      total,
		successfulRequests: success,
		failedRequests:     failed,
		averageLatency:     time.Duration(avgLatNs),
		errorRate:          errorRate,
	}
}

// isHealthy returns true if the client is healthy (error rate < 10%).
func (m *metrics) isHealthy() bool {
	return m.getHealthStatus().healthy
}
