// Package metrics defines Prometheus metrics for the D-HotStuff consensus
// protocol, matching the evaluation metrics from the paper §6.2.
//
// Primary metrics:
//
//   - Latency: time from client submit to receiving fc+1 consistent replies
//     (paper §6.2, Table 1).
//   - Throughput: average delivered transactions per second per replica
//     (paper §6.2, Fig. 4).
//
// All metrics are registered via promauto and are automatically collected
// by the default Prometheus registry.
package metrics

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "dhotstuff"

// TPS tracks the rolling throughput — transactions delivered per second.
//
// Paper §6.2 expected ranges (1MB payload, 250-byte txs):
//
//	n=4:  ~133,940 TPS
//	n=10: ~89,123 TPS
//	n=16: ~70,445 TPS
//	n=31: ~53,867 TPS
var TPS = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: namespace,
	Name:      "tps",
	Help:      "Transactions delivered per second (rolling 1s window).",
})

// LatencySeconds measures request latency from client submission to fc+1
// consistent replies.  Labeled by request_type: "regular", "join", or "leave".
//
// Buckets cover the paper's observed range:
//
//	regular latency: 0.136s (n=4) to 6.572s (n=31, 5MB payload)
//	join latency:    ~1.25–1.6× regular
//	leave latency:   ≈ regular
var LatencySeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: namespace,
	Name:      "latency_seconds",
	Help:      "Request latency from client submit to fc+1 consistent replies.",
	Buckets:   []float64{0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0},
}, []string{"request_type"})

// ViewChangesTotal counts the total number of view changes since startup.
//
// In the worst case, O(n) consecutive view changes occur before progress
// (paper §5.1), costing O(n³) total authenticators.
var ViewChangesTotal = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: namespace,
	Name:      "view_changes_total",
	Help:      "Total view changes since startup.",
})

// ActiveCommitteeSize tracks the current number of replicas in the committee.
//
// Changes on every membership-add or membership-remove operation.
var ActiveCommitteeSize = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: namespace,
	Name:      "active_committee_size",
	Help:      "Number of replicas in current committee.",
})

// ConfigNumber tracks the current configuration number (c).
//
// Incremented by config_store.go Install() on each membership change.
var ConfigNumber = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: namespace,
	Name:      "config_number",
	Help:      "Current configuration number (c).",
})

// JoinSyncDurationSeconds measures the time for a joining replica to
// synchronize the full execution history from existing members.
//
// Paper Fig. 3 shows linear growth with block count; snapshots are
// recommended to bound this in production.
var JoinSyncDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
	Namespace: namespace,
	Name:      "join_sync_duration_seconds",
	Help:      "Time for joining replica to sync historical state.",
	Buckets:   []float64{0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0},
})

// BlockHeight tracks the highest committed block height.
var BlockHeight = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: namespace,
	Name:      "block_height",
	Help:      "Highest committed block height.",
})

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------

// ObserveRequestLatency records the latency of a completed request.
//
// reqType must be one of: "regular", "join", "leave".
// start is the time.Time when the client submitted the request.
//
// Example:
//
//	start := time.Now()
//	// ... process request ...
//	metrics.ObserveRequestLatency("regular", start)
func ObserveRequestLatency(reqType string, start time.Time) {
	LatencySeconds.WithLabelValues(reqType).Observe(time.Since(start).Seconds())
}

// StartMetricsServer starts an HTTP server exposing Prometheus metrics
// on the given port at /metrics.
//
// This function blocks; call it in a goroutine:
//
//	go metrics.StartMetricsServer(9090)
func StartMetricsServer(port int) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	addr := fmt.Sprintf(":%d", port)
	log.Printf("metrics: serving Prometheus metrics on %s/metrics", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("metrics: ListenAndServe failed: %v", err)
	}
}
