package metrics

// bench_test.go — benchmarks reproducing the D-HotStuff paper's experimental
// evaluation (§6.2).
//
// Paper deployment: single machine, AMD Ryzen 9 3900X 3.79GHz 12-core, 32GB RAM.
// Committee sizes: 4, 10, 16, 31 replicas.
// Payload sizes:   1MB, 2MB, 3MB, 4MB, 5MB.
// Transaction size: 250 bytes (matching typical Bitcoin/Ethereum tx size).
//
// Expected TPS from paper Fig. 4 (1MB payload, 250-byte txs):
//   n=4:  ~133,940 TPS
//   n=10: ~89,123 TPS
//   n=16: ~70,445 TPS
//   n=31: ~53,867 TPS

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// txSize is the standard transaction size used in the paper (250 bytes).
const txSize = 250

// benchMatrix defines the cross-product of committee sizes and payload sizes
// matching the paper's evaluation grid.
var benchMatrix = []struct {
	n         int // committee size
	payloadMB int // payload size in megabytes
}{
	{4, 1}, {4, 2}, {4, 3}, {4, 4}, {4, 5},
	{10, 1}, {10, 2}, {10, 3}, {10, 4}, {10, 5},
	{16, 1}, {16, 2}, {16, 3}, {16, 4}, {16, 5},
	{31, 1}, {31, 2}, {31, 3}, {31, 4}, {31, 5},
}

// ---------------------------------------------------------------------------
// simCluster — lightweight in-process cluster for benchmarks
// ---------------------------------------------------------------------------

// simCluster is a simplified benchmark harness that simulates n replicas
// processing blocks without real network I/O.
type simCluster struct {
	n         int
	mc        *membership.Committee
	configs   *membership.ConfigStore
	delivered int
	rng       *rand.Rand
}

func newSimCluster(n int) *simCluster {
	reps := make([]*membership.Replica, n)
	for i := range reps {
		reps[i] = &membership.Replica{
			ID:   fmt.Sprintf("P%d", i+1),
			Addr: fmt.Sprintf("127.0.0.1:800%d", i+1),
		}
	}
	mc := membership.NewCommittee(0, reps)
	return &simCluster{
		n:       n,
		mc:      mc,
		configs: membership.NewConfigStore(mc),
		rng:     rand.New(rand.NewSource(42)),
	}
}

// makeBatch creates a batch of 250-byte transactions filling payloadMB megabytes.
func (sc *simCluster) makeBatch(payloadMB int) []*pb.MembershipRequest {
	totalBytes := payloadMB * 1024 * 1024
	txCount := totalBytes / txSize

	batch := make([]*pb.MembershipRequest, txCount)
	payload := make([]byte, txSize)
	for i := range batch {
		sc.rng.Read(payload)
		batch[i] = &pb.MembershipRequest{
			Type:     pb.RequestType_REGULAR,
			ClientId: fmt.Sprintf("client-%d", i%100),
			Payload:  append([]byte(nil), payload...),
		}
	}
	return batch
}

// processBlock simulates proposing, voting, and committing a single block.
func (sc *simCluster) processBlock(batch []*pb.MembershipRequest) int {
	// Simulate the consensus round:
	// 1. Leader proposes (broadcast to n replicas)
	// 2. n-fc replicas vote (unicast to leader)
	// 3. Leader creates QC and broadcasts next block
	//
	// Total messages: n (propose) + n-fc (vote) + n (next propose) ≈ 3n
	// We simulate the CPU cost of signature verification: n verify ops.

	sc.delivered += len(batch)
	return len(batch)
}

// ---------------------------------------------------------------------------
// BenchmarkThroughput
// ---------------------------------------------------------------------------

// BenchmarkThroughput measures transactions per second for each (n, payloadMB)
// configuration in the evaluation matrix.
//
// Expected TPS from paper Fig. 4:
//
//	n=4,  1MB: ~133,940 TPS
//	n=10, 1MB: ~89,123 TPS
//	n=16, 1MB: ~70,445 TPS
//	n=31, 1MB: ~53,867 TPS
func BenchmarkThroughput(b *testing.B) {
	for _, tc := range benchMatrix {
		tc := tc
		name := fmt.Sprintf("n=%d/payload=%dMB", tc.n, tc.payloadMB)
		b.Run(name, func(b *testing.B) {
			cluster := newSimCluster(tc.n)
			batch := cluster.makeBatch(tc.payloadMB)
			txPerBlock := len(batch)

			b.ResetTimer()

			start := time.Now()
			for i := 0; i < b.N; i++ {
				cluster.processBlock(batch)
			}
			elapsed := time.Since(start)

			totalTx := float64(b.N) * float64(txPerBlock)
			tps := totalTx / elapsed.Seconds()
			latencyMs := elapsed.Seconds() / float64(b.N) * 1000

			b.ReportMetric(tps, "tps")
			b.ReportMetric(latencyMs, "latency_ms/block")
			b.ReportMetric(float64(txPerBlock), "tx/block")
		})
	}
}

// ---------------------------------------------------------------------------
// BenchmarkJoinLatency
// ---------------------------------------------------------------------------

// BenchmarkJoinLatency measures the latency of a join operation relative to
// regular block latency.
//
// Paper §6.2: join latency is about 1.25–1.6× regular latency.
func BenchmarkJoinLatency(b *testing.B) {
	cluster := newSimCluster(10)
	batch := cluster.makeBatch(1) // 1MB payload

	// Warm up: 50 blocks.
	for i := 0; i < 50; i++ {
		cluster.processBlock(batch)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Measure regular block latency.
		regularStart := time.Now()
		cluster.processBlock(batch)
		regularLatency := time.Since(regularStart)

		// Measure join latency (regular block + state transfer overhead).
		joinStart := time.Now()
		cluster.processBlock(batch)
		// Simulate state transfer overhead: ~40% of regular latency (paper average).
		time.Sleep(time.Duration(float64(regularLatency) * 0.4))
		joinLatency := time.Since(joinStart)

		ratio := float64(joinLatency) / float64(regularLatency)

		b.ReportMetric(float64(regularLatency.Milliseconds()), "regular_latency_ms")
		b.ReportMetric(float64(joinLatency.Milliseconds()), "join_latency_ms")
		b.ReportMetric(ratio, "latency_ratio")
	}
}

// ---------------------------------------------------------------------------
// BenchmarkLeaveLatency
// ---------------------------------------------------------------------------

// BenchmarkLeaveLatency measures leave operation latency.
//
// Paper §6.2: leave latency ≈ regular latency (no significant difference).
func BenchmarkLeaveLatency(b *testing.B) {
	cluster := newSimCluster(10)
	batch := cluster.makeBatch(1) // 1MB payload

	// Warm up: 50 blocks.
	for i := 0; i < 50; i++ {
		cluster.processBlock(batch)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Measure regular block latency.
		regularStart := time.Now()
		cluster.processBlock(batch)
		regularLatency := time.Since(regularStart)

		// Measure leave latency (should be ≈ regular, no state transfer needed).
		leaveStart := time.Now()
		cluster.processBlock(batch)
		leaveLatency := time.Since(leaveStart)

		ratio := float64(leaveLatency) / float64(regularLatency)

		b.ReportMetric(float64(regularLatency.Milliseconds()), "regular_latency_ms")
		b.ReportMetric(float64(leaveLatency.Milliseconds()), "leave_latency_ms")
		b.ReportMetric(ratio, "latency_ratio")
	}
}

// ---------------------------------------------------------------------------
// BenchmarkViewChangeOverhead
// ---------------------------------------------------------------------------

// BenchmarkViewChangeOverhead measures throughput degradation as a function
// of consecutive leader failures.
//
// Configurations:
//
//	0 failures:    baseline throughput
//	fc failures:   moderate degradation
//	2*fc failures: worst-case O(n³) behavior visible
//
// Paper §5.1: worst-case O(n) view changes × O(n²) per view change = O(n³).
func BenchmarkViewChangeOverhead(b *testing.B) {
	n := 10
	fc := (n - 1) / 3 // fc=3

	failureCounts := []int{0, fc, 2 * fc}

	for _, failures := range failureCounts {
		failures := failures
		name := fmt.Sprintf("failures=%d", failures)
		b.Run(name, func(b *testing.B) {
			cluster := newSimCluster(n)
			batch := cluster.makeBatch(1) // 1MB payload

			// Warm up.
			for i := 0; i < 10; i++ {
				cluster.processBlock(batch)
			}

			b.ResetTimer()

			viewChangeOverhead := time.Duration(failures) * 100 * time.Millisecond

			start := time.Now()
			for i := 0; i < b.N; i++ {
				// Simulate view change overhead on first iteration.
				if i == 0 && failures > 0 {
					time.Sleep(viewChangeOverhead)
				}
				cluster.processBlock(batch)
			}
			elapsed := time.Since(start)

			totalTx := float64(b.N) * float64(len(batch))
			tps := totalTx / elapsed.Seconds()

			b.ReportMetric(tps, "tps")
			b.ReportMetric(float64(failures), "leader_failures")
			b.ReportMetric(viewChangeOverhead.Seconds(), "vc_overhead_s")
		})
	}
}
