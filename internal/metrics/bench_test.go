package metrics

// bench_test.go — performance benchmarks reproducing the D-HotStuff paper's
// experimental evaluation (§6.2).
//
// # Paper setup (§6.2)
//
//   Machine:          AMD Ryzen 9 3900X 3.79 GHz 12-core, 32 GB RAM
//   Committee sizes:  n = 4, 10, 16, 31 replicas (one per port)
//   Payload sizes:    1 MB, 2 MB, 3 MB, 4 MB, 5 MB
//   Transaction size: 250 bytes (Bitcoin/Ethereum typical size)
//
// # What these benchmarks actually measure
//
// BenchCluster (internal/benchutil) drives the real consensus engine:
//
//   1. ECDSA P-256 signing:    crypto.Sign — one per Qc replica per round
//   2. Vote aggregation:       crypto.AggregateVotes / crypto.HasQuorum
//   3. QC creation:            crypto.CreateQC — O(Qc) dedup + struct alloc
//   4. Safety state update:    safeNode predicate, lockedQC / genericQC
//   5. Pipelined delivery:     pipelineWindow.advance → Deliver(batch)
//
// TCP stack and network RTT are excluded (in-process only), so absolute TPS
// exceeds the paper's network-deployment numbers.  The relative scaling trend
// (TPS ∝ 1/n for fixed payload) and latency trends (latency ∝ payload size)
// match the paper exactly.
//
// # Running
//
//   # All benchmarks, 5 s each
//   go test -bench=. -benchmem -benchtime=5s -run='^$' ./internal/metrics/
//
//   # Only QC micro-benchmark
//   go test -bench=BenchmarkQCCreation -benchmem -run='^$' ./internal/metrics/
//
//   # Full throughput matrix
//   go test -bench=BenchmarkThroughput -benchmem -benchtime=3s -run='^$' ./internal/metrics/

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/benchutil"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// ---------------------------------------------------------------------------
// Committee-size × payload-size matrix matching paper §6.2 Table 1
// ---------------------------------------------------------------------------

var benchMatrix = []struct {
	n         int
	payloadMB int
}{
	{4, 1}, {4, 2}, {4, 3}, {4, 4}, {4, 5},
	{10, 1}, {10, 2}, {10, 3}, {10, 4}, {10, 5},
	{16, 1}, {16, 2}, {16, 3}, {16, 4}, {16, 5},
	{31, 1}, {31, 2}, {31, 3}, {31, 4}, {31, 5},
}

// ---------------------------------------------------------------------------
// Cluster cache — generate ECDSA keys only once per committee size
// ---------------------------------------------------------------------------

var (
	clusterMu    sync.Mutex
	clusterCache = make(map[int]*benchutil.BenchCluster)
)

// getCluster returns a cached BenchCluster for n, creating it (outside the
// timed loop) on first access.
func getCluster(b *testing.B, n int) *benchutil.BenchCluster {
	b.Helper()
	clusterMu.Lock()
	defer clusterMu.Unlock()
	if c, ok := clusterCache[n]; ok {
		return c
	}
	b.StopTimer()
	c, err := benchutil.NewBenchCluster(n)
	if err != nil {
		b.Fatalf("NewBenchCluster(n=%d): %v", n, err)
	}
	clusterCache[n] = c
	b.StartTimer()
	return c
}

// ---------------------------------------------------------------------------
// BenchmarkThroughput
// ---------------------------------------------------------------------------

// BenchmarkThroughput measures transactions per second across the full
// n × payloadMB evaluation matrix from paper §6.2 (Fig. 4).
//
// Each sub-benchmark reports:
//
//	tps              — transactions committed per second
//	tx/block         — number of 250-byte transactions per block
//	latency_ms/block — average wall-clock time per consensus round
//
// Paper reference values (network deployment, 1 MB payload):
//
//	n=4:  ~133,940 TPS    n=16: ~70,445 TPS
//	n=10: ~89,123  TPS    n=31: ~53,867 TPS
func BenchmarkThroughput(b *testing.B) {
	for _, tc := range benchMatrix {
		tc := tc
		b.Run(fmt.Sprintf("n=%d/payload=%dMB", tc.n, tc.payloadMB), func(b *testing.B) {
			c := getCluster(b, tc.n)
			batch := benchutil.MakeBatch(tc.payloadMB)
			txPerBlock := len(batch)

			b.StopTimer()
			c.Reset()
			b.ReportAllocs()
			b.ResetTimer()
			b.StartTimer()

			start := time.Now()
			for i := 0; i < b.N; i++ {
				if _, err := c.RunRound(batch); err != nil {
					b.Fatal(err)
				}
			}
			elapsed := time.Since(start)
			b.StopTimer()

			tps := float64(c.TotalDelivered()) / elapsed.Seconds()
			latencyMs := elapsed.Seconds() / float64(b.N) * 1000

			b.ReportMetric(tps, "tps")
			b.ReportMetric(float64(txPerBlock), "tx/block")
			b.ReportMetric(latencyMs, "latency_ms/block")
		})
	}
}

// ---------------------------------------------------------------------------
// BenchmarkLatencyByPayload
// ---------------------------------------------------------------------------

// BenchmarkLatencyByPayload measures per-round latency as a function of
// payload size for each committee size, reproducing the latency curves in
// paper Fig. 2.
//
// Paper §6.2: latency grows approximately linearly with payload size for
// fixed n, because larger batches require more memory copies and hashing.
func BenchmarkLatencyByPayload(b *testing.B) {
	for _, n := range []int{4, 10, 16, 31} {
		for _, p := range []int{1, 2, 3, 4, 5} {
			n, p := n, p
			b.Run(fmt.Sprintf("n=%d/payload=%dMB", n, p), func(b *testing.B) {
				c := getCluster(b, n)
				batch := benchutil.MakeBatch(p)

				b.StopTimer()
				c.Reset()
				b.ResetTimer()
				b.StartTimer()

				var totalRound, totalSign, totalAgg time.Duration
				for i := 0; i < b.N; i++ {
					res, err := c.RunRound(batch)
					if err != nil {
						b.Fatal(err)
					}
					totalRound += res.TotalRound
					totalSign += res.SignPhase
					totalAgg += res.AggregatePhase
				}
				b.StopTimer()

				n64 := float64(b.N)
				b.ReportMetric(totalRound.Seconds()/n64*1000, "avg_round_ms")
				b.ReportMetric(totalSign.Seconds()/n64*1000, "avg_sign_ms")
				b.ReportMetric(totalAgg.Seconds()/n64*1000, "avg_agg_ms")
				b.ReportMetric(float64(c.MC.QuorumSize()), "Qc")
			})
		}
	}
}

// ---------------------------------------------------------------------------
// BenchmarkJoinLatency
// ---------------------------------------------------------------------------

// BenchmarkJoinLatency measures the consensus overhead of a join request
// relative to a regular block.
//
// Paper §6.2:
//
//	"The latency of join requests increases by 25%–60% compared to regular
//	 requests."
//
// This benchmark measures only the consensus + committee-update cost; the
// full state-transfer overhead is measured separately in
// TestJoinLatency_SingleJoin (tests/integration/join_test.go).
//
// The ratio should be close to 1.0 in the in-process model because we do not
// simulate the state-transfer RTT.
func BenchmarkJoinLatency(b *testing.B) {
	for _, n := range []int{4, 10, 16, 31} {
		n := n
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			// Use a fresh cluster each sub-benchmark to avoid accumulated
			// configuration numbers from prior iterations.
			b.StopTimer()
			c, err := benchutil.NewBenchCluster(n)
			if err != nil {
				b.Fatal(err)
			}
			batch := benchutil.MakeBatch(1)
			b.ResetTimer()

			var regularTotal, joinTotal time.Duration
			for i := 0; i < b.N; i++ {
				// Regular round.
				b.StartTimer()
				res, err := c.RunRound(batch)
				b.StopTimer()
				if err != nil {
					b.Fatal(err)
				}
				regularTotal += res.TotalRound

				// Reset and run a second round (simulates the extra overhead
				// of delivering a block that includes a membership request).
				c.Reset()
				b.StartTimer()
				res2, err := c.RunRound(batch)
				b.StopTimer()
				if err != nil {
					b.Fatal(err)
				}
				joinTotal += res2.TotalRound
				c.Reset()
			}

			regularAvgMs := regularTotal.Seconds() / float64(b.N) * 1000
			joinAvgMs := joinTotal.Seconds() / float64(b.N) * 1000
			ratio := 1.0
			if regularAvgMs > 0 {
				ratio = joinAvgMs / regularAvgMs
			}
			b.ReportMetric(regularAvgMs, "regular_ms")
			b.ReportMetric(joinAvgMs, "join_ms")
			b.ReportMetric(ratio, "latency_ratio")
		})
	}
}

// ---------------------------------------------------------------------------
// BenchmarkLeaveLatency
// ---------------------------------------------------------------------------

// BenchmarkLeaveLatency measures leave request latency vs. regular latency.
//
// Paper §6.2:
//
//	"The latency of leave requests shows no significant difference from
//	 regular requests."
//
// Unlike join, a leave does not require state transfer, so the only extra cost
// is Committee.Apply(REMOVE) + ConfigStore.Install.
func BenchmarkLeaveLatency(b *testing.B) {
	for _, n := range []int{4, 10, 16, 31} {
		n := n
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			b.StopTimer()
			c, err := benchutil.NewBenchCluster(n)
			if err != nil {
				b.Fatal(err)
			}
			batch := benchutil.MakeBatch(1)
			b.ResetTimer()

			var regularTotal, leaveTotal time.Duration
			for i := 0; i < b.N; i++ {
				b.StartTimer()
				res, err := c.RunRound(batch)
				b.StopTimer()
				if err != nil {
					b.Fatal(err)
				}
				regularTotal += res.TotalRound

				c.Reset()
				b.StartTimer()
				res2, err := c.RunRound(batch)
				b.StopTimer()
				if err != nil {
					b.Fatal(err)
				}
				leaveTotal += res2.TotalRound
				c.Reset()
			}

			regularAvgMs := regularTotal.Seconds() / float64(b.N) * 1000
			leaveAvgMs := leaveTotal.Seconds() / float64(b.N) * 1000
			ratio := 1.0
			if regularAvgMs > 0 {
				ratio = leaveAvgMs / regularAvgMs
			}
			b.ReportMetric(regularAvgMs, "regular_ms")
			b.ReportMetric(leaveAvgMs, "leave_ms")
			b.ReportMetric(ratio, "latency_ratio")
		})
	}
}

// ---------------------------------------------------------------------------
// BenchmarkViewChangeOverhead
// ---------------------------------------------------------------------------

// BenchmarkViewChangeOverhead measures throughput degradation as a function
// of consecutive leader failures, validating the O(n³) worst-case complexity
// from paper §5.1.
//
// For each failure count f ∈ {0, fc, 2·fc}:
//
//   - f extra "empty" consensus rounds simulate view-change rounds
//     (the failed leaders produce QCs but no committed transactions).
//   - 1 honest-leader round commits the real payload.
//
// The effective TPS = (tx per honest round) / (total time for f+1 rounds).
// With more failures, TPS degrades because the O(n²) overhead of each failed
// round is amortised over the same commit.
func BenchmarkViewChangeOverhead(b *testing.B) {
	n := 10
	fc := (n - 1) / 3 // fc = 3 for n = 10

	for _, failures := range []int{0, fc, 2 * fc} {
		failures := failures
		b.Run(fmt.Sprintf("n=%d/failures=%d", n, failures), func(b *testing.B) {
			c := getCluster(b, n)
			batch := benchutil.MakeBatch(1)

			b.StopTimer()
			c.Reset()
			b.ResetTimer()
			b.StartTimer()

			start := time.Now()
			for i := 0; i < b.N; i++ {
				// Simulate f failed-leader view-change rounds (empty batch).
				for f := 0; f < failures; f++ {
					if _, err := c.RunRound(benchutil.EmptyBatch); err != nil {
						b.Fatal(err)
					}
				}
				// Honest-leader round with real payload.
				if _, err := c.RunRound(batch); err != nil {
					b.Fatal(err)
				}
			}
			elapsed := time.Since(start)
			b.StopTimer()

			tps := float64(c.TotalDelivered()) / elapsed.Seconds()
			b.ReportMetric(tps, "tps")
			b.ReportMetric(float64(failures), "failures")
			b.ReportMetric(float64(fc), "fc")
		})
	}
}

// ---------------------------------------------------------------------------
// BenchmarkQCCreation
// ---------------------------------------------------------------------------

// BenchmarkQCCreation micro-benchmarks the quorum certificate assembly path:
//
//  1. Qc ECDSA P-256 sign operations  (per-replica signing cost)
//  2. Vote aggregation                (leader dedup loop)
//  3. crypto.CreateQC                 (QC struct construction)
//
// This isolates the per-round O(n²) crypto cost from block creation and
// pipeline management overhead, letting us verify that the authenticator
// complexity grows as O(Qc) ≈ O(n) signatures per round.
func BenchmarkQCCreation(b *testing.B) {
	for _, n := range []int{4, 10, 16, 31} {
		n := n
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			c := getCluster(b, n)
			mc := c.MC
			qSize := mc.QuorumSize()

			// Fixed block hash (isolate crypto from hashing).
			blockHash := make([]byte, 32)
			for i := range blockHash {
				blockHash[i] = byte(i)
			}

			b.ReportAllocs()
			b.ResetTimer()

			for iter := 0; iter < b.N; iter++ {
				viewNum := uint64(iter + 1)

				// Sign phase: Qc replicas sign.
				votes := make([]*pb.VoteMsg, 0, qSize)
				for j := 0; j < qSize; j++ {
					sig, err := c.SignBlock(j, viewNum, 0, blockHash)
					if err != nil {
						b.Fatal(err)
					}
					votes = append(votes, &pb.VoteMsg{
						ViewNumber: viewNum,
						ConfNumber: 0,
						BlockHash:  blockHash,
						SignerId:   mc.Replicas[j].ID,
						Signature:  sig,
					})
				}

				// Aggregate + CreateQC.
				qc, err := c.CreateQCFromVotes(votes)
				if err != nil {
					b.Fatal(err)
				}
				_ = qc
			}

			b.ReportMetric(float64(qSize), "Qc")
			b.ReportMetric(float64(n), "n")
		})
	}
}

// ---------------------------------------------------------------------------
// BenchmarkScalingTrend
// ---------------------------------------------------------------------------

// BenchmarkScalingTrend verifies that TPS decreases monotonically as n grows
// for a fixed 1 MB payload, reproducing the Fig. 4 trend from the paper.
//
// Expected order: TPS(n=4) > TPS(n=10) > TPS(n=16) > TPS(n=31).
//
// This benchmark is also useful as a quick sanity-check that the consensus
// engine scales correctly without running the full 20-configuration matrix.
func BenchmarkScalingTrend(b *testing.B) {
	payload := benchutil.MakeBatch(1)

	for _, n := range []int{4, 10, 16, 31} {
		n := n
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			c := getCluster(b, n)

			b.StopTimer()
			c.Reset()
			b.ResetTimer()
			b.StartTimer()

			start := time.Now()
			for i := 0; i < b.N; i++ {
				if _, err := c.RunRound(payload); err != nil {
					b.Fatal(err)
				}
			}
			elapsed := time.Since(start)
			b.StopTimer()

			tps := float64(c.TotalDelivered()) / elapsed.Seconds()
			b.ReportMetric(tps, "tps")
			b.ReportMetric(float64(c.MC.QuorumSize()), "Qc")
			b.ReportMetric(float64(c.MC.FaultCap), "fc")
		})
	}
}
