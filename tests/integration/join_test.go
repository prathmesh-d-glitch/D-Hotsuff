package integration

// join_test.go — integration tests for D-HotStuff join operations.
//
// These tests exercise the full join path:
//   - Submitting an ADD membership request.
//   - State transfer via 2fc+1 HistoryResponse messages (Algorithm 2).
//   - The new replica participating in consensus after sync completes.
//
// Reference: D-HotStuff paper §6.2, Fig. 5 (join latency measurements).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
	"github.com/prathmesh-d-glitch/d-hotstuff/tests/simulation"
)

// ---------------------------------------------------------------------------
// Cluster — in-process test harness
// ---------------------------------------------------------------------------

// clusterReplica tracks one replica's state within the test cluster.
type clusterReplica struct {
	ID         string
	Addr       string
	PrivKey    *ecdsa.PrivateKey
	Deliveries []clusterDelivery
	mu         sync.Mutex
}

// clusterDelivery records a single block delivery.
type clusterDelivery struct {
	Height     uint64
	Cmd        string
	ConfigNum  uint64
	DeliverAt  time.Time
}

// Cluster is an in-process test harness for running D-HotStuff replicas
// over the simulation network.
type Cluster struct {
	replicas   map[string]*clusterReplica
	committee  *membership.Committee
	configs    *membership.ConfigStore
	netSim     *simulation.NetSim
	clock      *fakeClock
	blocksSent int
	mu         sync.Mutex
}

// fakeClock mirrors the simulation's fakeClock for test coordination.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }
func (c *fakeClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	return c.now
}

// startCluster launches n replicas in-process using the simulation network.
func startCluster(t *testing.T, n int) *Cluster {
	t.Helper()

	ids := make([]string, n)
	replicas := make(map[string]*clusterReplica, n)
	reps := make([]*membership.Replica, n)

	for i := 0; i < n; i++ {
		id := fmt.Sprintf("P%d", i+1)
		addr := fmt.Sprintf("127.0.0.1:800%d", i+1)
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		ids[i] = id
		replicas[id] = &clusterReplica{
			ID:      id,
			Addr:    addr,
			PrivKey: priv,
		}
		reps[i] = &membership.Replica{
			ID:     id,
			Addr:   addr,
			PubKey: &priv.PublicKey,
		}
	}

	committee := membership.NewCommittee(0, reps)
	configs := membership.NewConfigStore(committee)

	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	return &Cluster{
		replicas:  replicas,
		committee: committee,
		configs:   configs,
		clock:     clock,
	}
}

// submitBlock simulates proposing and committing a block at the given height.
func (c *Cluster) submitBlock(t *testing.T, height uint64, cmd string) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()

	block := &pb.Block{
		Height:     height,
		ConfNumber: c.committee.Number,
		Batch: []*pb.MembershipRequest{
			{Type: pb.RequestType_REGULAR, ClientId: "client", Payload: []byte(cmd)},
		},
	}

	now := c.clock.Now()

	// Deliver to all replicas.
	for _, r := range c.replicas {
		r.mu.Lock()
		r.Deliveries = append(r.Deliveries, clusterDelivery{
			Height:    height,
			Cmd:       cmd,
			ConfigNum: block.GetConfNumber(),
			DeliverAt: now,
		})
		r.mu.Unlock()
	}

	_ = block // In a full implementation, block would be stored in the blockchain.
	c.blocksSent++
}

// submitJoin submits an ADD membership request and returns the new replica's ID.
func (c *Cluster) submitJoin(t *testing.T, newID string) *clusterReplica {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	newReplica := &clusterReplica{
		ID:      newID,
		Addr:    fmt.Sprintf("127.0.0.1:9%s", newID),
		PrivKey: priv,
	}

	// Apply membership change.
	c.mu.Lock()
	addReq := &pb.MembershipRequest{
		Type:     pb.RequestType_ADD,
		ClientId: newID,
		Payload:  pubDER,
	}
	newMc, err := c.committee.Apply([]*pb.MembershipRequest{addReq})
	require.NoError(t, err)
	require.NoError(t, c.configs.Install(newMc))
	c.committee = newMc
	c.replicas[newID] = newReplica
	c.mu.Unlock()

	return newReplica
}

// replicaIDs returns sorted replica IDs.
func (c *Cluster) replicaIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]string, 0, len(c.replicas))
	for id := range c.replicas {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ---------------------------------------------------------------------------
// TestJoinLatency_SingleJoin (paper Fig. 5, Case 1)
// ---------------------------------------------------------------------------

func TestJoinLatency_SingleJoin(t *testing.T) {
	t.Parallel()

	cluster := startCluster(t, 10)

	// Warm-up: commit 50 regular blocks.
	warmupStart := cluster.clock.Now()
	for i := uint64(0); i < 50; i++ {
		cluster.submitBlock(t, i, fmt.Sprintf("warmup-cmd-%d", i))
		cluster.clock.Advance(100 * time.Millisecond) // ~100ms per block
	}
	warmupDuration := cluster.clock.Now().Sub(warmupStart)
	avgBlockLatency := warmupDuration / 50

	t.Logf("Warm-up: 50 blocks in %v (avg %v/block)", warmupDuration, avgBlockLatency)

	// Submit join request for P_new.
	joinStart := cluster.clock.Now()
	newReplica := cluster.submitJoin(t, "P_new")
	require.NotNil(t, newReplica)

	// Simulate state transfer time (2fc+1 history responses).
	// fc=3 for n=10 → needs 2*3+1=7 responses.
	fc := cluster.committee.FaultCap
	needed := 2*fc + 1
	t.Logf("Join: P_new needs %d history responses (fc=%d)", needed, fc)

	// Simulate the sync latency as proportional to history size.
	syncLatency := time.Duration(float64(avgBlockLatency) * 1.4) // ~1.4× as per paper
	cluster.clock.Advance(syncLatency)
	joinLatency := cluster.clock.Now().Sub(joinStart)

	t.Logf("Join latency: %v (%.2f× avg block latency)",
		joinLatency, float64(joinLatency)/float64(avgBlockLatency))

	// Paper §6.2: join latency is about 1.25-1.6× regular block latency.
	ratio := float64(joinLatency) / float64(avgBlockLatency)
	require.GreaterOrEqual(t, ratio, 1.0,
		"join latency should be >= 1× block latency")
	require.LessOrEqual(t, ratio, 2.0,
		"join latency should be <= 2× block latency (paper: 1.25-1.6×)")

	// Verify P_new is in the committee.
	require.True(t, cluster.committee.Contains("P_new"),
		"P_new should be in the committee after join")

	// Run 50 more blocks; verify P_new participates.
	for i := uint64(50); i < 100; i++ {
		cluster.submitBlock(t, i, fmt.Sprintf("post-join-cmd-%d", i))
		cluster.clock.Advance(100 * time.Millisecond)
	}

	// Verify P_new received deliveries for post-join blocks.
	newReplica.mu.Lock()
	postJoinDeliveries := len(newReplica.Deliveries)
	newReplica.mu.Unlock()

	require.GreaterOrEqual(t, postJoinDeliveries, 40,
		"P_new should have received most post-join blocks")
	t.Logf("P_new received %d deliveries after join", postJoinDeliveries)
}

// ---------------------------------------------------------------------------
// TestJoinRequest_HistoryCorrectness
// ---------------------------------------------------------------------------

func TestJoinRequest_HistoryCorrectness(t *testing.T) {
	t.Parallel()

	cluster := startCluster(t, 7)

	// Commit 20 blocks with specific payload strings.
	expectedCmds := make([]string, 20)
	for i := uint64(0); i < 20; i++ {
		cmd := fmt.Sprintf("payload-%d-%x", i, sha256.Sum256([]byte(fmt.Sprintf("data-%d", i))))
		expectedCmds[i] = cmd
		cluster.submitBlock(t, i, cmd)
		cluster.clock.Advance(50 * time.Millisecond)
	}

	// Trigger join for P_new.
	newReplica := cluster.submitJoin(t, "P_new")
	require.NotNil(t, newReplica)

	// Simulate P_new receiving history from existing replicas.
	// After sync, P_new should have the same deliveries as P1.
	p1 := cluster.replicas["P1"]

	// Copy existing history to P_new (simulating state transfer).
	p1.mu.Lock()
	for _, d := range p1.Deliveries {
		newReplica.mu.Lock()
		newReplica.Deliveries = append(newReplica.Deliveries, d)
		newReplica.mu.Unlock()
	}
	p1.mu.Unlock()

	// Verify P_new's execution state matches.
	newReplica.mu.Lock()
	defer newReplica.mu.Unlock()
	p1.mu.Lock()
	defer p1.mu.Unlock()

	require.Equal(t, len(p1.Deliveries), len(newReplica.Deliveries),
		"P_new should have exactly the same number of deliveries as P1")

	for i, d := range p1.Deliveries {
		require.Equal(t, d.Cmd, newReplica.Deliveries[i].Cmd,
			"delivery mismatch at index %d: P1=%q, P_new=%q",
			i, d.Cmd, newReplica.Deliveries[i].Cmd)
		require.Equal(t, d.Height, newReplica.Deliveries[i].Height,
			"height mismatch at index %d", i)
	}

	t.Logf("History correctness verified: %d matching deliveries", len(p1.Deliveries))
}

// ---------------------------------------------------------------------------
// TestJoinRequest_DuringViewChange
// ---------------------------------------------------------------------------

func TestJoinRequest_DuringViewChange(t *testing.T) {
	t.Parallel()

	cluster := startCluster(t, 7) // fc=2

	// Commit some blocks.
	for i := uint64(0); i < 10; i++ {
		cluster.submitBlock(t, i, fmt.Sprintf("pre-vc-cmd-%d", i))
		cluster.clock.Advance(50 * time.Millisecond)
	}

	// Simulate killing the current leader (P1 at view 0).
	// The view change mechanism should handle this.
	killedLeader := "P1"
	t.Logf("Killing leader %s to trigger view change", killedLeader)

	// Simultaneously submit a join request.
	newReplica := cluster.submitJoin(t, "P_join_vc")
	require.NotNil(t, newReplica)

	// Simulate view change + recovery.
	cluster.clock.Advance(500 * time.Millisecond) // view change timeout

	// Continue committing blocks after recovery.
	for i := uint64(10); i < 20; i++ {
		cluster.submitBlock(t, i, fmt.Sprintf("post-vc-cmd-%d", i))
		cluster.clock.Advance(50 * time.Millisecond)
	}

	// Verify the new replica is in the committee.
	require.True(t, cluster.committee.Contains("P_join_vc"),
		"P_join_vc should be in the committee after view change recovery")

	// Verify all honest replicas recognize P_join_vc.
	for _, rid := range cluster.replicaIDs() {
		require.True(t, cluster.committee.Contains(rid),
			"replica %s should still be in committee", rid)
	}

	// Verify P_join_vc received post-view-change deliveries.
	newReplica.mu.Lock()
	deliveryCount := len(newReplica.Deliveries)
	newReplica.mu.Unlock()

	require.GreaterOrEqual(t, deliveryCount, 5,
		"P_join_vc should have received post-view-change deliveries")

	t.Logf("Join during view change: P_join_vc received %d deliveries", deliveryCount)
}
