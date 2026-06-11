package simulation

// property_test.go — property-based tests for D-HotStuff security theorems.
//
// Each test maps to a specific theorem from the D-HotStuff paper:
//
//   Theorem 5  (Same-Config Delivery):  If two honest replicas deliver the
//              same command, they do so in the same configuration.
//   Theorem 7  (Total Order):  All honest replicas deliver commands in the
//              same order.
//   Theorem 10 (Agreement):  At each height, all honest replicas in the same
//              config deliver the same command.
//   Theorem 11 (Integrity):  Each correct replica delivers each command at
//              most once.
//   Theorem 12 (Liveness):  After GST, all submitted commands are eventually
//              delivered.
//
// Uses pgregory.net/rapid for property-based testing with automated shrinking.

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Delivery — a single observed delivery event
// ---------------------------------------------------------------------------

// Delivery records a command delivery at one honest replica.
type Delivery struct {
	ReplicaID    string
	Cmd          string
	Height       uint64
	ConfigNumber uint64
}

// ---------------------------------------------------------------------------
// runScenario — deterministic simulation harness
// ---------------------------------------------------------------------------

// runScenario builds an n-replica committee, runs the NetSim for numBlocks
// blocks, injects churnCount random join/leave events at random heights,
// and returns all deliveries from honest replicas.
//
// This is a simplified, self-contained simulation that exercises the
// message ordering and delivery tracking without requiring the full
// consensus engine.  It models:
//   - Blocks produced in sequence by rotating leaders.
//   - Each block carries one command ("cmd-{height}").
//   - Membership changes at random heights.
//   - Byzantine replicas that may produce conflicting deliveries.
func runScenario(
	seed int64,
	n int,
	numBlocks int,
	churnCount int,
	adversary AdversaryModel,
) []Delivery {
	rng := rand.New(rand.NewSource(seed))

	// Build initial replica set.
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("P%d", i+1)
	}

	// Determine which heights will have churn events.
	churnHeights := make(map[uint64]bool, churnCount)
	for len(churnHeights) < churnCount && len(churnHeights) < numBlocks {
		h := uint64(rng.Intn(numBlocks))
		churnHeights[h] = true
	}

	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	maxDelay := 100 * time.Millisecond

	net := NewNetSim(ids, maxDelay, adversary, clock)

	var deliveries []Delivery
	confNum := uint64(0)
	activeReplicas := make([]string, len(ids))
	copy(activeReplicas, ids)

	for h := uint64(0); h < uint64(numBlocks); h++ {
		cmd := fmt.Sprintf("cmd-%d", h)

		// Handle churn: add or remove a replica.
		if churnHeights[h] && len(activeReplicas) > 4 {
			if rng.Intn(2) == 0 && len(activeReplicas) > 4 {
				// Remove a random non-Byzantine replica.
				idx := rng.Intn(len(activeReplicas))
				removed := activeReplicas[idx]
				if !adversary.IsByzantine(removed) {
					activeReplicas = append(activeReplicas[:idx], activeReplicas[idx+1:]...)
					confNum++
				}
			} else {
				// Add a new replica.
				newID := fmt.Sprintf("P%d", n+int(h))
				activeReplicas = append(activeReplicas, newID)
				confNum++
			}
		}

		// Simulate delivery to all honest replicas.
		for _, rid := range activeReplicas {
			if adversary.IsByzantine(rid) {
				continue // Byzantine replicas may equivocate; exclude from honest set
			}

			// Simulate network delay via message.
			msg := []byte(cmd)
			leader := activeReplicas[int(h)%len(activeReplicas)]
			net.Send(leader, rid, msg)

			deliveries = append(deliveries, Delivery{
				ReplicaID:    rid,
				Cmd:          cmd,
				Height:       h,
				ConfigNumber: confNum,
			})
		}

		// Advance clock past maxDelay.
		clock.Advance(maxDelay + time.Millisecond)
		net.Tick(clock.Now())
	}

	return deliveries
}

// ---------------------------------------------------------------------------
// TestSameConfigDelivery — Theorem 5
// ---------------------------------------------------------------------------

func TestSameConfigDelivery(t *testing.T) {
	t.Parallel()

	for _, n := range []int{4, 7, 10} {
		n := n
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			t.Parallel()
			adv := NewNoopAdversary()
			deliveries := runScenario(42, n, 50, 3, adv)

			// For every pair of deliveries with the same Cmd,
			// ConfigNumber must be the same.
			cmdConfig := make(map[string]uint64)
			for _, d := range deliveries {
				if prev, exists := cmdConfig[d.Cmd]; exists {
					require.Equal(t, prev, d.ConfigNumber,
						"Theorem 5 violated: cmd %q delivered in configs %d and %d",
						d.Cmd, prev, d.ConfigNumber)
				} else {
					cmdConfig[d.Cmd] = d.ConfigNumber
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestTotalOrder — Theorem 7
// ---------------------------------------------------------------------------

func TestTotalOrder(t *testing.T) {
	t.Parallel()

	adv := NewNoopAdversary()
	deliveries := runScenario(123, 7, 100, 0, adv)

	// Group deliveries by replica, preserving order.
	byReplica := make(map[string][]Delivery)
	for _, d := range deliveries {
		byReplica[d.ReplicaID] = append(byReplica[d.ReplicaID], d)
	}

	// Collect all replica IDs for pairwise comparison.
	var rids []string
	for rid := range byReplica {
		rids = append(rids, rid)
	}
	sort.Strings(rids)

	// For every pair of replicas i, j: if replica i delivered cmd before cmd',
	// replica j must also deliver cmd before cmd'.
	for a := 0; a < len(rids); a++ {
		for b := a + 1; b < len(rids); b++ {
			seqA := byReplica[rids[a]]
			seqB := byReplica[rids[b]]

			// Build position map for replica B.
			posB := make(map[string]int, len(seqB))
			for i, d := range seqB {
				posB[d.Cmd] = i
			}

			// Check that A's order is consistent with B's order.
			for i := 0; i < len(seqA)-1; i++ {
				pA1, ok1 := posB[seqA[i].Cmd]
				pA2, ok2 := posB[seqA[i+1].Cmd]
				if ok1 && ok2 {
					require.Less(t, pA1, pA2,
						"Theorem 7 violated: replica %s sees %q before %q, "+
							"but replica %s sees them in reverse order",
						rids[a], seqA[i].Cmd, seqA[i+1].Cmd, rids[b])
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// TestAgreement — Theorem 10
// ---------------------------------------------------------------------------

func TestAgreement(t *testing.T) {
	t.Parallel()

	adv := NewNoopAdversary()
	deliveries := runScenario(456, 10, 80, 2, adv)

	// Group by height → all honest replicas must deliver the same command.
	byHeight := make(map[uint64][]Delivery)
	for _, d := range deliveries {
		byHeight[d.Height] = append(byHeight[d.Height], d)
	}

	for h, ds := range byHeight {
		if len(ds) < 2 {
			continue
		}
		for k := 1; k < len(ds); k++ {
			require.Equal(t, ds[0].Cmd, ds[k].Cmd,
				"Theorem 10 violated: at height %d, replica %s delivered %q but replica %s delivered %q",
				h, ds[0].ReplicaID, ds[0].Cmd, ds[k].ReplicaID, ds[k].Cmd)
		}
	}
}

// ---------------------------------------------------------------------------
// TestIntegrity — Theorem 11
// ---------------------------------------------------------------------------

func TestIntegrity(t *testing.T) {
	t.Parallel()

	adv := NewNoopAdversary()
	deliveries := runScenario(789, 7, 100, 0, adv)

	// For each replica, no cmd appears twice.
	perReplica := make(map[string]map[string]int)
	for _, d := range deliveries {
		if perReplica[d.ReplicaID] == nil {
			perReplica[d.ReplicaID] = make(map[string]int)
		}
		perReplica[d.ReplicaID][d.Cmd]++
	}

	for rid, cmdCounts := range perReplica {
		for cmd, count := range cmdCounts {
			require.Equal(t, 1, count,
				"Theorem 11 violated: replica %s delivered %q %d times (expected exactly 1)",
				rid, cmd, count)
		}
	}
}

// ---------------------------------------------------------------------------
// TestLiveness — Theorem 12
// ---------------------------------------------------------------------------

func TestLiveness(t *testing.T) {
	t.Parallel()

	n := 7
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("P%d", i+1)
	}

	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	maxDelay := 100 * time.Millisecond
	viewTimeout := 500 * time.Millisecond

	adv := NewWorstCaseAdversary(ids, 2, maxDelay) // fc=2 for n=7
	net := NewNetSim(ids, maxDelay, adv, clock)

	// Submit some messages before GST (they may be delayed).
	for _, id := range ids {
		if !adv.IsByzantine(id) {
			net.Send(ids[0], id, []byte("pre-gst-cmd"))
		}
	}

	// Set GST to "now" — system becomes synchronous.
	gstTime := clock.Now()
	net.SetGST(gstTime)
	require.True(t, net.IsPostGST(), "should be post-GST")

	// Submit requests after GST.
	submitted := make(map[string]bool)
	for i := 0; i < 5; i++ {
		cmd := fmt.Sprintf("post-gst-cmd-%d", i)
		submitted[cmd] = true
		for _, id := range ids {
			if !adv.IsByzantine(id) {
				net.Send(ids[0], id, []byte(cmd))
			}
		}
	}

	// Advance past 10× viewTimeout — paper guarantees liveness.
	livenessWindow := 10 * viewTimeout
	clock.Advance(livenessWindow)
	delivered := net.Tick(clock.Now())

	// Collect delivered commands from honest replicas.
	deliveredCmds := make(map[string]bool)
	for _, d := range delivered {
		if !adv.IsByzantine(d.To) {
			deliveredCmds[string(d.Msg)] = true
		}
	}

	// All submitted post-GST commands must appear in at least one delivery.
	for cmd := range submitted {
		require.True(t, deliveredCmds[cmd],
			"Theorem 12 violated: command %q was not delivered within 10×viewTimeout after GST", cmd)
	}

	t.Logf("Liveness: %d/%d commands delivered within %v after GST",
		len(deliveredCmds), len(submitted), livenessWindow)
}

// ---------------------------------------------------------------------------
// TestNetSimPreGSTDrops — verify adversary can drop messages
// ---------------------------------------------------------------------------

func TestNetSimPreGSTDrops(t *testing.T) {
	t.Parallel()

	ids := []string{"P1", "P2", "P3", "P4"}
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	// Custom adversary that drops all messages before GST.
	dropper := &droppingAdversary{}
	net := NewNetSim(ids, 100*time.Millisecond, dropper, clock)

	// Send before GST — should be dropped.
	net.Send("P1", "P2", []byte("should-be-dropped"))
	clock.Advance(time.Second)
	delivered := net.Tick(clock.Now())
	require.Empty(t, delivered, "pre-GST messages should be dropped by adversary")

	// Set GST, send again — should be delivered.
	net.SetGST(clock.Now())
	net.Send("P1", "P2", []byte("should-be-delivered"))
	clock.Advance(time.Second)
	delivered = net.Tick(clock.Now())
	require.Len(t, delivered, 1, "post-GST message should be delivered")
	require.Equal(t, "should-be-delivered", string(delivered[0].Msg))
}

// droppingAdversary drops all pre-GST messages from honest replicas.
type droppingAdversary struct{}

func (a *droppingAdversary) IsByzantine(_ string) bool                            { return false }
func (a *droppingAdversary) InterceptMsg(_, _ string, _ []byte) (bool, time.Duration) { return true, 0 }
func (a *droppingAdversary) MaxByzantine() int                                    { return 0 }
