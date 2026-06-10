// Package simulation implements a partial-synchrony network simulator for
// testing D-HotStuff safety and liveness properties.
//
// From paper §3.3:
//
//	"partially synchronous model [19]: unknown GST, known upper bound Δ
//	on delay.  After GST, messages between honest replicas delivered within Δ."
//
// The NetSim type models both the pre-GST chaos period (where an adversary
// can delay, reorder, or drop messages) and the post-GST synchronous period
// (where messages are delivered within Δ between honest replicas).
package simulation

import (
	"math/rand"
	"sort"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// fakeClock — deterministic clock for tests
// ---------------------------------------------------------------------------

// fakeClock is a manually advanced clock that enables deterministic tests.
// All time queries go through this clock rather than time.Now().
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// newFakeClock creates a clock starting at t.
func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{now: t}
}

// Now returns the current fake time.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d and returns the new time.
func (c *fakeClock) Advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	return c.now
}

// Set overwrites the current time.
func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// ---------------------------------------------------------------------------
// pendingMsg — a message queued in the network
// ---------------------------------------------------------------------------

// pendingMsg represents a message in transit in the simulated network.
type pendingMsg struct {
	From      string
	To        string
	Msg       []byte
	DeliverAt time.Time
}

// deliveredMsg is a message that has been delivered by the network simulator.
type deliveredMsg struct {
	From string
	To   string
	Msg  []byte
}

// ---------------------------------------------------------------------------
// simReplica — per-replica metadata tracked by NetSim
// ---------------------------------------------------------------------------

// simReplica holds per-replica bookkeeping within the simulation.
type simReplica struct {
	ID        string
	Byzantine bool
}

// ---------------------------------------------------------------------------
// AdversaryModel — pluggable Byzantine behaviour
// ---------------------------------------------------------------------------

// AdversaryModel controls how the adversary behaves in the simulation.
//
// The adversary controls at most fc Byzantine replicas and can:
//   - Decide which replicas are Byzantine (IsByzantine).
//   - Intercept and manipulate messages in the pre-GST period (InterceptMsg).
//   - Report the maximum number of Byzantine faults (MaxByzantine).
type AdversaryModel interface {
	// IsByzantine reports whether replicaID is controlled by the adversary.
	IsByzantine(replicaID string) bool

	// InterceptMsg is called for every message sent before GST.
	// It returns (drop, delay):
	//   drop=true  → message is silently discarded.
	//   drop=false → message is queued with an additional delay.
	InterceptMsg(from, to string, msg []byte) (drop bool, delay time.Duration)

	// MaxByzantine returns fc, the number of Byzantine replicas.
	MaxByzantine() int
}

// ---------------------------------------------------------------------------
// NetSim — the core network simulator
// ---------------------------------------------------------------------------

// NetSim simulates a partially synchronous network for D-HotStuff testing.
//
// Before GST, the adversary can delay, reorder, or drop messages.
// After GST, messages between honest replicas are delivered within Δ (maxDelay).
//
// All methods are safe for concurrent use.
type NetSim struct {
	replicas  map[string]*simReplica
	gst       time.Time     // Global Stabilization Time
	maxDelay  time.Duration // Δ: post-GST message delivery bound
	adversary AdversaryModel
	clock     *fakeClock
	rng       *rand.Rand
	mu        sync.Mutex
	msgQ      []pendingMsg
}

// NewNetSim creates a network simulator with the given replicas, maximum
// post-GST delay Δ, and adversary model.
//
// gst defaults to a far-future time (no GST yet); call SetGST to trigger
// the synchronous phase.
func NewNetSim(
	replicaIDs []string,
	maxDelay time.Duration,
	adversary AdversaryModel,
	clock *fakeClock,
) *NetSim {
	replicas := make(map[string]*simReplica, len(replicaIDs))
	for _, id := range replicaIDs {
		replicas[id] = &simReplica{
			ID:        id,
			Byzantine: adversary.IsByzantine(id),
		}
	}

	return &NetSim{
		replicas:  replicas,
		gst:       clock.Now().Add(365 * 24 * time.Hour), // far future = no GST yet
		maxDelay:  maxDelay,
		adversary: adversary,
		clock:     clock,
		rng:       rand.New(rand.NewSource(42)), // deterministic seed
		msgQ:      make([]pendingMsg, 0, 256),
	}
}

// SetGST triggers the synchronous phase.  After this time, messages between
// honest replicas are guaranteed to be delivered within Δ.
//
// Paper §3.3: "there exists a Global Stabilization Time (GST), unknown to
// the replicas, after which the network becomes synchronous."
func (n *NetSim) SetGST(t time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.gst = t
}

// GST returns the current GST.
func (n *NetSim) GST() time.Time {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.gst
}

// Send enqueues a message from replica `from` to replica `to`.
//
// Behaviour depends on the network phase:
//
//   - Before GST: the adversary's InterceptMsg controls whether the message
//     is dropped or delayed.  If from is Byzantine, the message is allowed
//     through regardless (the adversary can craft arbitrary messages).
//
//   - After GST: the message is queued with a random delay uniformly
//     sampled in [0, Δ] for honest→honest communication.  Byzantine senders
//     may still experience adversarial delays.
func (n *NetSim) Send(from, to string, msg []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()

	now := n.clock.Now()

	// Byzantine sender can always send (adversary controls them).
	isByzFrom := n.adversary.IsByzantine(from)

	if now.Before(n.gst) {
		// Pre-GST: adversary controls the network.
		drop, delay := n.adversary.InterceptMsg(from, to, msg)
		if drop && !isByzFrom {
			return // message dropped (Byzantine senders bypass drops)
		}
		n.msgQ = append(n.msgQ, pendingMsg{
			From:      from,
			To:        to,
			Msg:       copyBytes(msg),
			DeliverAt: now.Add(delay),
		})
	} else {
		// Post-GST: honest→honest delivered within Δ.
		delay := time.Duration(n.rng.Int63n(int64(n.maxDelay + 1)))
		n.msgQ = append(n.msgQ, pendingMsg{
			From:      from,
			To:        to,
			Msg:       copyBytes(msg),
			DeliverAt: now.Add(delay),
		})
	}
}

// Tick advances the simulation to `now` and returns all messages whose
// delivery time has passed.  Delivered messages are removed from the queue.
func (n *NetSim) Tick(now time.Time) []deliveredMsg {
	n.mu.Lock()
	defer n.mu.Unlock()

	var delivered []deliveredMsg
	remaining := n.msgQ[:0] // reuse backing array

	for _, m := range n.msgQ {
		if !m.DeliverAt.After(now) {
			delivered = append(delivered, deliveredMsg{
				From: m.From,
				To:   m.To,
				Msg:  m.Msg,
			})
		} else {
			remaining = append(remaining, m)
		}
	}

	n.msgQ = remaining
	return delivered
}

// PendingCount returns the number of messages currently in the queue.
func (n *NetSim) PendingCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.msgQ)
}

// IsPostGST reports whether the current clock time is at or past GST.
func (n *NetSim) IsPostGST() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return !n.clock.Now().Before(n.gst)
}

// ---------------------------------------------------------------------------
// WorstCaseAdversary — triggers O(n) view changes
// ---------------------------------------------------------------------------

// worstCaseAdversary corrupts exactly fc replicas (the first fc in sorted
// order) and delays all messages to the maximum Δ before GST.
//
// This triggers O(n) consecutive view changes before progress is made — the
// worst case for authenticator complexity (paper §5.1):
//
//	O(n) view-changes × O(n) sigs per QC × O(n) replicas = O(n³)
type worstCaseAdversary struct {
	fc        int
	byzantine map[string]bool
	maxDelay  time.Duration
}

// NewWorstCaseAdversary creates an adversary that corrupts the first fc
// replicas (sorted lexicographically) and delays all pre-GST messages
// to the maximum Δ.
//
// After GST, all messages are delivered within Δ (no drops).
func NewWorstCaseAdversary(replicaIDs []string, fc int, maxDelay time.Duration) AdversaryModel {
	sorted := make([]string, len(replicaIDs))
	copy(sorted, replicaIDs)
	sort.Strings(sorted)

	byz := make(map[string]bool, fc)
	for i := 0; i < fc && i < len(sorted); i++ {
		byz[sorted[i]] = true
	}

	return &worstCaseAdversary{
		fc:        fc,
		byzantine: byz,
		maxDelay:  maxDelay,
	}
}

func (a *worstCaseAdversary) IsByzantine(replicaID string) bool {
	return a.byzantine[replicaID]
}

func (a *worstCaseAdversary) InterceptMsg(_, _ string, _ []byte) (drop bool, delay time.Duration) {
	// Before GST: delay everything to maximum Δ (worst case).
	return false, a.maxDelay
}

func (a *worstCaseAdversary) MaxByzantine() int {
	return a.fc
}

// ---------------------------------------------------------------------------
// NoopAdversary — all honest, no interference
// ---------------------------------------------------------------------------

// noopAdversary is an adversary with zero Byzantine replicas and no
// message interference.  Useful as a baseline for correctness tests.
type noopAdversary struct{}

// NewNoopAdversary creates an adversary with no Byzantine replicas.
func NewNoopAdversary() AdversaryModel {
	return &noopAdversary{}
}

func (a *noopAdversary) IsByzantine(_ string) bool                            { return false }
func (a *noopAdversary) InterceptMsg(_, _ string, _ []byte) (bool, time.Duration) { return false, 0 }
func (a *noopAdversary) MaxByzantine() int                                    { return 0 }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// copyBytes returns a copy of b to prevent aliasing.
func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
