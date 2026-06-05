package consensus

// deliver.go — Deliver(batch) and the Three-Chain commit rule for D-HotStuff.
//
// Deliver is called exactly once per committed block (Algorithm 3, lines 25–26
// and the Deliver(batch) sub-procedure in lines 39–47).
//
// The Three-Chain commit rule (Algorithm 3, lines 25–26) states:
//
//	If bStar → bDouble → bPrime → b form a consecutive chain of parent links,
//	then b is committed and Deliver(b.batch) is called.
//
// This file is deliberately free of network I/O; all communication goes
// through the Executor and Replier interfaces.

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// Executor is called by Deliverer to run a single regular (non-membership)
// client request against the application state machine.
//
// Execute must be deterministic: all honest replicas that deliver the same
// request in the same order must produce the same result bytes.
type Executor interface {
	// Execute runs req against the application and returns the result payload
	// to be sent back to the originating client.
	Execute(req *pb.MembershipRequest) []byte
}

// Replier is called by Deliverer to return execution results to clients.
//
// Each successful Execute is paired with exactly one Reply call so that the
// client's waiting goroutine can unblock.
type Replier interface {
	// Reply sends result to the client identified by clientID.
	// confNum is the configuration epoch in which the request was committed;
	// clients can use it to detect committee changes.
	Reply(clientID string, confNum uint64, result []byte)
}

// Deliverer manages block delivery for a single D-HotStuff replica.
//
// It guarantees exactly-once delivery per block (Theorem 11 — Integrity):
// duplicate calls for the same block hash are silently ignored.
//
// Deliverer is safe for concurrent use; all state is protected by mu.
type Deliverer struct {
	configs   *membership.ConfigStore
	executor  Executor
	replier   Replier
	delivered map[string]bool // blockHash hex → already delivered
	mu        sync.Mutex
}

// NewDeliverer constructs a Deliverer backed by the provided dependencies.
// configs must already contain the genesis committee (config number 0).
func NewDeliverer(
	configs *membership.ConfigStore,
	executor Executor,
	replier Replier,
) *Deliverer {
	return &Deliverer{
		configs:   configs,
		executor:  executor,
		replier:   replier,
		delivered: make(map[string]bool),
	}
}

// Deliver commits block and executes its batch according to Algorithm 3
// lines 25–26 and the Deliver(batch) sub-procedure (lines 39–47).
//
// Steps:
//  1. Idempotency guard — if this block has already been delivered, return
//     immediately (Theorem 11, Integrity: each correct replica delivers each
//     value at most once).
//  2. Look up the committee Mc for this block's conf_number.
//  3. Split the batch into regular requests and membership requests (§4.5:
//     regular requests execute before membership changes).
//  4. Execute each regular request and reply to its originating client.
//  5. If there are membership requests, compute Mc+1 = Mc.Apply(membership)
//     and install it in the ConfigStore.
//  6. Mark the block as delivered and return nil.
//
// An error is returned only for unexpected failures (missing committee,
// malformed membership request, install conflict).  The caller should treat
// such errors as fatal for the replica.
func (d *Deliverer) Deliver(block *pb.Block) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Step 1 — Idempotency guard (Algorithm 3, Integrity invariant).
	key := string(hashBlock(block))
	if d.delivered[key] {
		return nil // already delivered; nothing to do
	}

	// Step 2 — Retrieve the committee for this epoch.
	mc, err := d.configs.AtNumber(block.GetConfNumber())
	if err != nil {
		return fmt.Errorf("consensus.Deliver: block at height %d conf %d: %w",
			block.GetHeight(), block.GetConfNumber(), err)
	}

	// Step 3 — Split batch per §4.5 ordering rule.
	// Deliver(batch), Algorithm 3 lines 39–47:
	//   regular requests run first, then membership requests.
	regular, membershipReqs := membership.ClassifyBatch(block.GetBatch())

	// Step 4 — Execute regular requests and reply to clients.
	// Algorithm 3, lines 42–44.
	for _, req := range regular {
		result := d.executor.Execute(req)
		d.replier.Reply(req.GetClientId(), block.GetConfNumber(), result)
	}

	// Step 5 — Apply membership changes if present.
	// Algorithm 3, lines 45–47: derive Mc+1 and install it.
	if len(membershipReqs) > 0 {
		newMc, err := mc.Apply(membershipReqs)
		if err != nil {
			return fmt.Errorf("consensus.Deliver: apply membership requests: %w", err)
		}
		if err := d.configs.Install(newMc); err != nil {
			return fmt.Errorf("consensus.Deliver: install committee Mc+1=%d: %w",
				newMc.Number, err)
		}
	}

	// Step 6 — Mark as delivered.
	d.delivered[key] = true
	return nil
}

// CheckThreeChain reports whether the four consecutive blocks form a valid
// three-chain — the commit condition in D-HotStuff.
//
// The three-chain rule (Algorithm 3, lines 25–26) requires:
//
//	bStar.ParentHash  == hash(bDouble)   (bStar certifies bDouble)
//	bDouble.ParentHash == hash(bPrime)   (bDouble certifies bPrime)
//	bPrime.ParentHash  == hash(b)        (bPrime certifies b)
//
// When all three parent-links hold, block b is safe to commit.
//
// Reference: D-HotStuff Algorithm 3, lines 25–26.
func (d *Deliverer) CheckThreeChain(bStar, bDouble, bPrime, b *pb.Block) bool {
	// Algorithm 3, line 25: three consecutive parent links.
	return bytes.Equal(bStar.GetParentHash(), hashBlock(bDouble)) &&
		bytes.Equal(bDouble.GetParentHash(), hashBlock(bPrime)) &&
		bytes.Equal(bPrime.GetParentHash(), hashBlock(b))
}
