// pipeline.go — Chained HotStuff pipelining for D-HotStuff.
//
// D-HotStuff inherits the pipelining property from Chained HotStuff (paper
// §3.4 and §4.1).  In Chained HotStuff each view v performs exactly ONE phase
// of consensus.  The phases for different blocks overlap in a sliding window:
//
//	view v+2  prepare   == view v+1 pre-commit == view v   commit   == view v-1 decide
//
// Concretely (paper §4.1 example):
//
//	"prepare for b4 == pre-commit for b3 == commit for b2 == decide for b1"
//
// This means that a block proposed in view v reaches the "decide" (commit)
// stage only after three more blocks have been proposed and certified on top
// of it.  The Window array tracks this sliding window:
//
//	Window[0] = oldest block, decide-ready once the three-chain completes
//	Window[1] = commit-stage block
//	Window[2] = pre-commit-stage block
//	Window[3] = newest block, in prepare stage
//
// # Throughput advantage
//
// Pipelining achieves O(1) amortised consensus phases per round, because
// a single view-change + propose message pipeline all three BFT phases
// simultaneously for three consecutive blocks.  The paper claims this
// pipelining is the primary source of the 4.2–7.6× throughput improvement
// over BFT-SMaRt, which runs the three phases sequentially for each batch.
package consensus

import (
	"bytes"

	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// PipelineState tracks the sliding window of in-flight blocks in Chained
// HotStuff's pipelining scheme.
//
// The four window slots correspond to the four stages of the commit pipeline:
//
//	[0] decide-ready   — this block commits when the three-chain completes
//	[1] commit         — one step from decide
//	[2] pre-commit     — two steps from decide
//	[3] prepare        — newest block, just proposed
//
// The window slides by one slot each time a new block is certified.
//
// Paper §4.1:
//
//	"prepare for b4 == pre-commit for b3 == commit for b2 == decide for b1"
type PipelineState struct {
	// Window holds the four most recent certified blocks.
	//
	//   Window[0]: decide-ready (oldest, will be delivered once three-chain is verified)
	//   Window[1]: commit stage
	//   Window[2]: pre-commit stage
	//   Window[3]: prepare stage (newest)
	Window [4]*pb.Block
}

// Advance shifts the pipeline window by one slot and inserts newBlock as the
// newest (prepare-stage) entry.
//
// After shifting:
//
//	Window = [old Window[1], old Window[2], old Window[3], newBlock]
//
// If the resulting window forms a valid three-chain (all four slots are
// non-nil and the parent hashes chain correctly), the oldest block
// (Window[0] before the shift) is returned as toDeliver for commitment.
// Otherwise, nil is returned.
//
// Paper §4.1 example applied:
//
//	Before Advance:  Window = [b1, b2, b3, b4]
//	Advance(b5) →    Window = [b2, b3, b4, b5]
//	If b5→b4→b3→b2 parent-chain holds, toDeliver = b1 (via three-chain b4→b3→b2→b1).
//
// Note: the block that gets delivered is the one that was in Window[0] *before*
// the shift — it is the decide-ready block whose three-chain has just been
// sealed by the arrival of newBlock.
func (p *PipelineState) Advance(newBlock *pb.Block) (toDeliver *pb.Block) {
	// The block being evicted from the window is the candidate for delivery.
	candidate := p.Window[0]

	// Shift the window: drop oldest, slide left, insert newest.
	p.Window[0] = p.Window[1]
	p.Window[1] = p.Window[2]
	p.Window[2] = p.Window[3]
	p.Window[3] = newBlock

	// Check three-chain on the *old* window state: do the three blocks
	// that were above the candidate chain correctly back to it?
	//
	// candidate is old Window[0], and old Window[1..3] are now Window[0..2].
	// Three-chain: Window[2]→Window[1]→Window[0]→candidate.
	if candidate != nil && p.CanCommit() {
		bStar := p.Window[2]   // was Window[3]
		bDouble := p.Window[1] // was Window[2]
		bPrime := p.Window[0]  // was Window[1]

		if bytes.Equal(bStar.GetParentHash(), hashBlock(bDouble)) &&
			bytes.Equal(bDouble.GetParentHash(), hashBlock(bPrime)) &&
			bytes.Equal(bPrime.GetParentHash(), hashBlock(candidate)) {
			return candidate
		}
	}

	return nil
}

// Reset clears all four pipeline slots.
//
// This is called on a view change where no three-chain was completed, ensuring
// that stale blocks from the previous leader's proposals do not contaminate the
// new leader's pipeline.
func (p *PipelineState) Reset() {
	p.Window = [4]*pb.Block{}
}

// CanCommit reports whether all four pipeline slots are occupied.
//
// This is a necessary (but not sufficient) condition for a three-chain commit;
// the parent-hash links must also form a contiguous chain.
func (p *PipelineState) CanCommit() bool {
	return p.Window[0] != nil &&
		p.Window[1] != nil &&
		p.Window[2] != nil &&
		p.Window[3] != nil
}
