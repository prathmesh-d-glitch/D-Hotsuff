// pipeline.go — sliding window for pipelined block commits.
package consensus

import (
	"bytes"

	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// PipelineState tracks the 4-slot sliding window used by Chained HotStuff.
// Window[0] is the oldest (commit-ready) block, Window[3] is the newest.
type PipelineState struct {
	Window [4]*pb.Block
}

// Advance shifts the window and inserts newBlock as the newest entry.
// Returns the block to commit if the three-chain condition is met, nil otherwise.
func (p *PipelineState) Advance(newBlock *pb.Block) (toDeliver *pb.Block) {
	candidate := p.Window[0]

	// shift left, insert at tail
	p.Window[0] = p.Window[1]
	p.Window[1] = p.Window[2]
	p.Window[2] = p.Window[3]
	p.Window[3] = newBlock

	if candidate != nil && p.CanCommit() {
		bStar := p.Window[2]
		bDouble := p.Window[1]
		bPrime := p.Window[0]

		if bytes.Equal(bStar.GetParentHash(), hashBlock(bDouble)) &&
			bytes.Equal(bDouble.GetParentHash(), hashBlock(bPrime)) &&
			bytes.Equal(bPrime.GetParentHash(), hashBlock(candidate)) {
			return candidate
		}
	}

	return nil
}

// Reset clears all slots, called on view-change to discard stale proposals.
func (p *PipelineState) Reset() {
	p.Window = [4]*pb.Block{}
}

// CanCommit returns true when all four slots are occupied.
func (p *PipelineState) CanCommit() bool {
	return p.Window[0] != nil &&
		p.Window[1] != nil &&
		p.Window[2] != nil &&
		p.Window[3] != nil
}
