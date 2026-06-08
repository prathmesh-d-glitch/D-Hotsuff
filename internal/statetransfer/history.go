// Package statetransfer implements join-time state synchronization for
// D-HotStuff.
//
// When a new replica is added to the committee (via an ADD membership
// request), it must obtain the execution history from existing members
// before it can participate in consensus.
//
// From Algorithm 2, line 4: "for batch ∈ hist do mark batch as delivered".
//
// History grows linearly with blocks (Fig. 3 in the paper shows linear join
// latency increase).  Use snapshots (statetransfer/syncer.go) to bound this
// in production deployments.
package statetransfer

import (
	"crypto/sha256"
	"errors"
	"fmt"

	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// ErrOutOfOrder is returned by Append when the block's height does not match
// the expected next height in the execution history.
var ErrOutOfOrder = errors.New("statetransfer: block height is out of order")

// ExecutionHistory is an ordered, append-only log of committed blocks that
// a joining replica replays to reconstruct the application state.
//
// Blocks are indexed by height (0 = genesis).  The history is valid iff
// every block's Height field equals its index in the Blocks slice.
type ExecutionHistory struct {
	// Blocks holds all committed blocks in ascending height order.
	Blocks []*pb.Block
}

// NewExecutionHistory creates an empty execution history ready for appending.
func NewExecutionHistory() *ExecutionHistory {
	return &ExecutionHistory{}
}

// Append adds block to the end of the history.
//
// The block's Height field must equal len(h.Blocks) — that is, it must be
// the immediate successor of the current tail.  This enforces strict
// monotonicity so that the replay logic in Syncer can rely on contiguous
// heights.
//
// Returns ErrOutOfOrder if the height does not match.
func (h *ExecutionHistory) Append(block *pb.Block) error {
	expected := uint64(len(h.Blocks))
	if block.GetHeight() != expected {
		return fmt.Errorf("%w: expected height %d, got %d",
			ErrOutOfOrder, expected, block.GetHeight())
	}
	h.Blocks = append(h.Blocks, block)
	return nil
}

// Since returns all blocks from height onwards.
//
// This is used for delta synchronization when the joining replica already
// has a snapshot up to some height and only needs the remaining blocks.
//
// If height >= len(h.Blocks), an empty slice is returned.
func (h *ExecutionHistory) Since(height uint64) []*pb.Block {
	if height >= uint64(len(h.Blocks)) {
		return nil
	}
	return h.Blocks[height:]
}

// Len returns the number of committed blocks in the history.
func (h *ExecutionHistory) Len() int {
	return len(h.Blocks)
}

// LatestHeight returns the height of the most recent block, or -1 if empty.
func (h *ExecutionHistory) LatestHeight() int64 {
	if len(h.Blocks) == 0 {
		return -1
	}
	return int64(len(h.Blocks) - 1)
}

// Hash computes a SHA-256 fingerprint of the entire history by concatenating
// the hashes of all block hashes.
//
// A joining replica uses this to verify that 2fc+1 responses from existing
// replicas agree on the same execution history (Algorithm 2, line 3).
//
// Formally: Hash = SHA-256( blockHash(b0) || blockHash(b1) || … || blockHash(bn) )
// where blockHash uses the same canonical encoding as the consensus layer
// (parent_hash || height_BE_8).
func (h *ExecutionHistory) Hash() []byte {
	hasher := sha256.New()
	for _, b := range h.Blocks {
		hasher.Write(blockDigest(b))
	}
	sum := hasher.Sum(nil)
	return sum
}

// ToProto serializes the execution history into a HistoryResponse message
// suitable for sending over the wire.
func (h *ExecutionHistory) ToProto() *pb.HistoryResponse {
	return &pb.HistoryResponse{
		History: h.Blocks,
	}
}

// HistoryFromProto deserializes a HistoryResponse into an ExecutionHistory.
//
// Validation: heights must be contiguous starting at 0.  Returns an error
// if any block's height does not match its position.
func HistoryFromProto(resp *pb.HistoryResponse) (*ExecutionHistory, error) {
	hist := &ExecutionHistory{
		Blocks: make([]*pb.Block, 0, len(resp.GetHistory())),
	}
	for i, b := range resp.GetHistory() {
		if b.GetHeight() != uint64(i) {
			return nil, fmt.Errorf(
				"statetransfer: non-contiguous history: block at index %d has height %d",
				i, b.GetHeight())
		}
		hist.Blocks = append(hist.Blocks, b)
	}
	return hist, nil
}

// blockDigest computes the canonical SHA-256 hash of a block, matching the
// consensus layer's hashBlock function: SHA-256(parent_hash || height_BE_8).
func blockDigest(b *pb.Block) []byte {
	hasher := sha256.New()
	hasher.Write(b.GetParentHash())

	var heightBuf [8]byte
	height := b.GetHeight()
	heightBuf[0] = byte(height >> 56)
	heightBuf[1] = byte(height >> 48)
	heightBuf[2] = byte(height >> 40)
	heightBuf[3] = byte(height >> 32)
	heightBuf[4] = byte(height >> 24)
	heightBuf[5] = byte(height >> 16)
	heightBuf[6] = byte(height >> 8)
	heightBuf[7] = byte(height)
	hasher.Write(heightBuf[:])

	return hasher.Sum(nil)
}
