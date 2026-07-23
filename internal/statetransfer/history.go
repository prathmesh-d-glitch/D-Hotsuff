// Package statetransfer handles join-time history sync for D-HotStuff.
// New replicas replay the committed block history before joining consensus.
package statetransfer

import (
	"crypto/sha256"
	"errors"
	"fmt"

	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// ErrOutOfOrder is returned when a block's height doesn't match what's expected next.
var ErrOutOfOrder = errors.New("statetransfer: block height is out of order")

// ExecutionHistory is an ordered, append-only log of committed blocks.
type ExecutionHistory struct {
	Blocks []*pb.Block
}

// NewExecutionHistory creates an empty history.
func NewExecutionHistory() *ExecutionHistory {
	return &ExecutionHistory{}
}

// Append adds block to the history. Height must equal the current length.
func (h *ExecutionHistory) Append(block *pb.Block) error {
	expected := uint64(len(h.Blocks))
	if block.GetHeight() != expected {
		return fmt.Errorf("%w: expected height %d, got %d",
			ErrOutOfOrder, expected, block.GetHeight())
	}
	h.Blocks = append(h.Blocks, block)
	return nil
}

// Since returns all blocks from height onwards (for delta sync).
func (h *ExecutionHistory) Since(height uint64) []*pb.Block {
	if height >= uint64(len(h.Blocks)) {
		return nil
	}
	return h.Blocks[height:]
}

// Len returns the number of committed blocks.
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

// Hash returns a SHA-256 fingerprint of the full history.
// Joining replicas use this to confirm 2fc+1 peers agree on the same history.
func (h *ExecutionHistory) Hash() []byte {
	hasher := sha256.New()
	for _, b := range h.Blocks {
		hasher.Write(blockDigest(b))
	}
	return hasher.Sum(nil)
}

// ToProto serializes the history for wire transfer.
func (h *ExecutionHistory) ToProto() *pb.HistoryResponse {
	return &pb.HistoryResponse{
		History: h.Blocks,
	}
}

// HistoryFromProto deserializes a HistoryResponse into an ExecutionHistory.
// Returns an error if heights are not contiguous starting from 0.
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

// blockDigest computes SHA-256(parentHash || height_BE8) — same as consensus hashBlock.
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
