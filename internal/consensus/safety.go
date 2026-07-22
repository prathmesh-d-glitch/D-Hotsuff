// Package consensus implements the D-HotStuff BFT consensus protocol.
// safeNode predicate: vote only if the block extends the lock OR the QC is newer.
package consensus

import (
	"bytes"
	"crypto/sha256"

	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// BlockchainReader is the read-only view of the local block store.
type BlockchainReader interface {
	Get(hash []byte) (*pb.Block, bool)
	Extends(childHash, ancestorHash []byte) bool
}

// SafetyState holds the per-replica lock and highest-known QC.
type SafetyState struct {
	LockedQC  *pb.QuorumCert // nil until first two-chain
	GenericQC *pb.QuorumCert // highest QC seen so far
}

// SafeNode returns true if it is safe to vote for node.
// Passes if: no lock yet, OR qc is newer than the lock, OR node extends the locked block.
func (s *SafetyState) SafeNode(node *pb.Block, qc *pb.QuorumCert, bc BlockchainReader) bool {
	if s.LockedQC == nil {
		return true // genesis — nothing locked yet
	}
	if qc.GetViewNumber() > s.LockedQC.GetViewNumber() {
		return true // newer quorum overrides the lock (liveness)
	}
	return bc.Extends(node.GetParentHash(), s.LockedQC.GetBlockHash()) // safety
}

// UpdateOnOneChain updates GenericQC when bStar directly certifies bDouble.
func (s *SafetyState) UpdateOnOneChain(bStar, bDouble *pb.Block) {
	if bytes.Equal(bStar.GetParentHash(), hashBlock(bDouble)) {
		s.GenericQC = bStar.GetJustify()
	}
}

// UpdateOnTwoChain updates LockedQC when a two-chain is observed.
func (s *SafetyState) UpdateOnTwoChain(bStar, bDouble, bPrime *pb.Block) {
	if !bytes.Equal(bStar.GetParentHash(), hashBlock(bDouble)) {
		return
	}
	if bytes.Equal(bDouble.GetParentHash(), hashBlock(bPrime)) {
		s.LockedQC = bDouble.GetJustify()
	}
}

// hashBlock returns SHA-256(parentHash || height_BE8).
func hashBlock(b *pb.Block) []byte {
	h := sha256.New()
	h.Write(b.GetParentHash())

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
	h.Write(heightBuf[:])

	return h.Sum(nil)
}
