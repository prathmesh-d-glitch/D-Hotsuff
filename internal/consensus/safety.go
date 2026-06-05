// Package consensus implements the core D-HotStuff BFT consensus protocol,
// including the safeNode predicate, safety state management, and the
// three-chain commit rule.
//
// The safeNode predicate (Algorithm 1, D-HotStuff paper) controls which
// proposed blocks a replica is willing to vote for.  It has two clauses:
//
//  1. Safety rule — the new block extends the currently locked block.
//     This prevents equivocation: a replica that has locked on a value
//     will not vote for an incompatible branch.
//
//  2. Liveness rule — the justifying QC is newer than the locked QC.
//     This allows the protocol to make progress even if a lock was set
//     during a view that failed to reach commit, by letting a newer
//     quorum override the stale lock.
//
// Reference: D-HotStuff Algorithm 1, lines 8–9.
package consensus

import (
	"bytes"
	"crypto/sha256"

	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// BlockchainReader provides read-only access to the local chain of committed
// and pending blocks.  The consensus layer uses it to check ancestry without
// taking ownership of the storage layer.
type BlockchainReader interface {
	// Get retrieves a block by its SHA-256 hash.
	// Returns (block, true) if found, (nil, false) otherwise.
	Get(hash []byte) (*pb.Block, bool)

	// Extends reports whether childHash refers to a block that descends from
	// (or equals) ancestorHash in the parent-chain.
	// Used by the Safety rule of safeNode.
	Extends(childHash, ancestorHash []byte) bool
}

// SafetyState holds the per-replica mutable safety variables defined in
// Algorithm 3 of the D-HotStuff paper.
//
//   - LockedQC:  the highest QC for which this replica has sent a commit vote
//     (nil at genesis — no lock yet).
//   - GenericQC: the highest QC this replica knows of (the "highQC" in the
//     paper's pseudocode), used by the leader to form the next block's justify.
type SafetyState struct {
	// LockedQC is the quorum certificate that this replica is currently locked
	// on (Algorithm 3, line 17).  Nil until the first two-chain is observed.
	LockedQC *pb.QuorumCert

	// GenericQC is the highest quorum certificate known to this replica
	// (Algorithm 3, line 18).  Updated whenever a one-chain is observed.
	GenericQC *pb.QuorumCert
}

// SafeNode implements the safeNode(node, qc) predicate from Algorithm 1.
//
// A replica votes for node only if SafeNode returns true.  The predicate
// has two independent clauses — either is sufficient:
//
//	safeNode(node, qc) =
//	    (node extends lockedQC.node)      // Safety rule
//	    OR
//	    (qc.viewNumber > lockedQC.viewNumber)  // Liveness rule
//
// Genesis case: if no lock has been set yet (s.LockedQC == nil), every
// well-formed block is trivially safe.
//
// Reference: D-HotStuff Algorithm 1, lines 8–9.
func (s *SafetyState) SafeNode(node *pb.Block, qc *pb.QuorumCert, bc BlockchainReader) bool {
	// Genesis case: no lock has been established yet; accept anything.
	if s.LockedQC == nil {
		return true
	}

	// Liveness rule (Algorithm 1, line 9, second clause):
	// A quorum certificate newer than our lock proves that at least Qc honest
	// replicas have moved on, so it is safe to follow them.
	if qc.GetViewNumber() > s.LockedQC.GetViewNumber() {
		return true
	}

	// Safety rule (Algorithm 1, line 9, first clause):
	// The proposed block must extend the block certified by our lock.
	// This prevents voting for a fork that diverges from the locked chain.
	return bc.Extends(node.GetParentHash(), s.LockedQC.GetBlockHash())
}

// UpdateOnOneChain updates GenericQC when a one-chain is observed.
//
// A one-chain is the condition:
//
//	bStar.ParentHash == hash(bDouble)
//
// meaning bStar's justify QC directly certifies bDouble.  When this holds,
// bStar.Justify becomes the new highest-known QC.
//
// Reference: Algorithm 3, lines 21–22.
func (s *SafetyState) UpdateOnOneChain(bStar, bDouble *pb.Block) {
	// Algorithm 3, line 21: one-chain condition.
	if bytes.Equal(bStar.GetParentHash(), hashBlock(bDouble)) {
		// Algorithm 3, line 22: update genericQC to the higher QC.
		s.GenericQC = bStar.GetJustify()
	}
}

// UpdateOnTwoChain updates LockedQC when a two-chain is observed.
//
// A two-chain requires both:
//
//	bStar.ParentHash  == hash(bDouble)   (one-chain, computed first)
//	bDouble.ParentHash == hash(bPrime)   (extends the one-chain by one step)
//
// When both hold, bDouble.Justify becomes the new locked QC, recording that
// the committee has formed consecutive quorums on bDouble → bPrime.
//
// Reference: Algorithm 3, lines 23–24.
func (s *SafetyState) UpdateOnTwoChain(bStar, bDouble, bPrime *pb.Block) {
	// Algorithm 3, line 23: verify one-chain first.
	oneChain := bytes.Equal(bStar.GetParentHash(), hashBlock(bDouble))
	if !oneChain {
		return
	}

	// Algorithm 3, line 24: two-chain condition — bDouble extends bPrime.
	if bytes.Equal(bDouble.GetParentHash(), hashBlock(bPrime)) {
		s.LockedQC = bDouble.GetJustify()
	}
}

// hashBlock returns the canonical SHA-256 digest of b used throughout the
// consensus layer to identify blocks.
//
// The digest covers: b.ParentHash || b.Height (8 bytes big-endian).
// This function is package-internal; external code should rely on the
// BlockHash field carried inside QuorumCert and VoteMsg.
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
