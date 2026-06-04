// Package crypto (continued) — quorum certificate creation.
//
// Efficiency analysis (D-HotStuff paper §5.1):
//
//	• A QC carries O(n) signatures, one per quorum member (Qc ≈ 2n/3).
//	• The leader broadcasts the QC-bearing block to all nc replicas, so
//	  each round incurs O(nc) messages × O(nc) authenticators = O(n^2) total.
//	• In the worst case there are O(n) view changes per configuration epoch,
//	  giving O(n^3) authenticators overall — equal to the DPSS threshold-sig
//	  baseline but without the latency of the re-sharing sub-protocol.
//
// This file is intentionally free of any blocking I/O; all crypto work
// (signature generation / verification) lives in signer.go.
package crypto

import (
	"errors"
	"fmt"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// ErrNotEnoughVotes is returned by CreateQC when the number of distinct valid
// votes is less than the quorum threshold Qc for the current committee.
var ErrNotEnoughVotes = errors.New("crypto: not enough votes to form a quorum certificate")

// CreateQC assembles a QuorumCert from a slice of VoteMsgs for committee c.
//
// Steps:
//  1. Validate that len(votes) >= c.QuorumSize(); return ErrNotEnoughVotes otherwise.
//  2. De-duplicate by SignerId — keep only the first vote from each replica.
//     Stop collecting once exactly c.QuorumSize() distinct votes are gathered.
//  3. Copy ViewNumber, ConfNumber, and BlockHash from votes[0] (all honest
//     votes in the same round share these fields by construction).
//  4. Populate Signatures and SignerIds in the same order.
//
// The caller is responsible for ensuring that the votes have already been
// individually verified (via Verify) before calling CreateQC, so this function
// does not re-verify signatures.
func CreateQC(votes []*pb.VoteMsg, c *membership.Committee) (*pb.QuorumCert, error) {
	if len(votes) < c.QuorumSize() {
		return nil, fmt.Errorf("%w: have %d votes, need %d (Qc) for committee size %d",
			ErrNotEnoughVotes, len(votes), c.QuorumSize(), c.Size())
	}

	qSize := c.QuorumSize()
	seen := make(map[string]bool, qSize)
	sigs := make([][]byte, 0, qSize)
	ids := make([]string, 0, qSize)

	for _, v := range votes {
		id := v.GetSignerId()
		if seen[id] {
			continue
		}
		seen[id] = true
		sigs = append(sigs, v.GetSignature())
		ids = append(ids, id)
		if len(sigs) >= qSize {
			break
		}
	}

	// Recheck after de-duplication: the slice might have had fewer than Qc
	// distinct signers even though len(votes) >= Qc.
	if len(sigs) < qSize {
		return nil, fmt.Errorf("%w: only %d distinct signers after deduplication, need %d",
			ErrNotEnoughVotes, len(sigs), qSize)
	}

	ref := votes[0]
	qc := &pb.QuorumCert{
		ViewNumber: ref.GetViewNumber(),
		ConfNumber: ref.GetConfNumber(),
		BlockHash:  ref.GetBlockHash(),
		Signatures: sigs,
		SignerIds:  ids,
	}

	return qc, nil
}

// AggregateVotes appends incoming to existing only if incoming.SignerId has not
// already been seen in existing.  This is called by the leader each time a
// VoteMsg arrives from a replica.
//
// The returned slice may be existing unchanged (if the vote was a duplicate) or
// a new slice with one additional element.  Use HasQuorum to test whether
// enough distinct votes have been collected to call CreateQC.
//
// Complexity: O(len(existing)) per call; amortised O(nc^2) to accumulate a
// full round of votes — acceptable given nc <= ~200.
func AggregateVotes(existing []*pb.VoteMsg, incoming *pb.VoteMsg) []*pb.VoteMsg {
	id := incoming.GetSignerId()
	for _, v := range existing {
		if v.GetSignerId() == id {
			return existing // duplicate, discard
		}
	}
	return append(existing, incoming)
}

// HasQuorum reports whether votes contains at least c.QuorumSize() distinct
// signer IDs.  The leader calls this after each AggregateVotes to decide
// whether to invoke CreateQC.
//
// Complexity: O(len(votes)).
func HasQuorum(votes []*pb.VoteMsg, c *membership.Committee) bool {
	seen := make(map[string]bool, c.QuorumSize())
	for _, v := range votes {
		seen[v.GetSignerId()] = true
		if len(seen) >= c.QuorumSize() {
			return true
		}
	}
	return false
}
