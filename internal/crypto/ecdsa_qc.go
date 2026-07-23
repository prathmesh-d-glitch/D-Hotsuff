// Package crypto (continued) — quorum certificate helpers.
package crypto

import (
	"errors"
	"fmt"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// ErrNotEnoughVotes is returned when there are too few votes to form a QC.
var ErrNotEnoughVotes = errors.New("crypto: not enough votes to form a quorum certificate")

// CreateQC assembles a QuorumCert from votes for committee c.
// De-duplicates by SignerId and takes the first QuorumSize() distinct votes.
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

	// check again after de-duplication
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

// AggregateVotes appends incoming to existing only if its SignerId is new.
func AggregateVotes(existing []*pb.VoteMsg, incoming *pb.VoteMsg) []*pb.VoteMsg {
	id := incoming.GetSignerId()
	for _, v := range existing {
		if v.GetSignerId() == id {
			return existing // duplicate, discard
		}
	}
	return append(existing, incoming)
}

// HasQuorum returns true when votes contains at least QuorumSize() distinct signers.
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
