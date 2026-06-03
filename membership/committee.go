// Package membership implements the committee management layer for D-HotStuff.
//
// A Committee (Mc) represents a single configuration epoch of the BFT cluster.
// The fundamental safety assumption from the paper is:
//
//	nc >= 3·fc + 1
//
// where nc = |Mc| is the committee size for epoch c and fc is the maximum
// number of Byzantine (faulty) replicas tolerated in that epoch.  This bound
// is the classical BFT lower limit: with fewer than 3f+1 participants a
// protocol cannot distinguish f faulty replicas from f slow-but-honest ones,
// making safety and liveness simultaneously impossible.
//
// FaultCap is derived from nc as fc = ⌊(nc−1)/3⌋, which is the largest f
// satisfying the inequality above.
package membership

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// Replica is one committee member in configuration Mc.
type Replica struct {
	// ID is the stable, unique string identity of this replica (e.g. "P1").
	// It matches the signer_id field in VoteMsg and QuorumCert on the wire.
	ID string

	// Addr is the TCP endpoint the replica listens on for peer RPCs (host:port).
	Addr string

	// PubKey is the replica's ECDSA P-256 public key used to verify its votes.
	PubKey *ecdsa.PublicKey
}

// Committee represents configuration Mc as defined in the D-HotStuff paper.
//
// Number is the configuration number c (0 = genesis).
// Replicas is the ordered set of committee members |Mc| = nc.
// FaultCap is fc = ⌊(nc − 1) / 3⌋, the maximum tolerable Byzantine replicas.
type Committee struct {
	// Number is the monotonically increasing configuration epoch (c).
	// The genesis committee has Number = 0.
	Number uint64

	// Replicas is the ordered list of committee members for this epoch.
	// The slice order determines leader rotation (see Leader).
	Replicas []*Replica

	// FaultCap is fc = ⌊(nc − 1) / 3⌋.
	// It is the largest f such that nc >= 3f + 1 holds.
	FaultCap int
}

// NewCommittee constructs a Committee from an ordered replica slice.
// FaultCap is computed automatically.
func NewCommittee(number uint64, replicas []*Replica) *Committee {
	nc := len(replicas)
	fc := 0
	if nc > 0 {
		fc = (nc - 1) / 3
	}
	return &Committee{
		Number:   number,
		Replicas: replicas,
		FaultCap: fc,
	}
}

// Size returns nc, the number of replicas in this configuration.
func (c *Committee) Size() int {
	return len(c.Replicas)
}

// QuorumSize returns Qc = ⌈(nc + fc + 1) / 2⌉, the minimum number of votes
// required to form a valid quorum certificate in configuration c.
//
// Derivation:
//
//	We need Qc > (nc + fc) / 2  (strict majority over the sum of all replicas
//	and faulty replicas, so that any two quorums share at least one honest replica).
//	The smallest integer strictly greater than x is ⌈x + 1/2⌉ = ⌊x⌋ + 1 when x
//	is a non-integer, or x + 1 when x is an integer.  For integer arithmetic:
//	    ⌈(nc + fc + 1) / 2⌉  =  (nc + fc + 1 + 1) / 2  =  (nc + fc + 2) / 2
//	using truncating integer division (equivalent to ceiling when the dividend
//	may be odd).
func (c *Committee) QuorumSize() int {
	nc := len(c.Replicas)
	// Integer ceiling of (nc + fc + 1) / 2.
	// Equivalent to ⌈(nc + fc + 1) / 2⌉ = (nc + fc + 2) / 2 in integer division.
	return (nc + c.FaultCap + 2) / 2
}

// Leader returns the replica that leads view v, following §4.1 of the paper:
// "the leader of view v is the replica at position v mod |Mc|".
//
// Panics if the committee is empty (a well-formed committee always has >= 4 members).
func (c *Committee) Leader(view uint64) *Replica {
	return c.Replicas[view%uint64(len(c.Replicas))]
}

// ReplicaByID returns the first Replica with the given id, or nil if not found.
func (c *Committee) ReplicaByID(id string) *Replica {
	for _, r := range c.Replicas {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// Contains reports whether a replica with the given id is a member of this
// committee.
func (c *Committee) Contains(id string) bool {
	return c.ReplicaByID(id) != nil
}

// Clone returns a shallow copy of the Committee.  The Replicas slice is
// duplicated so that appending to or removing from the copy does not affect
// the original.  The individual *Replica pointers are shared (Replica is
// treated as immutable once created).
func (c *Committee) Clone() *Committee {
	replicas := make([]*Replica, len(c.Replicas))
	copy(replicas, c.Replicas)
	return &Committee{
		Number:   c.Number,
		Replicas: replicas,
		FaultCap: c.FaultCap,
	}
}

// Apply processes a batch of MembershipRequests and returns the next
// configuration Mc+1.  The current Committee is not modified.
//
// For each request:
//   - ADD: req.Payload must be a PKIX DER-encoded ECDSA P-256 public key.
//     A new Replica with ID = req.ClientId is appended.
//   - REMOVE: the replica whose ID equals req.ClientId is removed.
//   - REGULAR: ignored (plain application commands do not change membership).
//
// FaultCap is recomputed for the new committee size.
// The returned committee's Number is c.Number + 1.
func (c *Committee) Apply(reqs []*pb.MembershipRequest) (*Committee, error) {
	next := c.Clone()
	next.Number = c.Number + 1

	for _, req := range reqs {
		switch req.GetType() {
		case pb.RequestType_ADD:
			rawKey, err := x509.ParsePKIXPublicKey(req.GetPayload())
			if err != nil {
				return nil, fmt.Errorf("membership.Apply ADD %q: parse PKIX public key: %w", req.GetClientId(), err)
			}
			ecKey, ok := rawKey.(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("membership.Apply ADD %q: payload is not an ECDSA public key", req.GetClientId())
			}
			next.Replicas = append(next.Replicas, &Replica{
				ID:     req.GetClientId(),
				PubKey: ecKey,
			})

		case pb.RequestType_REMOVE:
			target := req.GetClientId()
			filtered := next.Replicas[:0:0] // fresh slice, zero length, zero cap
			filtered = append(filtered, next.Replicas...)
			out := filtered[:0]
			found := false
			for _, r := range filtered {
				if r.ID == target {
					found = true
					continue
				}
				out = append(out, r)
			}
			if !found {
				return nil, fmt.Errorf("membership.Apply REMOVE: replica %q not in committee", target)
			}
			next.Replicas = out

		case pb.RequestType_REGULAR:
			// REGULAR requests carry application commands; they do not
			// affect committee membership and are intentionally ignored here.

		default:
			return nil, fmt.Errorf("membership.Apply: unknown request type %v", req.GetType())
		}
	}

	// Recompute FaultCap for the new committee size.
	nc := len(next.Replicas)
	if nc > 0 {
		next.FaultCap = (nc - 1) / 3
	} else {
		next.FaultCap = 0
	}

	return next, nil
}

// Validate reports an error if the committee violates the minimum BFT
// requirements:
//   - At least 4 replicas are required (nc >= 3·1 + 1 = 4).
//   - FaultCap >= 1 ensures the protocol can tolerate at least one fault.
func (c *Committee) Validate() error {
	if len(c.Replicas) < 4 {
		return errors.New("membership: committee must have at least 4 replicas (nc >= 3·fc + 1 with fc >= 1)")
	}
	if c.FaultCap < 1 {
		return fmt.Errorf("membership: FaultCap must be >= 1, got %d (nc=%d)", c.FaultCap, len(c.Replicas))
	}
	return nil
}
