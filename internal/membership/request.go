package membership

// request.go — request classification for D-HotStuff batch delivery.
//
// Per paper §4.5: within a committed block, regular (application) commands are
// executed first against the application state machine, then membership-change
// commands (ADD / REMOVE) are applied to derive the next committee Mc+1.
// This ordering ensures that any state transitions triggered by regular
// commands are committed before the committee topology changes.

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// RequestKind classifies a MembershipRequest by its effect on committee state.
type RequestKind int

const (
	// KindRegular represents an ordinary application command that does not
	// modify the committee membership.
	KindRegular RequestKind = iota

	// KindAdd represents a request to admit a new replica into the committee.
	KindAdd

	// KindRemove represents a request to expel an existing replica from the
	// committee.
	KindRemove
)

// String returns a human-readable label for the RequestKind (useful in logs).
func (k RequestKind) String() string {
	switch k {
	case KindRegular:
		return "REGULAR"
	case KindAdd:
		return "ADD"
	case KindRemove:
		return "REMOVE"
	default:
		return fmt.Sprintf("RequestKind(%d)", int(k))
	}
}

// kindOf maps a proto RequestType to our local RequestKind.
func kindOf(rt pb.RequestType) RequestKind {
	switch rt {
	case pb.RequestType_ADD:
		return KindAdd
	case pb.RequestType_REMOVE:
		return KindRemove
	default:
		return KindRegular
	}
}

// ClassifyBatch partitions batch into two ordered sub-slices:
//   - regular: all REGULAR requests, in original order.
//   - membership: all ADD and REMOVE requests, in original order.
//
// Per §4.5 of the paper, the regular slice should be delivered to the
// application state machine before the membership slice is applied to derive
// the next committee configuration.
//
// The input slice is not modified; both output slices reference the same
// underlying *MembershipRequest pointers.
func ClassifyBatch(batch []*pb.MembershipRequest) (regular, membership []*pb.MembershipRequest) {
	for _, req := range batch {
		switch kindOf(req.GetType()) {
		case KindRegular:
			regular = append(regular, req)
		default: // KindAdd, KindRemove
			membership = append(membership, req)
		}
	}
	return regular, membership
}

// HasMembershipRequests reports whether batch contains at least one ADD or
// REMOVE request.  The leader uses this to decide whether to trigger a config
// transition after committing the block.
func HasMembershipRequests(batch []*pb.MembershipRequest) bool {
	for _, req := range batch {
		if kindOf(req.GetType()) != KindRegular {
			return true
		}
	}
	return false
}

// ValidateMembershipRequest checks that req is semantically valid with respect
// to the current committee configuration:
//
//   - ADD: req.Payload must be a PKIX DER-encoded ECDSA public key, and the
//     replica identified by req.ClientId must not already be a committee member.
//   - REMOVE: req.ClientId must identify a current committee member.
//   - REGULAR: always valid (no membership constraints).
//
// Returns a descriptive error on the first constraint violation, or nil.
func ValidateMembershipRequest(req *pb.MembershipRequest, current *Committee) error {
	switch kindOf(req.GetType()) {
	case KindAdd:
		// Payload must be a parseable PKIX ECDSA public key.
		rawKey, err := x509.ParsePKIXPublicKey(req.GetPayload())
		if err != nil {
			return fmt.Errorf("membership: ADD %q: malformed PKIX public key in payload: %w",
				req.GetClientId(), err)
		}
		if _, ok := rawKey.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("membership: ADD %q: payload key is not ECDSA (got %T)",
				req.GetClientId(), rawKey)
		}
		// The replica must not already be a member.
		if current.Contains(req.GetClientId()) {
			return fmt.Errorf("membership: ADD %q: replica is already in committee Mc=%d",
				req.GetClientId(), current.Number)
		}

	case KindRemove:
		// The replica to remove must be a current member.
		if !current.Contains(req.GetClientId()) {
			return fmt.Errorf("membership: REMOVE %q: replica is not in committee Mc=%d",
				req.GetClientId(), current.Number)
		}

	case KindRegular:
		// No membership constraints; always valid.
	}

	return nil
}

// ReplicaFromRequest parses an ADD MembershipRequest into a *Replica.
//
// The req.Payload must be a PKIX DER-encoded ECDSA P-256 public key (the same
// format written by cmd/keygen and expected by Committee.Apply).
// The returned Replica has ID = req.ClientId; Addr is left empty because the
// network address is not carried in the membership request payload.
//
// Returns an error if req is not an ADD request or if the payload is malformed.
func ReplicaFromRequest(req *pb.MembershipRequest) (*Replica, error) {
	if kindOf(req.GetType()) != KindAdd {
		return nil, fmt.Errorf("membership: ReplicaFromRequest: expected ADD request, got %s",
			req.GetType())
	}
	if len(req.GetPayload()) == 0 {
		return nil, errors.New("membership: ReplicaFromRequest: payload is empty")
	}

	rawKey, err := x509.ParsePKIXPublicKey(req.GetPayload())
	if err != nil {
		return nil, fmt.Errorf("membership: ReplicaFromRequest: parse PKIX public key: %w", err)
	}
	ecKey, ok := rawKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("membership: ReplicaFromRequest: payload is not an ECDSA public key (got %T)", rawKey)
	}

	return &Replica{
		ID:     req.GetClientId(),
		PubKey: ecKey,
	}, nil
}
