package membership

// Complexity note:
//
// ValidateQC runs in O(n) time where n = len(qc.Signatures):
//   - One linear pass through the signature/signer-ID pairs.
//   - Each step: one map lookup (O(1) amortised), one ReplicaByID scan (O(nc),
//     but nc == n in a well-formed QC), and one signature verification (O(1)
//     ECDSA curve arithmetic).
//
// When the leader broadcasts a block to all nc replicas and each replica calls
// ValidateQC independently, the total work per round is O(nc * nc) = O(n^2).
// This is acceptable for the committee sizes targeted by D-HotStuff (nc <= ~200).
//
// The paper explicitly avoids threshold/aggregate signatures (e.g. BLS via DPSS)
// because the proactive secret-sharing re-sharing protocol has O(n^3) communication
// complexity, which outweighs the O(n) verification saving at practical scales.

import (
	"errors"
	"fmt"

	"crypto/ecdsa"

	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// SignatureVerifier abstracts ECDSA signature verification so that callers can
// inject real crypto or a deterministic stub in tests.
//
// Verify returns true iff sig is a valid DER-encoded ECDSA signature over
// blockHash produced with the private key corresponding to pubKey.
type SignatureVerifier interface {
	Verify(pubKey *ecdsa.PublicKey, blockHash []byte, sig []byte) bool
}

// Sentinel errors for QC validation.
var (
	// ErrInsufficientSignatures is returned when a QC carries fewer distinct
	// signatures than the quorum threshold Qc for the current committee.
	ErrInsufficientSignatures = errors.New("membership: insufficient signatures in QC")

	// ErrDuplicateSigner is returned when the same replica ID appears more than
	// once in qc.SignerIds, which would let a single replica double-count.
	ErrDuplicateSigner = errors.New("membership: duplicate signer ID in QC")

	// ErrUnknownSigner is returned when a signer ID in qc.SignerIds does not
	// match any replica in the current committee Mc.
	ErrUnknownSigner = errors.New("membership: unknown signer ID in QC")

	// ErrBadSignature is returned when a signature does not verify against
	// the corresponding replica's public key and the QC's block hash.
	ErrBadSignature = errors.New("membership: invalid signature in QC")
)

// ValidateQC checks that qc is a well-formed quorum certificate for the
// committee c, using verify to authenticate each individual ECDSA signature.
//
// A valid QC must satisfy all of the following:
//  1. At least Qc = c.QuorumSize() signatures are present.
//  2. len(qc.Signatures) == len(qc.SignerIds) (wire invariant).
//  3. Every signer ID is distinct (no double-counting of votes).
//  4. Every signer ID belongs to a known replica in c.
//  5. Every signature verifies under the corresponding replica's public key
//     over qc.BlockHash.
//
// Returns nil on success, or a sentinel error (possibly wrapped with context)
// on the first failure encountered.
func ValidateQC(qc *pb.QuorumCert, c *Committee, verify SignatureVerifier) error {
	sigs := qc.GetSignatures()
	ids := qc.GetSignerIds()

	// 1. Enough signatures?
	if len(sigs) < c.QuorumSize() {
		return fmt.Errorf("%w: have %d, need %d (Qc) for committee size %d",
			ErrInsufficientSignatures, len(sigs), c.QuorumSize(), c.Size())
	}

	// 2. Wire invariant: parallel slices must be the same length.
	if len(sigs) != len(ids) {
		return fmt.Errorf("%w: signature count %d != signer_id count %d",
			ErrInsufficientSignatures, len(sigs), len(ids))
	}

	seen := make(map[string]bool, len(ids))

	for i, signerID := range ids {
		// 3. Duplicate check.
		if seen[signerID] {
			return fmt.Errorf("%w: %q appears at index %d", ErrDuplicateSigner, signerID, i)
		}
		seen[signerID] = true

		// 4. Signer must be a current committee member.
		replica := c.ReplicaByID(signerID)
		if replica == nil {
			return fmt.Errorf("%w: %q is not in committee Mc=%d", ErrUnknownSigner, signerID, c.Number)
		}

		// 5. Signature must be cryptographically valid.
		if !verify.Verify(replica.PubKey, qc.GetBlockHash(), sigs[i]) {
			return fmt.Errorf("%w: signer %q at index %d", ErrBadSignature, signerID, i)
		}
	}

	return nil
}

// QuorumOf scans votes from distinct signers and returns the first c.QuorumSize()
// that form a quorum, together with a boolean indicating whether enough votes
// were collected.
//
// Duplicate signer IDs are silently skipped (only the first vote per signer is
// kept) so the caller does not need to pre-deduplicate the incoming vote stream.
//
// This is intended for use by the leader when accumulating VoteMsgs: once the
// second return value is true, the leader has enough material to construct a QC.
//
// Complexity: O(len(votes)) time and O(c.QuorumSize()) space.
func QuorumOf(votes []*pb.VoteMsg, c *Committee) ([]*pb.VoteMsg, bool) {
	qSize := c.QuorumSize()
	seen := make(map[string]bool, qSize)
	quorum := make([]*pb.VoteMsg, 0, qSize)

	for _, v := range votes {
		id := v.GetSignerId()
		if seen[id] {
			continue
		}
		seen[id] = true
		quorum = append(quorum, v)
		if len(quorum) >= qSize {
			return quorum, true
		}
	}

	return quorum, false
}
