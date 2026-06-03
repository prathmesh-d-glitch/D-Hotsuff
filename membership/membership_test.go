package membership_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prathmesh-d-glitch/d-hotstuff/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeReplicas returns n placeholder replicas with IDs "P1", "P2", …, "Pn".
// PubKey is left nil for tests that do not exercise signature verification.
func makeReplicas(t *testing.T, n int) []*membership.Replica {
	t.Helper()
	reps := make([]*membership.Replica, n)
	for i := range reps {
		reps[i] = &membership.Replica{
			ID:   idFor(i + 1),
			Addr: addrFor(i + 1),
		}
	}
	return reps
}

// makeReplicasWithKeys returns n replicas each with a fresh ECDSA P-256 key.
func makeReplicasWithKeys(t *testing.T, n int) ([]*membership.Replica, []*ecdsa.PrivateKey) {
	t.Helper()
	reps := make([]*membership.Replica, n)
	keys := make([]*ecdsa.PrivateKey, n)
	for i := range reps {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "generate key for replica %d", i+1)
		keys[i] = priv
		reps[i] = &membership.Replica{
			ID:     idFor(i + 1),
			Addr:   addrFor(i + 1),
			PubKey: &priv.PublicKey,
		}
	}
	return reps, keys
}

func idFor(i int) string   { return "P" + itoa(i) }
func addrFor(i int) string { return "127.0.0.1:800" + itoa(i) }

func itoa(i int) string {
	// Simple int→string without importing strconv at package level.
	const digits = "0123456789"
	if i < 10 {
		return string(digits[i])
	}
	return itoa(i/10) + string(digits[i%10])
}

// makeCommittee wraps membership.NewCommittee for brevity.
func makeCommittee(t *testing.T, n int) *membership.Committee {
	t.Helper()
	return membership.NewCommittee(0, makeReplicas(t, n))
}

// pkixPublicKey DER-encodes pub into a PKIX blob suitable for MembershipRequest.Payload.
func pkixPublicKey(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return der
}

// ---------------------------------------------------------------------------
// mockVerifier — deterministic SignatureVerifier for tests.
// ---------------------------------------------------------------------------

// mockVerifier accepts or rejects every verification call based on the
// acceptAll flag.  It records all calls so tests can assert on them.
type mockVerifier struct {
	acceptAll bool
}

func (m *mockVerifier) Verify(_ *ecdsa.PublicKey, _, _ []byte) bool {
	return m.acceptAll
}

// alwaysAccept returns a SignatureVerifier that accepts every signature.
var alwaysAccept = &mockVerifier{acceptAll: true}

// alwaysReject returns a SignatureVerifier that rejects every signature.
var alwaysReject = &mockVerifier{acceptAll: false}

// ---------------------------------------------------------------------------
// TestQuorumSize
// ---------------------------------------------------------------------------

func TestQuorumSize(t *testing.T) {
	t.Parallel()

	cases := []struct {
		n      int
		wantFc int
		wantQc int
	}{
		{n: 4, wantFc: 1, wantQc: 3},
		{n: 7, wantFc: 2, wantQc: 5},
		{n: 10, wantFc: 3, wantQc: 7},
		{n: 16, wantFc: 5, wantQc: 11},
		{n: 31, wantFc: 10, wantQc: 21},
	}

	for _, tc := range cases {
		tc := tc // capture
		t.Run(itoa(tc.n)+"-replicas", func(t *testing.T) {
			t.Parallel()
			c := makeCommittee(t, tc.n)

			require.Equal(t, tc.wantFc, c.FaultCap,
				"FaultCap: n=%d", tc.n)
			require.Equal(t, tc.wantQc, c.QuorumSize(),
				"QuorumSize: n=%d", tc.n)

			// Verify the BFT safety invariant nc >= 3*fc + 1.
			require.GreaterOrEqual(t, tc.n, 3*tc.wantFc+1,
				"BFT invariant nc >= 3*fc+1 violated for n=%d, fc=%d", tc.n, tc.wantFc)
		})
	}
}

// ---------------------------------------------------------------------------
// TestLeaderRotation
// ---------------------------------------------------------------------------

func TestLeaderRotation(t *testing.T) {
	t.Parallel()

	c := makeCommittee(t, 4) // P1, P2, P3, P4

	tests := []struct {
		view       uint64
		wantLeader string
	}{
		{0, "P1"},
		{1, "P2"},
		{2, "P3"},
		{3, "P4"},
		{4, "P1"}, // wraps around
		{8, "P1"}, // 8 mod 4 = 0
		{9, "P2"}, // 9 mod 4 = 1
	}

	for _, tc := range tests {
		tc := tc
		t.Run("view-"+itoa(int(tc.view)), func(t *testing.T) {
			t.Parallel()
			leader := c.Leader(tc.view)
			require.NotNil(t, leader)
			require.Equal(t, tc.wantLeader, leader.ID,
				"Leader(view=%d)", tc.view)
		})
	}
}

// ---------------------------------------------------------------------------
// TestConfigStoreInstallOrder
// ---------------------------------------------------------------------------

func TestConfigStoreInstallOrder(t *testing.T) {
	t.Parallel()

	genesis := makeCommittee(t, 4)
	store := membership.NewConfigStore(genesis)

	// Installing a committee with Number = 0 again must fail (already at 1).
	bad := membership.NewCommittee(0, makeReplicas(t, 4))
	err := store.Install(bad)
	require.ErrorIs(t, err, membership.ErrOutOfOrder,
		"installing config 0 a second time should return ErrOutOfOrder")

	// Jumping ahead to Number = 2 without installing 1 must also fail.
	jump := membership.NewCommittee(2, makeReplicas(t, 4))
	err = store.Install(jump)
	require.ErrorIs(t, err, membership.ErrOutOfOrder,
		"installing config 2 before config 1 should return ErrOutOfOrder")

	// Correct successor (Number = 1) must succeed.
	next := membership.NewCommittee(1, makeReplicas(t, 5))
	require.NoError(t, store.Install(next))
	require.Equal(t, 2, store.Len())
	require.Equal(t, uint64(1), store.Latest().Number)

	// AtNumber returns ErrNotFound for numbers beyond the store.
	_, err = store.AtNumber(99)
	require.ErrorIs(t, err, membership.ErrNotFound)
}

// ---------------------------------------------------------------------------
// TestCommitteeApplyAdd
// ---------------------------------------------------------------------------

func TestCommitteeApplyAdd(t *testing.T) {
	t.Parallel()

	c := makeCommittee(t, 4) // M0 with 4 replicas

	// Generate a fresh key for the new replica.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	addReq := &pb.MembershipRequest{
		Type:     pb.RequestType_ADD,
		ClientId: "P5",
		Payload:  pkixPublicKey(t, &priv.PublicKey),
	}

	next, err := c.Apply([]*pb.MembershipRequest{addReq})
	require.NoError(t, err)

	require.Equal(t, uint64(1), next.Number, "Number should increment to 1")
	require.Equal(t, 5, next.Size(), "committee should have 5 replicas after ADD")
	require.True(t, next.Contains("P5"), "new replica P5 should be in next committee")
	require.False(t, c.Contains("P5"), "original committee must be unchanged (immutability)")
}

// ---------------------------------------------------------------------------
// TestCommitteeApplyRemove
// ---------------------------------------------------------------------------

func TestCommitteeApplyRemove(t *testing.T) {
	t.Parallel()

	c := makeCommittee(t, 4) // M0: P1, P2, P3, P4
	require.True(t, c.Contains("P3"))

	removeReq := &pb.MembershipRequest{
		Type:     pb.RequestType_REMOVE,
		ClientId: "P3",
	}

	next, err := c.Apply([]*pb.MembershipRequest{removeReq})
	require.NoError(t, err)

	require.Equal(t, uint64(1), next.Number, "Number should increment to 1")
	require.Equal(t, 3, next.Size(), "committee should have 3 replicas after REMOVE")
	require.False(t, next.Contains("P3"), "P3 should be absent from next committee")
	require.True(t, c.Contains("P3"), "original committee must be unchanged (immutability)")

	// Removing a non-member must fail.
	_, err = c.Apply([]*pb.MembershipRequest{{
		Type:     pb.RequestType_REMOVE,
		ClientId: "P99",
	}})
	require.Error(t, err, "removing a non-member should return an error")
}

// ---------------------------------------------------------------------------
// TestValidateQC
// ---------------------------------------------------------------------------

// buildQC assembles a QuorumCert with the given signer IDs and a stub
// signature for each.  blockHash is shared across all signatures.
func buildQC(t *testing.T, blockHash []byte, signerIDs []string) *pb.QuorumCert {
	t.Helper()
	sigs := make([][]byte, len(signerIDs))
	for i := range sigs {
		sigs[i] = []byte("stub-sig") // opaque bytes; content verified by mock
	}
	return &pb.QuorumCert{
		BlockHash:  blockHash,
		Signatures: sigs,
		SignerIds:  signerIDs,
	}
}

func TestValidateQC(t *testing.T) {
	t.Parallel()

	// 4-replica committee: P1–P4, fc=1, Qc=3.
	reps, _ := makeReplicasWithKeys(t, 4)
	c := membership.NewCommittee(0, reps)

	blockHash := []byte("fake-block-hash-32-bytes-padded!!")

	t.Run("not-enough-signatures", func(t *testing.T) {
		t.Parallel()
		// Only 2 sigs for a committee that needs Qc=3.
		qc := buildQC(t, blockHash, []string{"P1", "P2"})
		err := membership.ValidateQC(qc, c, alwaysAccept)
		require.ErrorIs(t, err, membership.ErrInsufficientSignatures)
	})

	t.Run("duplicate-signer", func(t *testing.T) {
		t.Parallel()
		// P1 appears twice — only one unique signer despite 3 entries.
		qc := buildQC(t, blockHash, []string{"P1", "P2", "P1"})
		err := membership.ValidateQC(qc, c, alwaysAccept)
		require.ErrorIs(t, err, membership.ErrDuplicateSigner)
	})

	t.Run("unknown-signer", func(t *testing.T) {
		t.Parallel()
		// "P99" is not in the committee.
		qc := buildQC(t, blockHash, []string{"P1", "P2", "P99"})
		err := membership.ValidateQC(qc, c, alwaysAccept)
		require.ErrorIs(t, err, membership.ErrUnknownSigner)
	})

	t.Run("bad-signature", func(t *testing.T) {
		t.Parallel()
		qc := buildQC(t, blockHash, []string{"P1", "P2", "P3"})
		err := membership.ValidateQC(qc, c, alwaysReject)
		require.ErrorIs(t, err, membership.ErrBadSignature)
	})

	t.Run("valid-qc", func(t *testing.T) {
		t.Parallel()
		qc := buildQC(t, blockHash, []string{"P1", "P2", "P3"})
		err := membership.ValidateQC(qc, c, alwaysAccept)
		require.NoError(t, err, "a well-formed QC with Qc=3 distinct known signers should pass")
	})

	t.Run("exactly-quorum-size-passes", func(t *testing.T) {
		t.Parallel()
		// Qc = 3 for n=4; exactly 3 distinct valid signers must succeed.
		qc := buildQC(t, blockHash, []string{"P2", "P3", "P4"})
		require.NoError(t, membership.ValidateQC(qc, c, alwaysAccept))
	})

	t.Run("more-than-quorum-passes", func(t *testing.T) {
		t.Parallel()
		// All 4 signers — exceeds Qc; still valid.
		qc := buildQC(t, blockHash, []string{"P1", "P2", "P3", "P4"})
		require.NoError(t, membership.ValidateQC(qc, c, alwaysAccept))
	})
}
