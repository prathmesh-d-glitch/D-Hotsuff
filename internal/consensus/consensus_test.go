package consensus

import (
	"bytes"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeBlockchain implements BlockchainReader using an in-memory map.
//
// Extends performs a BFS walk up parent links to determine ancestry.
type fakeBlockchain struct {
	blocks map[string]*pb.Block // hex(hash) → block
}

func newFakeBlockchain() *fakeBlockchain {
	return &fakeBlockchain{blocks: make(map[string]*pb.Block)}
}

func (f *fakeBlockchain) Add(b *pb.Block) {
	h := hashBlock(b)
	f.blocks[string(h)] = b
}

func (f *fakeBlockchain) Get(hash []byte) (*pb.Block, bool) {
	b, ok := f.blocks[string(hash)]
	return b, ok
}

// Extends walks up the parent chain from childHash looking for ancestorHash.
func (f *fakeBlockchain) Extends(childHash, ancestorHash []byte) bool {
	if bytes.Equal(childHash, ancestorHash) {
		return true
	}
	visited := make(map[string]bool)
	cur := childHash
	for {
		key := string(cur)
		if visited[key] {
			return false // cycle guard
		}
		visited[key] = true
		b, ok := f.blocks[key]
		if !ok {
			return false
		}
		parent := b.GetParentHash()
		if bytes.Equal(parent, ancestorHash) {
			return true
		}
		if len(parent) == 0 {
			return false
		}
		cur = parent
	}
}

// countingExecutor records how many times Execute was called.
type countingExecutor struct {
	mu    sync.Mutex
	calls int
}

func (e *countingExecutor) Execute(_ *pb.MembershipRequest) []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	return []byte("ok")
}

func (e *countingExecutor) CallCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

// nopReplier discards all replies.
type nopReplier struct{}

func (n *nopReplier) Reply(_ string, _ uint64, _ []byte) {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeBlock constructs a block with the given parent hash and height.
func makeBlock(parentHash []byte, height uint64) *pb.Block {
	return &pb.Block{
		ParentHash: parentHash,
		Height:     height,
	}
}

// makeBlockWithJustify constructs a block with a justify QC pointing at blockHash.
func makeBlockWithJustify(parentHash []byte, height uint64, justifyBlockHash []byte, justifyView uint64) *pb.Block {
	return &pb.Block{
		ParentHash: parentHash,
		Height:     height,
		Justify: &pb.QuorumCert{
			ViewNumber: justifyView,
			BlockHash:  justifyBlockHash,
		},
	}
}

// makeTestCommittee returns an n-replica committee with placeholder IDs.
func makeTestCommittee(t *testing.T, n int) *membership.Committee {
	t.Helper()
	reps := make([]*membership.Replica, n)
	for i := range reps {
		reps[i] = &membership.Replica{ID: fmtID(i + 1)}
	}
	return membership.NewCommittee(0, reps)
}

func fmtID(i int) string {
	const digits = "0123456789"
	if i < 10 {
		return "P" + string(digits[i])
	}
	return "P" + fmtID(i/10) + string(digits[i%10])
}

// ---------------------------------------------------------------------------
// TestSafeNodeGenesisAlwaysTrue
// ---------------------------------------------------------------------------

func TestSafeNodeGenesisAlwaysTrue(t *testing.T) {
	t.Parallel()

	s := &SafetyState{LockedQC: nil} // genesis: no lock
	bc := newFakeBlockchain()

	block := makeBlock([]byte("any-parent"), 1)
	qc := &pb.QuorumCert{ViewNumber: 42, BlockHash: []byte("whatever")}

	// With no lock, any block should be safe.
	require.True(t, s.SafeNode(block, qc, bc),
		"SafeNode must return true at genesis (LockedQC == nil)")
}

// ---------------------------------------------------------------------------
// TestSafeNodeLivenessRule
// ---------------------------------------------------------------------------

func TestSafeNodeLivenessRule(t *testing.T) {
	t.Parallel()

	bc := newFakeBlockchain()

	// Create a locked QC at view 5.
	lockedQC := &pb.QuorumCert{ViewNumber: 5, BlockHash: []byte("locked-block")}
	s := &SafetyState{LockedQC: lockedQC}

	// Block is on a DIFFERENT branch (does not extend the locked block).
	block := makeBlock([]byte("unrelated-parent"), 10)

	// Incoming QC has a HIGHER view (7 > 5) → liveness rule kicks in.
	incomingQC := &pb.QuorumCert{ViewNumber: 7, BlockHash: []byte("newer-block")}

	require.True(t, s.SafeNode(block, incomingQC, bc),
		"SafeNode should return true via liveness rule (incoming QC view 7 > locked QC view 5)")
}

// ---------------------------------------------------------------------------
// TestSafeNodeSafetyRule
// ---------------------------------------------------------------------------

func TestSafeNodeSafetyRule(t *testing.T) {
	t.Parallel()

	bc := newFakeBlockchain()

	// Lock on a block at view 5.
	lockedQC := &pb.QuorumCert{ViewNumber: 5, BlockHash: []byte("locked-block")}
	s := &SafetyState{LockedQC: lockedQC}

	// Block is on a DIFFERENT branch — does NOT extend the locked block.
	block := makeBlock([]byte("unrelated-parent"), 10)

	// Incoming QC has the SAME view as lockedQC (5 == 5) → liveness does NOT fire.
	// And the block doesn't extend locked-block → safety also fails.
	incomingQC := &pb.QuorumCert{ViewNumber: 5, BlockHash: []byte("same-view-block")}

	require.False(t, s.SafeNode(block, incomingQC, bc),
		"SafeNode should return false when QC view == locked view and block doesn't extend lock")
}

// ---------------------------------------------------------------------------
// TestThreeChainDetection
// ---------------------------------------------------------------------------

func TestThreeChainDetection(t *testing.T) {
	t.Parallel()

	// Build a chain: b → b' → b'' → b*
	//   b (height=0, parent=genesis)
	//   b' (height=1, parent=hash(b))
	//   b'' (height=2, parent=hash(b'))
	//   b* (height=3, parent=hash(b''))
	b := makeBlock([]byte{0}, 0)
	bPrime := makeBlock(hashBlock(b), 1)
	bDouble := makeBlock(hashBlock(bPrime), 2)
	bStar := makeBlock(hashBlock(bDouble), 3)

	exec := &countingExecutor{}
	replier := &nopReplier{}
	configs := membership.NewConfigStore(makeTestCommittee(t, 4))
	deliverer := NewDeliverer(configs, exec, replier)

	// Valid three-chain: b*→b''→b'→b
	require.True(t, deliverer.CheckThreeChain(bStar, bDouble, bPrime, b),
		"three-chain should hold for correctly linked blocks")

	// Break one link: modify bDouble's parent hash to something wrong.
	brokenBDouble := makeBlock([]byte("wrong-parent"), 2)
	require.False(t, deliverer.CheckThreeChain(bStar, brokenBDouble, bPrime, b),
		"three-chain should fail when a parent link is broken")
}

// ---------------------------------------------------------------------------
// TestPipelineAdvance
// ---------------------------------------------------------------------------

func TestPipelineAdvance(t *testing.T) {
	t.Parallel()

	p := &PipelineState{}

	// Build 4 consecutive blocks with correct parent links.
	b1 := makeBlock([]byte{0}, 0)
	b2 := makeBlock(hashBlock(b1), 1)
	b3 := makeBlock(hashBlock(b2), 2)
	b4 := makeBlock(hashBlock(b3), 3)

	// Advance 1–3: pipeline not yet full, no delivery.
	require.Nil(t, p.Advance(b1), "advance 1: not enough blocks for delivery")
	require.False(t, p.CanCommit(), "CanCommit should be false with 1 block")

	require.Nil(t, p.Advance(b2), "advance 2: not enough blocks for delivery")
	require.Nil(t, p.Advance(b3), "advance 3: not enough blocks for delivery")
	require.False(t, p.CanCommit(), "CanCommit should be false with 3 blocks")

	// Advance 4: pipeline is now full, but the evicted Window[0] from
	// before the first Advance was nil, so no delivery yet.
	delivered := p.Advance(b4)
	require.Nil(t, delivered, "advance 4: Window[0] was nil before shift, so no delivery")
	require.True(t, p.CanCommit(), "CanCommit should be true with 4 blocks")

	// Now advance with b5 that extends b4.
	// This should deliver b1 (the block that was in Window[0]).
	b5 := makeBlock(hashBlock(b4), 4)
	delivered = p.Advance(b5)
	require.NotNil(t, delivered, "advance 5: should deliver b1")
	require.Equal(t, uint64(0), delivered.GetHeight(), "delivered block should be b1 (height 0)")
}

// ---------------------------------------------------------------------------
// TestDeliverOnce
// ---------------------------------------------------------------------------

func TestDeliverOnce(t *testing.T) {
	t.Parallel()

	exec := &countingExecutor{}
	replier := &nopReplier{}
	configs := membership.NewConfigStore(makeTestCommittee(t, 4))
	deliverer := NewDeliverer(configs, exec, replier)

	block := &pb.Block{
		Height:     0,
		ConfNumber: 0,
		Batch: []*pb.MembershipRequest{
			{Type: pb.RequestType_REGULAR, ClientId: "c1", Payload: []byte("cmd1")},
		},
	}

	// First delivery should execute.
	err := deliverer.Deliver(block)
	require.NoError(t, err)
	require.Equal(t, 1, exec.CallCount(), "executor should be called exactly once")

	// Second delivery of the same block should be a no-op (Theorem 11 Integrity).
	err = deliverer.Deliver(block)
	require.NoError(t, err)
	require.Equal(t, 1, exec.CallCount(),
		"executor should NOT be called again — duplicate delivery must be idempotent")
}

// ---------------------------------------------------------------------------
// TestViewChangeCollectsHighestQC
// ---------------------------------------------------------------------------

func TestViewChangeCollectsHighestQC(t *testing.T) {
	t.Parallel()

	safety := &SafetyState{}
	configs := membership.NewConfigStore(makeTestCommittee(t, 4))

	vc := NewViewChanger(0, safety, configs, nil, "P1")

	mc := configs.Latest()

	// Build 3 NewViewMsgs with different GenericQC view numbers.
	msgs := []*pb.NewViewMsg{
		{ViewNumber: 1, GenericQc: &pb.QuorumCert{ViewNumber: 10}},
		{ViewNumber: 1, GenericQc: &pb.QuorumCert{ViewNumber: 42}}, // highest
		{ViewNumber: 1, GenericQc: &pb.QuorumCert{ViewNumber: 7}},
	}

	highQC, ok := vc.OnNewViewMessages(msgs, mc)
	require.True(t, ok, "should have quorum with 3 messages (Qc=3 for n=4)")
	require.NotNil(t, highQC)
	require.Equal(t, uint64(42), highQC.GetViewNumber(),
		"highestViewQC should return the GenericQc with ViewNumber=42")
}

// ---------------------------------------------------------------------------
// TestPipelineReset
// ---------------------------------------------------------------------------

func TestPipelineReset(t *testing.T) {
	t.Parallel()

	p := &PipelineState{}
	b1 := makeBlock([]byte{0}, 0)
	b2 := makeBlock(hashBlock(b1), 1)

	p.Advance(b1)
	p.Advance(b2)
	require.False(t, p.CanCommit())

	p.Reset()
	require.False(t, p.CanCommit(), "after reset all slots should be nil")
	require.Nil(t, p.Window[0])
	require.Nil(t, p.Window[3])
}
