package statetransfer

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeBlock(parentHash []byte, height uint64) *pb.Block {
	return &pb.Block{
		ParentHash: parentHash,
		Height:     height,
	}
}

func makeHistory(n int) *ExecutionHistory {
	h := NewExecutionHistory()
	parent := []byte{0}
	for i := 0; i < n; i++ {
		b := makeBlock(parent, uint64(i))
		_ = h.Append(b)
		parent = blockDigest(b)
	}
	return h
}

func makeTestCommittee(n int) *membership.Committee {
	reps := make([]*membership.Replica, n)
	for i := range reps {
		reps[i] = &membership.Replica{
			ID:   fmtID(i + 1),
			Addr: fmtAddr(i + 1),
		}
	}
	return membership.NewCommittee(0, reps)
}

func fmtID(i int) string   { return "P" + itoa(i) }
func fmtAddr(i int) string { return "127.0.0.1:800" + itoa(i) }

func itoa(i int) string {
	const digits = "0123456789"
	if i < 10 {
		return string(digits[i])
	}
	return itoa(i/10) + string(digits[i%10])
}

// ---------------------------------------------------------------------------
// mockDHotStuffClient — implements pb.DHotStuffClient for tests.
// ---------------------------------------------------------------------------

type mockDHotStuffClient struct {
	pb.DHotStuffClient // embed to satisfy interface; unused methods panic

	historyResp *pb.HistoryResponse
	historyErr  error
	updateResp  *pb.UpdateResponse
	updateErr   error
	delay       time.Duration // optional delay before responding
}

func (m *mockDHotStuffClient) RequestHistory(
	ctx context.Context, _ *pb.HistoryRequest, _ ...grpc.CallOption,
) (*pb.HistoryResponse, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.historyResp, m.historyErr
}

func (m *mockDHotStuffClient) RequestUpdate(
	ctx context.Context, _ *pb.UpdateRequest, _ ...grpc.CallOption,
) (*pb.UpdateResponse, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.updateResp, m.updateErr
}

// ---------------------------------------------------------------------------
// mockRPCPool — implements RPCPool returning pre-configured clients per addr.
// ---------------------------------------------------------------------------

type mockRPCPool struct {
	clients map[string]pb.DHotStuffClient
}

func (p *mockRPCPool) GetClient(addr string) (pb.DHotStuffClient, error) {
	c, ok := p.clients[addr]
	if !ok {
		return nil, context.DeadlineExceeded
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// TestHistoryAppendMonotonic
// ---------------------------------------------------------------------------

func TestHistoryAppendMonotonic(t *testing.T) {
	t.Parallel()

	h := NewExecutionHistory()

	// Append blocks with heights 0, 1, 2 — all should succeed.
	require.NoError(t, h.Append(makeBlock([]byte{0}, 0)))
	require.NoError(t, h.Append(makeBlock([]byte{1}, 1)))
	require.NoError(t, h.Append(makeBlock([]byte{2}, 2)))

	require.Equal(t, 3, h.Len())

	// Appending height 4 (skipping 3) must return ErrOutOfOrder.
	err := h.Append(makeBlock([]byte{4}, 4))
	require.ErrorIs(t, err, ErrOutOfOrder,
		"appending height 4 when expected 3 should fail")

	// History length should still be 3 (the failed append is a no-op).
	require.Equal(t, 3, h.Len())
}

// ---------------------------------------------------------------------------
// TestHistoryHashConsistency
// ---------------------------------------------------------------------------

func TestHistoryHashConsistency(t *testing.T) {
	t.Parallel()

	// Two histories with identical blocks must produce the same hash.
	h1 := makeHistory(5)
	h2 := makeHistory(5)

	require.True(t, bytes.Equal(h1.Hash(), h2.Hash()),
		"identical histories must have the same Hash()")

	// A history with one different block must produce a different hash.
	h3 := NewExecutionHistory()
	for i := 0; i < 4; i++ {
		_ = h3.Append(makeBlock([]byte{byte(i)}, uint64(i)))
	}
	// Height 4 but with different parent
	_ = h3.Append(makeBlock([]byte("different-parent"), 4))

	require.False(t, bytes.Equal(h1.Hash(), h3.Hash()),
		"histories with different blocks must have different Hash() values")
}

// ---------------------------------------------------------------------------
// TestHistorySince
// ---------------------------------------------------------------------------

func TestHistorySince(t *testing.T) {
	t.Parallel()

	h := makeHistory(100)

	tail := h.Since(90)
	require.Len(t, tail, 10, "Since(90) on 100-block history should return 10 blocks")

	// Verify heights.
	for i, b := range tail {
		require.Equal(t, uint64(90+i), b.GetHeight())
	}

	// Since beyond end returns nil.
	require.Nil(t, h.Since(200))

	// Since(0) returns the full history.
	full := h.Since(0)
	require.Len(t, full, 100)
}

// ---------------------------------------------------------------------------
// TestSyncerRequestHistory_QuorumReached
// ---------------------------------------------------------------------------

func TestSyncerRequestHistory_QuorumReached(t *testing.T) {
	t.Parallel()

	// n=10 committee → fc=3, needed = 2*3+1 = 7.
	mc := makeTestCommittee(10)
	correctHist := makeHistory(5)
	correctResp := correctHist.ToProto()

	pool := &mockRPCPool{clients: make(map[string]pb.DHotStuffClient)}
	for _, r := range mc.Replicas {
		pool.clients[r.Addr] = &mockDHotStuffClient{
			historyResp: correctResp,
		}
	}

	syncer := NewSyncer("joiner", pool, 5*time.Second)
	ctx := context.Background()

	got, err := syncer.RequestHistory(ctx, mc)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, correctHist.Len(), got.Len(),
		"returned history should match the correct one")
	require.True(t, bytes.Equal(correctHist.Hash(), got.Hash()))
}

// ---------------------------------------------------------------------------
// TestSyncerRequestHistory_ByzantineResponses
// ---------------------------------------------------------------------------

func TestSyncerRequestHistory_ByzantineResponses(t *testing.T) {
	t.Parallel()

	// n=10, fc=3, needed=7.
	mc := makeTestCommittee(10)
	correctHist := makeHistory(5)
	correctResp := correctHist.ToProto()

	// Build a fabricated (Byzantine) history.
	fakeHist := NewExecutionHistory()
	for i := 0; i < 5; i++ {
		_ = fakeHist.Append(makeBlock([]byte("byzantine"), uint64(i)))
	}
	fakeResp := fakeHist.ToProto()

	pool := &mockRPCPool{clients: make(map[string]pb.DHotStuffClient)}
	for i, r := range mc.Replicas {
		if i < 3 {
			// First 3 replicas return Byzantine history.
			pool.clients[r.Addr] = &mockDHotStuffClient{
				historyResp: fakeResp,
			}
		} else {
			// Remaining 7 return correct history.
			pool.clients[r.Addr] = &mockDHotStuffClient{
				historyResp: correctResp,
			}
		}
	}

	syncer := NewSyncer("joiner", pool, 5*time.Second)
	ctx := context.Background()

	got, err := syncer.RequestHistory(ctx, mc)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.True(t, bytes.Equal(correctHist.Hash(), got.Hash()),
		"correct history should win over Byzantine responses")
}

// ---------------------------------------------------------------------------
// TestSyncerRequestHistory_ContextCancel
// ---------------------------------------------------------------------------

func TestSyncerRequestHistory_ContextCancel(t *testing.T) {
	t.Parallel()

	// n=10, fc=3, needed=7.
	mc := makeTestCommittee(10)

	// All replicas are very slow (1 minute delay).
	pool := &mockRPCPool{clients: make(map[string]pb.DHotStuffClient)}
	for _, r := range mc.Replicas {
		pool.clients[r.Addr] = &mockDHotStuffClient{
			historyResp: makeHistory(5).ToProto(),
			delay:       1 * time.Minute,
		}
	}

	syncer := NewSyncer("joiner", pool, 10*time.Second)

	// Cancel the context after 100ms.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := syncer.RequestHistory(ctx, mc)
	require.Error(t, err, "should fail due to context cancellation")
	require.ErrorIs(t, err, context.DeadlineExceeded,
		"error should wrap context.DeadlineExceeded")
}

// ---------------------------------------------------------------------------
// TestHistoryFromProto_Validation
// ---------------------------------------------------------------------------

func TestHistoryFromProto_Validation(t *testing.T) {
	t.Parallel()

	// Valid contiguous history.
	resp := &pb.HistoryResponse{
		History: []*pb.Block{
			makeBlock([]byte{0}, 0),
			makeBlock([]byte{1}, 1),
			makeBlock([]byte{2}, 2),
		},
	}
	h, err := HistoryFromProto(resp)
	require.NoError(t, err)
	require.Equal(t, 3, h.Len())

	// Non-contiguous: height jumps from 0 to 2.
	badResp := &pb.HistoryResponse{
		History: []*pb.Block{
			makeBlock([]byte{0}, 0),
			makeBlock([]byte{2}, 2), // should be 1
		},
	}
	_, err = HistoryFromProto(badResp)
	require.Error(t, err, "non-contiguous heights should be rejected")
}
