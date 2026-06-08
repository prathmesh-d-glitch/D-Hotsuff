package statetransfer

// syncer.go — join-time state synchronization for D-HotStuff.
//
// From Algorithm 2, lines 3–8:
//
//	"upon receiving 2fc+1 ⟨history, hist⟩ messages do:
//	   for batch ∈ hist do mark batch as delivered"
//	"wait until state transfer is completed"
//	"send new-view to leader of curView+1"
//
// The Syncer contacts all replicas in the current committee in parallel and
// waits until a quorum of matching history responses arrives.  It uses
// Hash() to compare histories without byte-for-byte equality checks.

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// DefaultSyncTimeout is the default deadline for a full state-sync round.
const DefaultSyncTimeout = 30 * time.Second

// RPCPool abstracts the gRPC connection pool so that Syncer can be tested
// with fake in-process clients.
type RPCPool interface {
	// GetClient returns a gRPC stub for the replica at addr.
	// The pool may cache connections; the caller must not close the client.
	GetClient(addr string) (pb.DHotStuffClient, error)
}

// histResp bundles a history response with its computed hash for quorum tallying.
type histResp struct {
	hist *ExecutionHistory
	hash string // hex-encoded SHA-256
	err  error
}

// Syncer implements join-time state transfer for a newly added (or recovering)
// D-HotStuff replica.
type Syncer struct {
	myID    string
	rpcPool RPCPool
	timeout time.Duration
}

// NewSyncer constructs a Syncer with the given dependencies.
// If timeout is zero, DefaultSyncTimeout is used.
func NewSyncer(myID string, pool RPCPool, timeout time.Duration) *Syncer {
	if timeout <= 0 {
		timeout = DefaultSyncTimeout
	}
	return &Syncer{
		myID:    myID,
		rpcPool: pool,
		timeout: timeout,
	}
}

// RequestHistory contacts every replica in mc in parallel, collects
// HistoryResponse messages, and returns the first execution history
// for which at least 2fc+1 replicas agree on the same Hash().
//
// Algorithm 2, line 3: "upon receiving 2fc+1 ⟨history, hist⟩ messages".
//
// 2fc+1 ensures at least fc+1 honest responses even with fc Byzantine
// replicas, because at most fc of the 2fc+1 matching responses could be
// from adversaries — leaving at least fc+1 from honest replicas, which
// guarantees the history is authentic.
func (s *Syncer) RequestHistory(
	ctx context.Context,
	mc *membership.Committee,
) (*ExecutionHistory, error) {
	needed := 2*mc.FaultCap + 1

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	results := make(chan histResp, mc.Size())

	// Fan out: one goroutine per replica.
	for _, r := range mc.Replicas {
		go func(addr string) {
			client, err := s.rpcPool.GetClient(addr)
			if err != nil {
				results <- histResp{err: fmt.Errorf("get client %s: %w", addr, err)}
				return
			}
			resp, err := client.RequestHistory(ctx, &pb.HistoryRequest{
				ReplicaId: s.myID,
			})
			if err != nil {
				results <- histResp{err: fmt.Errorf("request history from %s: %w", addr, err)}
				return
			}
			hist, err := HistoryFromProto(resp)
			if err != nil {
				results <- histResp{err: fmt.Errorf("parse history from %s: %w", addr, err)}
				return
			}
			results <- histResp{hist: hist, hash: string(hist.Hash())}
		}(r.Addr)
	}

	// Tally: count matching hashes.
	hashCount := make(map[string]int)
	hashHist := make(map[string]*ExecutionHistory) // first history per hash
	received := 0

	for received < mc.Size() {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("statetransfer.RequestHistory: %w (received %d/%d, needed %d)",
				ctx.Err(), received, mc.Size(), needed)
		case r := <-results:
			received++
			if r.err != nil {
				log.Printf("statetransfer: history response error: %v", r.err)
				continue
			}
			hashCount[r.hash]++
			if _, exists := hashHist[r.hash]; !exists {
				hashHist[r.hash] = r.hist
			}
			if hashCount[r.hash] >= needed {
				return hashHist[r.hash], nil
			}
		}
	}

	return nil, fmt.Errorf(
		"statetransfer.RequestHistory: no hash reached quorum (%d needed) after %d responses",
		needed, received)
}

// BroadcastHistory is called by existing replicas after delivering a
// membership-change block.  It sends the full execution history to each
// new member concurrently.
//
// Errors are logged but not returned — this is best-effort delivery.
// The joining replica will retry via RequestHistory if it does not receive
// the history promptly.
func (s *Syncer) BroadcastHistory(
	ctx context.Context,
	hist *ExecutionHistory,
	newMembers []*membership.Replica,
) error {
	// Not really an error-returning function in practice, but the signature
	// allows callers to detect total failure if desired.
	var wg sync.WaitGroup
	resp := hist.ToProto()

	for _, r := range newMembers {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			// We don't have a "push history" RPC in the proto, so the
			// existing replica simply logs that the history is ready.
			// In a full implementation, the joiner polls via RequestHistory.
			log.Printf("statetransfer: history (%d blocks) ready for %s",
				len(resp.GetHistory()), addr)
		}(r.Addr)
	}

	wg.Wait()
	return nil
}

// RequestUpdate contacts nc−fc replicas in mc and returns the block with the
// highest Height among their responses.
//
// This is the config-discovery update step from Algorithm 3, lines 29–35:
// the replica discovers the best committed block so it can fast-forward its
// local state without replaying the full history.
func (s *Syncer) RequestUpdate(
	ctx context.Context,
	mc *membership.Committee,
) (*pb.Block, error) {
	// Need nc - fc responses to tolerate fc Byzantine replicas.
	needed := mc.Size() - mc.FaultCap

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	type updateResp struct {
		block *pb.Block
		err   error
	}
	results := make(chan updateResp, mc.Size())

	for _, r := range mc.Replicas {
		go func(addr string) {
			client, err := s.rpcPool.GetClient(addr)
			if err != nil {
				results <- updateResp{err: err}
				return
			}
			resp, err := client.RequestUpdate(ctx, &pb.UpdateRequest{
				ReplicaId: s.myID,
			})
			if err != nil {
				results <- updateResp{err: err}
				return
			}
			results <- updateResp{block: resp.GetBestBlock()}
		}(r.Addr)
	}

	var bestBlock *pb.Block
	received := 0
	good := 0

	for received < mc.Size() {
		select {
		case <-ctx.Done():
			if good >= needed && bestBlock != nil {
				return bestBlock, nil
			}
			return nil, fmt.Errorf("statetransfer.RequestUpdate: %w (good=%d, needed=%d)",
				ctx.Err(), good, needed)
		case r := <-results:
			received++
			if r.err != nil {
				continue
			}
			good++
			if r.block != nil {
				if bestBlock == nil || r.block.GetHeight() > bestBlock.GetHeight() {
					bestBlock = r.block
				}
			}
			if good >= needed && bestBlock != nil {
				return bestBlock, nil
			}
		}
	}

	if good >= needed && bestBlock != nil {
		return bestBlock, nil
	}

	return nil, fmt.Errorf(
		"statetransfer.RequestUpdate: insufficient valid responses (%d good, %d needed)",
		good, needed)
}
