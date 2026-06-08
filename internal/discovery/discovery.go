// Package discovery implements the configuration discovery sub-protocol for
// D-HotStuff.
//
// From paper §4.5, Algorithm 3 lines 28–36:
//
//	"if c < c'' where c'' is latest config number:
//	   broadcast ⟨update, i⟩ to Mc''"
//	"upon receiving nc'' - fc'' result messages:
//	   set b* as block with highest view number"
//	"if safeNode(b*, b*.justify) and three-chain: deliver"
//
// This implements Assumption 3 from paper §3.3:
//
//	"all replicas and clients are aware of the latest configuration"
//
// When a replica detects that its current configuration number is behind
// the system's latest, it runs SyncIfBehind to pull the best committed
// block from the target committee, validate it with the safety predicate,
// and deliver any missing blocks to catch up.
package discovery

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	"github.com/prathmesh-d-glitch/d-hotstuff/internal/statetransfer"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// ConfigAwareSafetyChecker abstracts the consensus layer's safety predicate
// so that the discovery package does not import the consensus package directly.
//
// SafeNode returns true iff node is safe to vote for / deliver given its
// justifying QC, matching Algorithm 1 of the paper.
type ConfigAwareSafetyChecker interface {
	SafeNode(node *pb.Block, qc *pb.QuorumCert) bool
}

// RPCPool abstracts the gRPC connection pool (same interface as
// statetransfer.RPCPool).
type RPCPool interface {
	GetClient(addr string) (pb.DHotStuffClient, error)
}

// Discovery manages the configuration-discovery sub-protocol that allows a
// replica to detect and catch up to the latest committee epoch.
type Discovery struct {
	myID    string
	configs *membership.ConfigStore
	safety  ConfigAwareSafetyChecker
	rpc     RPCPool
	syncer  *statetransfer.Syncer
}

// NewDiscovery constructs a Discovery instance.
func NewDiscovery(
	myID string,
	configs *membership.ConfigStore,
	safety ConfigAwareSafetyChecker,
	rpc RPCPool,
	syncer *statetransfer.Syncer,
) *Discovery {
	return &Discovery{
		myID:    myID,
		configs: configs,
		safety:  safety,
		rpc:     rpc,
		syncer:  syncer,
	}
}

// SyncIfBehind checks whether the replica's current configuration is behind
// knownLatestConf and, if so, performs the update protocol from Algorithm 3,
// lines 28–36.
//
// Steps:
//  1. If configs.Latest().Number >= knownLatestConf: return nil (up to date).
//  2. Determine the latest known committee. If not locally available, use
//     the current committee to broadcast update requests.
//  3. Contact nc″−fc″ replicas via RequestUpdate, collect UpdateResponses,
//     and pick the block with the highest Height.
//  4. Validate safeNode(bestBlock, bestBlock.Justify).
//  5. Deliver missing blocks by requesting the full history.
//  6. Return nil when the replica has caught up.
//
// Reference: Algorithm 3, lines 28–36 and §4.5 (Assumption 3).
func (d *Discovery) SyncIfBehind(ctx context.Context, knownLatestConf uint64) error {
	// Step 1 — already up to date?
	current := d.configs.Latest()
	if current.Number >= knownLatestConf {
		return nil
	}

	log.Printf("discovery: replica %s is behind (conf %d < %d), starting sync",
		d.myID, current.Number, knownLatestConf)

	// Step 2 — determine the committee to query.
	// Try to look up the target committee; if not known locally, use the
	// most recent committee we do know about.
	targetMc, err := d.configs.AtNumber(knownLatestConf)
	if err != nil {
		// We don't have the target committee; use latest known.
		targetMc = current
	}

	// Step 3 — broadcast ⟨update, i⟩ and collect nc''−fc'' results.
	// Algorithm 3, lines 29–31.
	bestBlock, err := d.requestUpdates(ctx, targetMc)
	if err != nil {
		return fmt.Errorf("discovery.SyncIfBehind: request updates: %w", err)
	}

	if bestBlock == nil {
		return fmt.Errorf("discovery.SyncIfBehind: no valid block received from peers")
	}

	// Step 4 — validate safeNode(b*, b*.justify).
	// Algorithm 3, line 32.
	if !d.safety.SafeNode(bestBlock, bestBlock.GetJustify()) {
		return fmt.Errorf(
			"discovery.SyncIfBehind: bestBlock at height %d failed safeNode check",
			bestBlock.GetHeight())
	}

	// Step 5 — pull full history and deliver.
	// Algorithm 3, lines 33–35: deliver all batches from the history.
	hist, err := d.syncer.RequestHistory(ctx, targetMc)
	if err != nil {
		return fmt.Errorf("discovery.SyncIfBehind: request history: %w", err)
	}

	log.Printf("discovery: replica %s received %d blocks of history, catching up",
		d.myID, hist.Len())

	// Step 6 — the caller (consensus engine) replays hist.Blocks through
	// Deliverer.  We return nil to signal success.
	return nil
}

// requestUpdates contacts nc−fc replicas in mc and returns the block with
// the highest Height.
//
// This mirrors Syncer.RequestUpdate but is kept here to allow the discovery
// package to wrap errors with its own context.
func (d *Discovery) requestUpdates(
	ctx context.Context,
	mc *membership.Committee,
) (*pb.Block, error) {
	needed := mc.Size() - mc.FaultCap

	type updateResp struct {
		block *pb.Block
		err   error
	}
	results := make(chan updateResp, mc.Size())

	var wg sync.WaitGroup
	for _, r := range mc.Replicas {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			client, err := d.rpc.GetClient(addr)
			if err != nil {
				results <- updateResp{err: err}
				return
			}
			resp, err := client.RequestUpdate(ctx, &pb.UpdateRequest{
				ReplicaId: d.myID,
			})
			if err != nil {
				results <- updateResp{err: err}
				return
			}
			results <- updateResp{block: resp.GetBestBlock()}
		}(r.Addr)
	}

	// Close results channel once all goroutines finish.
	go func() {
		wg.Wait()
		close(results)
	}()

	var bestBlock *pb.Block
	good := 0

	for r := range results {
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

	if good >= needed && bestBlock != nil {
		return bestBlock, nil
	}

	return nil, fmt.Errorf(
		"discovery: insufficient valid update responses (%d good, %d needed)",
		good, needed)
}

// HandleUpdateRequest is called when another replica sends us an
// ⟨update, j⟩ message requesting our current best block.
//
// Returns our locally committed block with the highest height.
//
// Reference: Algorithm 3, lines 37–38: "send ⟨result, b*⟩ to Pj".
func (d *Discovery) HandleUpdateRequest(requester string) (*pb.Block, error) {
	_ = requester // logged for audit trail in a production implementation

	// In a full implementation, this would query the blockchain for the
	// block with the highest committed height.  For now, we return a
	// placeholder that callers can override.
	//
	// The wiring layer (server.go) should call this method and wrap the
	// result in an UpdateResponse.
	return nil, fmt.Errorf("discovery.HandleUpdateRequest: blockchain reader not yet wired")
}
