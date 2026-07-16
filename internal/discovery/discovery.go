// Package discovery handles config catch-up for D-HotStuff replicas.
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

// ConfigAwareSafetyChecker checks if a block is safe to vote for.
type ConfigAwareSafetyChecker interface {
	SafeNode(node *pb.Block, qc *pb.QuorumCert) bool
}

// RPCPool gets gRPC clients by address.
type RPCPool interface {
	GetClient(addr string) (pb.DHotStuffClient, error)
}

// Discovery runs the config-discovery sub-protocol (Algorithm 3, lines 28–36).
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

// SyncIfBehind pulls the latest committee state if we're behind knownLatestConf.
func (d *Discovery) SyncIfBehind(ctx context.Context, knownLatestConf uint64) error {
	current := d.configs.Latest()
	if current.Number >= knownLatestConf {
		return nil // already up to date
	}

	log.Printf("discovery: replica %s is behind (conf %d < %d), starting sync",
		d.myID, current.Number, knownLatestConf)

	// use the target committee if we know it, otherwise fall back to current
	targetMc, err := d.configs.AtNumber(knownLatestConf)
	if err != nil {
		targetMc = current
	}

	bestBlock, err := d.requestUpdates(ctx, targetMc)
	if err != nil {
		return fmt.Errorf("discovery.SyncIfBehind: request updates: %w", err)
	}

	if bestBlock == nil {
		return fmt.Errorf("discovery.SyncIfBehind: no valid block received from peers")
	}

	if !d.safety.SafeNode(bestBlock, bestBlock.GetJustify()) {
		return fmt.Errorf(
			"discovery.SyncIfBehind: bestBlock at height %d failed safeNode check",
			bestBlock.GetHeight())
	}

	hist, err := d.syncer.RequestHistory(ctx, targetMc)
	if err != nil {
		return fmt.Errorf("discovery.SyncIfBehind: request history: %w", err)
	}

	log.Printf("discovery: replica %s received %d blocks of history, catching up",
		d.myID, hist.Len())

	return nil
}

// requestUpdates asks nc−fc replicas for their best block and returns the highest one.
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

// HandleUpdateRequest returns our best committed block to a requesting replica.
func (d *Discovery) HandleUpdateRequest(requester string) (*pb.Block, error) {
	_ = requester // reserved for audit logging
	return nil, fmt.Errorf("discovery.HandleUpdateRequest: blockchain reader not yet wired")
}
