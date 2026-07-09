package consensus

// deliver.go — block delivery and three-chain commit rule.

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// Executor runs a single client request against the application state machine.
type Executor interface {
	Execute(req *pb.MembershipRequest) []byte
}

// Replier sends execution results back to the originating client.
type Replier interface {
	Reply(clientID string, confNum uint64, result []byte)
}

// Deliverer commits blocks exactly once and executes their batches.
type Deliverer struct {
	configs   *membership.ConfigStore
	executor  Executor
	replier   Replier
	delivered map[string]bool // blockHash → already delivered
	mu        sync.Mutex
}

// NewDeliverer constructs a Deliverer.
func NewDeliverer(
	configs *membership.ConfigStore,
	executor Executor,
	replier Replier,
) *Deliverer {
	return &Deliverer{
		configs:   configs,
		executor:  executor,
		replier:   replier,
		delivered: make(map[string]bool),
	}
}

// Deliver commits block and executes its batch. Duplicate calls are silently ignored.
func (d *Deliverer) Deliver(block *pb.Block) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// idempotency guard
	key := string(hashBlock(block))
	if d.delivered[key] {
		return nil
	}

	mc, err := d.configs.AtNumber(block.GetConfNumber())
	if err != nil {
		return fmt.Errorf("consensus.Deliver: block at height %d conf %d: %w",
			block.GetHeight(), block.GetConfNumber(), err)
	}

	// regular requests first, then membership changes
	regular, membershipReqs := membership.ClassifyBatch(block.GetBatch())

	for _, req := range regular {
		result := d.executor.Execute(req)
		d.replier.Reply(req.GetClientId(), block.GetConfNumber(), result)
	}

	if len(membershipReqs) > 0 {
		newMc, err := mc.Apply(membershipReqs)
		if err != nil {
			return fmt.Errorf("consensus.Deliver: apply membership requests: %w", err)
		}
		if err := d.configs.Install(newMc); err != nil {
			return fmt.Errorf("consensus.Deliver: install committee Mc+1=%d: %w",
				newMc.Number, err)
		}
	}

	d.delivered[key] = true
	return nil
}

// CheckThreeChain returns true if the four blocks form a consecutive parent-hash chain.
func (d *Deliverer) CheckThreeChain(bStar, bDouble, bPrime, b *pb.Block) bool {
	return bytes.Equal(bStar.GetParentHash(), hashBlock(bDouble)) &&
		bytes.Equal(bDouble.GetParentHash(), hashBlock(bPrime)) &&
		bytes.Equal(bPrime.GetParentHash(), hashBlock(b))
}
