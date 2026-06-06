//go:build !simulation

// dhotstuff.go — main D-HotStuff replica loop implementing Algorithm 3 from the paper.
//
// This file wires together the SafetyState, PipelineState, Deliverer, and
// ViewChanger into a single DHotStuff struct that drives the full consensus
// protocol for one replica.
//
// The design uses interfaces (Executor, Replier, NetworkSender,
// BlockchainReader) for dependency injection, keeping this core loop free
// of network or storage concerns.
//
// Reference: D-HotStuff Algorithm 3 (full protocol).
package consensus

import (
	"context"
	"fmt"
	"log"
	"sync"

	dhcrypto "github.com/prathmesh-d-glitch/d-hotstuff/internal/crypto"
	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// DHotStuff is the main consensus engine for a single D-HotStuff replica.
//
// It implements Algorithm 3 of the paper: propose, vote, update safety state,
// commit via the three-chain rule, and deliver batches to the application.
type DHotStuff struct {
	// myID is this replica's stable string identity.
	myID string

	// curView is the current view number (monotonically increasing).
	curView uint64

	// curConf is the configuration number of the latest known committee.
	curConf uint64

	// safety holds lockedQC and genericQC.
	safety *SafetyState

	// pipeline tracks the 4-block sliding window for pipelined commits.
	pipeline *PipelineState

	// deliverer handles exactly-once block delivery and membership install.
	deliverer *Deliverer

	// vc handles view-change (timeout → NewViewMsg).
	vc *ViewChanger

	// configs is the thread-safe append-only committee store.
	configs *membership.ConfigStore

	// blockchain provides read access to the local block store.
	blockchain BlockchainReader

	// net is the network transport for sending/broadcasting messages.
	net NetworkSender

	// signer provides ECDSA P-256 sign and verify.
	privKey interface {
		Sign(viewNum, confNum uint64, blockHash []byte) ([]byte, error)
	}

	// requestQ buffers incoming client requests for the next proposal.
	requestQ chan *pb.MembershipRequest

	// votesBuf accumulates votes per view for quorum detection.
	votesBuf map[uint64][]*pb.VoteMsg

	// newViewBuf accumulates NewViewMsgs per view for the leader.
	newViewBuf map[uint64][]*pb.NewViewMsg

	// mu protects all mutable state.
	mu sync.Mutex
}

// NewDHotStuff constructs a DHotStuff replica with the provided dependencies.
func NewDHotStuff(
	myID string,
	configs *membership.ConfigStore,
	blockchain BlockchainReader,
	net NetworkSender,
	executor Executor,
	replier Replier,
	signFn func(viewNum, confNum uint64, blockHash []byte) ([]byte, error),
	requestQSize int,
) *DHotStuff {
	safety := &SafetyState{}
	pipeline := &PipelineState{}
	deliverer := NewDeliverer(configs, executor, replier)
	vc := NewViewChanger(0, safety, configs, net, myID)

	return &DHotStuff{
		myID:       myID,
		curView:    0,
		curConf:    0,
		safety:     safety,
		pipeline:   pipeline,
		deliverer:  deliverer,
		vc:         vc,
		configs:    configs,
		blockchain: blockchain,
		net:        net,
		privKey:    &signerAdapter{signFn},
		requestQ:   make(chan *pb.MembershipRequest, requestQSize),
		votesBuf:   make(map[uint64][]*pb.VoteMsg),
		newViewBuf: make(map[uint64][]*pb.NewViewMsg),
	}
}

// signerAdapter wraps a function into the sign interface.
type signerAdapter struct {
	fn func(viewNum, confNum uint64, blockHash []byte) ([]byte, error)
}

func (s *signerAdapter) Sign(viewNum, confNum uint64, blockHash []byte) ([]byte, error) {
	return s.fn(viewNum, confNum, blockHash)
}

// SubmitRequest enqueues a client request for inclusion in the next proposal.
// It is non-blocking if the request queue has capacity; otherwise it blocks.
func (d *DHotStuff) SubmitRequest(req *pb.MembershipRequest) {
	d.requestQ <- req
}

// HandlePropose processes a proposed block received from the current leader.
//
// Implements Algorithm 3, lines 17–26:
//  1. Validate the block's configuration number.
//  2. Look up b* → b″ → b′ → b using the block's Justify chain.
//  3. If SafeNode holds: sign and send a vote to the leader.
//  4. Update safety state (one-chain → genericQC, two-chain → lockedQC).
//  5. If three-chain holds: deliver the committed block.
//  6. Advance the pipeline.
func (d *DHotStuff) HandlePropose(block *pb.Block) {
	d.mu.Lock()
	defer d.mu.Unlock()

	mc := d.configs.Latest()

	// Algorithm 3, line 17: validate conf_number.
	if block.GetConfNumber() > mc.Number {
		log.Printf("d-hotstuff: block conf_number %d > latest %d; ignoring",
			block.GetConfNumber(), mc.Number)
		return
	}

	qc := block.GetJustify()

	// Algorithm 3, line 18: look up the chain b* → b'' → b' → b.
	bStar := block
	var bDouble, bPrime, b *pb.Block

	if qc != nil {
		if bd, ok := d.blockchain.Get(qc.GetBlockHash()); ok {
			bDouble = bd
			if bDouble.GetJustify() != nil {
				if bp, ok := d.blockchain.Get(bDouble.GetJustify().GetBlockHash()); ok {
					bPrime = bp
					if bPrime.GetJustify() != nil {
						if bb, ok := d.blockchain.Get(bPrime.GetJustify().GetBlockHash()); ok {
							b = bb
						}
					}
				}
			}
		}
	}

	// Algorithm 3, line 19: safeNode check — vote only if it passes.
	if d.safety.SafeNode(bStar, qc, d.blockchain) {
		blockHash := hashBlock(bStar)
		sig, err := d.privKey.Sign(bStar.GetConfNumber(), mc.Number, blockHash)
		if err != nil {
			log.Printf("d-hotstuff: sign error: %v", err)
			return
		}

		vote := &pb.VoteMsg{
			ViewNumber: d.curView,
			ConfNumber: mc.Number,
			BlockHash:  blockHash,
			Signature:  sig,
			SignerId:   d.myID,
		}

		// Send vote to the current leader.
		leader := mc.Leader(d.curView)
		if err := d.net.Send(leader.Addr, vote); err != nil {
			log.Printf("d-hotstuff: send vote error: %v", err)
		}
	}

	// Algorithm 3, lines 21–22: update genericQC on one-chain.
	if bDouble != nil {
		d.safety.UpdateOnOneChain(bStar, bDouble)
	}

	// Algorithm 3, lines 23–24: update lockedQC on two-chain.
	if bDouble != nil && bPrime != nil {
		d.safety.UpdateOnTwoChain(bStar, bDouble, bPrime)
	}

	// Algorithm 3, lines 25–26: commit on three-chain.
	if bDouble != nil && bPrime != nil && b != nil {
		if d.deliverer.CheckThreeChain(bStar, bDouble, bPrime, b) {
			if err := d.deliverer.Deliver(b); err != nil {
				log.Printf("d-hotstuff: deliver error: %v", err)
			}
		}
	}

	// Advance the pipeline.
	if toDeliver := d.pipeline.Advance(bStar); toDeliver != nil {
		if err := d.deliverer.Deliver(toDeliver); err != nil {
			log.Printf("d-hotstuff: pipeline deliver error: %v", err)
		}
	}
}

// HandleVote processes an incoming vote from a replica (leader only).
//
// Votes are accumulated per view.  Once a quorum of distinct votes is
// collected, a QuorumCert is created and the leader proposes the next block.
func (d *DHotStuff) HandleVote(vote *pb.VoteMsg) {
	d.mu.Lock()
	defer d.mu.Unlock()

	view := vote.GetViewNumber()
	d.votesBuf[view] = dhcrypto.AggregateVotes(d.votesBuf[view], vote)

	mc := d.configs.Latest()
	if !dhcrypto.HasQuorum(d.votesBuf[view], mc) {
		return // not enough votes yet
	}

	// Quorum reached — create QC.
	qc, err := dhcrypto.CreateQC(d.votesBuf[view], mc)
	if err != nil {
		log.Printf("d-hotstuff: CreateQC error: %v", err)
		return
	}

	// Advance view.
	d.curView++
	delete(d.votesBuf, view) // clean up old view

	// Update genericQC if this QC is newer.
	if d.safety.GenericQC == nil || qc.GetViewNumber() > d.safety.GenericQC.GetViewNumber() {
		d.safety.GenericQC = qc
	}

	// Propose next block.
	d.propose(qc)
}

// HandleNewView processes an incoming NewViewMsg (leader only).
//
// The leader accumulates NewViewMsgs for its view.  Once a quorum is
// collected, it extracts the highest genericQC and proposes.
func (d *DHotStuff) HandleNewView(msg *pb.NewViewMsg) {
	d.mu.Lock()
	defer d.mu.Unlock()

	view := msg.GetViewNumber()
	d.newViewBuf[view] = append(d.newViewBuf[view], msg)

	mc := d.configs.Latest()
	highQC, ok := d.vc.OnNewViewMessages(d.newViewBuf[view], mc)
	if !ok {
		return // not enough new-view messages yet
	}

	delete(d.newViewBuf, view) // clean up

	// Use the highest QC from the collected NewViewMsgs.
	if highQC != nil {
		if d.safety.GenericQC == nil || highQC.GetViewNumber() > d.safety.GenericQC.GetViewNumber() {
			d.safety.GenericQC = highQC
		}
	}

	// Propose with the best QC.
	d.propose(d.safety.GenericQC)
}

// HandleTimeout is called when the view timer expires.
//
// Delegates to the ViewChanger which increments the view and sends a
// NewViewMsg to the next leader.  Clears vote buffers for the timed-out view.
func (d *DHotStuff) HandleTimeout(ctx context.Context) {
	d.mu.Lock()
	timedOutView := d.curView
	d.mu.Unlock()

	if err := d.vc.OnTimeout(ctx); err != nil {
		log.Printf("d-hotstuff: view-change error: %v", err)
	}

	d.mu.Lock()
	delete(d.votesBuf, timedOutView)
	// Reset pipeline on view change — no three-chain was completed.
	d.pipeline.Reset()
	d.curView = d.vc.CurView()
	d.mu.Unlock()
}

// propose builds and broadcasts a block proposal (leader logic).
//
// Implements Algorithm 3, lines 3–11:
//  1. Drain available requests from requestQ (non-blocking, up to batchSize).
//  2. Create a new block extending the QC's block hash with the batch.
//  3. Broadcast the block to the current committee.
func (d *DHotStuff) propose(justify *pb.QuorumCert) {
	// Must be called with d.mu held.
	mc := d.configs.Latest()

	// Algorithm 3, lines 3–5: collect batch from request queue.
	const batchSize = 100
	batch := make([]*pb.MembershipRequest, 0, batchSize)
	for i := 0; i < batchSize; i++ {
		select {
		case req := <-d.requestQ:
			batch = append(batch, req)
		default:
			break // no more requests available right now
		}
	}

	// Algorithm 3, lines 6–9: create block.
	var parentHash []byte
	var height uint64
	if justify != nil {
		parentHash = justify.GetBlockHash()
		// Look up the parent block to determine height.
		if parent, ok := d.blockchain.Get(parentHash); ok {
			height = parent.GetHeight() + 1
		}
	}

	block := &pb.Block{
		ParentHash: parentHash,
		Batch:      batch,
		Justify:    justify,
		Height:     height,
		ConfNumber: mc.Number,
	}

	// Algorithm 3, lines 10–11: broadcast to committee.
	if err := d.net.BroadcastToCommittee(mc, block); err != nil {
		log.Printf("d-hotstuff: broadcast propose error: %v", err)
	}
}

// String returns a human-readable description of the replica state.
func (d *DHotStuff) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fmt.Sprintf("DHotStuff{id=%s, view=%d, conf=%d}", d.myID, d.curView, d.curConf)
}
