//go:build !simulation

// dhotstuff.go — D-HotStuff replica loop (Algorithm 3).
package consensus

import (
	"context"
	"fmt"
	"log"
	"sync"

	dhcrypto "github.com/prathmesh-d-glitch/d-hotstuff/internal/crypto"
	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	"github.com/prathmesh-d-glitch/d-hotstuff/internal/reputation"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// DHotStuff is the consensus engine for one replica.
type DHotStuff struct {
	myID    string
	curView uint64
	curConf uint64

	safety    *SafetyState
	pipeline  *PipelineState
	deliverer *Deliverer
	vc        *ViewChanger

	configs    *membership.ConfigStore
	blockchain BlockchainReader
	net        NetworkSender

	repStore    *reputation.Store
	repSelector *reputation.LeaderSelector

	privKey interface {
		Sign(viewNum, confNum uint64, blockHash []byte) ([]byte, error)
	}

	requestQ   chan *pb.MembershipRequest
	votesBuf   map[uint64][]*pb.VoteMsg
	newViewBuf map[uint64][]*pb.NewViewMsg

	mu sync.Mutex
}

// NewDHotStuff builds a replica with all its dependencies wired in.
func NewDHotStuff(
	myID string,
	configs *membership.ConfigStore,
	blockchain BlockchainReader,
	net NetworkSender,
	executor Executor,
	replier Replier,
	signFn func(viewNum, confNum uint64, blockHash []byte) ([]byte, error),
	requestQSize int,
	repStore *reputation.Store,
) *DHotStuff {
	safety := &SafetyState{}
	pipeline := &PipelineState{}
	deliverer := NewDeliverer(configs, executor, replier)
	vc := NewViewChanger(0, safety, configs, net, myID)

	var repSelector *reputation.LeaderSelector
	if repStore != nil {
		repSelector = reputation.NewLeaderSelector(repStore)
	}

	return &DHotStuff{
		myID:        myID,
		curView:     0,
		curConf:     0,
		safety:      safety,
		pipeline:    pipeline,
		deliverer:   deliverer,
		vc:          vc,
		configs:     configs,
		blockchain:  blockchain,
		net:         net,
		repStore:    repStore,
		repSelector: repSelector,
		privKey:     &signerAdapter{signFn},
		requestQ:    make(chan *pb.MembershipRequest, requestQSize),
		votesBuf:    make(map[uint64][]*pb.VoteMsg),
		newViewBuf:  make(map[uint64][]*pb.NewViewMsg),
	}
}

// signerAdapter wraps a plain function into the sign interface.
type signerAdapter struct {
	fn func(viewNum, confNum uint64, blockHash []byte) ([]byte, error)
}

func (s *signerAdapter) Sign(viewNum, confNum uint64, blockHash []byte) ([]byte, error) {
	return s.fn(viewNum, confNum, blockHash)
}

// SubmitRequest enqueues a client request for the next proposal.
func (d *DHotStuff) SubmitRequest(req *pb.MembershipRequest) {
	d.requestQ <- req
}

// HandlePropose processes a block from the current leader (Algorithm 3, lines 17–26).
func (d *DHotStuff) HandlePropose(block *pb.Block) {
	d.mu.Lock()
	defer d.mu.Unlock()

	mc := d.configs.Latest()

	if block.GetConfNumber() > mc.Number {
		log.Printf("d-hotstuff: block conf_number %d > latest %d; ignoring",
			block.GetConfNumber(), mc.Number)
		return
	}

	qc := block.GetJustify()

	// walk the chain: b* → b'' → b' → b
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

	// vote if safeNode passes
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

		leader := d.selectLeader(mc)
		if err := d.net.Send(leader.Addr, vote); err != nil {
			log.Printf("d-hotstuff: send vote error: %v", err)
		}
	}

	// one-chain → update genericQC
	if bDouble != nil {
		d.safety.UpdateOnOneChain(bStar, bDouble)
	}

	// two-chain → update lockedQC
	if bDouble != nil && bPrime != nil {
		d.safety.UpdateOnTwoChain(bStar, bDouble, bPrime)
	}

	// three-chain → commit
	if bDouble != nil && bPrime != nil && b != nil {
		if d.deliverer.CheckThreeChain(bStar, bDouble, bPrime, b) {
			if err := d.deliverer.Deliver(b); err != nil {
				log.Printf("d-hotstuff: deliver error: %v", err)
			}
			if d.repStore != nil {
				leaderID := d.selectLeader(mc).ID
				d.repStore.RecordCommit(leaderID, b.GetHeight())
			}
		}
	}

	if toDeliver := d.pipeline.Advance(bStar); toDeliver != nil {
		if err := d.deliverer.Deliver(toDeliver); err != nil {
			log.Printf("d-hotstuff: pipeline deliver error: %v", err)
		}
	}
}

// HandleVote collects votes; proposes next block once quorum is reached.
func (d *DHotStuff) HandleVote(vote *pb.VoteMsg) {
	d.mu.Lock()
	defer d.mu.Unlock()

	mc := d.configs.Latest()

	replica := mc.ReplicaByID(vote.GetSignerId())
	if replica == nil {
		log.Printf("d-hotstuff: vote from unknown signer %q; dropping", vote.GetSignerId())
		return
	}

	if replica.PubKey == nil {
		log.Printf("d-hotstuff: signer %q has no public key; dropping vote", vote.GetSignerId())
		return
	}

	if !dhcrypto.Verify(
		replica.PubKey,
		vote.GetViewNumber(),
		vote.GetConfNumber(),
		vote.GetBlockHash(),
		vote.GetSignature(),
	) {
		log.Printf("d-hotstuff: invalid vote signature from %q; dropping", vote.GetSignerId())
		return
	}

	view := vote.GetViewNumber()
	d.votesBuf[view] = dhcrypto.AggregateVotes(d.votesBuf[view], vote)

	if !dhcrypto.HasQuorum(d.votesBuf[view], mc) {
		return // not enough votes yet
	}

	qc, err := dhcrypto.CreateQC(d.votesBuf[view], mc)
	if err != nil {
		log.Printf("d-hotstuff: CreateQC error: %v", err)
		return
	}

	d.curView++
	delete(d.votesBuf, view)

	if d.safety.GenericQC == nil || qc.GetViewNumber() > d.safety.GenericQC.GetViewNumber() {
		d.safety.GenericQC = qc
	}

	d.propose(qc)
}

// HandleNewView collects new-view messages; proposes when quorum is reached.
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

	delete(d.newViewBuf, view)

	if highQC != nil {
		if d.safety.GenericQC == nil || highQC.GetViewNumber() > d.safety.GenericQC.GetViewNumber() {
			d.safety.GenericQC = highQC
		}
	}

	d.propose(d.safety.GenericQC)
}

// HandleTimeout fires when the view timer expires; kicks off a view change.
func (d *DHotStuff) HandleTimeout(ctx context.Context) {
	d.mu.Lock()
	timedOutView := d.curView
	if d.repStore != nil {
		mc := d.configs.Latest()
		leader := d.selectLeader(mc)
		d.repStore.RecordTimeout(leader.ID)
	}
	d.mu.Unlock()

	if err := d.vc.OnTimeout(ctx); err != nil {
		log.Printf("d-hotstuff: view-change error: %v", err)
	}

	d.mu.Lock()
	delete(d.votesBuf, timedOutView)
	d.pipeline.Reset() // no three-chain completed in this view
	d.curView = d.vc.CurView()
	d.mu.Unlock()
}

func (d *DHotStuff) selectLeader(mc *membership.Committee) *membership.Replica {
	if d.repSelector != nil {
		return d.repSelector.Select(mc, d.curView)
	}
	return mc.Leader(d.curView)
}

// propose builds a block and broadcasts it (leader only, called with mu held).
func (d *DHotStuff) propose(justify *pb.QuorumCert) {
	mc := d.configs.Latest()

	leader := d.selectLeader(mc)
	if d.repStore != nil {
		d.repStore.RecordLeaderRound(leader.ID)
	}

	// drain up to batchSize requests (non-blocking)
	const batchSize = 100
	batch := make([]*pb.MembershipRequest, 0, batchSize)
	for i := 0; i < batchSize; i++ {
		select {
		case req := <-d.requestQ:
			batch = append(batch, req)
		default:
		}
	}

	var parentHash []byte
	var height uint64
	if justify != nil {
		parentHash = justify.GetBlockHash()
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

	if err := d.net.BroadcastToCommittee(mc, block); err != nil {
		log.Printf("d-hotstuff: broadcast propose error: %v", err)
	}
}

// String returns a quick summary of the replica's current state.
func (d *DHotStuff) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fmt.Sprintf("DHotStuff{id=%s, view=%d, conf=%d}", d.myID, d.curView, d.curConf)
}
