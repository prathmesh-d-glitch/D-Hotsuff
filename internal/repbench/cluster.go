// Package repbench benchmarks round-robin vs reputation-based leader selection
// under Byzantine fault scenarios. It measures view-changes, throughput degradation,
// and recovery time for both modes.
package repbench

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	dhcrypto "github.com/prathmesh-d-glitch/d-hotstuff/internal/crypto"
	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	"github.com/prathmesh-d-glitch/d-hotstuff/internal/reputation"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// hashBlock returns SHA-256(parentHash || height_BE8).
func hashBlock(b *pb.Block) []byte {
	h := sha256.New()
	h.Write(b.GetParentHash())
	var buf [8]byte
	ht := b.GetHeight()
	for i := 7; i >= 0; i-- {
		buf[i] = byte(ht)
		ht >>= 8
	}
	h.Write(buf[:])
	return h.Sum(nil)
}

// memBlockchain is an in-memory block store.
type memBlockchain struct {
	mu     sync.RWMutex
	blocks map[string]*pb.Block
}

func newMemBlockchain() *memBlockchain {
	return &memBlockchain{blocks: make(map[string]*pb.Block)}
}

func (m *memBlockchain) put(b *pb.Block) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocks[hex.EncodeToString(hashBlock(b))] = b
}

func (m *memBlockchain) Get(hash []byte) (*pb.Block, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.blocks[hex.EncodeToString(hash)]
	return b, ok
}

func (m *memBlockchain) Extends(childHash, ancestorHash []byte) bool {
	if bytes.Equal(childHash, ancestorHash) {
		return true
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	cur := hex.EncodeToString(childHash)
	target := hex.EncodeToString(ancestorHash)
	for i := 0; i < 1024; i++ {
		if cur == target {
			return true
		}
		b, ok := m.blocks[cur]
		if !ok {
			return false
		}
		cur = hex.EncodeToString(b.GetParentHash())
	}
	return false
}

// safeNodeState is minimal per-replica safety.
type safeNodeState struct {
	lockedQC  *pb.QuorumCert
	genericQC *pb.QuorumCert
}

func (s *safeNodeState) safeNode(node *pb.Block, qc *pb.QuorumCert, bc *memBlockchain) bool {
	if s.lockedQC == nil {
		return true
	}
	if qc.GetViewNumber() > s.lockedQC.GetViewNumber() {
		return true
	}
	return bc.Extends(node.GetParentHash(), s.lockedQC.GetBlockHash())
}

type pipelineWindow struct{ slots [4]*pb.Block }

func (p *pipelineWindow) advance(b *pb.Block) *pb.Block {
	candidate := p.slots[0]
	p.slots[0] = p.slots[1]
	p.slots[1] = p.slots[2]
	p.slots[2] = p.slots[3]
	p.slots[3] = b
	if candidate == nil {
		return nil
	}
	bStar := p.slots[2]
	bDouble := p.slots[1]
	bPrime := p.slots[0]
	if bStar == nil || bDouble == nil || bPrime == nil {
		return nil
	}
	if bytes.Equal(bStar.GetParentHash(), hashBlock(bDouble)) &&
		bytes.Equal(bDouble.GetParentHash(), hashBlock(bPrime)) &&
		bytes.Equal(bPrime.GetParentHash(), hashBlock(candidate)) {
		return candidate
	}
	return nil
}

func (p *pipelineWindow) reset() { p.slots = [4]*pb.Block{} }

// ─────────────────────────────────────────────────────────────────────────────
// RepBenchCluster — supports both round-robin and reputation modes
// ─────────────────────────────────────────────────────────────────────────────

// LeaderMode determines how the leader is selected each round.
type LeaderMode int

const (
	ModeRoundRobin  LeaderMode = iota // standard view % n
	ModeReputation                     // reputation + novelty based
)

// RepBenchCluster extends BenchCluster to support Byzantine replicas and
// reputation-based leader selection.
type RepBenchCluster struct {
	N    int
	Mode LeaderMode
	MC   *membership.Committee

	keys      []*ecdsa.PrivateKey
	safety    []*safeNodeState
	pipeline  *pipelineWindow
	chain     *memBlockchain
	curView   uint64
	curHeight uint64
	genericQC *pb.QuorumCert
	lastHash  []byte

	// Byzantine fault simulation
	byzantineIDs map[string]bool // replicas that will cause timeouts

	// Reputation (only used when Mode == ModeReputation)
	repStore    *reputation.Store
	repSelector *reputation.LeaderSelector

	// Stats
	delivered    int
	viewChanges  int
	successRound int
}

// NewRepBenchCluster creates a cluster with n replicas. byzantineIndices
// specifies which replicas (0-indexed) are Byzantine (they always time out).
func NewRepBenchCluster(n int, mode LeaderMode, byzantineIndices []int) (*RepBenchCluster, error) {
	if n < 4 {
		return nil, fmt.Errorf("repbench: n must be >= 4")
	}

	keys := make([]*ecdsa.PrivateKey, n)
	reps := make([]*membership.Replica, n)
	byzantineIDs := make(map[string]bool)
	for i := 0; i < n; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("repbench: keygen P%d: %w", i+1, err)
		}
		keys[i] = priv
		id := fmt.Sprintf("P%d", i+1)
		reps[i] = &membership.Replica{
			ID:     id,
			Addr:   fmt.Sprintf("127.0.0.1:%d", 8000+i+1),
			PubKey: &priv.PublicKey,
		}
	}
	for _, idx := range byzantineIndices {
		if idx >= 0 && idx < n {
			byzantineIDs[fmt.Sprintf("P%d", idx+1)] = true
		}
	}

	mc := membership.NewCommittee(0, reps)
	genesis := &pb.Block{ParentHash: make([]byte, 32), Height: 0, ConfNumber: 0}
	chain := newMemBlockchain()
	chain.put(genesis)
	genesisHash := hashBlock(genesis)
	genesisQC := &pb.QuorumCert{ViewNumber: 0, ConfNumber: 0, BlockHash: genesisHash}

	safety := make([]*safeNodeState, n)
	for i := range safety {
		safety[i] = &safeNodeState{genericQC: genesisQC}
	}

	c := &RepBenchCluster{
		N:            n,
		Mode:         mode,
		MC:           mc,
		keys:         keys,
		safety:       safety,
		pipeline:     &pipelineWindow{},
		chain:        chain,
		curView:      1,
		curHeight:    1,
		genericQC:    genesisQC,
		lastHash:     genesisHash,
		byzantineIDs: byzantineIDs,
	}

	if mode == ModeReputation {
		c.repStore = reputation.NewStore()
		c.repSelector = reputation.NewLeaderSelector(c.repStore)
	}

	return c, nil
}

// selectLeader returns the next leader according to the cluster's mode.
func (c *RepBenchCluster) selectLeader() *membership.Replica {
	if c.Mode == ModeReputation && c.repSelector != nil {
		return c.repSelector.Select(c.MC, c.curView)
	}
	return c.MC.Leader(c.curView)
}

// RoundResult holds per-round metrics.
type RoundResult struct {
	Leader      string
	WasTimeout  bool
	TxDelivered int
	RoundTime   time.Duration
	SignTime    time.Duration
}

// RunRound executes one round. If the leader is Byzantine, it simulates a
// timeout (skips proposal, costs ~same sign time for view-change NewViewMsg
// signing). Returns the round result.
func (c *RepBenchCluster) RunRound(batch []*pb.MembershipRequest) (RoundResult, error) {
	t0 := time.Now()
	leader := c.selectLeader()

	// Record leader round for reputation
	if c.repStore != nil {
		c.repStore.RecordLeaderRound(leader.ID)
	}

	// If leader is Byzantine → simulate timeout
	if c.byzantineIDs[leader.ID] {
		// Simulate view-change overhead: each replica signs a NewViewMsg
		signStart := time.Now()
		for i := 0; i < c.MC.QuorumSize() && i < len(c.keys); i++ {
			dummyHash := make([]byte, 32)
			_, err := dhcrypto.Sign(c.keys[i], c.curView, 0, dummyHash)
			if err != nil {
				return RoundResult{}, fmt.Errorf("repbench: view-change sign P%d: %w", i+1, err)
			}
		}
		signTime := time.Since(signStart)

		if c.repStore != nil {
			c.repStore.RecordTimeout(leader.ID)
		}

		c.viewChanges++
		c.curView++

		return RoundResult{
			Leader:     leader.ID,
			WasTimeout: true,
			RoundTime:  time.Since(t0),
			SignTime:   signTime,
		}, nil
	}

	// Honest leader → normal consensus round
	block := &pb.Block{
		ParentHash: c.lastHash,
		Batch:      batch,
		Justify:    c.genericQC,
		Height:     c.curHeight,
		ConfNumber: 0,
	}
	c.chain.put(block)
	blockHash := hashBlock(block)

	// Sign phase
	signStart := time.Now()
	qSize := c.MC.QuorumSize()
	votes := make([]*pb.VoteMsg, 0, qSize)
	for i := 0; i < qSize && i < len(c.keys); i++ {
		sig, err := dhcrypto.Sign(c.keys[i], c.curView, 0, blockHash)
		if err != nil {
			return RoundResult{}, fmt.Errorf("repbench: Sign P%d: %w", i+1, err)
		}
		votes = append(votes, &pb.VoteMsg{
			ViewNumber: c.curView,
			ConfNumber: 0,
			BlockHash:  blockHash,
			SignerId:   c.MC.Replicas[i].ID,
			Signature:  sig,
		})
	}
	signTime := time.Since(signStart)

	// Aggregate
	var acc []*pb.VoteMsg
	for _, v := range votes {
		acc = dhcrypto.AggregateVotes(acc, v)
	}
	qc, err := dhcrypto.CreateQC(acc, c.MC)
	if err != nil {
		return RoundResult{}, fmt.Errorf("repbench: CreateQC: %w", err)
	}
	qc.ViewNumber = c.curView

	// Update safety state
	for _, s := range c.safety {
		if s.safeNode(block, block.GetJustify(), c.chain) {
			s.genericQC = qc
			if parent, ok := c.chain.Get(block.GetParentHash()); ok {
				if bytes.Equal(block.GetParentHash(), hashBlock(parent)) {
					s.lockedQC = block.GetJustify()
				}
			}
		}
	}

	// Pipeline advance
	toCommit := c.pipeline.advance(block)
	var txDelivered int
	if toCommit != nil {
		txDelivered = len(toCommit.GetBatch())
		c.delivered += txDelivered
	}

	// Record commit for reputation
	if c.repStore != nil {
		c.repStore.RecordCommit(leader.ID, c.curHeight)
	}

	c.genericQC = qc
	c.lastHash = blockHash
	c.curView++
	c.curHeight++
	c.successRound++

	return RoundResult{
		Leader:      leader.ID,
		TxDelivered: txDelivered,
		RoundTime:   time.Since(t0),
		SignTime:    signTime,
	}, nil
}

// BenchResult holds the aggregate result of a benchmark run.
type BenchResult struct {
	Mode            string  `json:"mode"`
	N               int     `json:"n"`
	NumByzantine    int     `json:"num_byzantine"`
	TotalRounds     int     `json:"total_rounds"`
	SuccessRounds   int     `json:"success_rounds"`
	ViewChanges     int     `json:"view_changes"`
	TxDelivered     int     `json:"tx_delivered"`
	TPS             float64 `json:"tps_ktx"`
	AvgRoundMs      float64 `json:"avg_round_ms"`
	AvgSignMs       float64 `json:"avg_sign_ms"`
	ElapsedMs       float64 `json:"elapsed_ms"`
	MaxConsecFails  int     `json:"max_consec_fails"`
}

// RunBenchmark runs numRounds with the given batch and returns aggregate metrics.
func (c *RepBenchCluster) RunBenchmark(numRounds int, batch []*pb.MembershipRequest) (BenchResult, error) {
	start := time.Now()
	var totalRoundTime, totalSignTime time.Duration
	maxConsec := 0
	curConsec := 0

	for i := 0; i < numRounds; i++ {
		res, err := c.RunRound(batch)
		if err != nil {
			return BenchResult{}, err
		}
		totalRoundTime += res.RoundTime
		totalSignTime += res.SignTime

		if res.WasTimeout {
			curConsec++
			if curConsec > maxConsec {
				maxConsec = curConsec
			}
		} else {
			curConsec = 0
		}
	}

	elapsed := time.Since(start)
	modeName := "round-robin"
	if c.Mode == ModeReputation {
		modeName = "reputation"
	}

	tps := 0.0
	if elapsed.Seconds() > 0 {
		tps = float64(c.delivered) / elapsed.Seconds() / 1000.0 // ktx/s
	}

	return BenchResult{
		Mode:           modeName,
		N:              c.N,
		NumByzantine:   len(c.byzantineIDs),
		TotalRounds:    numRounds,
		SuccessRounds:  c.successRound,
		ViewChanges:    c.viewChanges,
		TxDelivered:    c.delivered,
		TPS:            tps,
		AvgRoundMs:     float64(totalRoundTime.Milliseconds()) / float64(numRounds),
		AvgSignMs:      float64(totalSignTime.Milliseconds()) / float64(numRounds),
		ElapsedMs:      float64(elapsed.Milliseconds()),
		MaxConsecFails: maxConsec,
	}, nil
}

// Reset clears all state for a fresh run (keeps keys and committee).
func (c *RepBenchCluster) Reset() {
	c.pipeline.reset()
	c.curView = 1
	c.curHeight = 1
	c.delivered = 0
	c.viewChanges = 0
	c.successRound = 0

	genesis := &pb.Block{ParentHash: make([]byte, 32), Height: 0, ConfNumber: 0}
	c.chain = newMemBlockchain()
	c.chain.put(genesis)
	genesisHash := hashBlock(genesis)
	c.genericQC = &pb.QuorumCert{ViewNumber: 0, ConfNumber: 0, BlockHash: genesisHash}
	c.lastHash = genesisHash

	for i := range c.safety {
		c.safety[i] = &safeNodeState{genericQC: c.genericQC}
	}

	if c.Mode == ModeReputation {
		c.repStore = reputation.NewStore()
		c.repSelector = reputation.NewLeaderSelector(c.repStore)
	}
}
