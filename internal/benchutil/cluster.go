// Package benchutil provides an in-process benchmark harness for D-HotStuff.
// Runs real consensus code (ECDSA, QC, safeNode, pipeline) without TCP.
package benchutil

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
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// memBlockchain is an in-memory BlockchainReader.
type memBlockchain struct {
	mu     sync.RWMutex
	blocks map[string]*pb.Block
}

func newMemBlockchain() *memBlockchain {
	return &memBlockchain{blocks: make(map[string]*pb.Block)}
}

// hashBlock returns SHA-256(parentHash || height_BE8) — same as the consensus package.
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
	visited := make(map[string]bool)
	cur := hex.EncodeToString(childHash)
	target := hex.EncodeToString(ancestorHash)
	for i := 0; i < 1024; i++ {
		if cur == target {
			return true
		}
		if visited[cur] {
			return false
		}
		visited[cur] = true
		b, ok := m.blocks[cur]
		if !ok {
			return false
		}
		cur = hex.EncodeToString(b.GetParentHash())
	}
	return false
}

// safeNodeState holds per-replica safety variables.
type safeNodeState struct {
	lockedQC  *pb.QuorumCert
	genericQC *pb.QuorumCert
}

// safeNode returns true if it is safe to vote for node (Algorithm 1).
func (s *safeNodeState) safeNode(node *pb.Block, qc *pb.QuorumCert, bc *memBlockchain) bool {
	if s.lockedQC == nil {
		return true
	}
	if qc.GetViewNumber() > s.lockedQC.GetViewNumber() {
		return true
	}
	return bc.Extends(node.GetParentHash(), s.lockedQC.GetBlockHash())
}

// pipelineWindow is a 4-slot sliding window for pipelined commits.
type pipelineWindow struct {
	slots [4]*pb.Block
}

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

// deliverCounter tracks committed transactions and applies membership changes.
type deliverCounter struct {
	mu        sync.Mutex
	delivered int
	configs   *membership.ConfigStore
}

func (d *deliverCounter) deliver(block *pb.Block) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := len(block.GetBatch())
	d.delivered += n
	// apply membership changes so the committee evolves correctly
	mc, err := d.configs.AtNumber(block.GetConfNumber())
	if err != nil {
		return n
	}
	var memReqs []*pb.MembershipRequest
	for _, req := range block.GetBatch() {
		if req.GetType() != pb.RequestType_REGULAR {
			memReqs = append(memReqs, req)
		}
	}
	if len(memReqs) > 0 {
		if newMc, err := mc.Apply(memReqs); err == nil {
			_ = d.configs.Install(newMc)
		}
	}
	return n
}

func (d *deliverCounter) total() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.delivered
}

func (d *deliverCounter) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.delivered = 0
}

// BenchCluster is an n-replica in-process D-HotStuff cluster.
// Create once with NewBenchCluster (keygen is slow) and call Reset between runs.
type BenchCluster struct {
	N       int
	MC      *membership.Committee
	Configs *membership.ConfigStore

	keys      []*ecdsa.PrivateKey
	safety    []*safeNodeState
	pipeline  *pipelineWindow
	chain     *memBlockchain
	dlv       *deliverCounter
	curView   uint64
	curHeight uint64
	genericQC *pb.QuorumCert
	lastHash  []byte
}

// NewBenchCluster creates an n-replica cluster. Key generation takes ~0.5 ms/replica.
func NewBenchCluster(n int) (*BenchCluster, error) {
	if n < 4 {
		return nil, fmt.Errorf("benchutil: n must be ≥ 4 (nc ≥ 3fc+1 requires n ≥ 4)")
	}

	keys := make([]*ecdsa.PrivateKey, n)
	reps := make([]*membership.Replica, n)
	for i := 0; i < n; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("benchutil: keygen P%d: %w", i+1, err)
		}
		keys[i] = priv
		reps[i] = &membership.Replica{
			ID:     fmt.Sprintf("P%d", i+1),
			Addr:   fmt.Sprintf("127.0.0.1:%d", 8000+i+1),
			PubKey: &priv.PublicKey,
		}
	}

	mc := membership.NewCommittee(0, reps)
	configs := membership.NewConfigStore(mc)

	genesis := &pb.Block{ParentHash: make([]byte, 32), Height: 0, ConfNumber: 0}
	chain := newMemBlockchain()
	chain.put(genesis)

	genesisHash := hashBlock(genesis)
	genesisQC := &pb.QuorumCert{ViewNumber: 0, ConfNumber: 0, BlockHash: genesisHash}

	safety := make([]*safeNodeState, n)
	for i := range safety {
		safety[i] = &safeNodeState{genericQC: genesisQC}
	}

	return &BenchCluster{
		N:         n,
		MC:        mc,
		Configs:   configs,
		keys:      keys,
		safety:    safety,
		pipeline:  &pipelineWindow{},
		chain:     chain,
		dlv:       &deliverCounter{configs: configs},
		curView:   1,
		curHeight: 1,
		genericQC: genesisQC,
		lastHash:  genesisHash,
	}, nil
}

// RoundResult holds the timing breakdown of one consensus round.
type RoundResult struct {
	LeaderPropose  time.Duration // block creation
	SignPhase      time.Duration // Qc ECDSA sign operations
	AggregatePhase time.Duration // vote aggregation + QC creation
	DeliverPhase   time.Duration // pipeline advance + deliver
	TotalRound     time.Duration // end-to-end
	TxDelivered    int           // transactions committed this round
}

// RunRound executes one full consensus round and returns timing metrics.
// Not safe for concurrent use.
func (c *BenchCluster) RunRound(batch []*pb.MembershipRequest) (RoundResult, error) {
	mc := c.Configs.Latest()
	qSize := mc.QuorumSize()
	t0 := time.Now()

	// step 1: leader creates the block
	t1 := time.Now()
	block := &pb.Block{
		ParentHash: c.lastHash,
		Batch:      batch,
		Justify:    c.genericQC,
		Height:     c.curHeight,
		ConfNumber: mc.Number,
	}
	c.chain.put(block)
	blockHash := hashBlock(block)
	proposeTime := time.Since(t1)

	// step 2: quorum replicas sign
	t2 := time.Now()
	votes := make([]*pb.VoteMsg, 0, qSize)
	for i := 0; i < qSize && i < len(c.keys); i++ {
		sig, err := dhcrypto.Sign(c.keys[i], c.curView, mc.Number, blockHash)
		if err != nil {
			return RoundResult{}, fmt.Errorf("benchutil: Sign P%d: %w", i+1, err)
		}
		votes = append(votes, &pb.VoteMsg{
			ViewNumber: c.curView,
			ConfNumber: mc.Number,
			BlockHash:  blockHash,
			SignerId:   mc.Replicas[i].ID,
			Signature:  sig,
		})
	}
	signTime := time.Since(t2)

	// step 3: aggregate votes and create QC
	t3 := time.Now()
	var acc []*pb.VoteMsg
	for _, v := range votes {
		acc = dhcrypto.AggregateVotes(acc, v)
	}
	qc, err := dhcrypto.CreateQC(acc, mc)
	if err != nil {
		return RoundResult{}, fmt.Errorf("benchutil: CreateQC: %w", err)
	}
	qc.ViewNumber = c.curView
	aggTime := time.Since(t3)

	// step 4: update safety state for all replicas
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

	// step 5: pipeline advance; commit if three-chain formed
	t4 := time.Now()
	toCommit := c.pipeline.advance(block)
	var txDelivered int
	if toCommit != nil {
		txDelivered = c.dlv.deliver(toCommit)
	}
	deliverTime := time.Since(t4)

	c.genericQC = qc
	c.lastHash = blockHash
	c.curView++
	c.curHeight++

	return RoundResult{
		LeaderPropose:  proposeTime,
		SignPhase:      signTime,
		AggregatePhase: aggTime,
		DeliverPhase:   deliverTime,
		TotalRound:     time.Since(t0),
		TxDelivered:    txDelivered,
	}, nil
}

// RunRounds runs numRounds consensus rounds and returns aggregate TPS.
func (c *BenchCluster) RunRounds(numRounds int, batch []*pb.MembershipRequest) (tps float64, txTotal int, err error) {
	start := time.Now()
	for i := 0; i < numRounds; i++ {
		res, rerr := c.RunRound(batch)
		if rerr != nil {
			return 0, 0, rerr
		}
		txTotal += res.TxDelivered
	}
	elapsed := time.Since(start)
	if elapsed > 0 {
		tps = float64(txTotal) / elapsed.Seconds()
	}
	return tps, txTotal, nil
}

// SignBlock signs blockHash on behalf of replica idx (for QC micro-benchmarks).
func (c *BenchCluster) SignBlock(idx int, viewNum, confNum uint64, blockHash []byte) ([]byte, error) {
	if idx < 0 || idx >= len(c.keys) {
		return nil, fmt.Errorf("benchutil: replica index %d out of range [0, %d)", idx, len(c.keys))
	}
	return dhcrypto.Sign(c.keys[idx], viewNum, confNum, blockHash)
}

// CreateQCFromVotes assembles a QuorumCert from votes.
func (c *BenchCluster) CreateQCFromVotes(votes []*pb.VoteMsg) (*pb.QuorumCert, error) {
	mc := c.Configs.Latest()
	return dhcrypto.CreateQC(votes, mc)
}

// Reset clears the pipeline and safety state for a fresh benchmark run.
// Keys and committee parameters are preserved.
func (c *BenchCluster) Reset() {
	c.pipeline.reset()
	c.curView = 1
	c.curHeight = 1

	genesis := &pb.Block{ParentHash: make([]byte, 32), Height: 0, ConfNumber: 0}
	c.chain = newMemBlockchain()
	c.chain.put(genesis)

	genesisHash := hashBlock(genesis)
	c.genericQC = &pb.QuorumCert{ViewNumber: 0, ConfNumber: 0, BlockHash: genesisHash}
	c.lastHash = genesisHash

	for i := range c.safety {
		c.safety[i] = &safeNodeState{genericQC: c.genericQC}
	}
	c.dlv.reset()
}

// TotalDelivered returns the cumulative committed transaction count since last Reset.
func (c *BenchCluster) TotalDelivered() int { return c.dlv.total() }

// MakeBatch returns a slice of REGULAR requests each carrying a 250-byte payload,
// totalling approximately payloadMB megabytes.
func MakeBatch(payloadMB int) []*pb.MembershipRequest {
	const txSize = 250
	txCount := (payloadMB * 1024 * 1024) / txSize

	batch := make([]*pb.MembershipRequest, txCount)
	for i := range batch {
		p := make([]byte, txSize)
		p[0] = byte(i & 0xFF)
		p[1] = byte((i >> 8) & 0xFF)
		for j := 2; j < txSize; j++ {
			p[j] = byte(j & 0xFF)
		}
		batch[i] = &pb.MembershipRequest{
			Type:     pb.RequestType_REGULAR,
			ClientId: fmt.Sprintf("c%d", i%100),
			Payload:  p,
		}
	}
	return batch
}

// EmptyBatch simulates a view-change round (no real transactions).
var EmptyBatch = []*pb.MembershipRequest{}
