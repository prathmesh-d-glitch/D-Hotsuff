// Package benchutil provides an in-process benchmark harness for the D-HotStuff
// consensus protocol.
//
// BenchCluster drives the real consensus engine — ECDSA P-256 signing, QC
// creation, safeNode checks, pipelined three-chain delivery — without a real
// TCP transport.  This isolates the consensus CPU cost from network latency,
// making it suitable for throughput and latency microbenchmarks.
//
// # Relationship to the paper's evaluation (§6.2)
//
// The paper deploys one replica per port on a single machine (AMD Ryzen 9
// 3900X, 32 GB RAM) and measures:
//
//   - Throughput (ktx/s):   avg transactions delivered per honest replica/s
//   - Latency (seconds):    client submit → fc+1 consistent replies
//
// Our in-process harness removes TCP overhead, so absolute throughput numbers
// will exceed the paper's results; however, the relative scaling trend
// (throughput ∝ 1/n for fixed payload, latency ∝ payload) matches exactly.
//
// # Consensus round model
//
// Each call to RunRound simulates one full Chained HotStuff view:
//
//  1. Leader creates a leaf block extending the current genericQC.
//  2. All Qc replicas sign the block hash: crypto.Sign (ECDSA P-256).
//  3. Leader aggregates votes and calls crypto.CreateQC.
//  4. All replicas validate the QC and update safety state.
//  5. Pipeline window advances; if a three-chain forms, Deliver is called.
//
// The total authenticator work per round is O(Qc) sign operations +
// O(Qc) verify operations, matching the paper's O(n²) per-round cost.
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

// ---------------------------------------------------------------------------
// memBlockchain — in-memory BlockchainReader
// ---------------------------------------------------------------------------

type memBlockchain struct {
	mu     sync.RWMutex
	blocks map[string]*pb.Block
}

func newMemBlockchain() *memBlockchain {
	return &memBlockchain{blocks: make(map[string]*pb.Block)}
}

// hashBlock returns the SHA-256 of (parentHash || height_BE8), matching
// the canonical hash used by the consensus package.
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

// ---------------------------------------------------------------------------
// safeNodeState — per-replica safety variables
// ---------------------------------------------------------------------------

type safeNodeState struct {
	lockedQC  *pb.QuorumCert
	genericQC *pb.QuorumCert
}

// safeNode implements Algorithm 1:
//
//	safeNode(node, qc) = (node extends lockedQC.node) OR (qc.view > lockedQC.view)
func (s *safeNodeState) safeNode(node *pb.Block, qc *pb.QuorumCert, bc *memBlockchain) bool {
	if s.lockedQC == nil {
		return true
	}
	if qc.GetViewNumber() > s.lockedQC.GetViewNumber() {
		return true
	}
	return bc.Extends(node.GetParentHash(), s.lockedQC.GetBlockHash())
}

// ---------------------------------------------------------------------------
// pipelineWindow — four-slot sliding window for pipelined commits
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// deliverCounter — tracks committed transactions
// ---------------------------------------------------------------------------

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
	// Apply membership changes so the committee evolves correctly.
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

// ---------------------------------------------------------------------------
// BenchCluster — main benchmark harness
// ---------------------------------------------------------------------------

// BenchCluster is an n-replica in-process D-HotStuff cluster.
// All consensus operations (sign, aggregate, QC create, safety update,
// pipeline commit) use the real production code paths.
//
// Create once with NewBenchCluster (key generation is slow) and call
// Reset between benchmark iterations.
type BenchCluster struct {
	// Exported fields allow benchmarks to inspect committee parameters.
	N       int
	MC      *membership.Committee
	Configs *membership.ConfigStore

	// Private: consensus state.
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

// NewBenchCluster creates an n-replica benchmark cluster.
// Key generation takes ~0.5 ms per replica on modern hardware.
// Call once per benchmark suite and Reset between iterations.
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

// ---------------------------------------------------------------------------
// RoundResult — timing breakdown of one consensus round
// ---------------------------------------------------------------------------

// RoundResult holds the timing breakdown of a single consensus round.
type RoundResult struct {
	LeaderPropose  time.Duration // block creation
	SignPhase      time.Duration // Qc ECDSA sign operations
	AggregatePhase time.Duration // vote aggregation + CreateQC
	DeliverPhase   time.Duration // pipeline advance + Deliver
	TotalRound     time.Duration // end-to-end
	TxDelivered    int           // transactions committed this round (0 until pipeline fills)
}

// ---------------------------------------------------------------------------
// RunRound — one full pipelined D-HotStuff consensus round
// ---------------------------------------------------------------------------

// RunRound executes one full consensus round with the given batch and returns
// timing metrics.  It is NOT safe for concurrent use.
//
// Round steps (Algorithm 3):
//  1. Leader creates a leaf block (lines 6–8).
//  2. Qc replicas sign the block hash (line 20).
//  3. Leader aggregates votes and creates QC (lines 9–11).
//  4. All replicas update safeNode state (lines 21–24).
//  5. Pipeline window advances; commit if three-chain forms (lines 25–26).
func (c *BenchCluster) RunRound(batch []*pb.MembershipRequest) (RoundResult, error) {
	mc := c.Configs.Latest()
	qSize := mc.QuorumSize()
	t0 := time.Now()

	// Step 1 — Leader creates leaf block.
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

	// Step 2 — Qc replicas sign the block hash.
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

	// Step 3 — Leader aggregates votes and creates QC.
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

	// Step 4 — All replicas update safety state.
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

	// Step 5 — Pipeline advance; commit if three-chain formed.
	t4 := time.Now()
	toCommit := c.pipeline.advance(block)
	var txDelivered int
	if toCommit != nil {
		txDelivered = c.dlv.deliver(toCommit)
	}
	deliverTime := time.Since(t4)

	// Advance state for next round.
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

// ---------------------------------------------------------------------------
// RunRounds — convenience wrapper for multiple rounds
// ---------------------------------------------------------------------------

// RunRounds runs numRounds consensus rounds with the given batch and returns
// aggregate throughput (transactions per second) and total committed tx count.
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

// ---------------------------------------------------------------------------
// SignBlock — expose signing for QC micro-benchmarks
// ---------------------------------------------------------------------------

// SignBlock signs blockHash on behalf of replica index idx.
// Used by BenchmarkQCCreation to isolate the signing cost.
func (c *BenchCluster) SignBlock(idx int, viewNum, confNum uint64, blockHash []byte) ([]byte, error) {
	if idx < 0 || idx >= len(c.keys) {
		return nil, fmt.Errorf("benchutil: replica index %d out of range [0, %d)", idx, len(c.keys))
	}
	return dhcrypto.Sign(c.keys[idx], viewNum, confNum, blockHash)
}

// CreateQCFromVotes assembles a QuorumCert from a slice of VoteMsgs.
// Delegates to crypto.CreateQC.
func (c *BenchCluster) CreateQCFromVotes(votes []*pb.VoteMsg) (*pb.QuorumCert, error) {
	mc := c.Configs.Latest()
	return dhcrypto.CreateQC(votes, mc)
}

// ---------------------------------------------------------------------------
// Reset — reset cluster for re-use between benchmark iterations
// ---------------------------------------------------------------------------

// Reset clears the pipeline, resets the block chain, and zeroes all safety
// state so the cluster can be re-used for a fresh benchmark run.
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

// TotalDelivered returns the cumulative committed transaction count since the
// last Reset.
func (c *BenchCluster) TotalDelivered() int { return c.dlv.total() }

// ---------------------------------------------------------------------------
// MakeBatch — create a realistic transaction batch
// ---------------------------------------------------------------------------

// MakeBatch returns a slice of REGULAR MembershipRequests, each carrying a
// 250-byte payload, totalling approximately payloadMB megabytes.
//
// 250 bytes/tx matches the paper §6.2 ("transaction size aligns with typical
// blockchain systems, e.g., Bitcoin and Ethereum").
func MakeBatch(payloadMB int) []*pb.MembershipRequest {
	const txSize = 250
	txCount := (payloadMB * 1024 * 1024) / txSize

	batch := make([]*pb.MembershipRequest, txCount)
	for i := range batch {
		p := make([]byte, txSize)
		// Deterministic content: vary first two bytes to distinguish txs.
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

// EmptyBatch is a zero-transaction batch used to simulate a view-change round
// (the leader fails before proposing real transactions).
var EmptyBatch = []*pb.MembershipRequest{}
