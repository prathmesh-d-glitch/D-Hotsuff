package reputation

import (
	"sort"
	"sync"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
)

const DefaultAlpha = 0.6
const DefaultBeta = 0.4

type ReplicaStats struct {
	RoundsAsLeader    uint64
	CommittedAsLeader uint64
	Timeouts          uint64
	LastLedHeight     uint64
}

func (s *ReplicaStats) CommitRate() float64 {
	if s.RoundsAsLeader == 0 {
		return 1.0
	}
	return float64(s.CommittedAsLeader) / float64(s.RoundsAsLeader)
}

func (s *ReplicaStats) Novelty(currentHeight uint64) float64 {
	if currentHeight == 0 {
		return 1.0
	}
	gap := currentHeight - s.LastLedHeight
	if s.LastLedHeight > currentHeight {
		gap = 0
	}
	return float64(gap) / float64(currentHeight)
}

type Store struct {
	mu    sync.RWMutex
	stats map[string]*ReplicaStats
	alpha float64
	beta  float64
}

func NewStore() *Store {
	return &Store{
		stats: make(map[string]*ReplicaStats),
		alpha: DefaultAlpha,
		beta:  DefaultBeta,
	}
}

func NewStoreWeighted(alpha, beta float64) *Store {
	if alpha+beta < 0.99 || alpha+beta > 1.01 {
		panic("reputation: alpha + beta must equal 1.0")
	}
	return &Store{
		stats: make(map[string]*ReplicaStats),
		alpha: alpha,
		beta:  beta,
	}
}

func (s *Store) get(id string) *ReplicaStats {
	st, ok := s.stats[id]
	if !ok {
		st = &ReplicaStats{}
		s.stats[id] = st
	}
	return st
}

func (s *Store) RecordLeaderRound(replicaID string) {
	s.mu.Lock()
	s.get(replicaID).RoundsAsLeader++
	s.mu.Unlock()
}

func (s *Store) RecordCommit(leaderID string, committedHeight uint64) {
	s.mu.Lock()
	st := s.get(leaderID)
	st.CommittedAsLeader++
	if committedHeight > st.LastLedHeight {
		st.LastLedHeight = committedHeight
	}
	s.mu.Unlock()
}

func (s *Store) RecordTimeout(replicaID string) {
	s.mu.Lock()
	s.get(replicaID).Timeouts++
	s.mu.Unlock()
}

func (s *Store) Score(replicaID string, currentHeight uint64) float64 {
	s.mu.RLock()
	st, ok := s.stats[replicaID]
	s.mu.RUnlock()

	if !ok {
		return s.alpha*1.0 + s.beta*1.0
	}
	return s.alpha*st.CommitRate() + s.beta*st.Novelty(currentHeight)
}

func (s *Store) Stats(replicaID string) ReplicaStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if st, ok := s.stats[replicaID]; ok {
		return *st
	}
	return ReplicaStats{}
}

type LeaderSelector struct {
	store *Store
}

func NewLeaderSelector(store *Store) *LeaderSelector {
	return &LeaderSelector{store: store}
}

func (ls *LeaderSelector) Select(c *membership.Committee, currentHeight uint64) *membership.Replica {
	if len(c.Replicas) == 0 {
		return nil
	}

	type scored struct {
		r     *membership.Replica
		score float64
	}

	candidates := make([]scored, len(c.Replicas))
	for i, r := range c.Replicas {
		candidates[i] = scored{r, ls.store.Score(r.ID, currentHeight)}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].r.ID < candidates[j].r.ID
	})

	return candidates[0].r
}

func (ls *LeaderSelector) ScoreTable(c *membership.Committee, currentHeight uint64) map[string]float64 {
	table := make(map[string]float64, len(c.Replicas))
	for _, r := range c.Replicas {
		table[r.ID] = ls.store.Score(r.ID, currentHeight)
	}
	return table
}
