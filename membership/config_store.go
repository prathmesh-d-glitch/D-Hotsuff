package membership

import (
	"errors"
	"fmt"
	"sync"
)

// Sentinel errors returned by ConfigStore methods.
var (
	// ErrNotFound is returned by AtNumber when no configuration with the
	// requested number has been installed.
	ErrNotFound = errors.New("membership: configuration not found")

	// ErrOutOfOrder is returned by Install when the incoming committee's
	// Number does not equal the current store length (i.e. it is not the
	// immediate successor of the latest installed configuration).
	ErrOutOfOrder = errors.New("membership: configuration number is out of order")
)

// ConfigStore is a thread-safe, append-only log of Committee configurations.
//
// Definitions from the D-HotStuff paper (Definitions 2–3):
//
//	"Current configuration of P" — the latest Mc that replica P has installed,
//	i.e. configs[len-1].
//
//	"Latest configuration of the system" — the Mc with the highest c for which
//	at least one honest replica has called Install.  Because Install is
//	append-only and monotone, this invariant is maintained automatically.
//
// All methods are safe for concurrent use by multiple goroutines.
type ConfigStore struct {
	mu          sync.RWMutex
	configs     []*Committee
	subscribers []chan<- *Committee
}

// NewConfigStore creates a ConfigStore pre-seeded with the genesis committee
// (configuration number 0).  genesis must not be nil.
func NewConfigStore(genesis *Committee) *ConfigStore {
	return &ConfigStore{
		configs: []*Committee{genesis},
	}
}

// Latest returns the most recently installed Committee (highest config number).
// It holds a read lock for the duration of the call.
func (s *ConfigStore) Latest() *Committee {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configs[len(s.configs)-1]
}

// AtNumber returns the Committee with configuration number c, or ErrNotFound
// if no such configuration has been installed yet.
//
// Because configurations are stored at index c (Number == index), the lookup
// is O(1).
func (s *ConfigStore) AtNumber(c uint64) (*Committee, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if c >= uint64(len(s.configs)) {
		return nil, fmt.Errorf("%w: config number %d", ErrNotFound, c)
	}
	return s.configs[c], nil
}

// Install appends next as the newest configuration.
//
// Rules enforced:
//   - next.Number must equal uint64(len(configs)), i.e. it must be the exact
//     successor of the current latest.  Any gap or duplicate returns ErrOutOfOrder.
//
// On success, Install notifies all subscribers via a non-blocking channel send
// so that the consensus engine can react to configuration changes without
// blocking the install path.
func (s *ConfigStore) Install(next *Committee) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	expected := uint64(len(s.configs))
	if next.Number != expected {
		return fmt.Errorf("%w: got %d, want %d", ErrOutOfOrder, next.Number, expected)
	}

	s.configs = append(s.configs, next)

	// Non-blocking fan-out to all subscribers.
	for _, ch := range s.subscribers {
		select {
		case ch <- next:
		default:
			// The subscriber's channel is full or unread; skip rather than block.
		}
	}

	return nil
}

// Len returns the total number of installed configurations (including genesis).
func (s *ConfigStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.configs)
}

// Subscribe registers ch to receive a *Committee every time Install succeeds.
// The send is non-blocking: if ch is full at the time of Install, that
// particular notification is dropped.  Callers should size ch appropriately
// (typically 1 is sufficient when the consumer processes updates promptly).
//
// Subscribe is safe to call concurrently with Install and other methods.
func (s *ConfigStore) Subscribe(ch chan<- *Committee) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscribers = append(s.subscribers, ch)
}
