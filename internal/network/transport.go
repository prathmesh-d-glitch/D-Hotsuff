package network

// transport.go — implements consensus.NetworkSender over gRPC.

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// DefaultRPCTimeout is the per-call deadline for outbound gRPC calls.
// Keep shorter than the consensus view timer.
const DefaultRPCTimeout = 2 * time.Second

// Transport implements consensus.NetworkSender using ConnPool for outbound connections.
type Transport struct {
	myAddr     string        // skip self in broadcasts
	pool       *ConnPool
	rpcTimeout time.Duration
}

// NewTransport constructs a Transport.
// Zero rpcTimeout falls back to DefaultRPCTimeout.
func NewTransport(myAddr string, pool *ConnPool, rpcTimeout time.Duration) *Transport {
	if rpcTimeout <= 0 {
		rpcTimeout = DefaultRPCTimeout
	}
	return &Transport{
		myAddr:     myAddr,
		pool:       pool,
		rpcTimeout: rpcTimeout,
	}
}

// Send unicasts msg to the replica at addr.
// *pb.Block → Propose RPC; *pb.NewViewMsg → SendNewView RPC.
func (t *Transport) Send(addr string, msg proto.Message) error {
	ctx, cancel := context.WithTimeout(context.Background(), t.rpcTimeout)
	defer cancel()

	client, err := t.pool.GetClient(ctx, addr)
	if err != nil {
		return fmt.Errorf("transport.Send to %q: %w", addr, err)
	}

	switch m := msg.(type) {
	case *pb.Block:
		// vote is returned as the RPC response value, not a separate call
		_, err = client.Propose(ctx, m)
		if err != nil {
			return fmt.Errorf("transport.Send Propose to %q: %w", addr, err)
		}

	case *pb.NewViewMsg:
		_, err = client.SendNewView(ctx, m)
		if err != nil {
			return fmt.Errorf("transport.Send NewView to %q: %w", addr, err)
		}

	default:
		return fmt.Errorf("transport.Send: unsupported message type %T", msg)
	}

	return nil
}

// BroadcastToCommittee sends msg to every replica in c concurrently.
// Skips self (leader calls HandlePropose directly instead of looping back).
func (t *Transport) BroadcastToCommittee(c *membership.Committee, msg proto.Message) error {
	replicas := c.Replicas

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		errMsgs []string
	)

	for _, r := range replicas {
		r := r
		if r.Addr == t.myAddr {
			continue // don't send to ourselves
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := t.Send(r.Addr, msg); err != nil {
				mu.Lock()
				errMsgs = append(errMsgs,
					fmt.Sprintf("  replica %s (%s): %v", r.ID, r.Addr, err))
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	if len(errMsgs) > 0 {
		// some replicas unreachable — BFT proceeds if quorum still responds
		return fmt.Errorf("transport.BroadcastToCommittee: %d send errors:\n%s",
			len(errMsgs), joinLines(errMsgs))
	}
	return nil
}

func joinLines(ss []string) string {
	out := make([]byte, 0, 128)
	for _, s := range ss {
		out = append(out, s...)
		out = append(out, '\n')
	}
	return string(out)
}
