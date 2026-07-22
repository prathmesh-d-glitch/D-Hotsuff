package consensus

// viewchange.go — view-change sub-protocol for D-HotStuff.

import (
	"context"
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// NetworkSender abstracts the transport layer used by consensus.
type NetworkSender interface {
	Send(addr string, msg proto.Message) error
	BroadcastToCommittee(c *membership.Committee, msg proto.Message) error
}

// ViewChanger handles timeouts: increments the view and notifies the next leader.
type ViewChanger struct {
	curView uint64
	safety  *SafetyState
	configs *membership.ConfigStore
	net     NetworkSender
	myID    string
	mu      sync.Mutex
}

// NewViewChanger constructs a ViewChanger.
func NewViewChanger(
	initialView uint64,
	safety *SafetyState,
	configs *membership.ConfigStore,
	net NetworkSender,
	myID string,
) *ViewChanger {
	return &ViewChanger{
		curView: initialView,
		safety:  safety,
		configs: configs,
		net:     net,
		myID:    myID,
	}
}

// CurView returns the current view number, safe for concurrent access.
func (vc *ViewChanger) CurView() uint64 {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	return vc.curView
}

// OnTimeout increments the view and sends a NewViewMsg to the next leader.
func (vc *ViewChanger) OnTimeout(ctx context.Context) error {
	vc.mu.Lock()

	vc.curView++
	view := vc.curView
	mc := vc.configs.Latest()
	nextLeader := mc.Leader(view)

	msg := &pb.NewViewMsg{
		ViewNumber: view,
		ConfNumber: mc.Number,
		GenericQc:  vc.safety.GenericQC,
	}

	addr := nextLeader.Addr
	vc.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("consensus.OnTimeout: context cancelled before send: %w", err)
	}

	if err := vc.net.Send(addr, msg); err != nil {
		return fmt.Errorf("consensus.OnTimeout: send NewViewMsg to %q (view %d): %w",
			addr, view, err)
	}

	return nil
}

// OnNewViewMessages returns the highest genericQC once a quorum of new-view messages is collected.
func (vc *ViewChanger) OnNewViewMessages(
	msgs []*pb.NewViewMsg,
	c *membership.Committee,
) (*pb.QuorumCert, bool) {
	if len(msgs) < c.QuorumSize() {
		return nil, false // not enough messages yet
	}
	return highestViewQC(msgs), true
}

// highestViewQC returns the QC with the largest view number among all messages.
func highestViewQC(msgs []*pb.NewViewMsg) *pb.QuorumCert {
	var best *pb.QuorumCert
	var bestView uint64

	for _, m := range msgs {
		qc := m.GetGenericQc()
		if qc == nil {
			continue
		}
		if best == nil || qc.GetViewNumber() > bestView {
			best = qc
			bestView = qc.GetViewNumber()
		}
	}

	return best
}
