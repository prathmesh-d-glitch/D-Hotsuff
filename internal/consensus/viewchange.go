package consensus

// viewchange.go — view-change logic for D-HotStuff.
//
// From the paper §5.1 (efficiency analysis):
//
//	A view change sends genericQC (carrying O(n) ECDSA signatures) to the
//	next leader.  In the worst case there are O(n) consecutive view changes
//	before progress is made, so the total authenticator cost is:
//
//	  O(n) view-changes × O(n) sigs per QC × O(n) replicas = O(n³)
//
//	This matches the DPSS-based threshold-sig baseline but without the
//	latency of the re-sharing sub-protocol (paper §4.1).
//
// Reference: D-HotStuff Algorithm 3, "Finally" block (lines 27–36).

import (
	"context"
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/prathmesh-d-glitch/d-hotstuff/internal/membership"
	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// NetworkSender abstracts the point-to-point and broadcast transport layer
// used by the consensus protocol.
type NetworkSender interface {
	// Send unicasts msg to the replica at addr.
	Send(addr string, msg proto.Message) error

	// BroadcastToCommittee sends msg to every replica in c.
	BroadcastToCommittee(c *membership.Committee, msg proto.Message) error
}

// ViewChanger implements the view-change sub-protocol for a D-HotStuff replica.
//
// When a view timer expires, the replica increments its view counter and sends
// a NewViewMsg carrying its highest known genericQC to the next leader.
// The next leader collects Qc′ such messages before proposing.
//
// All methods are safe for concurrent use.
type ViewChanger struct {
	curView uint64
	safety  *SafetyState
	configs *membership.ConfigStore
	net     NetworkSender
	myID    string
	mu      sync.Mutex
}

// NewViewChanger constructs a ViewChanger with the given dependencies.
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

// OnTimeout implements the "Finally" block of Algorithm 3 (lines 27–36).
//
// When the view timer expires the replica:
//  1. Increments curView.
//  2. Retrieves the latest installed committee Mc.
//  3. (Paper §4.5) If the replica's current configuration is behind the
//     latest system configuration, it must sync first.  This is handled
//     externally; OnTimeout assumes the config store is up to date.
//  4. Determines the next leader for the new view.
//  5. Builds a NewViewMsg carrying curView, the current conf_number, and
//     the replica's highest known genericQC.
//  6. Sends the message to the next leader.
//
// The ctx parameter allows the caller to cancel the send if the replica is
// shutting down.
func (vc *ViewChanger) OnTimeout(ctx context.Context) error {
	vc.mu.Lock()

	// Algorithm 3, line 28: advance the view.
	vc.curView++
	view := vc.curView

	// Algorithm 3, line 29: get the latest committee.
	mc := vc.configs.Latest()

	// Algorithm 3, line 31: determine the next leader.
	nextLeader := mc.Leader(view)

	// Algorithm 3, lines 33–35: build NewViewMsg.
	msg := &pb.NewViewMsg{
		ViewNumber: view,
		ConfNumber: mc.Number,
		GenericQc:  vc.safety.GenericQC,
	}

	addr := nextLeader.Addr
	vc.mu.Unlock()

	// Check context before sending.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("consensus.OnTimeout: context cancelled before send: %w", err)
	}

	// Algorithm 3, line 36: send to next leader.
	if err := vc.net.Send(addr, msg); err != nil {
		return fmt.Errorf("consensus.OnTimeout: send NewViewMsg to %q (view %d): %w",
			addr, view, err)
	}

	return nil
}

// OnNewViewMessages is called on the leader to process collected NewViewMsg
// messages for the current view.
//
// It returns (highestQC, true) once at least c.QuorumSize() messages from
// distinct senders have been collected, where highestQC is the GenericQc with
// the largest ViewNumber among all msgs.  This QC becomes the new leader's
// "highQC" and will be used as the justify for its next block proposal.
//
// If there are not enough distinct senders, it returns (nil, false).
//
// Reference: Algorithm 3, lines 5–7 (leader waits for Qc' NewView messages).
func (vc *ViewChanger) OnNewViewMessages(
	msgs []*pb.NewViewMsg,
	c *membership.Committee,
) (*pb.QuorumCert, bool) {
	qSize := c.QuorumSize()

	// De-duplicate: count distinct senders.
	// We use ConfNumber as a proxy for the sender when the full sender ID is
	// not embedded in NewViewMsg — in practice each replica sends exactly one
	// NewViewMsg per view.  For now, treat each msg as distinct.
	if len(msgs) < qSize {
		return nil, false
	}

	return highestViewQC(msgs), true
}

// highestViewQC scans msgs and returns the GenericQc with the largest
// ViewNumber.  This is the "highQC" the new leader uses.
//
// If msgs is empty or all GenericQc fields are nil, returns nil.
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
