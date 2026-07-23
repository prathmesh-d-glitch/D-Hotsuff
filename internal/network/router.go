package network

// router.go — dispatches incoming gRPC calls to the consensus engine.

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// ConsensusEngine is the narrow interface Router needs to dispatch RPCs.
// Keeps the network package from importing the consensus package directly.
type ConsensusEngine interface {
	HandlePropose(block *pb.Block) (*pb.VoteMsg, error)
	HandleNewView(msg *pb.NewViewMsg)
}

// BlockStore serves history and update requests for joining replicas.
type BlockStore interface {
	BestBlock() (*pb.Block, error)
	History() ([]*pb.Block, error)
}

// Router implements pb.DHotStuffServer and routes each RPC to the right handler.
type Router struct {
	pb.UnimplementedDHotStuffServer
	engine ConsensusEngine
	store  BlockStore
}

// NewRouter constructs a Router with the given engine and block store.
func NewRouter(engine ConsensusEngine, store BlockStore) *Router {
	return &Router{engine: engine, store: store}
}

// Propose signs the block and returns the vote — this is the hot consensus path.
func (r *Router) Propose(ctx context.Context, block *pb.Block) (*pb.VoteMsg, error) {
	if block == nil {
		return nil, status.Error(codes.InvalidArgument, "network.Router.Propose: nil block")
	}

	vote, err := r.engine.HandlePropose(block)
	if err != nil {
		// safeNode rejected or signing failed; don't count this toward quorum
		return nil, status.Errorf(codes.FailedPrecondition,
			"network.Router.Propose: engine rejected block at height %d: %v",
			block.GetHeight(), err)
	}

	return vote, nil
}

// SendNewView forwards a new-view message to the consensus engine during view-change.
func (r *Router) SendNewView(ctx context.Context, msg *pb.NewViewMsg) (*emptypb.Empty, error) {
	if msg == nil {
		return nil, status.Error(codes.InvalidArgument,
			"network.Router.SendNewView: nil message")
	}

	r.engine.HandleNewView(msg)
	return &emptypb.Empty{}, nil
}

// RequestUpdate returns our best committed block to a catching-up replica.
func (r *Router) RequestUpdate(ctx context.Context, req *pb.UpdateRequest) (*pb.UpdateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument,
			"network.Router.RequestUpdate: nil request")
	}

	best, err := r.store.BestBlock()
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"network.Router.RequestUpdate: block store error: %v", err)
	}

	return &pb.UpdateResponse{BestBlock: best}, nil
}

// RequestHistory returns the full committed chain for a joining replica.
func (r *Router) RequestHistory(ctx context.Context, req *pb.HistoryRequest) (*pb.HistoryResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument,
			"network.Router.RequestHistory: nil request")
	}

	history, err := r.store.History()
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"network.Router.RequestHistory: block store error: %v", err)
	}

	return &pb.HistoryResponse{History: history}, nil
}

// compile-time check that Router satisfies the gRPC server interface
var _ pb.DHotStuffServer = (*Router)(nil)

func routerError(code codes.Code, method, format string, args ...any) error {
	return status.Errorf(code, fmt.Sprintf("network.Router.%s: %s", method, format), args...)
}
