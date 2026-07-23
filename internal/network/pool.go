package network

// pool.go — outbound gRPC connection cache for D-HotStuff.
// One persistent connection per peer address; dials on first use.

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	pb "github.com/prathmesh-d-glitch/d-hotstuff/proto"
)

// DefaultDialTimeout is the max wait when establishing a new connection.
const DefaultDialTimeout = 5 * time.Second

// ConnPool caches one gRPC connection per peer address.
type ConnPool struct {
	mu    sync.RWMutex
	conns map[string]*grpc.ClientConn // "host:port" → connection
	opts  []grpc.DialOption
}

// NewConnPool constructs a ConnPool with the given dial options.
func NewConnPool(opts ...grpc.DialOption) *ConnPool {
	return &ConnPool{
		conns: make(map[string]*grpc.ClientConn),
		opts:  opts,
	}
}

// DefaultDialOpts returns production dial options: mutual TLS + keepalive.
func DefaultDialOpts(tlsCfg *tls.Config) []grpc.DialOption {
	var creds credentials.TransportCredentials
	if tlsCfg != nil {
		creds = credentials.NewTLS(tlsCfg)
	} else {
		// server-auth only (no client cert)
		creds = credentials.NewClientTLSFromCert(nil, "")
	}
	return []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second, // ping interval
			Timeout:             10 * time.Second, // pong timeout
			PermitWithoutStream: true,
		}),
		grpc.WithBlock(),
	}
}

// InsecureDialOpts returns dial options without TLS — for local testing only.
func InsecureDialOpts() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}
}

// GetConn returns a cached connection to addr, dialling if one doesn't exist.
func (p *ConnPool) GetConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	// fast path: already connected
	p.mu.RLock()
	cc, ok := p.conns[addr]
	p.mu.RUnlock()
	if ok {
		return cc, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// double-check after acquiring write lock
	if cc, ok = p.conns[addr]; ok {
		return cc, nil
	}

	dialCtx, cancel := context.WithTimeout(ctx, DefaultDialTimeout)
	defer cancel()

	//nolint:staticcheck
	cc, err := grpc.DialContext(dialCtx, addr, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("network.ConnPool: dial %q: %w", addr, err)
	}

	p.conns[addr] = cc
	return cc, nil
}

// GetClient returns a typed DHotStuffClient stub for addr.
func (p *ConnPool) GetClient(ctx context.Context, addr string) (pb.DHotStuffClient, error) {
	cc, err := p.GetConn(ctx, addr)
	if err != nil {
		return nil, err
	}
	return pb.NewDHotStuffClient(cc), nil
}

// Close gracefully shuts down all cached connections.
func (p *ConnPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var firstErr error
	for addr, cc := range p.conns {
		if err := cc.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("network.ConnPool: close %q: %w", addr, err)
		}
		delete(p.conns, addr)
	}
	return firstErr
}

// Len returns the number of open connections (useful in tests).
func (p *ConnPool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.conns)
}
