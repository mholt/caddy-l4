package l4proxy

import (
	"context"
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

// listenTCP returns a loopback TCP listener closed at the end of the test.
func listenTCP(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// tcpDownstream connects a real TCP client to a server end wrapped in a
// layer4.Connection, so half-closes behave like they do in production
// (net.Pipe has no CloseWrite).
func tcpDownstream(t *testing.T, h *Handler) (*net.TCPConn, *layer4.Connection) {
	t.Helper()
	ln := listenTCP(t)
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialing downstream: %v", err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accepting downstream: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client.(*net.TCPConn), layer4.WrapConnection(server, nil, h.logger)
}

// newTestProxy returns a proxy handler with a single upstream.
func newTestProxy(t *testing.T, upstreamAddr string) *Handler {
	t.Helper()
	parsed, err := caddy.ParseNetworkAddress(upstreamAddr)
	if err != nil {
		t.Fatalf("parsing upstream address: %v", err)
	}
	h := &Handler{logger: zap.NewNop(), ctx: caddy.Context{Context: context.Background()}}
	h.LoadBalancing = &LoadBalancing{SelectionPolicy: &RandomSelection{}}
	h.Upstreams = UpstreamPool{{peers: []*peer{{address: &parsed}}}}
	return h
}
