package l4proxy

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

// Ensure dialPeers binds to an explicitly configured local port for TCP.
func TestDialPeersUsesConfiguredLocalPortTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for upstream: %v", err)
	}
	defer ln.Close()

	localPortListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving local port: %v", err)
	}
	localPort := localPortListener.Addr().(*net.TCPAddr).Port
	localPortListener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			accepted <- conn
		}
	}()

	upstreamAddr := ln.Addr().String()
	localAddr := fmt.Sprintf("tcp/%s", fmt.Sprintf("127.0.0.1:%d", localPort))

	parsedUpstream, err := caddy.ParseNetworkAddress(upstreamAddr)
	if err != nil {
		t.Fatalf("parsing upstream address: %v", err)
	}

	h := &Handler{logger: zap.NewExample()}
	upstream := &Upstream{
		LocalAddr: localAddr,
		peers:     []*peer{{address: parsedUpstream}},
	}

	downClient, downServer := net.Pipe()
	defer downClient.Close()
	defer downServer.Close()
	down := layer4.WrapConnection(downServer, nil, h.logger)
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	upConns, err := h.dialPeers(upstream, repl, down)
	if err != nil {
		t.Fatalf("dialPeers: %v", err)
	}
	defer func() {
		for _, c := range upConns {
			c.Close()
		}
		select {
		case conn := <-accepted:
			if conn != nil {
				conn.Close()
			}
		default:
		}
	}()

	localTCPAddr, ok := upConns[0].LocalAddr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected TCP local address, got %T", upConns[0].LocalAddr())
	}
	if localTCPAddr.Port != localPort {
		t.Fatalf("expected local port %d, got %d", localPort, localTCPAddr.Port)
	}
}

// Ensure dialPeers binds to an explicitly configured local port for UDP.
func TestDialPeersUsesConfiguredLocalPortUDP(t *testing.T) {
	upstreamPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for upstream (udp): %v", err)
	}
	defer upstreamPC.Close()

	localPortPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving local udp port: %v", err)
	}
	localPort := localPortPC.LocalAddr().(*net.UDPAddr).Port
	localPortPC.Close()

	upstreamAddr := fmt.Sprintf("udp/%s", upstreamPC.LocalAddr().String())
	localAddr := fmt.Sprintf("udp/%s", fmt.Sprintf("127.0.0.1:%d", localPort))

	parsedUpstream, err := caddy.ParseNetworkAddress(upstreamAddr)
	if err != nil {
		t.Fatalf("parsing upstream address: %v", err)
	}

	h := &Handler{logger: zap.NewExample()}
	upstream := &Upstream{
		LocalAddr: localAddr,
		peers:     []*peer{{address: parsedUpstream}},
	}

	downClient, downServer := net.Pipe()
	defer downClient.Close()
	defer downServer.Close()
	down := layer4.WrapConnection(downServer, nil, h.logger)
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	upConns, err := h.dialPeers(upstream, repl, down)
	if err != nil {
		t.Fatalf("dialPeers udp: %v", err)
	}
	defer func() {
		for _, c := range upConns {
			c.Close()
		}
	}()

	localUDPAddr, ok := upConns[0].LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected UDP local address, got %T", upConns[0].LocalAddr())
	}
	if localUDPAddr.Port != localPort {
		t.Fatalf("expected local udp port %d, got %d", localPort, localUDPAddr.Port)
	}
}

// Ensure IPv6 source parsing and resolution works for TCP without requiring IPv6 connectivity.
func TestBuildDialerIPv6TCP(t *testing.T) {
	dialer, err := buildDialer("tcp6/[2001:db8::1]:4040", "tcp6", zap.NewNop())
	if err != nil {
		t.Fatalf("buildDialer ipv6 tcp: %v", err)
	}
	if dialer == nil {
		t.Fatalf("expected dialer")
	}
	addr, ok := dialer.LocalAddr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected TCPAddr, got %T", dialer.LocalAddr)
	}
	if addr.Port != 4040 {
		t.Fatalf("expected port 4040, got %d", addr.Port)
	}
	if !addr.IP.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("expected ip 2001:db8::1, got %s", addr.IP)
	}
}

// Ensure IPv6 source parsing and resolution works for UDP without requiring IPv6 connectivity.
func TestBuildDialerIPv6UDP(t *testing.T) {
	dialer, err := buildDialer("udp6/[2001:db8::2]:5353", "udp6", zap.NewNop())
	if err != nil {
		t.Fatalf("buildDialer ipv6 udp: %v", err)
	}
	if dialer == nil {
		t.Fatalf("expected dialer")
	}
	addr, ok := dialer.LocalAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected UDPAddr, got %T", dialer.LocalAddr)
	}
	if addr.Port != 5353 {
		t.Fatalf("expected port 5353, got %d", addr.Port)
	}
	if !addr.IP.Equal(net.ParseIP("2001:db8::2")) {
		t.Fatalf("expected ip 2001:db8::2, got %s", addr.IP)
	}
}

func TestBuildDialerDefaultsToTCPWhenNoProtocol(t *testing.T) {
	dialer, err := buildDialer("127.0.0.1:4040", "tcp", zap.NewNop())
	if err != nil {
		t.Fatalf("buildDialer default tcp: %v", err)
	}
	addr, ok := dialer.LocalAddr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected TCPAddr, got %T", dialer.LocalAddr)
	}
	if addr.Port != 4040 {
		t.Fatalf("expected port 4040, got %d", addr.Port)
	}
}

func TestBuildDialerDefaultsEphemeralPortWhenMissing(t *testing.T) {
	dialer, err := buildDialer("127.0.0.1", "tcp", zap.NewNop())
	if err != nil {
		t.Fatalf("buildDialer default port: %v", err)
	}
	addr, ok := dialer.LocalAddr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected TCPAddr, got %T", dialer.LocalAddr)
	}
	if addr.Port != 0 {
		t.Fatalf("expected port 0 (ephemeral), got %d", addr.Port)
	}
}

func TestBuildDialerDefaultsToUpstreamNetworkWhenEmptyProtocol(t *testing.T) {
	dialer, err := buildDialer("192.0.2.1:5353", "udp", zap.NewNop())
	if err != nil {
		t.Fatalf("buildDialer upstream default: %v", err)
	}
	addr, ok := dialer.LocalAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected UDPAddr, got %T", dialer.LocalAddr)
	}
	if addr.Port != 5353 {
		t.Fatalf("expected port 5353, got %d", addr.Port)
	}
}

func TestBuildDialerRejectsProtocolInLocalAddr(t *testing.T) {
	if _, err := buildDialer("udp/127.0.0.1:53", "udp", zap.NewNop()); err == nil {
		t.Fatalf("expected error for protocol in local_address")
	}
}

func TestBuildDialerRejectsUnixForTCPUpstream(t *testing.T) {
	if _, err := buildDialer("/tmp/l4proxy-test.sock", "tcp", zap.NewNop()); err == nil {
		t.Fatalf("expected error for unix local_address with tcp upstream")
	}
}

func TestBuildDialerRejectsIPForUnixUpstream(t *testing.T) {
	if _, err := buildDialer("127.0.0.1", "unix", zap.NewNop()); err == nil {
		t.Fatalf("expected error for ip local_address with unix upstream")
	}
}

// Active health checks should honor local_address when provided.
func TestActiveHealthCheckUsesLocalAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer ln.Close()

	accepted := make(chan *net.TCPAddr, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				accepted <- tcpAddr
			}
			_ = conn.Close()
		}
	}()

	upAddr, err := caddy.ParseNetworkAddress(ln.Addr().String())
	if err != nil {
		t.Fatalf("parse upstream addr: %v", err)
	}

	h := &Handler{
		logger: zap.NewExample(),
		HealthChecks: &HealthChecks{
			Active: &ActiveHealthChecks{
				Timeout: caddy.Duration(2 * time.Second),
				logger:  zap.NewExample(),
			},
		},
	}

	upstream := &Upstream{
		LocalAddr: "127.0.0.1", // defaults to tcp with ephemeral port
		peers:     []*peer{{address: upAddr}},
	}

	if err := h.doActiveHealthCheck(upstream, upstream.peers[0]); err != nil {
		t.Fatalf("active health check: %v", err)
	}

	select {
	case remote := <-accepted:
		if !remote.IP.Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("expected local bind ip 127.0.0.1, got %s", remote.IP)
		}
	default:
		t.Fatalf("no health check connection observed")
	}
}
