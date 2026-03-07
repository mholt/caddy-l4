package l4proxy

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

type fakeLookup struct {
	ips []net.IP
	err error
}

func (f fakeLookup) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f.ips, f.err
}

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
	localAddr := fmt.Sprintf("127.0.0.1:%d", localPort)

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
	localAddr := fmt.Sprintf("127.0.0.1:%d", localPort)

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

// Build-local-address selection tests
func TestSelectLocalAddrIPv6TCP(t *testing.T) {
	addrs := buildLocalAddrs("[2001:db8::1]:4040", "tcp6", 6, zap.NewNop())
	if len(addrs) != 1 {
		t.Fatalf("expected 1 addr, got %d", len(addrs))
	}
	addr := addrs[0]
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected TCPAddr, got %T", addr)
	}
	if tcpAddr.Port != 4040 {
		t.Fatalf("expected port 4040, got %d", tcpAddr.Port)
	}
	if !tcpAddr.IP.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("expected ip 2001:db8::1, got %s", tcpAddr.IP)
	}
}

func TestSelectLocalAddrIPv6UDP(t *testing.T) {
	addrs := buildLocalAddrs("[2001:db8::2]:5353", "udp6", 6, zap.NewNop())
	if len(addrs) != 1 {
		t.Fatalf("expected 1 addr, got %d", len(addrs))
	}
	addr := addrs[0]
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected UDPAddr, got %T", addr)
	}
	if udpAddr.Port != 5353 {
		t.Fatalf("expected port 5353, got %d", udpAddr.Port)
	}
	if !udpAddr.IP.Equal(net.ParseIP("2001:db8::2")) {
		t.Fatalf("expected ip 2001:db8::2, got %s", udpAddr.IP)
	}
}

func TestSelectLocalAddrDefaultsToUpstreamFamily(t *testing.T) {
	addrs := buildLocalAddrs("192.0.2.1:5353", "udp", 0, zap.NewNop())
	if len(addrs) != 1 {
		t.Fatalf("expected 1 addr, got %d", len(addrs))
	}
	if _, ok := addrs[0].(*net.UDPAddr); !ok {
		t.Fatalf("expected UDPAddr, got %T", addrs[0])
	}
}

func TestSelectLocalAddrSkipsMismatchedFamilies(t *testing.T) {
	if addrs := buildLocalAddrs("::1", "tcp4", 4, zap.NewNop()); len(addrs) != 0 {
		t.Fatalf("expected no addr for ipv6 source with tcp4 upstream")
	}
	if addrs := buildLocalAddrs("127.0.0.1", "tcp6", 6, zap.NewNop()); len(addrs) != 0 {
		t.Fatalf("expected no addr for ipv4 source with tcp6 upstream")
	}
}

func TestSelectLocalAddrChoosesMatchingFromList(t *testing.T) {
	addrs := buildLocalAddrs("127.0.0.1, ::1", "tcp6", 6, zap.NewNop())
	if len(addrs) == 0 {
		t.Fatalf("expected matching addr")
	}
	if tcpAddr, ok := addrs[0].(*net.TCPAddr); !ok || tcpAddr.IP.To4() != nil {
		t.Fatalf("expected ipv6 local addr, got %T %v", addrs[0], addrs[0])
	}

	addrs = buildLocalAddrs("127.0.0.1, ::1", "tcp4", 4, zap.NewNop())
	if len(addrs) == 0 {
		t.Fatalf("expected matching addr")
	}
	if tcpAddr, ok := addrs[0].(*net.TCPAddr); !ok || tcpAddr.IP.To4() == nil {
		t.Fatalf("expected ipv4 local addr, got %T %v", addrs[0], addrs[0])
	}
}

func TestResolveDestFamilyWithPreferences(t *testing.T) {
	orig := lookupIP
	t.Cleanup(func() { lookupIP = orig })

	table := []struct {
		name   string
		netw   string
		host   string
		pref   string
		ips    []net.IP
		expect int
		err    bool
	}{
		{name: "literal v4 disallowed by pref", netw: "tcp", host: "192.0.2.1:80", pref: "ipv6_only", ips: nil, err: true},
		{name: "literal v6 disallowed by pref", netw: "tcp", host: "[2001:db8::1]:80", pref: "ipv4_only", ips: nil, err: true},
		{name: "hint tcp4 vs ipv6_only", netw: "tcp4", host: "example.com:80", pref: "ipv6_only", ips: []net.IP{net.ParseIP("2001:db8::1")}, err: true},
		{name: "hint tcp6 vs ipv4_only", netw: "tcp6", host: "example.com:80", pref: "ipv4_only", ips: []net.IP{net.ParseIP("192.0.2.1")}, err: true},
		{name: "pref v4_only with AAAA", netw: "tcp", host: "example.com:80", pref: "ipv4_only", ips: []net.IP{net.ParseIP("2001:db8::1")}, err: true},
		{name: "pref v6_only with AAAA", netw: "tcp", host: "example.com:80", pref: "ipv6_only", ips: []net.IP{net.ParseIP("2001:db8::1")}, expect: 6},
		{name: "pref v6_first with both", netw: "tcp", host: "example.com:80", pref: "ipv6_first", ips: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}, expect: 6},
		{name: "pref v4_first with both", netw: "tcp", host: "example.com:80", pref: "ipv4_first", ips: []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1")}, expect: 4},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			lookupIP = fakeLookup{ips: tt.ips}.LookupIP
			got, err := resolveDestFamily(tt.netw, tt.host, tt.pref)
			if tt.err {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expect {
				t.Fatalf("got %d, want %d", got, tt.expect)
			}
		})
	}
}

func TestSelectLocalAddrUnix(t *testing.T) {
	addrs := buildLocalAddrs("/tmp/l4proxy-src.sock", "unix", 0, zap.NewNop())
	if len(addrs) != 1 {
		t.Fatalf("expected 1 unix addr, got %d", len(addrs))
	}
	if _, ok := addrs[0].(*net.UnixAddr); !ok {
		t.Fatalf("expected UnixAddr, got %T", addrs[0])
	}

	// IPs should be ignored for unix upstreams
	if addrs := buildLocalAddrs("127.0.0.1", "unix", 0, zap.NewNop()); len(addrs) != 0 {
		t.Fatalf("expected no ip addr for unix upstream")
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
	case <-time.After(2 * time.Second):
		t.Fatalf("no health check connection observed")
	}
}
