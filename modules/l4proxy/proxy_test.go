package l4proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
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
		LocalAddrs: []string{localAddr},
		localAddrs: []string{localAddr},
		peers:      []*peer{{address: &parsedUpstream}},
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
		LocalAddrs: []string{localAddr},
		localAddrs: []string{localAddr},
		peers:      []*peer{{address: &parsedUpstream}},
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
	addrs := buildLocalAddrs([]string{"[2001:db8::1]:4040"}, "tcp6", 6, zap.NewNop())
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
	addrs := buildLocalAddrs([]string{"[2001:db8::2]:5353"}, "udp6", 6, zap.NewNop())
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
	addrs := buildLocalAddrs([]string{"192.0.2.1:5353"}, "udp", 0, zap.NewNop())
	if len(addrs) != 1 {
		t.Fatalf("expected 1 addr, got %d", len(addrs))
	}
	if _, ok := addrs[0].(*net.UDPAddr); !ok {
		t.Fatalf("expected UDPAddr, got %T", addrs[0])
	}
}

func TestSelectLocalAddrSkipsMismatchedFamilies(t *testing.T) {
	if addrs := buildLocalAddrs([]string{"::1"}, "tcp4", 4, zap.NewNop()); len(addrs) != 0 {
		t.Fatalf("expected no addr for ipv6 source with tcp4 upstream")
	}
	if addrs := buildLocalAddrs([]string{"127.0.0.1"}, "tcp6", 6, zap.NewNop()); len(addrs) != 0 {
		t.Fatalf("expected no addr for ipv4 source with tcp6 upstream")
	}
}

func TestSelectLocalAddrChoosesMatchingFromList(t *testing.T) {
	addrs := buildLocalAddrs([]string{"127.0.0.1", "::1"}, "tcp6", 6, zap.NewNop())
	if len(addrs) == 0 {
		t.Fatalf("expected matching addr")
	}
	if tcpAddr, ok := addrs[0].(*net.TCPAddr); !ok || tcpAddr.IP.To4() != nil {
		t.Fatalf("expected ipv6 local addr, got %T %v", addrs[0], addrs[0])
	}

	addrs = buildLocalAddrs([]string{"127.0.0.1", "::1"}, "tcp4", 4, zap.NewNop())
	if len(addrs) == 0 {
		t.Fatalf("expected matching addr")
	}
	if tcpAddr, ok := addrs[0].(*net.TCPAddr); !ok || tcpAddr.IP.To4() == nil {
		t.Fatalf("expected ipv4 local addr, got %T %v", addrs[0], addrs[0])
	}
}

func TestTransparentLocalAddr(t *testing.T) {
	tests := []struct {
		name    string
		remote  net.Addr
		network string
		wantIP  string
		wantFam int
		wantUDP bool
	}{
		{
			name:    "tcp ipv4",
			remote:  &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
			network: "tcp4",
			wantIP:  "192.0.2.10",
			wantFam: 4,
		},
		{
			name:    "udp ipv6",
			remote:  &net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 12345, Zone: "eth0"},
			network: "udp6",
			wantIP:  "2001:db8::10",
			wantFam: 6,
			wantUDP: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transparentLocalAddr(tt.remote, tt.network)
			if err != nil {
				t.Fatalf("transparentLocalAddr: %v", err)
			}
			family, err := ipFamilyFromAddr(got)
			if err != nil {
				t.Fatalf("ipFamilyFromAddr: %v", err)
			}
			if family != tt.wantFam {
				t.Fatalf("family = %d, want %d", family, tt.wantFam)
			}

			var ip net.IP
			var port int
			switch addr := got.(type) {
			case *net.TCPAddr:
				if tt.wantUDP {
					t.Fatalf("got TCP address, want UDP")
				}
				ip, port = addr.IP, addr.Port
			case *net.UDPAddr:
				if !tt.wantUDP {
					t.Fatalf("got UDP address, want TCP")
				}
				ip, port = addr.IP, addr.Port
			default:
				t.Fatalf("unexpected address type %T", got)
			}
			if !ip.Equal(net.ParseIP(tt.wantIP)) {
				t.Fatalf("IP = %s, want %s", ip, tt.wantIP)
			}
			if port != 0 {
				t.Fatalf("port = %d, want 0", port)
			}
		})
	}
}

func TestTransparentLocalAddrRejectsNonIPClient(t *testing.T) {
	if _, err := transparentLocalAddr(&net.UnixAddr{Name: "/tmp/client.sock", Net: "unix"}, "tcp"); err == nil {
		t.Fatal("expected non-IP client address to be rejected")
	}
	if _, err := transparentLocalAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, "unix"); err == nil {
		t.Fatal("expected Unix upstream network to be rejected")
	}
}

// Known placeholders in local_address should be replaced at provision time,
// while unknown (runtime) placeholders must be preserved for per-connection expansion.
func TestProvisionExpandsKnownPlaceholdersInLocalAddr(t *testing.T) {
	t.Setenv("L4PROXY_TEST_BIND", "192.0.2.77")

	dialAddr := "127.0.0.1:59991"
	t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

	h := &Handler{logger: zap.NewNop()}
	u := &Upstream{
		Dial:       []string{dialAddr},
		LocalAddrs: []string{"{env.L4PROXY_TEST_BIND}", "{l4.conn.local_addr}"},
	}
	if err := u.provision(caddy.Context{}, h); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if got, want := len(u.localAddrs), 2; got != want {
		t.Fatalf("provisioned localAddrs: got %d entries, want %d", got, want)
	}
	if got, want := u.localAddrs[0], "192.0.2.77"; got != want {
		t.Fatalf("known placeholder should be resolved: got %q, want %q", got, want)
	}
	if got, want := u.localAddrs[1], "{l4.conn.local_addr}"; got != want {
		t.Fatalf("unknown (per-connection) placeholder should be preserved at provision: got %q, want %q", got, want)
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

// resolver_preference must be one of a fixed set of values; provision must reject
// anything else (including typos like "ipv46_only") rather than silently falling
// back to ipv4_first.
func TestProvisionRejectsInvalidResolverPreference(t *testing.T) {
	cases := []struct {
		name string
		pref string
	}{
		{"typo", "ipv46_only"},
		{"garbage", "not-a-preference"},
		{"mixed_case", "IPv4_Only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialAddr := "127.0.0.1:59992"
			t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

			h := &Handler{logger: zap.NewNop()}
			u := &Upstream{
				Dial:               []string{dialAddr},
				ResolverPreference: tc.pref,
			}
			err := u.provision(caddy.Context{}, h)
			if err == nil {
				t.Fatalf("expected provision to reject resolver_preference=%q", tc.pref)
			}
			if !strings.Contains(err.Error(), "resolver_preference") {
				t.Fatalf("unexpected error for %q: %v", tc.pref, err)
			}
		})
	}
}

// Valid resolver_preference values (including empty string) must provision cleanly.
func TestProvisionAcceptsValidResolverPreference(t *testing.T) {
	valid := []string{"", "ipv4_only", "ipv6_only", "ipv4_first", "ipv6_first"}
	for i, pref := range valid {
		t.Run(pref, func(t *testing.T) {
			dialAddr := fmt.Sprintf("127.0.0.1:5999%d", 3+i)
			t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

			h := &Handler{logger: zap.NewNop()}
			u := &Upstream{
				Dial:               []string{dialAddr},
				ResolverPreference: pref,
			}
			if err := u.provision(caddy.Context{}, h); err != nil {
				t.Fatalf("provision rejected valid resolver_preference %q: %v", pref, err)
			}
		})
	}
}

// An "_only" resolver_preference paired with a local_address whose family can
// never match must be rejected at provision, otherwise every source would be
// silently skipped and the OS default would silently override the user's intent.
// Only the two contradictory combinations are invalid; mixed-family sources and
// "_first" preferences (which allow cross-family fallback) must continue to pass.
func TestProvisionRejectsIncompatibleLocalAddrAndResolverPreference(t *testing.T) {
	cases := []struct {
		name       string
		localAddrs []string
		preference string
	}{
		{"v4_src_with_ipv6_only", []string{"10.0.0.5"}, "ipv6_only"},
		{"v6_src_with_ipv4_only", []string{"2001:db8::5"}, "ipv4_only"},
		{"v4_src_with_port_with_ipv6_only", []string{"10.0.0.5:5555"}, "ipv6_only"},
		{"v6_src_bracketed_with_ipv4_only", []string{"[2001:db8::5]:5555"}, "ipv4_only"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialAddr := fmt.Sprintf("127.0.0.1:6100%d", i)
			t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

			h := &Handler{logger: zap.NewNop()}
			u := &Upstream{
				Dial:               []string{dialAddr},
				LocalAddrs:         tc.localAddrs,
				ResolverPreference: tc.preference,
			}
			err := u.provision(caddy.Context{}, h)
			if err == nil {
				t.Fatalf("expected provision to reject local_address=%v with resolver_preference=%q",
					tc.localAddrs, tc.preference)
			}
			if !strings.Contains(err.Error(), "resolver_preference") {
				t.Fatalf("unexpected error for %v + %q: %v", tc.localAddrs, tc.preference, err)
			}
		})
	}
}

// Compatible combinations must provision cleanly: either the preference is not
// "_only", or at least one local_address matches the "_only" family, or an
// unresolved runtime placeholder prevents provision-time validation.
func TestProvisionAcceptsCompatibleLocalAddrAndResolverPreference(t *testing.T) {
	cases := []struct {
		name       string
		localAddrs []string
		preference string
	}{
		{"v4_only_with_v4_src", []string{"10.0.0.5"}, "ipv4_only"},
		{"v6_only_with_v6_src", []string{"2001:db8::5"}, "ipv6_only"},
		{"v4_only_with_mixed_sources", []string{"2001:db8::5", "10.0.0.5"}, "ipv4_only"},
		{"v6_only_with_mixed_sources", []string{"10.0.0.5", "2001:db8::5"}, "ipv6_only"},
		{"ipv4_first_with_v6_src", []string{"2001:db8::5"}, "ipv4_first"},
		{"ipv6_first_with_v4_src", []string{"10.0.0.5"}, "ipv6_first"},
		{"no_preference_with_v6_src", []string{"2001:db8::5"}, ""},
		{"ipv4_only_with_placeholder", []string{"{l4.vars.src}"}, "ipv4_only"},
		{"ipv6_only_with_placeholder", []string{"{l4.vars.src}"}, "ipv6_only"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialAddr := fmt.Sprintf("127.0.0.1:6200%d", i)
			t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

			h := &Handler{logger: zap.NewNop()}
			u := &Upstream{
				Dial:               []string{dialAddr},
				LocalAddrs:         tc.localAddrs,
				ResolverPreference: tc.preference,
			}
			if err := u.provision(caddy.Context{}, h); err != nil {
				t.Fatalf("provision rejected compatible config %v + %q: %v", tc.localAddrs, tc.preference, err)
			}
		})
	}
}

// local_address is not supported for Unix upstreams; provision must reject any
// such combination so that the invalid config surfaces early with a clear error.
func TestProvisionRejectsLocalAddrForUnixUpstream(t *testing.T) {
	for _, netw := range []string{"unix", "unixpacket", "unixgram"} {
		t.Run(netw, func(t *testing.T) {
			dialAddr := netw + "//tmp/l4proxy-provision-test-" + netw + ".sock"
			t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

			h := &Handler{logger: zap.NewNop()}
			u := &Upstream{
				Dial:       []string{dialAddr},
				LocalAddrs: []string{"/tmp/l4proxy-src.sock"},
			}
			err := u.provision(caddy.Context{}, h)
			if err == nil {
				t.Fatalf("expected provision to reject local_address for %s upstream", netw)
			}
			if !strings.Contains(err.Error(), "local_address is not supported for Unix socket upstreams") {
				t.Fatalf("unexpected error for %s upstream: %v", netw, err)
			}
		})
	}
}

func TestProvisionTransparentProxy(t *testing.T) {
	dialAddr := "127.0.0.1:63001"
	t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

	u := &Upstream{Dial: []string{dialAddr}, Transparent: true}
	err := u.provision(caddy.Context{}, &Handler{logger: zap.NewNop()})
	if transparentProxySupported && err != nil {
		t.Fatalf("provision rejected transparent proxying on Linux: %v", err)
	}
	if !transparentProxySupported && (err == nil || !strings.Contains(err.Error(), "only supported on Linux")) {
		t.Fatalf("provision error = %v, want unsupported-platform error", err)
	}
}

func TestProvisionRejectsTransparentProxyConflicts(t *testing.T) {
	if !transparentProxySupported {
		t.Skip("conflict validation follows the platform support check")
	}

	cases := []struct {
		name     string
		upstream *Upstream
		want     string
	}{
		{
			name:     "local address",
			upstream: &Upstream{LocalAddrs: []string{"127.0.0.1"}},
			want:     "local_address",
		},
		{
			name:     "resolver preference",
			upstream: &Upstream{ResolverPreference: "ipv4_only"},
			want:     "resolver_preference",
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialAddr := fmt.Sprintf("127.0.0.1:6310%d", i)
			t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })
			tc.upstream.Dial = []string{dialAddr}
			tc.upstream.Transparent = true

			err := tc.upstream.provision(caddy.Context{}, &Handler{logger: zap.NewNop()})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("provision error = %v, want conflict mentioning %s", err, tc.want)
			}
		})
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
		LocalAddrs: []string{"127.0.0.1"}, // defaults to tcp with ephemeral port
		localAddrs: []string{"127.0.0.1"},
		peers:      []*peer{{address: &upAddr}},
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

// newHandleTestConn returns a paired in-memory downstream connection: the
// client end (for the test to drive) and a layer4.Connection wrapping the
// server end (handed to Handle).
func newHandleTestConn(t *testing.T, h *Handler) (net.Conn, *layer4.Connection) {
	t.Helper()
	downClient, downServer := net.Pipe()
	t.Cleanup(func() {
		_ = downClient.Close()
		_ = downServer.Close()
	})
	return downClient, layer4.WrapConnection(downServer, nil, h.logger)
}

// TestHandleReturnsErrorWhenNoUpstreamAvailable covers the branch where the
// selection policy yields no upstream and retrying is disabled (TryDuration 0),
// so Handle returns the "no upstreams available" error immediately.
func TestHandleReturnsErrorWhenNoUpstreamAvailable(t *testing.T) {
	h := &Handler{logger: zap.NewNop(), ctx: caddy.Context{Context: context.Background()}}
	h.LoadBalancing = &LoadBalancing{SelectionPolicy: &RandomSelection{}}
	// no upstreams configured -> Select always returns nil

	_, down := newHandleTestConn(t, h)

	err := h.Handle(down, nil)
	if err == nil || !strings.Contains(err.Error(), "no upstreams available") {
		t.Fatalf("expected a 'no upstreams available' error, got %v", err)
	}
}

// TestHandleReturnsErrorWhenDialFails covers the branch where an upstream is
// selected but dialing every peer fails and retrying is disabled, so Handle
// surfaces the dial error.
func TestHandleReturnsErrorWhenDialFails(t *testing.T) {
	// Reserve a port and immediately release it so connecting is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a closed port: %v", err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()

	parsed, err := caddy.ParseNetworkAddress(closedAddr)
	if err != nil {
		t.Fatalf("parsing upstream address: %v", err)
	}

	h := &Handler{logger: zap.NewNop(), ctx: caddy.Context{Context: context.Background()}}
	h.LoadBalancing = &LoadBalancing{SelectionPolicy: &RandomSelection{}}
	h.Upstreams = UpstreamPool{{peers: []*peer{{address: &parsed}}}}

	_, down := newHandleTestConn(t, h)

	if err := h.Handle(down, nil); err == nil {
		t.Fatal("expected a dial error when the upstream is unreachable, got nil")
	}
}

// TestHandleRetriesThenGivesUp covers the retry loop: with no upstream ever
// becoming available, Handle keeps calling tryAgain until TryDuration elapses,
// then returns the error. It also exercises the "proxyErr already set" branch
// on the second and later iterations.
func TestHandleRetriesThenGivesUp(t *testing.T) {
	h := &Handler{logger: zap.NewNop(), ctx: caddy.Context{Context: context.Background()}}
	h.LoadBalancing = &LoadBalancing{
		SelectionPolicy: &RandomSelection{},
		TryDuration:     caddy.Duration(80 * time.Millisecond),
		TryInterval:     caddy.Duration(10 * time.Millisecond),
	}

	_, down := newHandleTestConn(t, h)

	start := time.Now()
	err := h.Handle(down, nil)
	if err == nil || !strings.Contains(err.Error(), "no upstreams available") {
		t.Fatalf("expected a 'no upstreams available' error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("expected Handle to retry for about TryDuration, returned after %s", elapsed)
	}
}

// TestHandleRetriesDialFailureThenGivesUp covers the dial-failure retry branch:
// an upstream is selected but unreachable, so Handle loops (tryAgain -> continue)
// until TryDuration elapses, then returns the dial error.
func TestHandleRetriesDialFailureThenGivesUp(t *testing.T) {
	// Reserve a port and immediately release it so connecting is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a closed port: %v", err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()

	parsed, err := caddy.ParseNetworkAddress(closedAddr)
	if err != nil {
		t.Fatalf("parsing upstream address: %v", err)
	}

	h := &Handler{logger: zap.NewNop(), ctx: caddy.Context{Context: context.Background()}}
	h.LoadBalancing = &LoadBalancing{
		SelectionPolicy: &RandomSelection{},
		TryDuration:     caddy.Duration(80 * time.Millisecond),
		TryInterval:     caddy.Duration(10 * time.Millisecond),
	}
	h.Upstreams = UpstreamPool{{peers: []*peer{{address: &parsed}}}}

	_, down := newHandleTestConn(t, h)

	start := time.Now()
	if err := h.Handle(down, nil); err == nil {
		t.Fatal("expected a dial error after exhausting retries, got nil")
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("expected Handle to retry for about TryDuration, returned after %s", elapsed)
	}
}

// TestHandleProxiesDataToUpstream covers the success path: an upstream is
// selected and dialed, data flows in both directions, and Handle returns nil
// once the downstream connection is closed.
func TestHandleProxiesDataToUpstream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for echo upstream: %v", err)
	}
	defer ln.Close()

	// Echo server: write back whatever is read, then close.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(c)
		}
	}()

	parsed, err := caddy.ParseNetworkAddress(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing upstream address: %v", err)
	}

	h := &Handler{logger: zap.NewNop(), ctx: caddy.Context{Context: context.Background()}}
	h.LoadBalancing = &LoadBalancing{SelectionPolicy: &RandomSelection{}}
	h.Upstreams = UpstreamPool{{peers: []*peer{{address: &parsed}}}}

	downClient, down := newHandleTestConn(t, h)

	errCh := make(chan error, 1)
	go func() { errCh <- h.Handle(down, nil) }()

	msg := []byte("ping")
	if _, err := downClient.Write(msg); err != nil {
		t.Fatalf("writing to downstream: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(downClient, got); err != nil {
		t.Fatalf("reading echoed bytes: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q, want %q", got, "ping")
	}

	// Closing the downstream ends the proxy duplex and unblocks Handle.
	_ = downClient.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Handle returned an error on the success path: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return after the downstream connection was closed")
	}
}
