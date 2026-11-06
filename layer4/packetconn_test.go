package layer4

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/vnxme/hybrid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func init() {
	caddy.RegisterModule(&testEchoHandler{})
	caddy.RegisterModule(&testErrorMatcher{})
	caddy.RegisterModule(&testPrefixMatcher{})
	caddy.RegisterModule(&testWaitMatcher{})
}

// testErrorMatcher fails matching with an error.
type testErrorMatcher struct{}

func (*testErrorMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.testErrorMatcher",
		New: func() caddy.Module { return new(testErrorMatcher) },
	}
}

func (*testErrorMatcher) Match(_ *Connection) (bool, error) {
	return false, errors.New("test matcher error")
}

// testWaitMatcher waits for the packet after the first one with WaitForMore, as the QUIC matcher does,
// and mismatches, leaving the packet waited for unread.
type testWaitMatcher struct{}

func (*testWaitMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.testWaitMatcher",
		New: func() caddy.Module { return new(testWaitMatcher) },
	}
}

func (*testWaitMatcher) Match(cx *Connection) (bool, error) {
	if len(cx.MatchingBytes()) == 0 {
		return false, ErrConsumedAllPrefetchedBytes
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return false, cx.WaitForMore(ctx)
}

// testEchoHandler is a terminal handler serving a connection with echoHandler.
type testEchoHandler struct{}

func (*testEchoHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.testEcho",
		New: func() caddy.Module { return new(testEchoHandler) },
	}
}

func (*testEchoHandler) Handle(cx *Connection, _ Handler) error { return echoHandler(cx) }

// testPrefixMatcher matches once it has read Prefix, which makes the routes
// prefetch as many packets as it takes.
type testPrefixMatcher struct {
	Prefix string `json:"prefix"`
}

func (*testPrefixMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.testPrefixMatcher",
		New: func() caddy.Module { return new(testPrefixMatcher) },
	}
}

func (m *testPrefixMatcher) Match(cx *Connection) (bool, error) {
	buf := make([]byte, len(m.Prefix))
	if _, err := io.ReadFull(cx, buf); err != nil {
		return false, err
	}
	return string(buf) == m.Prefix, nil
}

// testRoute returns a route with a matcher given by its name and config, and handlers given by their names.
func testRoute(matcher, config string, handlers ...string) *Route {
	r := &Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{caddy.ModuleMap{matcher: json.RawMessage(config)}},
	}
	for _, h := range handlers {
		r.HandlersRaw = append(r.HandlersRaw, json.RawMessage(fmt.Sprintf(`{"handler":%q}`, h)))
	}
	return r
}

// testPrefixRoute returns a route matching the flows starting with prefix, served by the handlers given by names.
func testPrefixRoute(prefix string, handlers ...string) *Route {
	return testRoute("testPrefixMatcher", fmt.Sprintf(`{"prefix":%q}`, prefix), handlers...)
}

// testServerAddr is the address of the trunk end a wrapper wraps in place of a UDP socket.
var testServerAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}

// testClients emulates the clients of a socket over the other end of a trunk, which they share, without sockets:
// each client writes from an address of its own, and gets the packets written to that address. Unlike a socket,
// a trunk neither drops nor reorders packets, so a client needn't retry.
type testClients struct {
	end    hybrid.FromToPacketConn
	server net.Addr

	mu      sync.Mutex
	inboxes map[string]chan string
	port    int
}

// testClient is a client of testClients.
type testClient struct {
	clients *testClients
	addr    net.Addr
	inbox   chan string
}

// newTestClients emulates the clients of the end of a trunk with address server, which it returns,
// over the other end. Both ends are closed once the test ends.
func newTestClients(t *testing.T, server net.Addr) (net.PacketConn, *testClients) {
	t.Helper()

	end, serverEnd := hybrid.BufferedTrunk(1024, nil, server)
	t.Cleanup(func() {
		_ = end.Close()
		_ = serverEnd.Close()
	})

	cs := &testClients{end: end, server: server, inboxes: make(map[string]chan string), port: 1000}
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, _, dst, _, err := end.ReadFromTo(buf)
			if err != nil && n == 0 {
				var nerr net.Error
				if errors.As(err, &nerr) && nerr.Temporary() { //nolint:staticcheck // SA1019: a short buffer
					continue
				}
				return
			}
			cs.mu.Lock()
			inbox := cs.inboxes[dst.String()]
			cs.mu.Unlock()
			if inbox != nil {
				inbox <- string(buf[:n])
			}
		}
	}()
	return serverEnd, cs
}

// client returns a client with the next address of the IP version of the server.
func (cs *testClients) client() *testClient {
	cs.mu.Lock()
	cs.port++
	port := cs.port
	cs.mu.Unlock()

	ip := net.IPv4(198, 51, 100, 1)
	if cs.server.(*net.UDPAddr).IP.To4() == nil {
		ip = net.ParseIP("2001:db8::1")
	}
	return cs.clientAt(&net.UDPAddr{IP: ip, Port: port})
}

// clientAt returns a client with address addr.
func (cs *testClients) clientAt(addr net.Addr) *testClient {
	c := &testClient{clients: cs, addr: addr, inbox: make(chan string, 1024)}
	cs.mu.Lock()
	cs.inboxes[addr.String()] = c.inbox
	cs.mu.Unlock()
	return c
}

// write writes packets to the server one by one, failing the test on an error.
func (c *testClient) write(t *testing.T, pkts ...string) {
	t.Helper()

	for _, pkt := range pkts {
		if _, err := c.clients.end.WriteToFrom([]byte(pkt), c.clients.server, c.addr, 0); err != nil {
			t.Fatalf("client %s: failed to write | %s", c.addr, err)
		}
	}
}

// read reads a packet written to the client, failing the test if none comes in time.
func (c *testClient) read(t *testing.T) string {
	t.Helper()

	select {
	case pkt := <-c.inbox:
		return pkt
	case <-time.After(3 * time.Second):
		t.Fatalf("client %s: no packet", c.addr)
		return ""
	}
}

// exchange writes a packet to the server and reads a reply, failing the test if none comes in time.
func (c *testClient) exchange(t *testing.T, pkt string) string {
	t.Helper()

	c.write(t, pkt)
	return c.read(t)
}

// provisionWrapper provisions pcw until the test ends.
func provisionWrapper(t *testing.T, pcw *PacketConnWrapper) {
	t.Helper()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := pcw.Provision(ctx); err != nil {
		t.Fatalf("provision failed | %s", err)
	}
}

// wrapTrunk provisions pcw, wraps the end of a trunk with address server with it, and returns that end, the clients
// of the other end, and the fallback connection, which are closed once the test ends.
func wrapTrunk(t *testing.T, pcw *PacketConnWrapper, server net.Addr) (net.PacketConn, *testClients, net.PacketConn) {
	t.Helper()

	provisionWrapper(t, pcw)
	pc, clients := newTestClients(t, server)
	fallback := pcw.WrapPacketConn(pc)
	t.Cleanup(func() { _ = fallback.Close() })
	return pc, clients, fallback
}

// startEchoWrapper wraps a trunk with a wrapper whose only route echoes the flows starting with prefix,
// and returns the wrapped end of the trunk, the clients of the other end, and the fallback connection.
func startEchoWrapper(t *testing.T, prefix string, matchingTimeout time.Duration) (
	net.PacketConn, *testClients, net.PacketConn,
) {
	t.Helper()

	return wrapTrunk(t, &PacketConnWrapper{
		Routes:          RouteList{testPrefixRoute(prefix, "testEcho")},
		MatchingTimeout: caddy.Duration(matchingTimeout),
	}, testServerAddr)
}

// readFallback reads a packet from the fallback connection, failing the test if none comes in time.
func readFallback(t *testing.T, fallback net.PacketConn) (string, net.Addr) {
	t.Helper()

	buf := make([]byte, 64<<10)
	_ = fallback.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, addr, err := fallback.ReadFrom(buf)
	if err != nil {
		t.Fatalf("failed to read from the fallback connection | %s", err)
	}
	return string(buf[:n]), addr
}

// expectFallback reads packets from the fallback connection, failing the test unless they're those given, in order.
func expectFallback(t *testing.T, fallback net.PacketConn, want ...string) {
	t.Helper()

	for i, w := range want {
		if got, _ := readFallback(t, fallback); got != w {
			t.Fatalf("packet %d: the fallback connection got %d bytes, want %d bytes of %q...",
				i, len(got), len(w), w[:min(len(w), 16)])
		}
	}
}

// expectNoFallback fails the test if the fallback connection gets a packet within a short time.
func expectNoFallback(t *testing.T, fallback net.PacketConn) {
	t.Helper()

	buf := make([]byte, 64<<10)
	_ = fallback.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, addr, err := fallback.ReadFrom(buf); err == nil {
		t.Errorf("the fallback connection got %q from %s, want nothing", buf[:n], addr)
	}
}

// TestPCWMatchedFlow asserts that a flow a route matches is served by its handler,
// while the fallback connection gets nothing of it.
func TestPCWMatchedFlow(t *testing.T) {
	_, clients, fallback := startEchoWrapper(t, "ECHO", time.Second)

	c := clients.client()
	for i := range 3 {
		want := fmt.Sprintf("ECHO-%d", i)
		if got := c.exchange(t, want); got != want {
			t.Fatalf("got reply %q, want %q", got, want)
		}
	}
	expectNoFallback(t, fallback)
}

// TestPCWUnmatchedFlow asserts that a flow no route matches goes to the fallback connection
// with all its packets, and that the replies written to the fallback connection reach the client.
func TestPCWUnmatchedFlow(t *testing.T) {
	_, clients, fallback := startEchoWrapper(t, "ECHO", time.Second)

	c := clients.client()
	c.write(t, "hello")
	got, addr := readFallback(t, fallback)
	if got != "hello" {
		t.Fatalf("the fallback connection got %q, want %q", got, "hello")
	}
	if addr.String() != c.addr.String() {
		t.Errorf("the fallback connection got a packet from %s, want %s", addr, c.addr)
	}

	if _, err := fallback.WriteTo([]byte("reply"), addr); err != nil {
		t.Fatalf("failed to write to the fallback connection | %s", err)
	}
	if got = c.read(t); got != "reply" {
		t.Errorf("got reply %q, want %q", got, "reply")
	}

	// The flow stays released, so a packet matching the route goes to the fallback connection as well
	c.write(t, "ECHO")
	expectFallback(t, fallback, "ECHO")
}

// TestPCWReleaseOrder asserts that a released flow goes to the fallback connection with
// the packets read while matching, including one read in part, followed by the later ones, in order.
func TestPCWReleaseOrder(t *testing.T) {
	_, clients, fallback := startEchoWrapper(t, "ECHO-ECHO", time.Second)

	large := string(bytes.Repeat([]byte{'a'}, 2*prefetchChunkSize+1))
	want := []string{"EC", large, "three", "four"}

	c := clients.client()
	// The first packet is too short for the matcher, which reads a chunk of the second one, then mismatches
	c.write(t, want[:2]...)
	time.Sleep(50 * time.Millisecond)
	c.write(t, want[2:]...)
	expectFallback(t, fallback, want...)
}

// TestPCWReleaseBurst asserts that the packets coming while a flow is being matched,
// some read ahead of the matcher, some queued on the split connection, are all released in order.
func TestPCWReleaseBurst(t *testing.T) {
	_, clients, fallback := startEchoWrapper(t, "ECHO-ECHO", time.Second)

	want := []string{"EC"}
	for i := range 24 {
		want = append(want, fmt.Sprintf("packet-%02d", i))
	}
	clients.client().write(t, want...)
	expectFallback(t, fallback, want...)
}

// TestPCWReleaseWaitedPacket asserts that a packet a matcher has waited for with WaitForMore,
// as the QUIC matcher does, but left unread, is released along with the others, in order.
func TestPCWReleaseWaitedPacket(t *testing.T) {
	_, clients, fallback := wrapTrunk(t, &PacketConnWrapper{
		Routes: RouteList{testRoute("testWaitMatcher", "{}", "testEcho")},
	}, testServerAddr)

	c := clients.client()
	c.write(t, "first")
	time.Sleep(50 * time.Millisecond) // So that the matcher waits for the second packet
	c.write(t, "second", "third")
	expectFallback(t, fallback, "first", "second", "third")
}

// TestPCWMatchingTimeout asserts that a flow failing to complete the matching phase
// in time goes to the fallback connection rather than being dropped.
func TestPCWMatchingTimeout(t *testing.T) {
	const matchingTimeout = 200 * time.Millisecond
	_, clients, fallback := startEchoWrapper(t, "ECHO-ECHO", matchingTimeout)

	c := clients.client()
	start := time.Now()
	c.write(t, "EC")
	expectFallback(t, fallback, "EC")
	if d := time.Since(start); d < matchingTimeout {
		t.Errorf("the flow was released after %s, before the matching timeout of %s", d, matchingTimeout)
	}

	c.write(t, "HO-ECHO")
	expectFallback(t, fallback, "HO-ECHO")
}

// TestPCWMatcherError asserts that a flow whose matching fails with an error is released.
func TestPCWMatcherError(t *testing.T) {
	_, clients, fallback := wrapTrunk(t, &PacketConnWrapper{
		Routes: RouteList{testRoute("testErrorMatcher", "{}", "testEcho")},
	}, testServerAddr)

	clients.client().write(t, "hello")
	expectFallback(t, fallback, "hello")
}

// TestPCWNonTerminalRoute asserts that a flow matched by a route is closed rather than released,
// even if no handler of the route is terminal, as its handlers may have consumed or changed its packets.
func TestPCWNonTerminalRoute(t *testing.T) {
	_, clients, fallback := wrapTrunk(t, &PacketConnWrapper{
		Routes: RouteList{testPrefixRoute("ECHO")},
	}, testServerAddr)

	clients.client().write(t, "ECHO", "ECHO")
	expectNoFallback(t, fallback)
}

// TestPCWConcurrentFlows asserts that many flows, matched and released, are served at once,
// each flow getting its own packets and replies only.
func TestPCWConcurrentFlows(t *testing.T) {
	_, clients, fallback := startEchoWrapper(t, "ECHO", time.Second)

	// Serve the fallback connection as a QUIC server would: record the packets of each client and reply to them
	var (
		mu       sync.Mutex
		received = make(map[string][]string)
		served   = make(chan struct{})
	)
	go func() {
		defer close(served)
		buf := make([]byte, 1024)
		for {
			n, addr, err := fallback.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			received[addr.String()] = append(received[addr.String()], string(buf[:n]))
			mu.Unlock()
			_, _ = fallback.WriteTo(append([]byte("re:"), buf[:n]...), addr)
		}
	}()

	const flows, packets = 50, 10
	var wg sync.WaitGroup
	released := make([]*testClient, flows)
	for i := range flows {
		matched := clients.client()
		released[i] = clients.client()
		wg.Go(func() {
			for j := range packets {
				want := fmt.Sprintf("ECHO-%d-%d", i, j)
				if got := matched.exchange(t, want); got != want {
					t.Errorf("matched client %d: got reply %q, want %q", i, got, want)
				}
			}
		})
		wg.Go(func() {
			for j := range packets {
				pkt := fmt.Sprintf("other-%d-%d", i, j)
				released[i].write(t, pkt)
				if got := released[i].read(t); got != "re:"+pkt {
					t.Errorf("released client %d: got reply %q, want %q", i, got, "re:"+pkt)
				}
			}
		})
	}
	wg.Wait()
	_ = fallback.Close()
	<-served

	mu.Lock()
	defer mu.Unlock()
	if len(received) != flows {
		t.Errorf("the fallback connection got packets from %d clients, want %d", len(received), flows)
	}
	for i, c := range released {
		var want []string
		for j := range packets {
			want = append(want, fmt.Sprintf("other-%d-%d", i, j))
		}
		if got := received[c.addr.String()]; fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("the fallback connection got %q from released client %d, want %q", got, i, want)
		}
	}
}

// TestPCWFlowExpiry asserts that once a flow has been idle for the idle timeout, its next packet
// starts a new flow, which is matched afresh: a released flow may be matched then, and a matched one released.
func TestPCWFlowExpiry(t *testing.T) {
	const idleTimeout = 200 * time.Millisecond
	_, clients, fallback := wrapTrunk(t, &PacketConnWrapper{
		Routes:      RouteList{testPrefixRoute("ECHO", "testEcho")},
		IdleTimeout: caddy.Duration(idleTimeout),
	}, testServerAddr)
	const expiry = 3 * idleTimeout // A flow ends within 1.25 idle timeouts of its last packet

	c := clients.client()
	c.write(t, "other")
	expectFallback(t, fallback, "other")

	time.Sleep(expiry)
	if got := c.exchange(t, "ECHO-1"); got != "ECHO-1" {
		t.Fatalf("got reply %q, want %q", got, "ECHO-1")
	}
	expectNoFallback(t, fallback)

	time.Sleep(expiry)
	c.write(t, "other again")
	expectFallback(t, fallback, "other again")
}

// TestPCWEmptyPackets asserts that empty packets, which UDP allows, are neither lost
// nor taken for the end of a flow, whether the flow is matched or released.
func TestPCWEmptyPackets(t *testing.T) {
	_, clients, fallback := startEchoWrapper(t, "ECHO", time.Second)

	matched := clients.client()
	for _, want := range []string{"ECHO", "", "ECHO-2"} {
		if got := matched.exchange(t, want); got != want {
			t.Fatalf("got reply %q, want %q", got, want)
		}
	}
	expectNoFallback(t, fallback)

	clients.client().write(t, "", "x", "")
	expectFallback(t, fallback, "", "x", "")
}

// TestPCWPacketSizes asserts that packets as large as the buffers they're read into are served
// whole, whether matched or released, while a larger packet is dropped.
func TestPCWPacketSizes(t *testing.T) {
	_, clients, fallback := startEchoWrapper(t, "ECHO", time.Second)

	want := "ECHO" + string(bytes.Repeat([]byte{'m'}, udpBufSize-4))
	if got := clients.client().exchange(t, want); got != want {
		t.Fatalf("got a reply of %d bytes, want the %d bytes sent", len(got), len(want))
	}

	largest := string(bytes.Repeat([]byte{'r'}, udpBufSize))
	clients.client().write(t, largest, largest+"!", "small")
	expectFallback(t, fallback, largest, "small")
}

// TestPCWFallbackShortBuffer asserts that the fallback connection reads a packet larger than
// the buffer it's read into with a temporary error, which a QUIC server, reading packets into buffers of about
// 1.4 KB, skips, whereas it would stop for good on any other error, and then reads the next packet.
func TestPCWFallbackShortBuffer(t *testing.T) {
	_, clients, fallback := startEchoWrapper(t, "ECHO", time.Second)

	clients.client().write(t, "first", string(bytes.Repeat([]byte{'l'}, 2000)), "last")

	buf := make([]byte, 1452)
	read := func() (string, error) {
		_ = fallback.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := fallback.ReadFrom(buf)
		return string(buf[:n]), err
	}
	if got, err := read(); err != nil || got != "first" {
		t.Fatalf("the fallback connection got %q, %v, want %q, nil", got, err, "first")
	}
	_, err := read()
	//nolint:staticcheck // SA1019: Temporary is what a QUIC server checks
	if nerr := net.Error(nil); !errors.As(err, &nerr) || !nerr.Temporary() || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("the fallback connection got the long packet with %v, want a temporary %v", err, io.ErrShortBuffer)
	}
	if got, err := read(); err != nil || got != "last" {
		t.Fatalf("the fallback connection got %q, %v, want %q, nil", got, err, "last")
	}
}

// TestPCWIPv6 asserts that the flows of an IPv6 socket are matched and released.
func TestPCWIPv6(t *testing.T) {
	_, clients, fallback := wrapTrunk(t, &PacketConnWrapper{
		Routes: RouteList{testPrefixRoute("ECHO", "testEcho")},
	}, &net.UDPAddr{IP: net.ParseIP("2001:db8::443"), Port: 443})

	if got := clients.client().exchange(t, "ECHO"); got != "ECHO" {
		t.Fatalf("got reply %q, want %q", got, "ECHO")
	}

	c := clients.client()
	c.write(t, "other")
	got, addr := readFallback(t, fallback)
	if got != "other" {
		t.Fatalf("the fallback connection got %q, want %q", got, "other")
	}
	if addr.String() != c.addr.String() {
		t.Errorf("the fallback connection got a packet from %s, want %s", addr, c.addr)
	}
}

// TestPCWNilAddr asserts that a read with no address and no error, as Caddy's packet conns
// make once closed on some platforms, doesn't start a flow, which would be released with an empty packet.
func TestPCWNilAddr(t *testing.T) {
	pcw := &PacketConnWrapper{Routes: RouteList{testPrefixRoute("ECHO", "testEcho")}}
	provisionWrapper(t, pcw)
	pc, clients := newTestClients(t, testServerAddr)
	fallback := pcw.WrapPacketConn(&nilAddrPacketConn{PacketConn: pc})
	t.Cleanup(func() { _ = fallback.Close() })

	if got := clients.client().exchange(t, "ECHO"); got != "ECHO" {
		t.Fatalf("got reply %q, want %q", got, "ECHO")
	}
	expectNoFallback(t, fallback)
}

// TestPCWSocketClosed asserts that closing the wrapped socket, as Caddy does once it's
// no longer used, closes the fallback connection.
func TestPCWSocketClosed(t *testing.T) {
	pc, _, fallback := startEchoWrapper(t, "ECHO", time.Second)

	result := make(chan error, 1)
	go func() {
		_, _, err := fallback.ReadFrom(make([]byte, 1024))
		result <- err
	}()
	_ = pc.Close()

	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("reading the fallback connection returned %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reading the fallback connection didn't return once the socket closed")
	}
}

// TestPCWClose asserts that closing the fallback connection stops serving the socket,
// but leaves it open.
func TestPCWClose(t *testing.T) {
	pc, clients, fallback := startEchoWrapper(t, "ECHO", time.Second)

	if err := fallback.Close(); err != nil {
		t.Fatalf("failed to close the fallback connection | %s", err)
	}

	clients.client().write(t, "ECHO")
	buf := make([]byte, 1024)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("failed to read from the socket | %s", err)
	}
	if string(buf[:n]) != "ECHO" {
		t.Errorf("read %q from the socket, want %q", buf[:n], "ECHO")
	}
}

// TestPCWLogs asserts that the wrapper logs that it has started wrapping the socket, and once
// the socket is closed, as Caddy does, why its splitter has stopped and the packets it has dropped, at the debug
// level, as it happens on every start and shutdown.
func TestPCWLogs(t *testing.T) {
	pcw := &PacketConnWrapper{Routes: RouteList{testPrefixRoute("ECHO", "testEcho")}}
	provisionWrapper(t, pcw)
	core, logs := observer.New(zap.DebugLevel)
	pcw.logger = zap.New(core)

	pc, _ := newTestClients(t, testServerAddr)
	fallback := pcw.WrapPacketConn(pc)
	t.Cleanup(func() { _ = fallback.Close() })
	_ = pc.Close()

	// The error that has stopped the splitter is passed to ErrorFunc once it has stopped, maybe after Accept returns
	const startMsg, errorMsg, stopMsg, dropsMsg = "started wrapping packet connection", "packet connection error",
		"stopped wrapping packet connection", "packet connection drops"
	waitFor(t, 3*time.Second, func() bool {
		return logs.FilterMessage(startMsg).Len() == 1 && logs.FilterMessage(errorMsg).Len() == 1 &&
			logs.FilterMessage(stopMsg).Len() == 1 && logs.FilterMessage(dropsMsg).Len() == 1
	}, func() string {
		return fmt.Sprintf("got logs %v, want %q, %q, %q and %q", logs.All(), startMsg, errorMsg, stopMsg, dropsMsg)
	})
	for _, msg := range []string{startMsg, errorMsg, stopMsg, dropsMsg} {
		if entry := logs.FilterMessage(msg).All()[0]; entry.Level != zap.DebugLevel {
			t.Errorf("got entry %q at level %s, want %s", msg, entry.Level, zap.DebugLevel)
		}
	}
	for msg, key := range map[string]string{startMsg: "address", errorMsg: "error", stopMsg: "error", dropsMsg: "drops"} {
		if _, ok := logs.FilterMessage(msg).All()[0].ContextMap()[key]; !ok {
			t.Errorf("got entry %q without %q", msg, key)
		}
	}
}

// TestPCWNoGoroutineLeak asserts that no goroutine is left once the socket is closed,
// as Caddy does, or the fallback connection is, while flows are being matched, served and released.
func TestPCWNoGoroutineLeak(t *testing.T) {
	for _, closeFallback := range []bool{false, true} {
		t.Run(fmt.Sprintf("closeFallback=%t", closeFallback), func(t *testing.T) {
			// A long matching timeout keeps a flow being matched until the end
			pcw := &PacketConnWrapper{
				Routes:          RouteList{testPrefixRoute("ECHO-ECHO", "testEcho")},
				MatchingTimeout: caddy.Duration(time.Minute),
			}
			provisionWrapper(t, pcw)
			pc, clients := newTestClients(t, testServerAddr)
			before := runtime.NumGoroutine()
			fallback := pcw.WrapPacketConn(pc)
			t.Cleanup(func() { _ = fallback.Close() })

			if got := clients.client().exchange(t, "ECHO-ECHO"); got != "ECHO-ECHO" {
				t.Fatalf("got reply %q, want %q", got, "ECHO-ECHO")
			}
			clients.client().write(t, "other-packet")
			expectFallback(t, fallback, "other-packet")
			clients.client().write(t, "EC")
			time.Sleep(50 * time.Millisecond) // So that the flow is being matched

			if closeFallback {
				_ = fallback.Close()
			} else {
				_ = pc.Close()
			}
			waitFor(t, 3*time.Second, func() bool { return runtime.NumGoroutine() <= before }, func() string {
				return fmt.Sprintf("%d goroutines left, want %d at most", runtime.NumGoroutine(), before)
			})
		})
	}
}

// TestPCWUDP asserts that the wrapper serves UDP sockets as it serves trunks,
// over IPv4 and over IPv6 if available.
func TestPCWUDP(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			pc, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Skipf("failed to listen | %s", err)
			}
			t.Cleanup(func() { _ = pc.Close() })
			pcw := &PacketConnWrapper{Routes: RouteList{testPrefixRoute("ECHO", "testEcho")}}
			provisionWrapper(t, pcw)
			fallback := pcw.WrapPacketConn(pc)
			t.Cleanup(func() { _ = fallback.Close() })

			matched := dialPacketServer(t, pc.LocalAddr().String())
			if got := mustExchange(t, matched, []byte("ECHO")); string(got) != "ECHO" {
				t.Fatalf("got reply %q, want %q", got, "ECHO")
			}

			released := dialPacketServer(t, pc.LocalAddr().String())
			if _, err = released.Write([]byte("other")); err != nil {
				t.Fatalf("failed to write | %s", err)
			}
			got, addr := readFallback(t, fallback)
			if got != "other" {
				t.Fatalf("the fallback connection got %q, want %q", got, "other")
			}
			if addr.String() != released.LocalAddr().String() {
				t.Errorf("the fallback connection got a packet from %s, want %s", addr, released.LocalAddr())
			}
		})
	}
}
