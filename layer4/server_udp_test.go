package layer4

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&testReadLengthMatcher{})
}

// testReadLengthMatcher matches once it has read Length bytes, which makes the
// routes prefetch as many chunks of a packet as it takes.
type testReadLengthMatcher struct {
	Length int `json:"length"`
}

func (*testReadLengthMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.testReadLengthMatcher",
		New: func() caddy.Module { return new(testReadLengthMatcher) },
	}
}

func (m *testReadLengthMatcher) Match(cx *Connection) (bool, error) {
	buf := make([]byte, m.Length)
	if _, err := io.ReadFull(cx, buf); err != nil {
		return false, err
	}
	return true, nil
}

// startPacketServer serves a UDP socket with the given handler until the test ends,
// and returns the address of the socket.
func startPacketServer(t *testing.T, handler Handler, idleTimeout time.Duration) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen | %s", err)
	}

	server := new(Server)
	server.compiledRoute = handler
	server.logger = zap.NewNop()
	server.IdleTimeout = caddy.Duration(idleTimeout)

	serveDone := make(chan struct{})
	go func() {
		_ = server.servePacket(pc)
		close(serveDone)
	}()

	t.Cleanup(func() {
		_ = pc.Close()
		select {
		case <-serveDone:
		case <-time.After(3 * time.Second):
			t.Error("servePacket did not return after socket close")
		}
	})

	return pc.LocalAddr().String()
}

// dialPacketServer dials the given address over UDP until the test ends.
func dialPacketServer(t *testing.T, addr string) net.Conn {
	t.Helper()

	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("failed to dial | %s", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// exchange writes a packet to c and reads its echo, retrying as UDP may drop either of them, e.g. while
// a flow is ending. It skips other replies, e.g. late echoes of the retries of a previous exchange.
func exchange(c net.Conn, b []byte) ([]byte, error) {
	reply := make([]byte, 64<<10)
	for range 20 {
		if _, err := c.Write(b); err != nil {
			return nil, fmt.Errorf("failed to write | %w", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		for {
			n, err := c.Read(reply)
			if err == nil {
				if bytes.Equal(reply[:n], b) {
					return reply[:n], nil
				}
				continue
			}
			var nerr net.Error
			if !errors.As(err, &nerr) || !nerr.Timeout() {
				return nil, fmt.Errorf("failed to read | %w", err)
			}
			break
		}
	}
	return nil, fmt.Errorf("no echo of %d bytes", len(b))
}

// mustExchange is exchange failing the test on an error.
func mustExchange(t *testing.T, c net.Conn, b []byte) []byte {
	t.Helper()

	reply, err := exchange(c, b)
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

// echoHandler writes every packet read back to the client, until reading fails.
func echoHandler(cx *Connection) error {
	_ = cx.SetReadDeadline(time.Time{})
	buf := make([]byte, 64<<10)
	for {
		n, err := cx.Read(buf)
		if err != nil {
			return nil
		}
		if _, err = cx.Write(buf[:n]); err != nil {
			return err
		}
	}
}

// TestServePacketSortsFlows asserts that the packets of each client go to a handler
// of their own, which replies to that client only.
func TestServePacketSortsFlows(t *testing.T) {
	var (
		mu       sync.Mutex
		handlers int
		mixed    []string
	)
	addr := startPacketServer(t, HandlerFunc(func(cx *Connection) error {
		mu.Lock()
		handlers++
		mu.Unlock()

		_ = cx.SetReadDeadline(time.Time{})
		var client string
		buf := make([]byte, 1024)
		for {
			n, err := cx.Read(buf)
			if err != nil {
				return nil
			}
			id, _, _ := strings.Cut(string(buf[:n]), "/")
			if client == "" {
				client = id
			} else if id != client {
				mu.Lock()
				mixed = append(mixed, fmt.Sprintf("%s got a packet of %s", client, id))
				mu.Unlock()
			}
			if _, err = cx.Write(buf[:n]); err != nil {
				return err
			}
		}
	}), 30*time.Second)

	const clients, packets = 10, 5
	var wg sync.WaitGroup
	for i := range clients {
		c := dialPacketServer(t, addr)
		wg.Go(func() {
			for j := range packets {
				want := fmt.Sprintf("client-%d/packet-%d", i, j)
				got, err := exchange(c, []byte(want))
				if err != nil {
					t.Errorf("client %d: %s", i, err)
					return
				}
				if string(got) != want {
					t.Errorf("client %d: got reply %q, want %q", i, got, want)
				}
			}
		})
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if handlers != clients {
		t.Errorf("got %d handlers, want one per client, i.e. %d", handlers, clients)
	}
	for _, m := range mixed {
		t.Error(m)
	}
}

// TestServePacketLargePacket asserts that once matched, a flow passes packets larger than a prefetch chunk
// to the handler whole, keeping their boundaries.
func TestServePacketLargePacket(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	const first = "hello"
	routes := RouteList{&Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"testReadLengthMatcher": json.RawMessage(fmt.Sprintf(`{"length":%d}`, len(first)))},
		},
	}}
	if err := routes.Provision(ctx); err != nil {
		t.Fatalf("provision failed | %s", err)
	}
	addr := startPacketServer(t, routes.Compile(zap.NewNop(), time.Second, HandlerFunc(echoHandler)), 30*time.Second)

	c := dialPacketServer(t, addr)
	if got := mustExchange(t, c, []byte(first)); string(got) != first {
		t.Fatalf("got reply %q, want %q", got, first)
	}
	for i, size := range []int{prefetchChunkSize + 1, 4 * prefetchChunkSize, 8000} {
		want := bytes.Repeat([]byte{byte('a' + i)}, size)
		if got := mustExchange(t, c, want); !bytes.Equal(got, want) {
			t.Fatalf("packet %d: got a reply of %d bytes, want the %d bytes sent", i, len(got), len(want))
		}
	}
}

// TestServePacketMatchingAcrossPackets asserts that a matcher reading past a short packet into one prefetched
// in part, as it's larger than a prefetch chunk, reads it rather than spin, and that both packets reach the handler
// whole once matched.
func TestServePacketMatchingAcrossPackets(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	routes := RouteList{&Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"testReadLengthMatcher": json.RawMessage(`{"length":9}`)},
		},
	}}
	if err := routes.Provision(ctx); err != nil {
		t.Fatalf("provision failed | %s", err)
	}
	addr := startPacketServer(t, routes.Compile(zap.NewNop(), 3*time.Second, HandlerFunc(echoHandler)), 30*time.Second)

	c := dialPacketServer(t, addr)
	want := [][]byte{[]byte("EC"), bytes.Repeat([]byte{'a'}, 2*prefetchChunkSize+1)}
	for _, pkt := range want {
		if _, err := c.Write(pkt); err != nil {
			t.Fatalf("failed to write | %s", err)
		}
	}
	buf := make([]byte, 64<<10)
	for i, w := range want {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("packet %d: failed to read | %s", i, err)
		}
		if !bytes.Equal(buf[:n], w) {
			t.Fatalf("packet %d: got a reply of %d bytes, want the %d bytes sent", i, n, len(w))
		}
	}
}

// TestServePacketShortMatchingTimeout asserts that a matching timeout shorter than a second leaves a flow
// the time to complete the matching phase, rather than expire at once.
func TestServePacketShortMatchingTimeout(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	routes := RouteList{&Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"testReadLengthMatcher": json.RawMessage(`{"length":10}`)},
		},
	}}
	if err := routes.Provision(ctx); err != nil {
		t.Fatalf("provision failed | %s", err)
	}
	addr := startPacketServer(t, routes.Compile(zap.NewNop(), 200*time.Millisecond, HandlerFunc(echoHandler)),
		30*time.Second)

	// A deadline kept in whole seconds would expire at once in most cases, so try several flows
	for i := range 5 {
		c := dialPacketServer(t, addr)
		if _, err := c.Write([]byte("hello")); err != nil {
			t.Fatalf("flow %d: failed to write | %s", i, err)
		}
		time.Sleep(100 * time.Millisecond)
		if _, err := c.Write([]byte("world")); err != nil {
			t.Fatalf("flow %d: failed to write | %s", i, err)
		}
		buf := make([]byte, 1024)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("flow %d: no reply, as the matching phase hasn't completed | %s", i, err)
		}
		if string(buf[:n]) != "hello" {
			t.Fatalf("flow %d: got reply %q, want %q", i, buf[:n], "hello")
		}
	}
}

// TestServePacketLargeFirstPacket asserts that the first packet of a flow, prefetched in part while matching
// as it's larger than a prefetch chunk, reaches the handler whole rather than split in two reads.
func TestServePacketLargeFirstPacket(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	routes := RouteList{&Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"testReadLengthMatcher": json.RawMessage(`{"length":5}`)},
		},
	}}
	if err := routes.Provision(ctx); err != nil {
		t.Fatalf("provision failed | %s", err)
	}
	addr := startPacketServer(t, routes.Compile(zap.NewNop(), time.Second, HandlerFunc(echoHandler)), 30*time.Second)

	c := dialPacketServer(t, addr)
	want := bytes.Repeat([]byte{'a'}, 4*prefetchChunkSize)
	if got := mustExchange(t, c, want); !bytes.Equal(got, want) {
		t.Fatalf("got a reply of %d bytes, want the %d bytes sent", len(got), len(want))
	}
}

// TestServePacketEmptyPacket asserts that an empty packet, which UDP allows, reaches the handler
// as such rather than ending the flow.
func TestServePacketEmptyPacket(t *testing.T) {
	var handlers atomic.Int64
	addr := startPacketServer(t, HandlerFunc(func(cx *Connection) error {
		handlers.Add(1)
		return echoHandler(cx)
	}), 30*time.Second)

	c := dialPacketServer(t, addr)
	for _, want := range []string{"first", "", "last"} {
		if got := mustExchange(t, c, []byte(want)); string(got) != want {
			t.Fatalf("got reply %q, want %q", got, want)
		}
	}
	if got := handlers.Load(); got != 1 {
		t.Errorf("got %d handlers, want 1", got)
	}
}

// TestServePacketCloseEndsFlow asserts that once a handler closes its connection,
// the next packet of the client starts a new handler.
func TestServePacketCloseEndsFlow(t *testing.T) {
	var handlers atomic.Int64
	addr := startPacketServer(t, HandlerFunc(func(cx *Connection) error {
		handlers.Add(1)
		_ = cx.SetReadDeadline(time.Time{})
		buf := make([]byte, 1024)
		n, err := cx.Read(buf)
		if err != nil {
			return nil
		}
		_, err = cx.Write(buf[:n])
		return err // The connection is closed once the handler returns
	}), 30*time.Second)

	c := dialPacketServer(t, addr)
	for i := range 3 {
		want := fmt.Sprintf("packet-%d", i)
		if got := mustExchange(t, c, []byte(want)); string(got) != want {
			t.Fatalf("got reply %q, want %q", got, want)
		}
	}
	if got := handlers.Load(); got < 3 {
		t.Errorf("got %d handlers, want one per packet, i.e. 3 at least", got)
	}
}

// TestServePacketIdleTimeout asserts that a flow without packets ends after the idle timeout,
// so that a handler reading it gets io.EOF, and that the next packet starts a new handler.
func TestServePacketIdleTimeout(t *testing.T) {
	const idleTimeout = 300 * time.Millisecond

	var handlers atomic.Int64
	idle := make(chan time.Duration, 10)
	addr := startPacketServer(t, HandlerFunc(func(cx *Connection) error {
		handlers.Add(1)
		_ = cx.SetReadDeadline(time.Time{})
		buf := make([]byte, 1024)
		n, err := cx.Read(buf)
		if err != nil {
			return nil
		}
		if _, err = cx.Write(buf[:n]); err != nil {
			return err
		}
		start := time.Now()
		if _, err = cx.Read(buf); !errors.Is(err, io.EOF) {
			t.Errorf("got error %v reading an idle flow, want io.EOF", err)
		}
		idle <- time.Since(start)
		return nil
	}), idleTimeout)

	c := dialPacketServer(t, addr)
	if got := mustExchange(t, c, []byte("first")); string(got) != "first" {
		t.Fatalf("got reply %q, want %q", got, "first")
	}
	select {
	case d := <-idle:
		if d < idleTimeout/2 {
			t.Errorf("the flow ended after %s, want about the idle timeout of %s", d, idleTimeout)
		}
	case <-time.After(10 * idleTimeout):
		t.Fatalf("the flow didn't end within %s", 10*idleTimeout)
	}

	if got := mustExchange(t, c, []byte("second")); string(got) != "second" {
		t.Fatalf("got reply %q, want %q", got, "second")
	}
	if got := handlers.Load(); got != 2 {
		t.Errorf("got %d handlers, want 2", got)
	}
}

// TestServePacketWaitForMore asserts that HasMore and WaitForMore, which the QUIC matcher relies on,
// see the packets of the flow of a connection.
func TestServePacketWaitForMore(t *testing.T) {
	send := make(chan string)
	result := make(chan error, 1)
	addr := startPacketServer(t, HandlerFunc(func(cx *Connection) error {
		result <- func() error {
			_ = cx.SetReadDeadline(time.Time{})
			buf := make([]byte, 1024)
			read := func(want string) error {
				n, err := cx.Read(buf)
				if err != nil {
					return fmt.Errorf("reading %q: %w", want, err)
				}
				if string(buf[:n]) != want {
					return fmt.Errorf("read %q, want %q", buf[:n], want)
				}
				return nil
			}

			if err := read("a"); err != nil {
				return err
			}
			if cx.HasMore() {
				return errors.New("HasMore reported a packet before any was sent")
			}

			// Nothing comes, so WaitForMore returns once its context is done
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			err := cx.WaitForMore(ctx)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				return fmt.Errorf("WaitForMore returned %v without a packet, want %v", err, context.DeadlineExceeded)
			}

			// A packet comes, so WaitForMore returns before its context is done, keeping the packet for Read
			send <- "b"
			ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
			err = cx.WaitForMore(ctx)
			cancel()
			if err != nil {
				return fmt.Errorf("WaitForMore returned %v with a packet sent", err)
			}
			if err = read("b"); err != nil {
				return err
			}

			// Packets come while nobody reads, so HasMore reports them
			send <- "c"
			send <- "d"
			deadline := time.Now().Add(3 * time.Second)
			for !cx.HasMore() {
				if time.Now().After(deadline) {
					return errors.New("HasMore reported no packet with packets sent")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if err = read("c"); err != nil {
				return err
			}
			return read("d")
		}()
		close(send)
		return nil
	}), 30*time.Second)

	c := dialPacketServer(t, addr)
	if _, err := c.Write([]byte("a")); err != nil {
		t.Fatalf("failed to write | %s", err)
	}
	for b := range send {
		if _, err := c.Write([]byte(b)); err != nil {
			t.Fatalf("failed to write | %s", err)
		}
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
