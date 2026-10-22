package layer4

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// testReadByteMatcher consumes one byte and matches, which is enough to drive a
// UDP datagram through matching and into a handler that then parks reading for
// more (a live UDP "session").
type testReadByteMatcher struct{}

func (*testReadByteMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.testReadByteMatcher",
		New: func() caddy.Module { return new(testReadByteMatcher) },
	}
}

func (m *testReadByteMatcher) Match(cx *Connection) (bool, error) {
	buf := make([]byte, 1)
	n, err := io.ReadFull(cx, buf)
	return n > 0, err
}

// TestServePacketNoGoroutineLeakOnShutdown asserts that when the UDP server
// loop exits (reload/shutdown), every live per-session handler goroutine is
// released rather than leaking: on the buggy code each handler stays parked on
// its readCh (the loop never closes it on exit) and/or blocks forever on the
// now-undrained closeCh. Regression guard for
// https://github.com/mholt/caddy-l4/issues/464.
func TestServePacketNoGoroutineLeakOnShutdown(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	caddy.RegisterModule(&testReadByteMatcher{})

	routes := RouteList{&Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"testReadByteMatcher": json.RawMessage("{}")},
		},
	}}
	if err := routes.Provision(ctx); err != nil {
		t.Fatalf("provision failed | %s", err)
	}

	var started, finished atomic.Int64
	compiled := routes.Compile(zap.NewNop(), time.Second,
		HandlerFunc(func(con *Connection) error {
			// Clear the matching read deadline so the handler parks on the
			// packetConn's readCh — the exact live-session state that leaked
			// on shutdown — instead of being released by a deadline.
			_ = con.SetReadDeadline(time.Time{})
			started.Add(1)
			_, _ = io.Copy(io.Discard, con)
			finished.Add(1)
			return nil
		}))

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen | %s", err)
	}

	server := new(Server)
	server.compiledRoute = compiled
	server.logger = zap.NewNop()
	// Long idle timeout: handlers must be released by the shutdown path, not
	// by their own idle timer firing inside the test window.
	server.IdleTimeout = caddy.Duration(30 * time.Second)

	serveDone := make(chan struct{})
	go func() {
		_ = server.servePacket(pc)
		close(serveDone)
	}()

	// Distinct client sockets => distinct source ports => distinct packetConns
	// => distinct handler goroutines. sessions > closeCh capacity (10) so the
	// leak is not masked by the buffered channel absorbing the first sends.
	const sessions = 25
	clients := make([]net.Conn, 0, sessions)
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()
	for i := 0; i < sessions; i++ {
		c, derr := net.Dial("udp", pc.LocalAddr().String())
		if derr != nil {
			t.Fatalf("dial %d | %s", i, derr)
		}
		clients = append(clients, c)
		if _, werr := c.Write([]byte("x")); werr != nil {
			t.Fatalf("write %d | %s", i, werr)
		}
	}

	waitFor(t, 3*time.Second, func() bool { return started.Load() == sessions },
		func() string {
			return fmt.Sprintf("handlers started: got %d, want %d", started.Load(), sessions)
		})

	// Shut the loop down by closing the socket: the reader goroutine errors,
	// servePacket returns, and its deferred cleanup must release every parked
	// handler.
	_ = pc.Close()

	select {
	case <-serveDone:
	case <-time.After(3 * time.Second):
		t.Fatal("servePacket did not return after socket close")
	}

	waitFor(t, 3*time.Second, func() bool { return finished.Load() == sessions },
		func() string {
			return fmt.Sprintf("leaked handler goroutines: %d of %d still parked after shutdown",
				int64(sessions)-finished.Load(), sessions)
		})
}

func waitFor(t *testing.T, d time.Duration, cond func() bool, msg func() string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg())
}
