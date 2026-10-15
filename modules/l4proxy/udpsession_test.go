package l4proxy

// Regression test for https://github.com/mholt/caddy-l4/issues/464
// "UDP session goroutines leak permanently when the server stops".
//
// servePacket's run loop is the only receiver on closeCh, and it exits as soon
// as the packet conn reports an error - which App.Stop causes by closing the
// conns. Each live pseudo-session then announces its closure with a blocking
// send on that channel. closeCh is buffered at 10, so once the buffer fills
// every further session parks forever: Read never returns, io.Copy in
// Handler.proxy never returns, and the deferred conn.Close never runs.
//
// This drives the real layer4 server end to end - Provision, Start, live UDP
// sessions, then Stop - so the leak is the library's own, not a hand-built
// state. Without the fix the goroutines stay parked in packetConn.Read after
// Stop and this test fails; with it every session unwinds.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

var inPacketConnRead = regexp.MustCompile(`layer4\.\(\*packetConn\)\.Read`)

// udpSessionsParked counts goroutines parked in packetConn.Read, i.e. one per
// live UDP pseudo-session.
func udpSessionsParked(t *testing.T) int {
	t.Helper()
	var sb strings.Builder
	if err := pprof.Lookup("goroutine").WriteTo(&sb, 2); err != nil {
		t.Fatalf("dumping goroutines: %v", err)
	}
	return len(inPacketConnRead.FindAllString(sb.String(), -1))
}

// listenUDPEcho starts a UDP echo server and returns its port.
func listenUDPEcho(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for echo upstream: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// freeUDPPort reserves and releases a loopback UDP port for the server to bind.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}

// TestStopWithLiveUDPSessionsDoesNotLeak asserts that stopping the app while
// UDP sessions are live lets every session goroutine unwind, rather than
// parking forever on a closeCh send whose only receiver has already exited.
func TestStopWithLiveUDPSessionsDoesNotLeak(t *testing.T) {
	const (
		sessions    = 15 // deliberately above closeCh's 10-slot buffer
		idleTimeout = 2 * time.Second
	)

	backend := listenUDPEcho(t)
	listen := freeUDPPort(t)

	app := &layer4.App{
		Servers: map[string]*layer4.Server{
			"repro": {
				Listen:      []string{fmt.Sprintf("udp/127.0.0.1:%d", listen)},
				IdleTimeout: caddy.Duration(idleTimeout),
				Routes: layer4.RouteList{&layer4.Route{HandlersRaw: []json.RawMessage{
					json.RawMessage(fmt.Sprintf(
						`{"handler":"proxy","upstreams":[{"dial":["udp/127.0.0.1:%d"]}]}`, backend)),
				}}},
			},
		},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := app.Provision(ctx); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	if err := app.Start(); err != nil {
		t.Fatalf("starting: %v", err)
	}

	// One datagram from each of N distinct source ports: N sessions.
	clients := make([]net.Conn, 0, sessions)
	for i := 0; i < sessions; i++ {
		c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", listen))
		if err != nil {
			t.Fatalf("dialing session %d: %v", i, err)
		}
		if _, err := c.Write([]byte("hello")); err != nil {
			t.Fatalf("writing session %d: %v", i, err)
		}
		clients = append(clients, c)
	}
	t.Cleanup(func() {
		for _, c := range clients {
			_ = c.Close()
		}
	})

	// Well inside the idle timeout, so every session is alive and parked in
	// packetConn.Read waiting for its next datagram.
	time.Sleep(300 * time.Millisecond)
	live := udpSessionsParked(t)
	if live < sessions {
		t.Fatalf("setup: only %d of %d sessions were created", live, sessions)
	}

	// What a config reload does to the outgoing server.
	if err := app.Stop(); err != nil {
		t.Fatalf("stopping: %v", err)
	}

	// Twice the idle timeout: every session has had its chance to unwind.
	time.Sleep(2 * idleTimeout)

	if stuck := udpSessionsParked(t); stuck > 0 {
		t.Errorf("leaked %d of %d session goroutines: still parked in "+
			"packetConn.Read after Stop()", stuck, live)
	}
}
