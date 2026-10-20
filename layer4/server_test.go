// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package layer4

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// TestServePacketReleasesHandlersOnExit checks that when the packet server
// loop exits while associations are still live, which is what happens on a
// config reload when the old server's socket is closed under it, every
// handler goroutine finishes instead of blocking forever on the close
// notification channel that the exited loop no longer drains.
//
// Before the fix, the handlers stayed parked after the loop exited: first on
// readCh, which nothing closed any more, and then, once the idle timeout
// fired, on the send to closeCh, which nothing drained any more. The number
// of associations is deliberately larger than the closeCh buffer of 10, so
// that even the second stage would leave most of them blocked.
func TestServePacketReleasesHandlersOnExit(t *testing.T) {
	const associations = 30

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var started, finished atomic.Int32
	server := &Server{
		IdleTimeout: caddy.Duration(time.Minute), // must not fire during the test
		logger:      zap.NewNop(),
		compiledRoute: HandlerFunc(func(cx *Connection) error {
			started.Add(1)
			defer finished.Add(1)
			// The compiled route clears the matching deadline before handing
			// the connection to a terminal handler; do the same here, since a
			// packetConn that never had a deadline set reports it as exceeded.
			_ = cx.SetReadDeadline(time.Time{})
			// Consume until the server closes our read channel.
			_, _ = io.Copy(io.Discard, cx)
			return nil
		}),
	}

	served := make(chan error, 1)
	go func() { served <- server.servePacket(pc) }()

	// One datagram from each of N distinct source ports creates N associations.
	for i := 0; i < associations; i++ {
		c, err := net.Dial("udp", pc.LocalAddr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	waitFor(t, "all handlers to start", func() bool { return started.Load() == associations })

	// Closing the socket makes ReadFrom fail, which is how the loop exits on
	// a reload: the old fakeClosePacketConn returns an error to the old loop.
	if err := pc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("servePacket did not return after the socket was closed")
	}

	waitFor(t, "all handlers to finish", func() bool { return finished.Load() == associations })
	if n := finished.Load(); n != associations {
		t.Fatalf("%d of %d handlers still running after the server loop exited", associations-n, associations)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
