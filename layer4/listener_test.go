package layer4

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestListener_HandOffKeepsPrefetchedBytes ensures that the prefetch buffer of a connection handed off
// to the wrapped listener isn't returned to the pool and reused by subsequent connections before
// the consumer of the wrapped listener has read the prefetched bytes (issue #481).
func TestListener_HandOffKeepsPrefetchedBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	lw := &ListenerWrapper{
		logger: zap.NewNop(),
		// prefetch like routes would do for any matcher, then fall through to the wrapped listener
		compiledRoute: HandlerFunc(func(cx *Connection) error {
			if err := cx.prefetch(); err != nil {
				return err
			}
			return listenerHandler{}.Handle(cx)
		}),
	}
	wl := lw.WrapListener(ln)
	defer func() { _ = wl.Close() }()

	const (
		numConns   = 32
		payloadLen = 1024
	)

	payloadFor := func(i int) []byte {
		return bytes.Repeat([]byte(fmt.Sprintf("%04d", i)), payloadLen/4)
	}

	clients := make([]net.Conn, 0, numConns)
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	// Accept all connections before reading any of them, so that every hand-off completes
	// and the pool has a chance to give a released buffer to the next connection.
	accepted := make([]net.Conn, 0, numConns)
	defer func() {
		for _, c := range accepted {
			_ = c.Close()
		}
	}()
	for i := 0; i < numConns; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		if _, err = c.Write(payloadFor(i)); err != nil {
			t.Fatal(err)
		}

		s, err := wl.Accept()
		if err != nil {
			t.Fatal(err)
		}
		accepted = append(accepted, s)
	}

	for i, s := range accepted {
		_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, payloadLen)
		if _, err := io.ReadFull(s, got); err != nil {
			t.Fatalf("conn %d: reading payload: %v", i, err)
		}
		if want := payloadFor(i); !bytes.Equal(got, want) {
			t.Fatalf("conn %d: got payload starting with %q, want %q", i, got[:8], want[:8])
		}
	}
}
