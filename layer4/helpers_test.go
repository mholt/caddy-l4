package layer4

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// nilAddrPacketConn reads nothing, with no address and no error, first, as Caddy's packet conns do once closed
// on some platforms, then reads from the underlying PacketConn.
type nilAddrPacketConn struct {
	net.PacketConn
	once atomic.Bool
}

func (c *nilAddrPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.once.CompareAndSwap(false, true) {
		return 0, nil, nil
	}
	return c.PacketConn.ReadFrom(p)
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

// waitFor waits until cond is true, failing the test with msg if it isn't within d.
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
