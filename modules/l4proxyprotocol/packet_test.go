package l4proxyprotocol

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

// fakeDatagramConn is a net.Conn that hands out one preloaded datagram per
// Read, emulating how a layer4.Connection backed by a packet (UDP) conn
// delivers data on message boundaries.
type fakeDatagramConn struct {
	datagrams     [][]byte
	idx           int
	local, remote net.Addr
}

func (f *fakeDatagramConn) Read(b []byte) (int, error) {
	if f.idx >= len(f.datagrams) {
		return 0, io.EOF
	}
	n := copy(b, f.datagrams[f.idx])
	f.idx++
	return n, nil
}

func (f *fakeDatagramConn) Write(b []byte) (int, error)      { return len(b), nil }
func (f *fakeDatagramConn) Close() error                     { return nil }
func (f *fakeDatagramConn) LocalAddr() net.Addr              { return f.local }
func (f *fakeDatagramConn) RemoteAddr() net.Addr             { return f.remote }
func (f *fakeDatagramConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeDatagramConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeDatagramConn) SetWriteDeadline(time.Time) error { return nil }

// buildDatagram mirrors l4proxy's packetProxyProtocolConn.Write: a PROXY v2
// header (built from src/dst) immediately followed by the payload, all in a
// single datagram.
func buildDatagram(src, dst *net.UDPAddr, payload []byte) []byte {
	h := proxyproto.HeaderProxyFromAddrs(2, src, dst)
	buf := new(bytes.Buffer)
	_, _ = h.WriteTo(buf)
	buf.Write(payload)
	return buf.Bytes()
}

// TestPacketConnStripsHeaderFromEveryDatagram is the core regression test for
// issue #451: caddy-l4's packet PROXY protocol writer prepends a header to
// every datagram, so the reader must strip a header from every datagram — not
// just the first, as go-proxyproto's stream reader does.
func TestPacketConnStripsHeaderFromEveryDatagram(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 12345}
	dst := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 443}

	payloads := [][]byte{[]byte("first"), []byte("second"), []byte("third")}
	datagrams := make([][]byte, 0, len(payloads))
	for _, pl := range payloads {
		datagrams = append(datagrams, buildDatagram(src, dst, pl))
	}

	conn := newPacketConn(&fakeDatagramConn{datagrams: datagrams, local: dst, remote: src}, false)

	// Priming reads the first datagram so addresses reflect the PROXY header.
	if err := conn.prime(0); err != nil {
		t.Fatalf("prime failed: %v", err)
	}
	assertString(t, "1.2.3.4:12345", conn.RemoteAddr().String())
	assertString(t, "5.6.7.8:443", conn.LocalAddr().String())

	// Every datagram's payload must come back with its header stripped.
	for i, want := range payloads {
		b := make([]byte, maxDatagramSize)
		n, err := conn.Read(b)
		if err != nil {
			t.Fatalf("datagram %d: Read error: %v", i, err)
		}
		if got := string(b[:n]); got != string(want) {
			t.Fatalf("datagram %d: got %q, want %q (PROXY header not stripped?)", i, got, want)
		}
	}

	// After the last datagram, the underlying EOF should surface.
	if _, err := conn.Read(make([]byte, maxDatagramSize)); err != io.EOF {
		t.Fatalf("expected io.EOF after last datagram, got %v", err)
	}
}

// TestPacketConnPassesThroughWhenHeaderNotRequired verifies that datagrams
// without a PROXY header are forwarded unchanged when the policy does not
// require one.
func TestPacketConnPassesThroughWhenHeaderNotRequired(t *testing.T) {
	datagrams := [][]byte{[]byte("no-header-here"), []byte("still-plain")}
	conn := newPacketConn(&fakeDatagramConn{
		datagrams: datagrams,
		local:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000},
		remote:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6000},
	}, false)

	if err := conn.prime(0); err != nil {
		t.Fatalf("prime failed: %v", err)
	}
	// No PROXY header seen, so addresses fall back to the underlying conn.
	assertString(t, "127.0.0.1:6000", conn.RemoteAddr().String())

	for i, want := range datagrams {
		b := make([]byte, maxDatagramSize)
		n, err := conn.Read(b)
		if err != nil {
			t.Fatalf("datagram %d: Read error: %v", i, err)
		}
		if got := string(b[:n]); got != string(want) {
			t.Fatalf("datagram %d: got %q, want %q", i, got, want)
		}
	}
}

// TestPacketConnRequiredHeaderMissing verifies that a datagram lacking a
// required PROXY header is rejected.
func TestPacketConnRequiredHeaderMissing(t *testing.T) {
	conn := newPacketConn(&fakeDatagramConn{
		datagrams: [][]byte{[]byte("plain datagram")},
		local:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000},
		remote:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6000},
	}, true)

	err := conn.prime(0)
	if err != ErrPacketHeaderRequired {
		t.Fatalf("expected ErrPacketHeaderRequired, got %v", err)
	}
}

// TestPacketConnPayloadLargerThanReadBuffer verifies that a datagram payload
// larger than the caller's buffer is delivered across multiple Reads without
// loss or corruption.
func TestPacketConnPayloadLargerThanReadBuffer(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1}
	dst := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 2}

	payload := bytes.Repeat([]byte("A"), 1000)
	conn := newPacketConn(&fakeDatagramConn{
		datagrams: [][]byte{buildDatagram(src, dst, payload)},
		local:     dst,
		remote:    src,
	}, false)

	if err := conn.prime(0); err != nil {
		t.Fatalf("prime failed: %v", err)
	}

	// Read in small chunks to force the leftover-payload path.
	var got []byte
	for {
		b := make([]byte, 64)
		n, err := conn.Read(b)
		got = append(got, b[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read error: %v", err)
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("reassembled payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}
