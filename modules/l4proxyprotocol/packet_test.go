package l4proxyprotocol

import (
	"bytes"
	"io"
	"net"
	"strings"
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

	conn := newPacketConn(&fakeDatagramConn{datagrams: datagrams, local: dst, remote: src}, proxyproto.USE)

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
	}, proxyproto.USE)

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
	}, proxyproto.REQUIRE)

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
	}, proxyproto.USE)

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

// TestPacketConnAddrsFollowPolicy verifies that the addresses from the PROXY
// header are only reported under the policies trusting them, as on the stream
// path: IGNORE strips the header but keeps the immediate peer's addresses, so
// an untrusted sender can't spoof them.
func TestPacketConnAddrsFollowPolicy(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 12345}
	dst := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 443}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6000}
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}

	for _, tc := range []struct {
		name                  string
		policy                proxyproto.Policy
		wantRemote, wantLocal string
	}{
		{"USE", proxyproto.USE, src.String(), dst.String()},
		{"REQUIRE", proxyproto.REQUIRE, src.String(), dst.String()},
		{"IGNORE", proxyproto.IGNORE, peer.String(), local.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newPacketConn(&fakeDatagramConn{
				datagrams: [][]byte{buildDatagram(src, dst, []byte("payload"))},
				local:     local,
				remote:    peer,
			}, tc.policy)
			if err := conn.prime(0); err != nil {
				t.Fatalf("prime failed: %v", err)
			}
			assertString(t, tc.wantRemote, conn.RemoteAddr().String())
			assertString(t, tc.wantLocal, conn.LocalAddr().String())

			b := make([]byte, maxDatagramSize)
			n, err := conn.Read(b)
			if err != nil {
				t.Fatalf("Read error: %v", err)
			}
			assertString(t, "payload", string(b[:n]))
		})
	}
}

// malformedDatagram starts with the PROXY v2 signature, but carries an
// unsupported address family, so its header fails to parse.
var malformedDatagram = []byte("\r\n\r\n\x00\r\nQUIT\n\x21\x99\x00\x00payload")

// TestPacketConnDropsBadDatagrams verifies that a datagram whose PROXY header
// is malformed, or missing while required, is dropped once the connection has
// been primed, rather than failing the Read and ending the whole session.
func TestPacketConnDropsBadDatagrams(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 12345}
	dst := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 443}

	for _, tc := range []struct {
		name   string
		policy proxyproto.Policy
		want   []string
	}{
		// a datagram without a header is dropped only if one is required
		{"REQUIRE", proxyproto.REQUIRE, []string{"first", "last"}},
		{"USE", proxyproto.USE, []string{"first", "plain", "last"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newPacketConn(&fakeDatagramConn{
				datagrams: [][]byte{
					buildDatagram(src, dst, []byte("first")),
					malformedDatagram,
					[]byte("plain"),
					buildDatagram(src, dst, []byte("last")),
				},
				local:  dst,
				remote: src,
			}, tc.policy)
			if err := conn.prime(0); err != nil {
				t.Fatalf("prime failed: %v", err)
			}

			var got []string
			for {
				b := make([]byte, maxDatagramSize)
				n, err := conn.Read(b)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("Read error after %q: %v", got, err)
				}
				got = append(got, string(b[:n]))
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPacketConnPrimeRejectsMalformedHeader verifies that a malformed PROXY
// header on the first datagram still fails priming, as the stream path rejects
// such a connection.
func TestPacketConnPrimeRejectsMalformedHeader(t *testing.T) {
	conn := newPacketConn(&fakeDatagramConn{
		datagrams: [][]byte{malformedDatagram},
		local:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000},
		remote:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6000},
	}, proxyproto.USE)
	if err := conn.prime(0); err == nil {
		t.Fatal("expected prime to fail on a malformed PROXY header")
	}
}
