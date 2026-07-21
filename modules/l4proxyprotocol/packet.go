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

package l4proxyprotocol

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"time"

	"github.com/pires/go-proxyproto"
)

// maxDatagramSize bounds a single datagram read from a packet connection. It
// matches the buffer size layer4 uses for reading UDP datagrams (sized for
// jumbo frames), so a whole datagram is always returned by a single Read.
const maxDatagramSize = 9000

// ErrPacketHeaderRequired is returned while reading from a packet connection
// when a PROXY header is required by policy but a datagram arrives without one.
var ErrPacketHeaderRequired = errors.New("PROXY header required but not received")

// packetConn wraps a packet (e.g. UDP) connection whose datagrams are each
// prefixed with a PROXY protocol header, stripping the header from every
// datagram it reads.
//
// This differs fundamentally from a stream connection: on a stream a single
// PROXY header precedes the whole byte stream and is consumed once (which is
// what github.com/pires/go-proxyproto does). caddy-l4's packet PROXY protocol
// writer (see modules/l4proxy) instead prepends a header to every datagram, so
// the reader has to strip one header per datagram rather than only once.
type packetConn struct {
	net.Conn

	// requireHeader rejects datagrams that arrive without a PROXY header.
	requireHeader bool

	// readBuf is a reusable buffer for reading a whole datagram.
	readBuf []byte
	// payload holds the not-yet-consumed payload of the current datagram.
	payload []byte
	// pendingErr is a read error observed together with payload data; it is
	// surfaced only after the buffered payload has been fully consumed.
	pendingErr error

	// srcAddr and dstAddr are taken from the first PROXY header seen and are
	// reported by RemoteAddr and LocalAddr respectively, mirroring the stream
	// handler's behavior.
	srcAddr, dstAddr net.Addr
}

// newPacketConn wraps conn, which must deliver exactly one datagram per Read
// (as a layer4.Connection backed by a packet conn does).
func newPacketConn(conn net.Conn, requireHeader bool) *packetConn {
	return &packetConn{
		Conn:          conn,
		requireHeader: requireHeader,
		readBuf:       make([]byte, maxDatagramSize),
	}
}

// prime reads the first datagram so that RemoteAddr and LocalAddr reflect the
// PROXY header before any payload is forwarded downstream. The stripped payload
// (if any) is buffered for the next Read. A non-zero timeout bounds the wait;
// if it elapses before a datagram arrives, priming is a no-op unless a header
// is required (nothing has been consumed, so later datagrams are still read).
func (c *packetConn) prime(timeout time.Duration) error {
	if timeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = c.Conn.SetReadDeadline(time.Time{}) }()
	}
	payload, err := c.readDatagram()
	if len(payload) > 0 {
		c.payload = append(c.payload[:0], payload...)
	}
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() && !c.requireHeader {
			return nil
		}
		return err
	}
	return nil
}

// readDatagram reads a single datagram and returns its payload with the PROXY
// header (if any) stripped off. The returned slice is safe to retain: it does
// not alias the reusable read buffer.
func (c *packetConn) readDatagram() ([]byte, error) {
	n, err := c.Conn.Read(c.readBuf)
	if n == 0 {
		return nil, err
	}
	payload, herr := c.stripHeader(c.readBuf[:n])
	if herr != nil {
		return nil, herr
	}
	out := make([]byte, len(payload))
	copy(out, payload)
	return out, err
}

// stripHeader parses and removes a PROXY protocol header from the front of a
// datagram, returning the remaining payload. If no header is present, the
// datagram is returned unchanged (or rejected when a header is required).
func (c *packetConn) stripHeader(datagram []byte) ([]byte, error) {
	br := bufio.NewReader(bytes.NewReader(datagram))
	header, err := proxyproto.Read(br)
	if err != nil {
		if errors.Is(err, proxyproto.ErrNoProxyProtocol) {
			if c.requireHeader {
				return nil, ErrPacketHeaderRequired
			}
			return datagram, nil
		}
		return nil, err
	}
	// Record the addresses from the first PROXY (not LOCAL) header so that
	// RemoteAddr/LocalAddr stay stable across the connection's datagrams.
	if header.Command == proxyproto.PROXY && c.srcAddr == nil {
		c.srcAddr, c.dstAddr = header.SourceAddr, header.DestinationAddr
	}
	// Everything after the header is the datagram's payload.
	remaining, _ := io.ReadAll(br)
	return remaining, nil
}

// Read returns the header-stripped payload of the packet stream. Each datagram
// is unwrapped independently.
func (c *packetConn) Read(b []byte) (int, error) {
	// Serve any leftover payload from the current datagram first.
	if len(c.payload) > 0 {
		n := copy(b, c.payload)
		c.payload = c.payload[n:]
		return n, nil
	}
	if c.pendingErr != nil {
		err := c.pendingErr
		c.pendingErr = nil
		return 0, err
	}
	for {
		payload, err := c.readDatagram()
		if len(payload) > 0 {
			n := copy(b, payload)
			if n < len(payload) {
				c.payload = append(c.payload[:0], payload[n:]...)
			}
			// Surface any read error only after the payload is drained.
			c.pendingErr = err
			return n, nil
		}
		if err != nil {
			return 0, err
		}
		// Header-only datagram (e.g. no payload); move on to the next one.
	}
}

// RemoteAddr returns the source address from the PROXY header if one was seen,
// otherwise the underlying connection's remote address.
func (c *packetConn) RemoteAddr() net.Addr {
	if c.srcAddr != nil {
		return c.srcAddr
	}
	return c.Conn.RemoteAddr()
}

// LocalAddr returns the destination address from the PROXY header if one was
// seen, otherwise the underlying connection's local address.
func (c *packetConn) LocalAddr() net.Addr {
	if c.dstAddr != nil {
		return c.dstAddr
	}
	return c.Conn.LocalAddr()
}

// Interface guard
var _ net.Conn = (*packetConn)(nil)
