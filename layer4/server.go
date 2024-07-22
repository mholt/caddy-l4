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
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

const MatchingTimeoutDefault = 3 * time.Second

// Server represents a Caddy layer4 server.
type Server struct {
	// The network address to bind to. Any Caddy network address
	// is an acceptable value:
	// https://caddyserver.com/docs/conventions#network-addresses
	Listen []string `json:"listen,omitempty"`

	// Routes express composable logic for handling byte streams.
	Routes RouteList `json:"routes,omitempty"`

	// Maximum time connections have to complete the matching phase (the first terminal handler is matched). Default: 3s.
	MatchingTimeout caddy.Duration `json:"matching_timeout,omitempty"`

	logger        *zap.Logger
	listenAddrs   []caddy.NetworkAddress
	compiledRoute Handler
}

// Provision sets up the server.
func (s *Server) Provision(ctx caddy.Context, logger *zap.Logger) error {
	s.logger = logger

	if s.MatchingTimeout <= 0 {
		s.MatchingTimeout = caddy.Duration(MatchingTimeoutDefault)
	}

	for i, address := range s.Listen {
		addr, err := caddy.ParseNetworkAddress(address)
		if err != nil {
			return fmt.Errorf("parsing listener address '%s' in position %d: %v", address, i, err)
		}
		s.listenAddrs = append(s.listenAddrs, addr)
	}

	err := s.Routes.Provision(ctx)
	if err != nil {
		return err
	}
	s.compiledRoute = s.Routes.Compile(s.logger, time.Duration(s.MatchingTimeout), nopNextHandler{})

	return nil
}

func (s Server) serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			s.logger.Error("timeout accepting connection", zap.Error(err))
			continue
		}
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s Server) servePacket(pc net.PacketConn) error {
	// Spawn a goroutine whose only job is to consume packets from the socket
	// and send to the packets channel.
	packets := make(chan packet, 10)
	go func(packets chan packet) {
		for {
			buf := udpBufPool.Get().([]byte)
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				packets <- packet{err: err}
				return
			}
			packets <- packet{
				pooledBuf: buf,
				n:         n,
				addr:      addr,
			}
		}
	}(packets)

	// udpConns tracks active packetConns by downstream address:port. They will
	// be removed from this map after being closed.
	udpConns := make(map[string]*packetConn)
	// closeCh is used to receive notifications of socket closures from
	// packetConn, which allows us to to remove stale connections (whose
	// proxy handlers have completed) from the udpConns map.
	closeCh := make(chan string, 10)
	for {
		select {
		case addr := <-closeCh:
			// UDP connection is closed (either implicitly through timeout or by
			// explicit call to Close()).
			delete(udpConns, addr)

		case pkt := <-packets:
			if pkt.err != nil {
				return pkt.err
			}
			conn, ok := udpConns[pkt.addr.String()]
			if !ok {
				// No existing proxy handler is running for this downstream.
				// Create one now.
				conn = &packetConn{
					PacketConn: pc,
					readCh:     make(chan *packet, 5),
					addr:       pkt.addr,
					closeCh:    closeCh,
				}
				udpConns[pkt.addr.String()] = conn
				go func(conn *packetConn) {
					s.handle(conn)
					// It might seem cleaner to send to closeCh here rather than
					// in packetConn, but doing it earlier in packetConn closes
					// the gap between the proxy handler shutting down and new
					// packets coming in from the same downstream.  Should that
					// happen, we'll just spin up a new handler concurrent to
					// the old one shutting down.
				}(conn)
			}
			conn.readCh <- &pkt
		}
	}
}

func (s Server) handle(conn net.Conn) {
	defer conn.Close()

	buf := bufPool.Get().([]byte)
	buf = buf[:0]
	defer bufPool.Put(buf)

	cx := WrapConnection(conn, buf, s.logger)

	start := time.Now()
	err := s.compiledRoute.Handle(cx)
	duration := time.Since(start)
	if err != nil {
		s.logger.Error("handling connection", zap.String("remote", cx.RemoteAddr().String()), zap.Error(err))
	}

	s.logger.Debug("connection stats",
		zap.String("remote", cx.RemoteAddr().String()),
		zap.Uint64("read", cx.bytesRead),
		zap.Uint64("written", cx.bytesWritten),
		zap.Duration("duration", duration),
	)
}

// UnmarshalCaddyfile sets up the Server from Caddyfile tokens. Syntax:
//
//	<addresses> {
//		matching_timeout <duration>
//		@a <matcher> [<matcher_args>]
//		@b {
//			<matcher> [<matcher_args>]
//			<matcher> [<matcher_args>]
//		}
//		route @a @b {
//			<handler> [<handler_args>]
//		}
//		@c <matcher> {
//			<matcher_option> [<matcher_option_args>]
//		}
//		route @c {
//			<handler> [<handler_args>]
//			<handler> {
//				<handler_option> [<handler_option_args>]
//			}
//		}
//	}
func (s *Server) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Wrapper name and all same-line options are treated as network addresses
	for ok := true; ok; ok = d.NextArg() {
		addr := d.Val()
		if _, err := caddy.ParseNetworkAddress(addr); err != nil {
			return d.Errf("parsing network address '%s': %v", addr, err)
		}
		s.Listen = append(s.Listen, addr)
	}

	if err := ParseCaddyfileNestedRoutes(d, &s.Routes, &s.MatchingTimeout); err != nil {
		return err
	}

	return nil
}

type packet struct {
	// The underlying bytes slice that was gotten from udpBufPool.  It's up to
	// packetConn to return it to udpBufPool once it's consumed.
	pooledBuf []byte
	// Number of bytes read from socket
	n int
	// Error that occurred while reading from socket
	err error
	// Address of downstream
	addr net.Addr
}

type packetConn struct {
	net.PacketConn
	addr    net.Addr
	readCh  chan *packet
	closeCh chan string
	// If not nil, then the previous Read() call didn't consume all the data
	// from the buffer, and this packet will be reused in the next Read()
	// without waiting for readCh.
	lastPacket *packet
	lastBuf    *bytes.Buffer
}

func (pc *packetConn) Read(b []byte) (n int, err error) {
	if pc.lastPacket != nil {
		// There is a partial buffer to continue reading from the previous
		// packet.
		n, err = pc.lastBuf.Read(b)
		if pc.lastBuf.Len() == 0 {
			udpBufPool.Put(pc.lastPacket.pooledBuf)
			pc.lastPacket = nil
			pc.lastBuf = nil
		}
		return
	}
	select {
	case pkt := <-pc.readCh:
		if pkt == nil {
			// Channel is closed. Return EOF below.
			break
		}
		buf := bytes.NewBuffer(pkt.pooledBuf[:pkt.n])
		n, err = buf.Read(b)
		if buf.Len() == 0 {
			// Buffer fully consumed, release it.
			udpBufPool.Put(pkt.pooledBuf)
		} else {
			// Buffer only partially consumed. Keep track of it for
			// next Read() call.
			pc.lastPacket = pkt
			pc.lastBuf = buf
		}
		return
	// TODO: idle timeout should be configurable per server
	case <-time.After(30 * time.Second):
		break
	}
	// Idle timeout simulates socket closure.
	//
	// Although Close() also does this, we inform the server loop early about
	// the closure to ensure that if any new packets are received from this
	// connection in the meantime, a new handler will be started.
	pc.closeCh <- pc.addr.String()
	// Returning EOF here ensures that io.Copy() waiting on the downstream for
	// reads will terminate.
	return 0, io.EOF
}

func (pc packetConn) Write(b []byte) (n int, err error) {
	return pc.PacketConn.WriteTo(b, pc.addr)
}

func (pc *packetConn) Close() error {
	if pc.lastPacket != nil {
		udpBufPool.Put(pc.lastPacket.pooledBuf)
		pc.lastPacket = nil
	}
	// This will abort any active Read() from another goroutine and return EOF
	close(pc.readCh)
	// Drain pending packets to ensure we release buffers back to the pool
	for pkt := range pc.readCh {
		udpBufPool.Put(pkt.pooledBuf)
	}
	// We may have already done this earlier in Read(), but just in case
	// Read() wasn't being called, (re-)notify server loop we're closed.
	pc.closeCh <- pc.addr.String()
	// We don't call net.PacketConn.Close() here as we would stop the UDP
	// server.
	return nil
}

func (pc packetConn) RemoteAddr() net.Addr { return pc.addr }

var udpBufPool = sync.Pool{
	New: func() interface{} {
		// Buffers need to be as large as the largest datagram we'll consume, because
		// ReadFrom() can't resume partial reads.  (This is standard for UDP
		// sockets on *nix.)  So our buffer sizes are 9000 bytes to accommodate
		// networks with jumbo frames.  See also https://github.com/golang/go/issues/18056
		return make([]byte, 9000)
	},
}

// Interface guard
var _ caddyfile.Unmarshaler = (*Server)(nil)
