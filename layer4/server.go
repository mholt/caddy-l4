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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/vnxme/hybrid"
	"go.uber.org/zap"
)

const (
	idleTimeoutDefault     = 30 * time.Second
	MatchingTimeoutDefault = 3 * time.Second
)

// Server represents a Caddy layer4 server.
type Server struct {
	// The network address to bind to. Any Caddy network address
	// is an acceptable value:
	// https://caddyserver.com/docs/conventions#network-addresses
	Listen []string `json:"listen,omitempty"`

	// Routes express composable logic for handling byte streams.
	Routes RouteList `json:"routes,omitempty"`

	// Maximum time before packet connection association (by downstream address:port) is removed. Default: 30s.
	// Note: this field is only relevant for packet connections (e.g., UDP).
	IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`
	// Maximum time connections have to complete the matching phase (the first terminal handler is matched). Default: 3s.
	MatchingTimeout caddy.Duration `json:"matching_timeout,omitempty"`

	logger        *zap.Logger
	listenAddrs   []caddy.NetworkAddress
	compiledRoute Handler
}

// Provision sets up the server.
func (s *Server) Provision(ctx caddy.Context, logger *zap.Logger) error {
	s.logger = logger

	if s.IdleTimeout <= 0 {
		s.IdleTimeout = caddy.Duration(idleTimeoutDefault)
	}

	if s.MatchingTimeout <= 0 {
		s.MatchingTimeout = caddy.Duration(MatchingTimeoutDefault)
	}

	repl := caddy.NewReplacer()
	for i, address := range s.Listen {
		address = repl.ReplaceAll(address, "")
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
	s.compiledRoute = s.Routes.Compile(s.logger, time.Duration(s.MatchingTimeout), nopHandler{})

	return nil
}

func (s *Server) serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			s.logger.Error("timeout accepting connection", zap.Error(err))
			continue
		}
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) servePacket(pc net.PacketConn) error {
	// The splitter sorts the packets of the socket into flows by downstream
	// address:port, and serves each flow as a split connection until it's
	// closed or idle. It stops once the socket is closed. As it drops the
	// first packet of a new flow if the accept queue is full, the queue is
	// long enough to absorb a burst of new downstreams while this loop waits
	// to be scheduled.
	// The splitter never closes the socket, which Caddy may not expect closed
	// more than once, while closing it makes the splitter stop on its own.
	ln := hybrid.Split(hybrid.FakeClosePacketConn(pc, nil), &hybrid.SplitConfig{
		AcceptQueueSize: udpAcceptQueueSize,
		IdleTimeout:     time.Duration(s.IdleTimeout),
		ReadBufferSize:  udpBufSize,
		// Caddy closes the socket on every shutdown and reload, and a client
		// gone makes a write fail, so these errors aren't worth an error log
		ErrorFunc: func(err error) {
			s.logger.Debug("packet connection error",
				zap.String("network", pc.LocalAddr().Network()),
				zap.String("address", pc.LocalAddr().String()),
				zap.Error(err),
			)
		},
	})
	for {
		sc, err := ln.AcceptSplit()
		if err != nil {
			s.logger.Debug("packet connection drops",
				zap.String("network", ln.Addr().Network()),
				zap.String("address", ln.Addr().String()),
				zap.Any("drops", ln.Stats()),
			)
			return err
		}
		go s.handle(newPacketConn(sc))
	}
}

func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	buf := bufPool.Get().([]byte)
	buf = buf[:0]
	defer bufPool.Put(buf)

	cx := WrapConnection(conn, buf, s.logger)

	s.logger.Debug("started handling connection",
		zap.String("network", cx.LocalAddr().Network()),
		zap.String("local", cx.LocalAddr().String()),
		zap.String("remote", cx.RemoteAddr().String()),
	)

	start := time.Now()
	err := s.compiledRoute.Handle(cx)
	duration := time.Since(start)
	if err != nil {
		s.logger.Error("handling connection",
			zap.String("network", cx.LocalAddr().Network()),
			zap.String("local", cx.LocalAddr().String()),
			zap.String("remote", cx.RemoteAddr().String()),
			zap.Error(err),
		)
	}

	s.logger.Debug("stopped handling connection; connection stats",
		zap.String("network", cx.LocalAddr().Network()),
		zap.String("local", cx.LocalAddr().String()),
		zap.String("remote", cx.RemoteAddr().String()),
		zap.Uint64("read", cx.bytesRead),
		zap.Uint64("written", cx.bytesWritten),
		zap.Duration("duration", duration),
	)
}

// UnmarshalCaddyfile sets up the Server from Caddyfile tokens. Syntax:
//
//	<address:port> [<address:port>] {
//		idle_timeout <duration>
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
		s.Listen = append(s.Listen, d.Val())
	}

	if err := ParseCaddyfileNestedRoutes(d, &s.Routes, &s.MatchingTimeout, &s.IdleTimeout); err != nil {
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
}

type packetConn struct {
	// The split connection of the flow, which the packets are read from by
	// the goroutine started by newPacketConn, and written to directly.
	net.PacketConn
	addr   net.Addr
	readCh chan *packet
	// If not nil, then the previous Read() call didn't consume all the data
	// from the buffer, and this packet will be reused in the next Read()
	// without waiting for readCh.
	lastPacket  *packet
	lastBuf     *bytes.Reader
	lastBufSize int

	// stores time.Time as Unix nanoseconds, or zero for no deadline, as Read may be
	// called concurrently with SetReadDeadline
	deadline      atomic.Int64
	deadlineTimer *time.Timer
}

// newPacketConn returns a packetConn serving the flow of sc. Its goroutine
// moves the packets from sc to readCh, and closes readCh once sc is closed,
// by Close or by the splitter, as the flow is idle or the socket is closed.
func newPacketConn(sc hybrid.SplitConn) *packetConn {
	pc := &packetConn{
		PacketConn: sc,
		addr:       sc.RemoteAddr(),
		readCh:     make(chan *packet, 5),
	}
	go func() {
		defer close(pc.readCh)
		for {
			buf := udpBufPool.Get().([]byte)
			n, err := sc.Read(buf)
			if err != nil {
				udpBufPool.Put(buf)
				return
			}
			pc.readCh <- &packet{
				pooledBuf: buf,
				n:         n,
			}
		}
	}()
	return pc
}

// SetDeadline sets the read deadline of the connection and the write deadline
// of the split connection, whose read deadline must stay clear, so as not to
// interrupt the goroutine moving its packets to readCh.
func (pc *packetConn) SetDeadline(t time.Time) error {
	_ = pc.SetReadDeadline(t)
	return pc.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline to wait for data from the underlying net.PacketConn.
func (pc *packetConn) SetReadDeadline(t time.Time) error {
	var ns int64
	if !t.IsZero() {
		ns = t.UnixNano()
	}
	pc.deadline.Store(ns)
	if pc.deadlineTimer != nil {
		pc.deadlineTimer.Reset(time.Until(t))
	} else {
		pc.deadlineTimer = time.NewTimer(time.Until(t))
	}
	return nil
}

// deadlineExceeded reports whether the read deadline has passed.
func (pc *packetConn) deadlineExceeded() bool {
	ns := pc.deadline.Load()
	return ns != 0 && ns < time.Now().UnixNano()
}

// lastFrameSize returns the size of the last packet read from the connection and whether it's depleted.
// should be called for every successful Read().
func (pc *packetConn) lastFrameStat() (int, bool) {
	return pc.lastBufSize, pc.lastPacket == nil
}

func (pc *packetConn) Read(b []byte) (n int, err error) {
	if pc.lastPacket != nil {
		// There is a partial buffer to continue reading from the previous
		// packet. Its io.EOF is ignored, as the packet may be empty, e.g. if
		// it's been kept by WaitForMore.
		n, _ = pc.lastBuf.Read(b)
		if pc.lastBuf.Len() == 0 {
			udpBufPool.Put(pc.lastPacket.pooledBuf)
			pc.lastPacket = nil
			pc.lastBuf = nil
		}
		return
	}
	// check deadline
	if pc.deadlineExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	for {
		select {
		case pkt := <-pc.readCh:
			if pkt == nil {
				// Channel is closed, as the flow has ended, e.g. as it's been
				// idle. Returning EOF here ensures that io.Copy() waiting on
				// the downstream for reads will terminate.
				return 0, io.EOF
			}
			// An empty packet, which UDP allows, reads as 0, nil, rather than
			// with the io.EOF of an empty buffer, as the flow goes on
			buf := bytes.NewReader(pkt.pooledBuf[:pkt.n])
			n, _ = buf.Read(b)
			if buf.Len() == 0 {
				// Buffer fully consumed, release it.
				udpBufPool.Put(pkt.pooledBuf)
			} else {
				// Buffer only partially consumed. Keep track of it for
				// next Read() call.
				pc.lastPacket = pkt
				pc.lastBuf = buf
			}
			pc.lastBufSize = pkt.n
			return
		case <-pc.deadlineTimer.C:
			// deadline may change during the wait, recheck
			if pc.deadlineExceeded() {
				return 0, os.ErrDeadlineExceeded
			}
			// next loop will run.
		}
	}
}

func (pc *packetConn) Write(b []byte) (n int, err error) {
	return pc.WriteTo(b, pc.addr)
}

func (pc *packetConn) Close() error {
	if pc.lastPacket != nil {
		udpBufPool.Put(pc.lastPacket.pooledBuf)
		pc.lastPacket = nil
	}
	// Closing the split connection ends the flow, so that the next packet
	// from the downstream starts a new one, and makes the goroutine moving
	// its packets close readCh, which aborts any active Read(). It doesn't
	// close the UDP socket.
	_ = pc.PacketConn.Close()
	// Drain pending packets to ensure we release buffers back to the pool
	for pkt := range pc.readCh {
		udpBufPool.Put(pkt.pooledBuf)
	}
	return nil
}

func (pc *packetConn) RemoteAddr() net.Addr { return pc.addr }

var udpBufPool = sync.Pool{
	New: func() any {
		// Buffers need to be as large as the largest datagram we'll consume, because
		// ReadFrom() can't resume partial reads.  (This is standard for UDP
		// sockets on *nix.)  So our buffer sizes are 9000 bytes to accommodate
		// networks with jumbo frames.  See also https://github.com/golang/go/issues/18056
		return make([]byte, udpBufSize)
	},
}

// udpBufSize is the size of the buffers of udpBufPool, and the largest packet
// read from a UDP socket. The splitter drops a larger one.
const udpBufSize = 9000

// udpAcceptQueueSize is the number of new flows of a UDP socket waiting to be
// handled, beyond which the splitter drops their first packets.
const udpAcceptQueueSize = 1024

// Interface guard
var _ caddyfile.Unmarshaler = (*Server)(nil)
