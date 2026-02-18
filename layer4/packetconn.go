package layer4

import (
	"bytes"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(&PacketConnWrapper{})
}

// PacketConnWrapper is a Caddy module that wraps App as a packet conn wrapper, it doesn't support tcp.
type PacketConnWrapper struct {
	// Routes express composable logic for handling byte streams.
	Routes RouteList `json:"routes,omitempty"`

	// Maximum time connections have to complete the matching phase (the first terminal handler is matched). Default: 3s.
	MatchingTimeout caddy.Duration `json:"matching_timeout,omitempty"`

	// probably should extract packet conn handling logic, but this will do
	server *Server

	ctx caddy.Context
}

// CaddyModule returns the Caddy module information.
func (*PacketConnWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.packetconns.layer4",
		New: func() caddy.Module { return new(PacketConnWrapper) },
	}
}

// Provision sets up the PacketConnWrapper.
func (pcw *PacketConnWrapper) Provision(ctx caddy.Context) error {
	pcw.ctx = ctx

	if pcw.MatchingTimeout <= 0 {
		pcw.MatchingTimeout = caddy.Duration(MatchingTimeoutDefault)
	}

	err := pcw.Routes.Provision(ctx)
	if err != nil {
		return err
	}

	logger := ctx.Logger()

	pcw.server = &Server{
		logger:        logger,
		compiledRoute: pcw.Routes.Compile(logger, time.Duration(pcw.MatchingTimeout), packetConnHandler{}),
	}

	return nil
}

// WrapPacketConn wraps up a packet conn.
func (pcw *PacketConnWrapper) WrapPacketConn(pc net.PacketConn) net.PacketConn {
	pipe := make(chan *packet, 10)
	go func() {
		err := pcw.server.servePacket(&packetConnWithPipe{
			PacketConn: pc,
			packetPipe: pipe,
		})
		pipe <- &packet{
			err: err,
		}
		// server.servePacket will wait for all handling to finish before returning,
		// so it's safe to close the pipe here as no new value will be sent
		close(pipe)
	}()
	wpc := &wrappedPacketConn{
		pc:         pc,
		packetPipe: pipe,
	}
	// set the deadline to zero time to initialize the timer
	_ = wpc.SetReadDeadline(time.Time{})
	return wpc
}

// UnmarshalCaddyfile sets up the PacketConnWrapper from Caddyfile tokens. Syntax:
//
//	layer4 {
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
func (pcw *PacketConnWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	if err := ParseCaddyfileNestedRoutes(d, &pcw.Routes, &pcw.MatchingTimeout, nil); err != nil {
		return err
	}

	return nil
}

// packetConnHandler is a connection handler that unwraps the incoming connection to channel as a packet conn wrapper.
type packetConnHandler struct{}

func (packetConnHandler) Handle(conn *Connection) error {
	// perhaps an interface is better
	pc, ok := conn.Context.Value(connCtxKey).(*packetConn)
	if !ok {
		return errNotPacketConn
	}
	// impossible to be false, check nonetheless
	pcwp, ok := pc.PacketConn.(*packetConnWithPipe)
	if !ok {
		return errNotPacketConn
	}
	// get the first buffer to read, Read shouldn't be called on packetConn from now on
	var firstBuf []byte
	if len(conn.buf) > 0 && conn.offset < len(conn.buf) {
		switch {
		// data is fully consumed
		case pc.lastBuf == nil:
			firstBuf = conn.buf[conn.offset:]
		// data is partially consumed
		case pc.lastBuf != nil && pc.lastBuf.Len() > 0:
			// reuse matching buffer
			n := copy(conn.buf, conn.buf[conn.offset:])
			buf := bytes.NewBuffer(conn.buf[:n])
			_, _ = buf.ReadFrom(pc.lastBuf)

			// release last packet buffer
			udpBufPool.Put(pc.lastPacket.pooledBuf)
			pc.lastPacket = nil
			pc.lastBuf = nil

			firstBuf = buf.Bytes()
		}
	}

	// first use the buffer if any
	if len(firstBuf) > 0 {
		pcwp.packetPipe <- &packet{
			pooledBuf: firstBuf,
			n:         len(firstBuf),
			err:       nil,
			addr:      pc.addr,
		}
	}

	// pass the packet to the pipe
	// reuse the idle timer for idle timeout since Read isn't called anymore
	if pc.idleTimer == nil {
		pc.idleTimer = time.NewTimer(udpAssociationIdleTimeout)
	} else {
		pc.idleTimer.Reset(udpAssociationIdleTimeout)
	}
	for {
		select {
		case pkt := <-pc.readCh:
			pcwp.packetPipe <- pkt
			pc.idleTimer.Reset(udpAssociationIdleTimeout)
		case <-pc.idleTimer.C:
			return errHijacked
		}
	}
}

// packetConnWithPipe will send all the data it read to the channel from which the wrapper can receive
// typical udp data.
type packetConnWithPipe struct {
	net.PacketConn
	packetPipe chan *packet
}

type wrappedPacketConn struct {
	pc         net.PacketConn
	packetPipe chan *packet
	// stores time.Time as Unix as ReadFrom maybe called concurrently with SetReadDeadline
	deadline      atomic.Int64
	deadlineTimer *time.Timer
}

func (w *wrappedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// check deadline
	if isDeadlineExceeded(time.Unix(w.deadline.Load(), 0)) {
		return 0, nil, os.ErrDeadlineExceeded
	}
	for {
		select {
		case pkt := <-w.packetPipe:
			if pkt == nil {
				// Channel is closed. Return net.ErrClosed below.
				return 0, nil, net.ErrClosed
			}
			if pkt.err != nil {
				return 0, nil, pkt.err
			}
			n = copy(p, pkt.pooledBuf[:pkt.n])
			// discard the remaining data
			udpBufPool.Put(pkt.pooledBuf)
			return n, pkt.addr, nil
		case <-w.deadlineTimer.C:
			// deadline may change during the wait, recheck
			if isDeadlineExceeded(time.Unix(w.deadline.Load(), 0)) {
				return 0, nil, os.ErrDeadlineExceeded
			}
		}
	}
}

func (w *wrappedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return w.pc.WriteTo(p, addr)
}

func (w *wrappedPacketConn) Close() error {
	return w.pc.Close()
}

func (w *wrappedPacketConn) LocalAddr() net.Addr {
	return w.pc.LocalAddr()
}

func (w *wrappedPacketConn) SetDeadline(t time.Time) error {
	_ = w.SetReadDeadline(t)
	return w.pc.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline, it will reset the internal timer if already set.
// error will always be nil.
func (w *wrappedPacketConn) SetReadDeadline(t time.Time) error {
	w.deadline.Store(t.Unix())
	if w.deadlineTimer != nil {
		w.deadlineTimer.Reset(time.Until(t))
	} else {
		w.deadlineTimer = time.NewTimer(time.Until(t))
	}
	return nil
}

func (w *wrappedPacketConn) SetWriteDeadline(t time.Time) error {
	return w.pc.SetWriteDeadline(t)
}

var (
	errNotPacketConn = errors.New("no packetConn found in connection context")
	connCtxKey       = caddy.CtxKey("underlying_conn")
)

// Interface guards
var (
	_ caddy.Module            = (*PacketConnWrapper)(nil)
	_ caddy.PacketConnWrapper = (*PacketConnWrapper)(nil)
	_ caddyfile.Unmarshaler   = (*PacketConnWrapper)(nil)
)
