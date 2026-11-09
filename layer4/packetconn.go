package layer4

import (
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/vnxme/hybrid"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&PacketConnWrapper{})
}

// PacketConnWrapper is a Caddy module that wraps App as a packet conn wrapper, it doesn't support tcp.
type PacketConnWrapper struct {
	// Routes express composable logic for handling byte streams.
	Routes RouteList `json:"routes,omitempty"`

	// Maximum time before packet connection association (by downstream address:port) is removed. Default: 30s.
	IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`
	// Maximum time connections have to complete the matching phase (the first terminal handler is matched). Default: 3s.
	MatchingTimeout caddy.Duration `json:"matching_timeout,omitempty"`

	compiledRoute Handler

	logger *zap.Logger
	ctx    caddy.Context
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
	pcw.logger = ctx.Logger()

	if pcw.IdleTimeout <= 0 {
		pcw.IdleTimeout = caddy.Duration(idleTimeoutDefault)
	}

	if pcw.MatchingTimeout <= 0 {
		pcw.MatchingTimeout = caddy.Duration(MatchingTimeoutDefault)
	}

	err := pcw.Routes.Provision(ctx)
	if err != nil {
		return err
	}
	// The flows no route matches are released in handle rather than by the last handler,
	// so that those failing to complete the matching phase are released as well
	pcw.compiledRoute = pcw.Routes.Compile(pcw.logger, time.Duration(pcw.MatchingTimeout), nopHandler{})

	return nil
}

// WrapPacketConn wraps up a packet conn: it splits pc into flows by downstream address:port, serves each flow
// with the routes, and returns the fallback connection, which serves the flows no route matches, e.g. to a QUIC
// server. Closing the returned connection stops serving pc, but leaves it open.
func (pcw *PacketConnWrapper) WrapPacketConn(pc net.PacketConn) net.PacketConn {
	// The splitter never closes pc, as its owner, e.g. Caddy, may not expect it closed more than once,
	// while closing pc makes the splitter stop on its own, with Accept returning the error that has stopped it.
	ln := hybrid.Split(hybrid.FakeClosePacketConn(pc, nil), &hybrid.SplitConfig{
		AcceptQueueSize: udpAcceptQueueSize,
		IdleTimeout:     time.Duration(pcw.IdleTimeout),
		ReadBufferSize:  udpBufSize,
		FallbackConn:    true,
		// Caddy closes pc on every shutdown, and a client gone makes a write fail,
		// so these errors aren't worth an error log
		ErrorFunc: func(err error) {
			pcw.logger.Debug("packet connection error",
				zap.String("network", pc.LocalAddr().Network()),
				zap.String("address", pc.LocalAddr().String()),
				zap.Error(err),
			)
		},
	})
	go pcw.serve(ln)
	// Closing the fallback connection stops the splitter, which interrupts its loops with deadlines rather than
	// by closing pc, and makes the fallback connection return the packets queued, then net.ErrClosed. A packet
	// longer than the buffer it's read into fails as a temporary error, which a QUIC server skips.
	return hybrid.FakeClosePacketConn(ln.Fallback(), ln.Stop)
}

// serve accepts the split connections of new flows until the splitter stops.
func (pcw *PacketConnWrapper) serve(ln hybrid.SplitListener) {
	pcw.logger.Debug("started wrapping packet connection",
		zap.String("network", ln.Addr().Network()),
		zap.String("address", ln.Addr().String()),
	)
	for {
		sc, err := ln.AcceptSplit()
		if err != nil {
			pcw.logger.Debug("packet connection drops",
				zap.String("network", ln.Addr().Network()),
				zap.String("address", ln.Addr().String()),
				zap.Any("drops", ln.Stats()),
			)
			pcw.logger.Debug("stopped wrapping packet connection",
				zap.String("network", ln.Addr().Network()),
				zap.String("address", ln.Addr().String()),
				zap.Error(err),
			)
			return
		}
		go pcw.handle(newPacketConn(sc))
	}
}

// handle serves a flow with the routes, and releases it to the fallback connection unless a route matches it.
func (pcw *PacketConnWrapper) handle(pc *packetConn) {
	defer func() { _ = pc.Close() }()

	buf := bufPool.Get().([]byte)
	buf = buf[:0]
	defer bufPool.Put(buf)

	cx := WrapConnection(pc, buf, pcw.logger)

	start := time.Now()
	err := pcw.compiledRoute.Handle(cx)
	duration := time.Since(start)
	if err != nil {
		pcw.logger.Error("handling connection",
			zap.String("remote", cx.RemoteAddr().String()),
			zap.Error(err),
		)
	}

	// No route has matched the flow, e.g. as no matcher has recognized it before the matching timeout,
	// so no handler has consumed its packets, which go to the fallback connection along with the rest
	if !cx.routed {
		if err = pc.release(cx.prefetchedPackets()); err != nil {
			pcw.logger.Error("releasing connection",
				zap.String("remote", cx.RemoteAddr().String()),
				zap.Error(err),
			)
			return
		}
		pcw.logger.Debug("released connection",
			zap.String("remote", cx.RemoteAddr().String()),
			zap.Uint64("read", cx.bytesRead),
			zap.Duration("duration", duration),
		)
		return
	}

	pcw.logger.Debug("connection stats",
		zap.String("remote", cx.RemoteAddr().String()),
		zap.Uint64("read", cx.bytesRead),
		zap.Uint64("written", cx.bytesWritten),
		zap.Duration("duration", duration),
	)
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

	if err := ParseCaddyfileNestedRoutes(d, &pcw.Routes, &pcw.MatchingTimeout, &pcw.IdleTimeout); err != nil {
		return err
	}

	return nil
}

// Interface guards
var (
	_ caddy.Module            = (*PacketConnWrapper)(nil)
	_ caddy.PacketConnWrapper = (*PacketConnWrapper)(nil)
	_ caddyfile.Unmarshaler   = (*PacketConnWrapper)(nil)
)
