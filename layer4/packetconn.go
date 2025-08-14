package layer4

import (
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
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

	if pcw.MatchingTimeout <= 0 {
		pcw.MatchingTimeout = caddy.Duration(MatchingTimeoutDefault)
	}

	err := pcw.Routes.Provision(ctx)
	if err != nil {
		return err
	}
	// TODO: replace listenerHandler with a similar structure compatible with packet conns
	pcw.compiledRoute = pcw.Routes.Compile(pcw.logger, time.Duration(pcw.MatchingTimeout), listenerHandler{})

	return nil
}

// WrapPacketConn wraps up a packet conn.
func (pcw *PacketConnWrapper) WrapPacketConn(pc net.PacketConn) net.PacketConn {
	// TODO: return a struct that implements net.PacketConn and spawn a goroutine to handle pcw.compiledRoute
	return pc
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

	if err := ParseCaddyfileNestedRoutes(d, &pcw.Routes, &pcw.MatchingTimeout); err != nil {
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
