package l4close

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&HandleClose{})
}

// HandleClose is able to close connections.
type HandleClose struct{}

// CaddyModule returns the Caddy module information.
func (*HandleClose) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.close",
		New: func() caddy.Module { return new(HandleClose) },
	}
}

// Handle handles the connection.
func (h *HandleClose) Handle(cx *layer4.Connection, _ layer4.Handler) error {
	return cx.Close()
}

// UnmarshalCaddyfile sets up the HandleClose from Caddyfile tokens. Syntax:
//
//	close
func (h *HandleClose) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed layer4 connection handler '%s': blocks are not supported", wrapper)
	}

	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*HandleClose)(nil)
	_ layer4.NextHandler    = (*HandleClose)(nil)
)
