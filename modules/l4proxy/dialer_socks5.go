package l4proxy

import (
	"context"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.org/x/net/proxy"
)

var (
	_ ContextDialer         = (*SOCKS5Dialer)(nil)
	_ caddy.CleanerUpper    = (*SOCKS5Dialer)(nil)
	_ caddy.Provisioner     = (*SOCKS5Dialer)(nil)
	_ caddyfile.Unmarshaler = (*SOCKS5Dialer)(nil)
)

type SOCKS5Dialer struct {
	dialer proxy.ContextDialer
}

// CaddyModule returns the Caddy module information.
func (*SOCKS5Dialer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.proxy.upstream.dial_via.socks5",
		New: func() caddy.Module { return new(SOCKS5Dialer) },
	}
}

// DialContext implements [ContextDialer].
func (s *SOCKS5Dialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	return s.dialer.DialContext(ctx, network, address)
}

// UnmarshalCaddyfile implements [caddyfile.Unmarshaler].
func (s *SOCKS5Dialer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// tbd
	return nil
}

// Provision implements [caddy.Provisioner].
func (s *SOCKS5Dialer) Provision(caddy.Context) error {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, &net.Dialer{Timeout: 10 * time.Second})

	if err != nil {
		return err
	}

	s.dialer = dialer.(proxy.ContextDialer)

	return nil
}

// Cleanup implements [caddy.CleanerUpper].
func (s *SOCKS5Dialer) Cleanup() error {
	return nil
}
