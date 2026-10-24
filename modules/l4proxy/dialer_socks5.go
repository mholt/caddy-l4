package l4proxy

import (
	"context"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"
)

func init() {
	caddy.RegisterModule(&SOCKS5Dialer{})
}

type SOCKS5Dialer struct {
	logger        *zap.Logger
	dialer        proxy.ContextDialer
	ServerAddress string
}

// CaddyModule returns the Caddy module information.
func (*SOCKS5Dialer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.proxy.upstream.transport.socks5",
		New: func() caddy.Module { return new(SOCKS5Dialer) },
	}
}

// DialContext implements [ContextDialer].
func (s *SOCKS5Dialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	s.logger.Debug("dialing through socks5",
		zap.String("upstream_network", network),
		zap.String("upstream", address),
		zap.String("socks_server", s.ServerAddress))

	return s.dialer.DialContext(ctx, network, address)
}

// UnmarshalCaddyfile implements [caddyfile.Unmarshaler].
func (s *SOCKS5Dialer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.NextArg()

	if !d.NextArg() {
		return d.ArgErr()
	}

	s.ServerAddress = d.Val()

	return nil
}

// Provision implements [caddy.Provisioner].
func (s *SOCKS5Dialer) Provision(c caddy.Context) error {
	s.logger = c.Logger(s)
	dialer, err := proxy.SOCKS5("tcp", s.ServerAddress, nil, &net.Dialer{Timeout: 10 * time.Second})

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

var (
	_ ContextDialer         = (*SOCKS5Dialer)(nil)
	_ caddy.CleanerUpper    = (*SOCKS5Dialer)(nil)
	_ caddy.Provisioner     = (*SOCKS5Dialer)(nil)
	_ caddyfile.Unmarshaler = (*SOCKS5Dialer)(nil)
)
