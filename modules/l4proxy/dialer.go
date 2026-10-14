package l4proxy

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
)

// A ContextDialer dials using a context.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func DefaultDialer() ContextDialer {
	return &net.Dialer{}
}

func dialWithLocalAddrs(ctx context.Context, dialer ContextDialer, localAddrs []net.Addr, network, addr string) (net.Conn, error) {
	if len(localAddrs) == 0 {
		return dialer.DialContext(ctx, network, addr)
	}

	// code below can only run if dial_via was NOT specified in the upstream
	// see (*Upstream).provision()

	var lastErr error
	for _, la := range localAddrs {
		d := &net.Dialer{LocalAddr: la}
		conn, err := d.Dial(network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func tlsDialWithLocalAddrs(ctx context.Context, dialer ContextDialer, localAddrs []net.Addr, network, addr string, cfg *tls.Config) (net.Conn, error) {

	rawConn, err := dialWithLocalAddrs(ctx, dialer, localAddrs, network, addr)

	if err != nil {
		return nil, err
	}

	// yoinked from tls.DialWithDialer

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if cfg.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := cfg.Clone()
		c.ServerName = hostname
		cfg = c
	}

	conn := tls.Client(rawConn, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}

	return conn, nil
}
