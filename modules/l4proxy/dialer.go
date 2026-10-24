package l4proxy

import (
	"context"
	"net"
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
		if dialer == nil {
			return DefaultDialer().DialContext(ctx, network, addr)
		}
		return dialer.DialContext(ctx, network, addr)
	}

	// code below can only run if transport was NOT specified in the upstream
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
