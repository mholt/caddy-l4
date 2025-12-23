package layer4

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&ListenerWrapper{})
}

// ListenerWrapper is a Caddy module that wraps App as a listener wrapper, it doesn't support udp.
type ListenerWrapper struct {
	// Routes express composable logic for handling byte streams.
	Routes RouteList `json:"routes,omitempty"`

	// Maximum time connections have to complete the matching phase (the first terminal handler is matched). Default: 3s.
	MatchingTimeout caddy.Duration `json:"matching_timeout,omitempty"`

	compiledRoute Handler

	logger *zap.Logger
	ctx    caddy.Context
}

// CaddyModule returns the Caddy module information.
func (*ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.layer4",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision sets up the ListenerWrapper.
func (lw *ListenerWrapper) Provision(ctx caddy.Context) error {
	lw.ctx = ctx
	lw.logger = ctx.Logger()

	if lw.MatchingTimeout <= 0 {
		lw.MatchingTimeout = caddy.Duration(MatchingTimeoutDefault)
	}

	err := lw.Routes.Provision(ctx)
	if err != nil {
		return err
	}
	lw.compiledRoute = lw.Routes.Compile(lw.logger, time.Duration(lw.MatchingTimeout), listenerHandler{})

	return nil
}

func (lw *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	// TODO make channel capacity configurable
	connChan := make(chan net.Conn, runtime.GOMAXPROCS(0))
	li := &listener{
		Listener:      l,
		logger:        lw.logger,
		compiledRoute: lw.compiledRoute,
		done:          make(chan struct{}),
		connChan:      connChan,
		wg:            new(sync.WaitGroup),
	}
	go li.loop()
	return li
}

// UnmarshalCaddyfile sets up the ListenerWrapper from Caddyfile tokens. Syntax:
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
func (lw *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	if err := ParseCaddyfileNestedRoutes(d, &lw.Routes, &lw.MatchingTimeout, nil); err != nil {
		return err
	}

	return nil
}

type listener struct {
	net.Listener
	logger        *zap.Logger
	compiledRoute Handler

	closed atomic.Bool
	done   chan struct{}
	// closed when there is a non-recoverable error and all handle goroutines are done
	connChan chan net.Conn

	// count running handles
	wg *sync.WaitGroup
}

func (l *listener) Close() error {
	l.closed.Store(true)
	return l.Listener.Close()
}

// loop accept connection from underlying listener and pipe the connection if there are any
func (l *listener) loop() {
	for {
		conn, err := l.Listener.Accept()
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() && !l.closed.Load() {
			l.logger.Error("timeout accepting connection", zap.Error(err))
			continue
		}
		if err != nil {
			break
		}

		l.wg.Add(1)
		go l.handle(conn)
	}

	// closing remaining conns in channel to release resources
	go func() {
		l.wg.Wait()
		close(l.connChan)
	}()
	close(l.done)
	for conn := range l.connChan {
		_ = conn.Close()
	}
}

// errHijacked is used when a handler takes over the connection, it's lifetime is not managed by handle
var errHijacked = errors.New("hijacked connection")

func (l *listener) handle(conn net.Conn) {
	var err error
	defer func() {
		l.wg.Done()
		if !errors.Is(err, errHijacked) {
			_ = conn.Close()
		}
	}()

	buf := bufPool.Get().([]byte)
	buf = buf[:0]
	defer bufPool.Put(buf)

	cx := WrapConnection(conn, buf, l.logger)
	cx.Context = context.WithValue(cx.Context, listenerCtxKey, l)

	start := time.Now()
	err = l.compiledRoute.Handle(cx)
	duration := time.Since(start)
	if err != nil && !errors.Is(err, errHijacked) {
		l.logger.Error("handling connection", zap.Error(err))
	}

	l.logger.Debug("connection stats",
		zap.String("remote", cx.RemoteAddr().String()),
		zap.Uint64("read", cx.bytesRead),
		zap.Uint64("written", cx.bytesWritten),
		zap.Duration("duration", duration),
	)
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.connChan:
		if ok {
			return conn, nil
		}
		return nil, net.ErrClosed
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *listener) pipeConnection(conn *Connection) error {
	// can't use l4tls.GetConnectionStates because of import cycle
	// TODO export tls_connection_states as a special constant
	var connectionStates []*tls.ConnectionState
	if val := conn.GetVar("tls_connection_states"); val != nil {
		connectionStates = val.([]*tls.ConnectionState)
	}
	if len(connectionStates) > 0 {
		l.connChan <- &tlsConnection{
			Conn:      conn,
			connState: connectionStates[len(connectionStates)-1],
		}
	} else {
		l.connChan <- conn
	}
	return errHijacked
}

// tlsConnection implements ConnectionState interface to use it with h2
type tlsConnection struct {
	net.Conn
	connState *tls.ConnectionState
}

func (tc *tlsConnection) ConnectionState() tls.ConnectionState {
	return *tc.connState
}

// Interface guards
var (
	_ caddy.Module          = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)
