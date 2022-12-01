package layer4

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
}

// ListenerWrapper is a Caddy module that wraps App as a listener wrapper, it doesn't support udp.
type ListenerWrapper struct {
	// Routes express composable logic for handling byte streams.
	Routes RouteList `json:"routes,omitempty"`

	compiledRoute Handler

	logger *zap.Logger
	ctx    caddy.Context
}

// CaddyModule returns the Caddy module information.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.layer4",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision sets up the ListenerWrapper.
func (lw *ListenerWrapper) Provision(ctx caddy.Context) error {
	lw.ctx = ctx
	lw.logger = ctx.Logger()

	err := lw.Routes.Provision(ctx)
	if err != nil {
		return err
	}
	lw.compiledRoute = lw.Routes.Compile(listenerHandler{}, lw.logger)

	return nil
}

func (lw *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	// TODO make channel capacity configurable
	connChan := make(chan net.Conn, runtime.GOMAXPROCS(0))
	li := &listener{
		Listener:      l,
		logger:        lw.logger,
		compiledRoute: lw.compiledRoute,
		connChan:      connChan,
		wg:            new(sync.WaitGroup),
	}
	go li.loop()
	return li
}

type listener struct {
	net.Listener
	logger        *zap.Logger
	compiledRoute Handler

	// closed when there is a non-recoverable error and all handle goroutines are done
	connChan chan net.Conn
	err      error

	// count running handles
	wg *sync.WaitGroup
}

// loop accept connection from underlying listener and pipe the connection if there are any
func (l *listener) loop() {
	for {
		conn, err := l.Listener.Accept()
		if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
			l.logger.Error("temporary error accepting connection", zap.Error(err))
			continue
		}
		if err != nil {
			l.err = err
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
	for conn := range l.connChan {
		conn.Close()
	}
}

// errHijacked is used when a handler takes over the connection, it's lifetime is not managed by handle
var errHijacked = errors.New("hijacked connection")

func (l *listener) handle(conn net.Conn) {
	var err error
	defer func() {
		l.wg.Done()
		if err != errHijacked {
			conn.Close()
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
	if err != nil && err != errHijacked {
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
	for conn := range l.connChan {
		return conn, nil
	}
	return nil, l.err

}

func (l *listener) pipeConnection(conn net.Conn) error {
	l.connChan <- conn
	return errHijacked
}

// Interface guards
var (
	_ caddy.Module          = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
)
