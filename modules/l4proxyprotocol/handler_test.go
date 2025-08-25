package l4proxyprotocol

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func assertString(t *testing.T, expected string, value string) {
	t.Helper()
	if value != expected {
		t.Fatalf("Expected '%s' but got '%s'\n", expected, value)
	}
}

func TestProxyProtocolHandleV1(t *testing.T) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	cx := layer4.WrapConnection(in, []byte{}, zap.NewNop())
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = out.Close() }()
		_, err := out.Write(ProxyV1Example)
		assertNoError(t, err)
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := Handler{}
	err := handler.Provision(ctx)
	assertNoError(t, err)

	var nextCx *layer4.Connection
	err = handler.Handle(cx, layer4.HandlerFunc(func(c *layer4.Connection) error {
		nextCx = c
		return nil
	}))
	assertNoError(t, err)

	if nextCx == nil {
		t.Fatalf("handler did not call next")
	}

	assertString(t, "192.168.0.1:56324", nextCx.RemoteAddr().String())
	assertString(t, "192.168.0.11:443", nextCx.LocalAddr().String())

	_, _ = io.Copy(io.Discard, in)
}

func TestProxyProtocolHandleV2(t *testing.T) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	cx := layer4.WrapConnection(in, []byte{}, zap.NewNop())
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = out.Close() }()
		_, err := out.Write(ProxyV2Example)
		assertNoError(t, err)
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := Handler{}
	err := handler.Provision(ctx)
	assertNoError(t, err)

	var nextCx *layer4.Connection
	err = handler.Handle(cx, layer4.HandlerFunc(func(c *layer4.Connection) error {
		nextCx = c
		return nil
	}))
	assertNoError(t, err)

	if nextCx == nil {
		t.Fatalf("handler did not call next")
	}

	assertString(t, "127.0.0.1:47111", nextCx.RemoteAddr().String())
	assertString(t, "127.0.0.1:443", nextCx.LocalAddr().String())

	_, _ = io.Copy(io.Discard, in)
}

func TestProxyProtocolHandleGarbage(t *testing.T) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	cx := layer4.WrapConnection(in, []byte{}, zap.NewNop())
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = out.Close() }()
		_, err := out.Write([]byte("some garbage"))
		assertNoError(t, err)
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := Handler{}
	err := handler.Provision(ctx)
	assertNoError(t, err)

	var nextCx *layer4.Connection
	err = handler.Handle(cx, layer4.HandlerFunc(func(c *layer4.Connection) error {
		nextCx = c
		return nil
	}))
	if err == nil || err.Error() != "parsing the PROXY header: invalid signature" {
		t.Fatalf("handler did not return an error or the wrong error -> %s", err)
	}

	if nextCx != nil {
		t.Fatalf("handler did call next")
	}

	_, _ = io.Copy(io.Discard, in)
}
