package layer4

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type testIoMatcher struct{}

func (*testIoMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.testIoMatcher",
		New: func() caddy.Module { return new(testIoMatcher) },
	}
}

func (m *testIoMatcher) Match(cx *Connection) (bool, error) {
	buf := make([]byte, 1)
	n, err := io.ReadFull(cx, buf)
	return n > 0, err
}

func TestMatchingTimeoutWorks(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	caddy.RegisterModule(&testIoMatcher{})

	routes := RouteList{&Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"testIoMatcher": json.RawMessage("{}")}, // any io using matcher
		},
	}}

	err := routes.Provision(ctx)
	if err != nil {
		t.Fatalf("provision failed | %s", err)
	}

	matched := false
	loggerCore, logs := observer.New(zapcore.WarnLevel)
	compiledRoutes := routes.Compile(zap.New(loggerCore), 5*time.Millisecond,
		HandlerFunc(func(con *Connection) error {
			matched = true
			return nil
		}))

	in, out := net.Pipe()
	defer func() { _ = in.Close() }()
	defer func() { _ = out.Close() }()

	cx := WrapConnection(out, []byte{}, zap.NewNop())
	defer func() { _ = cx.Close() }()

	err = compiledRoutes.Handle(cx)
	if err != nil {
		t.Fatalf("handle failed | %s", err)
	}

	// verify the matching aborted error was logged
	if logs.Len() != 1 {
		t.Fatalf("logs should contain 1 entry but has %d", logs.Len())
	}
	logEntry := logs.All()[0]
	if logEntry.Level != zapcore.WarnLevel {
		t.Fatalf("wrong log level | %s", logEntry.Level)
	}
	if logEntry.Message != "matching connection" {
		t.Fatalf("wrong log message | %s", logEntry.Message)
	}
	if !(logEntry.Context[1].Key == "error" && errors.Is(logEntry.Context[1].Interface.(error), ErrMatchingTimeout)) { //nolint:staticcheck
		t.Fatalf("wrong error | %v", logEntry.Context[1].Interface)
	}

	// since matching failed no handler should be called
	if matched {
		t.Fatal("handler was called but should not")
	}
}

// used to test the timeout of udp associations
type testIoUdpMatcher struct{}

func (*testIoUdpMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.testIoUdpMatcher",
		New: func() caddy.Module { return new(testIoUdpMatcher) },
	}
}

var (
	testConnection *Connection
	handlingDone   chan struct{}
)

func (m *testIoUdpMatcher) Match(cx *Connection) (bool, error) {
	// normally deadline exceeded error is handled during prefetch, and custom matcher can't
	// read more than what's prefetched, but it's a test.
	cx.matching = false
	buf := make([]byte, 10)
	n, err := io.ReadFull(cx, buf)
	if err != nil {
		cx.SetVar("time", time.Now())
		cx.SetVar("err", err)
		testConnection = cx
		close(handlingDone)
	}
	return n > 0, err
}

func TestMatchingTimeoutWorksUDP(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	caddy.RegisterModule(&testIoUdpMatcher{})

	routes := RouteList{&Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"testIoUdpMatcher": json.RawMessage("{}")}, // any io using matcher
		},
	}}

	err := routes.Provision(ctx)
	if err != nil {
		t.Fatalf("provision failed | %s", err)
	}

	matchingTimeout := time.Second

	compiledRoutes := routes.Compile(zap.NewNop(), matchingTimeout,
		HandlerFunc(func(con *Connection) error {
			return nil
		}))

	handlingDone = make(chan struct{})

	// Because udp is connectionless and every read can be from different addresses. A mapping between
	// addresses and data read is created. A virtual connection can only read data from a certain address.
	// Using real udp sockets and server to test timeout.
	// We can't wait for the handler to finish this way, but that is tested above.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen | %s", err)
	}
	defer func() { _ = pc.Close() }()

	server := new(Server)
	server.compiledRoute = compiledRoutes
	server.logger = zap.NewNop()
	go func() {
		_ = server.servePacket(pc)
	}()

	now := time.Now()

	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to dial | %s", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("failed to write | %s", err)
	}

	// only wait for the matcher to return
	<-handlingDone
	if !errors.Is(testConnection.GetVar("err").(error), os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded error but got %s", testConnection.GetVar("err"))
	}

	elapsed := testConnection.GetVar("time").(time.Time).Sub(now)
	if elapsed < matchingTimeout || elapsed > 2*matchingTimeout {
		t.Fatalf("timeout takes too long %s", elapsed)
	}
}
