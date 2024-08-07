package layer4

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"io"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type testIoMatcher struct {
}

func (testIoMatcher) CaddyModule() caddy.ModuleInfo {
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

	caddy.RegisterModule(testIoMatcher{})

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
	if !(logEntry.Context[1].Key == "error" && errors.Is(logEntry.Context[1].Interface.(error), ErrMatchingTimeout)) {
		t.Fatalf("wrong error | %v", logEntry.Context[1].Interface)
	}

	// since matching failed no handler should be called
	if matched {
		t.Fatal("handler was called but should not")
	}
}
