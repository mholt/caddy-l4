package layer4

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type testMatcher struct {
	Called bool
}

func (testMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.test",
		New: func() caddy.Module { return new(testMatcher) },
	}
}

func (*testMatcher) Provision(_ caddy.Context) (err error) {
	return nil
}

func (m *testMatcher) Match(cx *Connection) (bool, error) {
	m.Called = true
	buf := make([]byte, 1)
	_, err := cx.Read(buf)
	if err != nil {
		return false, err
	}
	return false, nil
}

type sentinelHandler struct {
	Called bool
}

func (h *sentinelHandler) Handle(_ *Connection) error {
	h.Called = true
	return nil
}

func TestMatchingTimeoutWorks(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	caddy.RegisterModule(testMatcher{})

	route := &Route{
		MatcherSetsRaw: []caddy.ModuleMap{
			{"test": json.RawMessage("{}")},
			{"test": json.RawMessage("{}")},
		},
	}
	routes := RouteList{route}

	err := routes.Provision(ctx)
	if err != nil {
		t.Fatalf("provision failed | %s", err)
	}

	// verify Provision sets a default value
	if route.MatchingTimeout <= 0 {
		t.Fatalf("matching timeout should have a default > 0 but got %v", route.MatchingTimeout)
	}
	// overwrite default with very short value for fast test
	route.MatchingTimeout = caddy.Duration(5 * time.Millisecond)

	sentinel := &sentinelHandler{}
	loggerCore, logs := observer.New(zapcore.ErrorLevel)
	compiledRoutes := routes.Compile(sentinel, zap.New(loggerCore))

	in, out := net.Pipe()
	defer in.Close()
	defer out.Close()

	cx := WrapConnection(out, []byte{}, zap.NewNop())
	defer cx.Close()

	err = compiledRoutes.Handle(cx)
	if err != nil {
		t.Fatalf("unexpected handler error | %v", err)
	}

	// verify the matching aborted error was logged
	if logs.Len() != 1 {
		t.Fatalf("logs should contain 1 entry but has %d", logs.Len())
	}
	logEntry := logs.All()[0]
	if logEntry.Level != zapcore.ErrorLevel {
		t.Fatalf("wrong log level | %s", logEntry.Level)
	}
	if logEntry.Message != "matching connection" {
		t.Fatalf("wrong log message | %s", logEntry.Message)
	}
	if !(logEntry.Context[1].Key == "error" && errors.Is(logEntry.Context[1].Interface.(error), ErrMatchingTimeout)) {
		t.Fatalf("wrong error | %v", logEntry.Context[1].Interface)
	}

	// 1st matcher was called but should produce a timeout error
	if route.matcherSets[0][0].(*testMatcher).Called != true {
		t.Fatal("test matcher 1 was not called but should")
	}

	// 2nd matcher should not be called because 1st matcher produced an error
	if route.matcherSets[1][0].(*testMatcher).Called != false {
		t.Fatal("test matcher 2 was called but should not")
	}

	// since matching failed no handler should be called
	if sentinel.Called != false {
		t.Fatal("sentinel handler was called but should not")
	}
}
