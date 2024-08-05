package layer4

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
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

func TestCompiledRouteTimeoutWorks(t *testing.T) {
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

	compiledRoutes := routes.Compile(zap.NewNop(), 5*time.Millisecond,
		NextHandlerFunc(func(con *Connection, next Handler) error {
			matched = true
			return next.Handle(con)
		}))

	in, out := net.Pipe()
	defer in.Close()
	defer out.Close()

	cx := WrapConnection(out, []byte{}, zap.NewNop())
	defer cx.Close()

	err = compiledRoutes.Handle(cx)
	if !errors.Is(err, ErrMatchingTimeout) {
		t.Fatalf("expected ErrMatchingTimeout but got  %s", err)
	}

	// since matching failed no handler should be called
	if matched {
		t.Fatal("handler was called but should not")
	}
}

type testFalseMatcher struct {
}

func (testFalseMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.testFalseMatcher",
		New: func() caddy.Module { return new(testFalseMatcher) },
	}
}

func (m *testFalseMatcher) Match(_ *Connection) (bool, error) {
	return false, nil
}

// See https://github.com/mholt/caddy-l4/pull/210
func TestCompiledRouteCallsFallbackIfNothingMatches(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	caddy.RegisterModule(testFalseMatcher{})

	routes := RouteList{&Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"testFalseMatcher": json.RawMessage("{}")}, // always false
		},
	}}

	err := routes.Provision(ctx)
	if err != nil {
		t.Fatalf("provision failed | %s", err)
	}

	fallbackWasCalled := false
	compiledRoute := routes.Compile(zap.NewNop(), 5*time.Millisecond,
		NextHandlerFunc(func(con *Connection, next Handler) error {
			fallbackWasCalled = true
			return nil
		}))

	in, out := net.Pipe()
	defer out.Close()

	cx := WrapConnection(out, []byte{}, zap.NewNop())
	defer cx.Close()

	go func() {
		_, _ = in.Write([]byte("Hi"))
		_ = in.Close()
	}()

	err = compiledRoute.Handle(cx)
	if err != nil {
		t.Fatalf("handle failed | %s", err)
	}

	if !fallbackWasCalled {
		t.Fatal("fallback handler was not called")
	}
}
