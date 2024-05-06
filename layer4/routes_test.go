package layer4

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

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

	routes := RouteList{&Route{}}

	err := routes.Provision(ctx)
	if err != nil {
		t.Fatalf("provision failed | %s", err)
	}

	sentinel := &sentinelHandler{}
	compiledRoutes := routes.Compile(sentinel, zap.NewNop(), 5*time.Millisecond)

	in, out := net.Pipe()
	defer in.Close()
	defer out.Close()

	cx := WrapConnection(out, []byte{}, zap.NewNop())
	defer cx.Close()

	err = compiledRoutes.Handle(cx)
	if err == nil {
		t.Fatalf("missing error")
	}

	if !errors.Is(err, ErrMatchingTimeout) {
		t.Fatalf("unexpected handler error | %v", err)
	}

	// since matching failed no handler should be called
	if sentinel.Called != false {
		t.Fatal("sentinel handler was called but should not")
	}
}
