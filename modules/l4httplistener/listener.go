// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4httplistener

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a handler that can send connections to channels to simulate net.Listener that can be used for caddy http app.
type Handler struct {
	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.listener",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.ctx = ctx
	h.logger = ctx.Logger(h)
	return nil
}

// Handle handles the downstream connection.
func (h Handler) Handle(down *layer4.Connection, _ layer4.Handler) error {
	// TODO extract tls connection state to serve http2 when underlying conn qualifies
	//l4tls.GetConnectionStates(down)

	listener := down.Context.Value(layer4.ListenerCtxKey).(*layer4.Listener)
	select {
	case listener.ConnChan <- down:
		return layer4.ErrHijacked
	// listener already stopped accepting
	case <-listener.ErrChan:
		return nil
	}
}

// Interface guards
var (
	_ layer4.NextHandler = (*Handler)(nil)
	_ caddy.Provisioner  = (*Handler)(nil)
)
