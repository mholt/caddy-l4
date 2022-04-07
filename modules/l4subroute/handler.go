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

package l4subroute

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements a handler that compiles and executes routes.
// This is useful for a batch of routes that all inherit the same
// matchers, or for multiple routes that should be treated as a
// single route.
type Handler struct {
	// The primary list of routes to compile and execute.
	Routes layer4.RouteList `json:"routes,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.subroute",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the module.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)

	if h.Routes != nil {
		err := h.Routes.Provision(ctx)
		if err != nil {
			return fmt.Errorf("setting up subroutes: %v", err)
		}
	}
	return nil
}

// Handle handles the connections.
func (h *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	subroute := h.Routes.Compile(next, h.logger)
	return subroute.Handle(cx)
}

// Interface guards
var (
	_ caddy.Provisioner  = (*Handler)(nil)
	_ layer4.NextHandler = (*Handler)(nil)
)
