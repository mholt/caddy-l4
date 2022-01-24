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

package l4proxyprotocol

import (
	"fmt"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mastercactapus/proxyprotocol"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a connection handler that accepts the PROXY protocol.
type Handler struct {
	// How long to wait for the PROXY protocol header to be received (default 5s).
	Timeout caddy.Duration `json:"timeout,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.proxy_protocol",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the module.
func (h *Handler) Provision(ctx caddy.Context) error {
	if h.Timeout == 0 {
		h.Timeout = caddy.Duration(5 * time.Second)
	}

	h.logger = ctx.Logger(h)
	return nil
}

// Handle handles the connections.
func (h *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	var deadline time.Time
	if h.Timeout != 0 {
		deadline = time.Now().Add(time.Duration(h.Timeout))
	}
	conn := proxyprotocol.NewConn(cx, deadline)

	if _, err := conn.ProxyHeader(); err != nil {
		return fmt.Errorf("parsing the PROXY protocol header: %v", err)
	}
	h.logger.Debug("received the PROXY protocol header",
		zap.String("remote", conn.RemoteAddr().String()),
		zap.String("local", conn.LocalAddr().String()),
	)

	// Set conn as a custom variable on cx.
	cx.SetVar("l4.proxy_protocol.conn", conn)

	return next.Handle(cx.Wrap(conn))
}

// GetConn gets the connection which holds the information received from the PROXY protocol.
func GetConn(cx *layer4.Connection) net.Conn {
	if val := cx.GetVar("l4.proxy_protocol.conn"); val != nil {
		return val.(net.Conn)
	}
	return cx.Conn
}

// Interface guards
var (
	_ caddy.Provisioner  = (*Handler)(nil)
	_ layer4.NextHandler = (*Handler)(nil)
)
