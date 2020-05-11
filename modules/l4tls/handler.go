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

package l4tls

import (
	"crypto/tls"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a connection handler that terminates TLS.
type Handler struct {
	ConnectionPolicies caddytls.ConnectionPolicies `json:"connection_policies,omitempty"`

	config *tls.Config
	ctx    caddy.Context
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.tls",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the module.
func (t *Handler) Provision(ctx caddy.Context) error {
	t.ctx = ctx

	// ensure there is at least one policy, which will act as default
	if len(t.ConnectionPolicies) == 0 {
		t.ConnectionPolicies = append(t.ConnectionPolicies, new(caddytls.ConnectionPolicy))
	}

	err := t.ConnectionPolicies.Provision(ctx)
	if err != nil {
		return fmt.Errorf("setting up Handler connection policies: %v", err)
	}

	return nil
}

// Handle handles the connections.
func (t *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	// get the TLS config to use for this connection
	tlsCfg := t.ConnectionPolicies.TLSConfig(t.ctx)

	// if no prior matcher or handler read the ClientHello
	// yet, we'll prepare to do so
	clientHello, haveClientHello := cx.GetVar("tls_client_hello").(ClientHelloInfo)
	if !haveClientHello {
		underlyingGetConfigForClient := tlsCfg.GetConfigForClient
		tlsCfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHello.ClientHelloInfo = *hello
			return underlyingGetConfigForClient(hello)
		}
	}

	// terminate TLS by performing the handshake
	tlsConn := tls.Server(cx.Conn, tlsCfg)
	if !haveClientHello {
		err := tlsConn.Handshake()
		if err != nil {
			return err
		}
		cx.SetVar("tls_client_hello", clientHello)
	}

	// now all future reads/writes will be
	// decrypted/encrypted at this point
	cx.Conn = tlsConn

	return next.Handle(cx)
}

// Interface guards
var (
	_ caddy.Provisioner  = (*Handler)(nil)
	_ layer4.NextHandler = (*Handler)(nil)
)
