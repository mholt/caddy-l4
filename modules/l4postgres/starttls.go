// Copyright 2024 Matthew Holt
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

package l4postgres

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&Handler{})
}

// Handler negotiates the PostgreSQL SSLRequest preamble so that a following
// `tls` handler can terminate TLS and downstream matchers can then match the
// (now cleartext) startup message — e.g. by user, database, or
// application_name.
//
// PostgreSQL does not begin TLS with a ClientHello: the client first sends an
// 8-byte SSLRequest and waits for a single byte, 'S' (server will use TLS) or
// 'N' (continue in plaintext). The generic `tls` handler expects a ClientHello
// immediately, so it cannot terminate a Postgres connection on its own. This
// handler reads the SSLRequest, replies 'S', and passes the connection on; put
// a `tls` handler next to perform the actual TLS handshake.
//
// It must be preceded by a matcher that confirms the connection is a Postgres
// SSLRequest (e.g. the postgres matcher), so the 8 bytes it consumes really are
// the SSLRequest.
//
// Example (Caddyfile):
//
//	route {
//		postgres
//		postgres_starttls
//		tls
//		# downstream matchers now see the cleartext startup message
//		proxy ...
//	}
type Handler struct{}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.postgres_starttls",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Handle reads the SSLRequest, replies 'S', and hands off to the next handler.
func (h *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	var msg [minMessageLen]byte
	if _, err := io.ReadFull(cx, msg[:]); err != nil {
		return fmt.Errorf("reading Postgres SSLRequest: %v", err)
	}
	length := binary.BigEndian.Uint32(msg[:lenFieldSize])
	code := binary.BigEndian.Uint32(msg[lenFieldSize:])
	if length != minMessageLen || code != sslRequestCode {
		return fmt.Errorf("expected a Postgres SSLRequest (length 8, code %d); got length %d, code %d "+
			"(precede this handler with a matcher that confirms an SSLRequest)", sslRequestCode, length, code)
	}

	// Tell the client we will speak TLS; it then begins a standard TLS
	// handshake, which a following `tls` handler terminates.
	if _, err := cx.Write([]byte{'S'}); err != nil {
		return fmt.Errorf("replying 'S' to Postgres SSLRequest: %v", err)
	}

	return next.Handle(cx)
}

// UnmarshalCaddyfile sets up the Handler from Caddyfile tokens. Syntax:
//
//	postgres_starttls
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed %s handler: blocks are not supported", wrapper)
	}
	return nil
}

// Interface guards
var (
	_ layer4.NextHandler    = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
)
