// Copyright 2026 Ingolf Gehrhardt
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

// Package l4audit provides a connection handler that emits exactly one
// structured audit log record per connection — who connected, what they
// asked for, and the decision — and then continues the chain.
package l4audit

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&Handler{})
}

// Handler is a connection handler that emits one audit log record per
// connection it handles: who connected (remote), what they asked for
// (sni, when a TLS ClientHello is available in the connection's
// prefetched bytes) and the decision (verdict, a free-form label
// assigned by the config author).
//
// In a layer4 firewall every decision is a route, so placing this
// handler in a route labels that route's decision:
//
//	route @allowed {
//		audit allowed
//		proxy 10.0.3.14:443
//	}
//	route {
//		audit denied
//		proxy 127.0.0.1:9
//	}
//
// The handler is fully transparent: it only peeks at the prefetched
// bytes (never consuming them, so subsequent handlers still receive
// them), it never fails a connection because of audit parsing, and it
// always continues the chain. Records are written at INFO level to the
// logger named `layer4.handlers.audit`, which a log `include` filter
// can route to a dedicated audit sink.
type Handler struct {
	// Verdict is the label recorded in the audit record of every
	// connection, e.g. "allowed" or "denied". Any string is
	// accepted; the module assigns it no semantics.
	Verdict string `json:"verdict,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.audit",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h) // logger name: "layer4.handlers.audit"
	return nil
}

// Handle emits the audit record and continues the chain. It must never
// consume the prefetched bytes (see Connection.MatchingBytes) and never
// fail the connection because of audit parsing.
func (h *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	logger := h.logger
	if logger == nil {
		// Provision is normally called before Handle; fall back to
		// the connection's logger if it was not (e.g. in tests)
		logger = cx.Logger
	}

	fields := []zap.Field{
		zap.String("verdict", h.Verdict),
		zap.String("network", cx.LocalAddr().Network()),
		zap.String("local", cx.LocalAddr().String()),
		zap.String("remote", cx.RemoteAddr().String()),
	}
	if sni, ok := extractSNI(cx.MatchingBytes()); ok {
		if sni != "" {
			fields = append(fields, zap.String("sni", sni))
		}
	} else if logger.Core().Enabled(zap.DebugLevel) {
		logger.Debug("no TLS ClientHello found in prefetched bytes",
			zap.String("remote", cx.RemoteAddr().String()))
	}
	logger.Info("audit", fields...)

	return next.Handle(cx)
}

// UnmarshalCaddyfile sets up the Handler from Caddyfile tokens. Syntax:
//
//	audit <verdict>
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Exactly one argument (the verdict label) is required
	if !d.NextArg() {
		// a block opening is not an argument
		if d.NextBlock(d.Nesting()) {
			return d.Errf("malformed layer4 connection handler '%s': blocks are not supported", wrapper)
		}
		return d.Errf("malformed layer4 connection handler '%s': expected exactly one argument", wrapper)
	}
	h.Verdict = d.Val()

	// No further same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed layer4 connection handler '%s': blocks are not supported", wrapper)
	}

	return nil
}

// extractSNI parses the TLS ClientHello contained in buf — a
// non-consuming view of the connection's prefetched bytes — and
// returns the server name it carries, if any.
//
// The hello is parsed by the standard library, exactly like a real
// handshake would parse it: a crypto/tls server is run over the
// buffered bytes alone and the parsed hello is captured in
// GetConfigForClient before the handshake fails for lack of further
// data. All handshake errors are expected and ignored.
//
// ok is false if buf does not contain a complete ClientHello record
// (e.g. a non-TLS protocol, a truncated hello, or no prefetched
// bytes at all); the caller then omits the sni field. If ok is true,
// sni may still be empty (e.g. Encrypted Client Hello).
func extractSNI(buf []byte) (sni string, ok bool) {
	if len(buf) == 0 {
		return "", false
	}

	cfg := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni, ok = hello.ServerName, true
			return nil, nil
		},
	}

	// GetConfigForClient runs as soon as the ClientHello has been
	// parsed, which happens before the handshake needs any bytes
	// that are not in buf; the error returned afterwards is
	// therefore expected and ignored.
	conn := tls.Server(&bufferedConn{Reader: bytes.NewReader(buf), Writer: io.Discard}, cfg)
	_ = conn.Handshake()

	return sni, ok
}

// bufferedConn adapts a byte reader to net.Conn so that a crypto/tls
// server can parse a ClientHello out of buffered bytes alone. Writes
// are discarded and deadlines are no-ops, because all reads are served
// from memory and return immediately.
type bufferedConn struct {
	io.Reader
	io.Writer
}

func (bufferedConn) Close() error                     { return nil }
func (bufferedConn) LocalAddr() net.Addr              { return nil }
func (bufferedConn) RemoteAddr() net.Addr             { return nil }
func (bufferedConn) SetDeadline(time.Time) error      { return nil }
func (bufferedConn) SetReadDeadline(time.Time) error  { return nil }
func (bufferedConn) SetWriteDeadline(time.Time) error { return nil }

// Interface guards
var (
	_ caddy.Provisioner     = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ layer4.NextHandler    = (*Handler)(nil)
)
