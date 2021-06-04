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
	"encoding/json"
	"fmt"
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MatchTLS{})
}

// MatchTLS is able to match TLS connections. Its structure
// is different from the auto-generated documentation. This
// value should be a map of matcher names to their values.
type MatchTLS struct {
	MatchersRaw caddy.ModuleMap `json:"-" caddy:"namespace=tls.handshake_match"`

	matchers []caddytls.ConnectionMatcher
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (MatchTLS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.tls",
		New: func() caddy.Module { return new(MatchTLS) },
	}
}

// UnmarshalJSON satisfies the json.Unmarshaler interface.
func (m *MatchTLS) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &m.MatchersRaw)
}

// MarshalJSON satisfies the json.Marshaler interface.
func (m MatchTLS) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.MatchersRaw)
}

// Provision sets up the handler.
func (m *MatchTLS) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	mods, err := ctx.LoadModule(m, "MatchersRaw")
	if err != nil {
		return fmt.Errorf("loading TLS matchers: %v", err)
	}
	for _, modIface := range mods.(map[string]interface{}) {
		m.matchers = append(m.matchers, modIface.(caddytls.ConnectionMatcher))
	}
	return nil
}

// Match returns true if the connection is a TLS handshake.
func (m MatchTLS) Match(cx *layer4.Connection) (bool, error) {
	// read the header bytes
	const recordHeaderLen = 5
	hdr := make([]byte, recordHeaderLen)
	_, err := io.ReadFull(cx, hdr)
	if err != nil {
		return false, err
	}

	const recordTypeHandshake = 0x16
	if hdr[0] != recordTypeHandshake {
		return false, nil
	}

	// get length of the ClientHello message and read it
	length := int(uint16(hdr[3])<<8 | uint16(hdr[4])) // ignoring version in hdr[1:3] - like https://github.com/inetaf/tcpproxy/blob/master/sni.go#L170
	rawHello := make([]byte, length)
	_, err = io.ReadFull(cx, rawHello)
	if err != nil {
		return false, err
	}

	// parse the ClientHello
	chi := parseRawClientHello(rawHello)
	chi.Conn = cx

	// also add values to the replacer
	repl := cx.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("l4.tls.server_name", chi.ClientHelloInfo.ServerName)
	repl.Set("l4.tls.version", chi.Version)

	for _, matcher := range m.matchers {
		// TODO: even though we have more data than the standard lib's
		// ClientHelloInfo lets us fill, the matcher modules we use do
		// not accept our own type; but the advantage of this is that
		// we can reuse TLS connection matchers from the tls app - but
		// it would be nice if we found a way to give matchers all
		// the infoz
		if !matcher.Match(&chi.ClientHelloInfo) {
			return false, nil
		}
	}

	m.logger.Debug("matched",
		zap.String("remote", cx.RemoteAddr().String()),
		zap.String("server_name", chi.ClientHelloInfo.ServerName),
	)

	return true, nil
}

// Interface guards
var (
	_ layer4.ConnMatcher = (*MatchTLS)(nil)
	_ caddy.Provisioner  = (*MatchTLS)(nil)
	_ json.Marshaler     = (*MatchTLS)(nil)
	_ json.Unmarshaler   = (*MatchTLS)(nil)
)
