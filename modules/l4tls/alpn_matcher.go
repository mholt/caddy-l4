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
	"slices"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(&MatchALPN{})
}

type MatchALPN []string

// CaddyModule returns the Caddy module information.
func (*MatchALPN) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.handshake_match.alpn",
		New: func() caddy.Module { return new(MatchALPN) },
	}
}

func (m *MatchALPN) Match(hello *tls.ClientHelloInfo) bool {
	repl := caddy.NewReplacer()
	if ctx := hello.Context(); ctx != nil {
		// In some situations the existing context may have no replacer
		if replAny := ctx.Value(caddy.ReplacerCtxKey); replAny != nil {
			repl = replAny.(*caddy.Replacer)
		}
	}

	clientProtocols := hello.SupportedProtos
	for _, alpn := range *m {
		alpn = repl.ReplaceAll(alpn, "")
		if slices.Contains(clientProtocols, alpn) {
			return true
		}
	}
	return false
}

// UnmarshalCaddyfile sets up the MatchALPN from Caddyfile tokens. Syntax:
//
//	alpn <values...>
func (m *MatchALPN) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		wrapper := d.Val()

		// At least one same-line option must be provided
		if d.CountRemainingArgs() == 0 {
			return d.ArgErr()
		}

		*m = append(*m, d.RemainingArgs()...)

		// No blocks are supported
		if d.NextBlock(d.Nesting()) {
			return d.Errf("malformed TLS handshake matcher '%s': blocks are not supported", wrapper)
		}
	}

	return nil
}

// Interface guards
var (
	_ caddytls.ConnectionMatcher = (*MatchALPN)(nil)
	_ caddyfile.Unmarshaler      = (*MatchALPN)(nil)
)
