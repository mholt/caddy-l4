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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(MatchALPN{})
}

type MatchALPN []string

// CaddyModule returns the Caddy module information.
func (MatchALPN) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.handshake_match.alpn",
		New: func() caddy.Module { return new(MatchALPN) },
	}
}

func (m MatchALPN) Match(hello *tls.ClientHelloInfo) bool {
	clientProtocols := hello.SupportedProtos
	for _, alpn := range m {
		for _, clientProtocol := range clientProtocols {
			if alpn == string(clientProtocol) {
				return true
			}
		}
	}
	return false
}

// Interface guards
var (
	_ caddytls.ConnectionMatcher = (*MatchALPN)(nil)
)
