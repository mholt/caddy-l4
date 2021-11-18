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

package l4xmpp

import (
	"io"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(MatchXMPP{})
}

// MatchXMPP is able to match XMPP connections.
type MatchXMPP struct{}

// CaddyModule returns the Caddy module information.
func (MatchXMPP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.xmpp",
		New: func() caddy.Module { return new(MatchXMPP) },
	}
}

// Match returns true if the connection looks like XMPP.
func (m MatchXMPP) Match(cx *layer4.Connection) (bool, error) {
	p := make([]byte, minXmppLength)
	n, err := io.ReadFull(cx, p)
	if err != nil || n < minXmppLength { // needs at least 50 (fix for adium/pidgin)
		return false, nil
	}
	return strings.Contains(string(p), xmppWord), nil
}

var xmppWord = "jabber"
var minXmppLength = 50

// Interface guard
var _ layer4.ConnMatcher = (*MatchXMPP)(nil)
