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

package l4proxy

import (
	"bufio"

	"github.com/caddyserver/caddy/v2"
	"github.com/mastercactapus/proxyprotocol"
	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(MatchPROXY{})
}

type MatchPROXY struct{}

// CaddyModule returns the Caddy module information.
func (MatchPROXY) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.PROXY",
		New: func() caddy.Module { return new(MatchPROXY) },
	}
}

// Match returns true if the connection looks like SSH.
func (m MatchPROXY) Match(cx *layer4.Connection) (bool, error) {
	_, err := proxyprotocol.Parse(bufio.NewReader(cx))
	if err != nil {
		return false, err
	}
	return true, nil
}

// Interface guard
var _ layer4.ConnMatcher = (*MatchPROXY)(nil)
