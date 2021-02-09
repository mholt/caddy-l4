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

package l4ssh

import (
	"bytes"
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(MatchSSH{})
}

// MatchSSH is able to match SSH connections.
type MatchSSH struct{}

// CaddyModule returns the Caddy module information.
func (MatchSSH) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.ssh",
		New: func() caddy.Module { return new(MatchSSH) },
	}
}

// Match returns true if the connection looks like SSH.
func (m MatchSSH) Match(cx *layer4.Connection) (bool, error) {
	p := make([]byte, len(sshPrefix))
	n, err := io.ReadFull(cx, p)
	if err != nil || n < len(sshPrefix) {
		return false, nil
	}
	return bytes.Equal(p, sshPrefix), nil
}

var sshPrefix = []byte("SSH-")

// Interface guard
var _ layer4.ConnMatcher = (*MatchSSH)(nil)
