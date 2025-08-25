// Copyright 2024 VNXME
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

package l4regexp

import (
	"io"
	"regexp"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchRegexp{})
}

// MatchRegexp is able to match any connections with regular expressions.
type MatchRegexp struct {
	Count   uint16 `json:"count,omitempty"`
	Pattern string `json:"pattern,omitempty"`

	compiled *regexp.Regexp
}

// CaddyModule returns the Caddy module information.
func (m *MatchRegexp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.regexp",
		New: func() caddy.Module { return new(MatchRegexp) },
	}
}

// Match returns true if the connection bytes match the regular expression.
func (m *MatchRegexp) Match(cx *layer4.Connection) (bool, error) {
	// Read a number of bytes
	buf := make([]byte, m.Count)
	n, err := io.ReadFull(cx, buf)
	if err != nil || n < int(m.Count) {
		return false, err
	}

	// Match these bytes against the regular expression
	return m.compiled.Match(buf), nil
}

// Provision parses m's regular expression and sets m's minimum read bytes count.
func (m *MatchRegexp) Provision(_ caddy.Context) (err error) {
	repl := caddy.NewReplacer()
	if m.Count == 0 {
		m.Count = minCount
	}
	m.compiled, err = regexp.Compile(repl.ReplaceAll(m.Pattern, ""))
	if err != nil {
		return err
	}
	return nil
}

// UnmarshalCaddyfile sets up the MatchRegexp from Caddyfile tokens. Syntax:
//
//	regexp <pattern> [<count>]
func (m *MatchRegexp) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// One or two same-line argument must be provided
	if d.CountRemainingArgs() == 0 || d.CountRemainingArgs() > 2 {
		return d.ArgErr()
	}

	_, m.Pattern = d.NextArg(), d.Val()
	if d.NextArg() {
		val, err := strconv.ParseUint(d.Val(), 10, 16)
		if err != nil {
			return d.Errf("parsing %s count: %v", wrapper, err)
		}
		m.Count = uint16(val)
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed %s option: blocks are not supported", wrapper)
	}

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchRegexp)(nil)
	_ caddyfile.Unmarshaler = (*MatchRegexp)(nil)
	_ layer4.ConnMatcher    = (*MatchRegexp)(nil)
)

const (
	minCount uint16 = 4 // by default, read this many bytes to match against
)
