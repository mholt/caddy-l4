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
	"encoding/hex"
	"io"
	"regexp"
	"strconv"
	"strings"

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
	Hex     bool   `json:"hex,omitempty"`
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

	// When the hex option is enabled, match the regular expression against an
	// uppercase hexadecimal representation of the bytes. This makes it possible
	// to match byte sequences that aren't valid UTF-8, at the cost of the extra
	// conversion. Otherwise, match the raw bytes as-is.
	if m.Hex {
		return m.compiled.MatchString(strings.ToUpper(hex.EncodeToString(buf))), nil
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
//	regexp <pattern> [<count>] [hex]
//
// The optional count and hex arguments may appear in any order. When hex is
// present, the pattern is matched against an uppercase hexadecimal
// representation of the bytes instead of the raw bytes.
func (m *MatchRegexp) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// One to three same-line arguments must be provided
	if d.CountRemainingArgs() == 0 || d.CountRemainingArgs() > 3 {
		return d.ArgErr()
	}

	_, m.Pattern = d.NextArg(), d.Val()
	hasCount := false
	for d.NextArg() {
		val := d.Val()
		if val == hexOption {
			if m.Hex {
				return d.Errf("duplicate %s %s option", wrapper, hexOption)
			}
			m.Hex = true
			continue
		}
		if hasCount {
			return d.Errf("malformed %s option: unexpected argument %q", wrapper, val)
		}
		count, err := strconv.ParseUint(val, 10, 16)
		if err != nil {
			return d.Errf("parsing %s count: %v", wrapper, err)
		}
		m.Count, hasCount = uint16(count), true
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
	hexOption = "hex" // enables matching against a hexadecimal representation of the bytes

	minCount uint16 = 4 // by default, read this many bytes to match against
)
