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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchTLS{})
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
func (*MatchTLS) CaddyModule() caddy.ModuleInfo {
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
func (m *MatchTLS) MarshalJSON() ([]byte, error) {
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
func (m *MatchTLS) Match(cx *layer4.Connection) (bool, error) {
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

// UnmarshalCaddyfile sets up the MatchTLS from Caddyfile tokens. Syntax:
//
//	tls {
//		matcher [<args...>]
//		matcher [<args...>]
//	}
//	tls matcher [<args...>]
//	tls
func (m *MatchTLS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	matcherSet, err := ParseCaddyfileNestedMatcherSet(d)
	if err != nil {
		return err
	}
	m.MatchersRaw = matcherSet

	return nil
}

// Interface guards
var (
	_ layer4.ConnMatcher    = (*MatchTLS)(nil)
	_ caddy.Provisioner     = (*MatchTLS)(nil)
	_ caddyfile.Unmarshaler = (*MatchTLS)(nil)
	_ json.Marshaler        = (*MatchTLS)(nil)
	_ json.Unmarshaler      = (*MatchTLS)(nil)
)

// ParseCaddyfileNestedMatcherSet parses the Caddyfile tokens for a nested
// matcher set, and returns its raw module map value.
func ParseCaddyfileNestedMatcherSet(d *caddyfile.Dispenser) (caddy.ModuleMap, error) {
	matcherMap := make(map[string]caddytls.ConnectionMatcher)

	tokensByMatcherName := make(map[string][]caddyfile.Token)
	for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
		matcherName := d.Val()
		tokensByMatcherName[matcherName] = append(tokensByMatcherName[matcherName], d.NextSegment()...)
	}

	for matcherName, tokens := range tokensByMatcherName {
		dd := caddyfile.NewDispenser(tokens)
		dd.Next() // consume wrapper name
		// TODO: delete this workaround when the corresponding matchers implement caddyfile.Unmarshaler interface
		if matcherName == "local_ip" {
			cm, err := unmarshalCaddyfileMatchLocalIP(dd.NewFromNextSegment())
			if err != nil {
				return nil, err
			}
			matcherMap[matcherName] = cm
		} else if matcherName == "remote_ip" {
			cm, err := unmarshalCaddyfileMatchRemoteIP(dd.NewFromNextSegment())
			if err != nil {
				return nil, err
			}
			matcherMap[matcherName] = cm
		} else if matcherName == "sni" {
			cm, err := unmarshalCaddyfileMatchServerName(dd.NewFromNextSegment())
			if err != nil {
				return nil, err
			}
			matcherMap[matcherName] = cm
		} else {
			mod, err := caddy.GetModule("tls.handshake_match." + matcherName)
			if err != nil {
				return nil, d.Errf("getting matcher module '%s': %v", matcherName, err)
			}
			unm, ok := mod.New().(caddyfile.Unmarshaler)
			if !ok {
				return nil, d.Errf("matcher module '%s' is not a Caddyfile unmarshaler", matcherName)
			}
			err = unm.UnmarshalCaddyfile(dd.NewFromNextSegment())
			if err != nil {
				return nil, err
			}
			cm, ok := unm.(caddytls.ConnectionMatcher)
			if !ok {
				return nil, fmt.Errorf("matcher module '%s' is not a connection matcher", matcherName)
			}
			matcherMap[matcherName] = cm
		}
	}

	matcherSet := make(caddy.ModuleMap)
	for name, matcher := range matcherMap {
		jsonBytes, err := json.Marshal(matcher)
		if err != nil {
			return nil, fmt.Errorf("marshaling %T matcher: %v", matcher, err)
		}
		matcherSet[name] = jsonBytes
	}

	return matcherSet, nil
}

// TODO: move to https://github.com/caddyserver/caddy/tree/master/modules/caddytls/matchers.go
// unmarshalCaddyfileMatchLocalIP sets up the MatchLocalIP from Caddyfile tokens. Syntax:
//
//	local_ip <ranges...>
func unmarshalCaddyfileMatchLocalIP(d *caddyfile.Dispenser) (*caddytls.MatchLocalIP, error) {
	m := caddytls.MatchLocalIP{}

	for d.Next() {
		wrapper := d.Val()

		// At least one same-line option must be provided
		if d.CountRemainingArgs() == 0 {
			return nil, d.ArgErr()
		}

		prefixes, err := layer4.ParseNetworks(d.RemainingArgs())
		if err != nil {
			return nil, err
		}
		for _, prefix := range prefixes {
			m.Ranges = append(m.Ranges, prefix.String())
		}

		// No blocks are supported
		if d.NextBlock(d.Nesting()) {
			return nil, d.Errf("malformed TLS handshake matcher '%s': blocks are not supported", wrapper)
		}
	}

	return &m, nil
}

// TODO: move to https://github.com/caddyserver/caddy/tree/master/modules/caddytls/matchers.go
// unmarshalCaddyfileMatchRemoteIP sets up the MatchRemoteIP from Caddyfile tokens. Syntax:
//
//	remote_ip <ranges...>
//
// Note: IPs and CIDRs starting with ! symbol are treated as not_ranges
func unmarshalCaddyfileMatchRemoteIP(d *caddyfile.Dispenser) (*caddytls.MatchRemoteIP, error) {
	m := caddytls.MatchRemoteIP{}

	for d.Next() {
		wrapper := d.Val()

		// At least one same-line option must be provided
		if d.CountRemainingArgs() == 0 {
			return nil, d.ArgErr()
		}

		rangesRaw, notRangesRaw := make([]string, 0, d.CountRemainingArgs()), make([]string, 0, d.CountRemainingArgs())
		for d.NextArg() {
			val := d.Val()
			if len(val) > 1 && val[0] == '!' {
				notRangesRaw = append(notRangesRaw, val[1:])
			} else {
				rangesRaw = append(rangesRaw, val)
			}
		}

		prefixes, err := layer4.ParseNetworks(rangesRaw)
		if err != nil {
			return nil, err
		}
		for _, prefix := range prefixes {
			m.Ranges = append(m.Ranges, prefix.String())
		}

		notPrefixes, err := layer4.ParseNetworks(notRangesRaw)
		if err != nil {
			return nil, err
		}
		for _, notPrefix := range notPrefixes {
			m.NotRanges = append(m.NotRanges, notPrefix.String())
		}

		// No blocks are supported
		if d.NextBlock(d.Nesting()) {
			return nil, d.Errf("malformed TLS handshake matcher '%s': blocks are not supported", wrapper)
		}
	}

	return &m, nil
}

// TODO: move to https://github.com/caddyserver/caddy/tree/master/modules/caddytls/matchers.go
// unmarshalCaddyfileMatchServerName sets up the MatchServerName from Caddyfile tokens. Syntax:
//
//	sni <domains...>
func unmarshalCaddyfileMatchServerName(d *caddyfile.Dispenser) (*caddytls.MatchServerName, error) {
	m := caddytls.MatchServerName{}

	for d.Next() {
		wrapper := d.Val()

		// At least one same-line option must be provided
		if d.CountRemainingArgs() == 0 {
			return nil, d.ArgErr()
		}

		m = append(m, d.RemainingArgs()...)

		// No blocks are supported
		if d.NextBlock(d.Nesting()) {
			return nil, d.Errf("malformed TLS handshake matcher '%s': blocks are not supported", wrapper)
		}
	}

	return &m, nil
}
