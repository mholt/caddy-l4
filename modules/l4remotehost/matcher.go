// Copyright 2026 ChrisJr404
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

package l4remotehost

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchRemoteHost{})
}

// allow tests to stub the reverse DNS lookup
var lookupAddr = net.DefaultResolver.LookupAddr

// MatchRemoteHost matches connections by the remote host name, resolved from the
// remote IP via a reverse DNS (PTR) lookup. Host names may be given verbatim or as
// a wildcard like *.example.com, which matches any subdomain of example.com.
//
// A lookup happens on every connection this matcher inspects, so it is not free;
// keep it behind a cheaper matcher (or restrict the listener) when it sits in a
// hot path.
type MatchRemoteHost struct {
	Hosts []string `json:"hosts,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*MatchRemoteHost) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.remote_host",
		New: func() caddy.Module { return new(MatchRemoteHost) },
	}
}

// Provision prepares m's host names for matching.
func (m *MatchRemoteHost) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	for i, h := range m.Hosts {
		m.Hosts[i] = strings.ToLower(strings.TrimSuffix(h, "."))
	}
	return nil
}

// Match returns true if the remote host name matches one of the configured names.
func (m *MatchRemoteHost) Match(cx *layer4.Connection) (bool, error) {
	ipStr, err := remoteIP(cx)
	if err != nil {
		return false, err
	}

	reqCtx := cx.Context
	if reqCtx == nil {
		reqCtx = context.Background()
	}

	names, err := lookupAddr(reqCtx, ipStr)
	if err != nil {
		// A missing or failed PTR record just means this matcher doesn't apply.
		m.logger.Debug("reverse lookup failed", zap.String("remote_ip", ipStr), zap.Error(err))
		return false, nil
	}

	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		for _, host := range m.Hosts {
			if hostMatches(name, host) {
				return true, nil
			}
		}
	}
	return false, nil
}

// hostMatches reports whether name matches host, where host may be a *.suffix wildcard.
func hostMatches(name, host string) bool {
	if suffix, ok := strings.CutPrefix(host, "*."); ok {
		return strings.HasSuffix(name, "."+suffix)
	}
	return name == host
}

// remoteIP returns the remote IP of the connection as a string, without the port.
func remoteIP(cx *layer4.Connection) (string, error) {
	remote := cx.Conn.RemoteAddr().String()
	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote // OK; probably didn't have a port
	}
	if net.ParseIP(ipStr) == nil {
		return "", fmt.Errorf("invalid remote IP address: %s", ipStr)
	}
	return ipStr, nil
}

// UnmarshalCaddyfile sets up the MatchRemoteHost from Caddyfile tokens. Syntax:
//
//	remote_host <hosts...>
func (m *MatchRemoteHost) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// At least one same-line option must be provided
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}

	for d.NextArg() {
		m.Hosts = append(m.Hosts, d.Val())
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed layer4 connection matcher '%s': blocks are not supported", wrapper)
	}

	return nil
}

// Interface guards
var (
	_ caddy.Module          = (*MatchRemoteHost)(nil)
	_ layer4.ConnMatcher    = (*MatchRemoteHost)(nil)
	_ caddy.Provisioner     = (*MatchRemoteHost)(nil)
	_ caddyfile.Unmarshaler = (*MatchRemoteHost)(nil)
)
