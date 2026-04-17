// Copyright (c) 2024 SICK AG
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

package l4remoteiplist

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&RemoteIPList{})
}

type RemoteIPList struct {
	RemoteIPFile string `json:"remote_ip_file"`

	logger       *zap.Logger
	remoteIPList *IPList
}

// CaddyModule returns the Caddy module information.
func (*RemoteIPList) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.remote_ip_list",
		New: func() caddy.Module { return new(RemoteIPList) },
	}
}

// Provision implements caddy.Provisioner.
func (m *RemoteIPList) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	remoteIPList, err := NewIPList(m.RemoteIPFile, ctx, m.logger)
	if err != nil {
		m.logger.Error("error creating a new IP list", zap.Error(err))
		return err
	}
	m.remoteIPList = remoteIPList
	m.remoteIPList.StartMonitoring()
	return nil
}

// The Match will return true if the remote IP is found in the remote IP list
func (m *RemoteIPList) Match(cx *layer4.Connection) (bool, error) {
	remoteIP, err := m.getRemoteIP(cx)
	if err != nil {
		// Error, tread IP as matched
		m.logger.Error("error parsing the remote IP from the connection", zap.Error(err))
		return true, err
	}

	// IP not matched
	m.logger.Debug("received request", zap.String("remote_addr", remoteIP.String()))

	if m.remoteIPList.IsMatched(remoteIP) {
		m.logger.Info("matched IP found", zap.String("remote_addr", remoteIP.String()))
		return true, nil
	}
	return false, nil
}

// Returns the remote IP address for a given layer4 connection.
// Same method as in layer4.MatchRemoteIP.getRemoteIP
func (m *RemoteIPList) getRemoteIP(cx *layer4.Connection) (netip.Addr, error) {
	remote := cx.Conn.RemoteAddr().String()

	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote
	}

	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid remote IP address: %s", ipStr)
	}
	return ip, nil
}

// UnmarshalCaddyfile sets up the ip_file from Caddyfile. Syntax:
//
// remote_ip_list <ip_file>
func (m *RemoteIPList) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Only one same-line argument is supported
	if d.CountRemainingArgs() > 1 {
		return d.ArgErr()
	}

	if d.NextArg() {
		m.RemoteIPFile = d.Val()
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed %s option: blocks are not supported", wrapper)
	}

	return nil
}

func (m *RemoteIPList) Cleanup() error {
	m.remoteIPList.StopMonitoring()
	return nil
}

// Interface guards
var (
	_ layer4.ConnMatcher    = (*RemoteIPList)(nil)
	_ caddy.Provisioner     = (*RemoteIPList)(nil)
	_ caddy.CleanerUpper    = (*RemoteIPList)(nil)
	_ caddyfile.Unmarshaler = (*RemoteIPList)(nil)
)
