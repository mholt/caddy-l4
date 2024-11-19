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

	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&RemoteIpList{})
}

type RemoteIpList struct {
	RemoteIpFile string `json:"ip_file"`

	logger       *zap.Logger
	remoteIpList *IpList
}

// CaddyModule returns the Caddy module information.
func (*RemoteIpList) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.remote_ip_list",
		New: func() caddy.Module { return new(RemoteIpList) },
	}
}

// Provision implements caddy.Provisioner.
func (m *RemoteIpList) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	remoteIpList, err := NewIpList(m.RemoteIpFile, &ctx, m.logger)
	if err != nil {
		m.logger.Error("error creating a new IP list", zap.Error(err))
		return err
	}
	m.remoteIpList = remoteIpList
	m.remoteIpList.StartMonitoring()
	return nil
}

// The Match will return true if the remote IP is found in the remote IP list
func (m *RemoteIpList) Match(cx *layer4.Connection) (bool, error) {
	remoteIP, err := m.getRemoteIP(cx)
	if err != nil {
		// Error, tread IP as matched
		m.logger.Error("error parsing the remote IP from the connection", zap.Error(err))
		return true, err
	}

	// IP not matched
	m.logger.Debug("received request", zap.String("remote_addr", remoteIP.String()))

	if m.remoteIpList.IsMatched(remoteIP) {
		m.logger.Info("matched IP found", zap.String("remote_addr", remoteIP.String()))
		return true, nil
	}
	return false, nil
}

// Returns the remote IP address for a given layer4 connection.
// Same method as in layer4.MatchRemoteIP.getRemoteIP
func (m *RemoteIpList) getRemoteIP(cx *layer4.Connection) (netip.Addr, error) {
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
func (m *RemoteIpList) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Only one same-line argument is supported
	if d.CountRemainingArgs() > 1 {
		return d.ArgErr()
	}

	if d.NextArg() {
		m.RemoteIpFile = d.Val()
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed %s option: blocks are not supported", wrapper)
	}

	return nil
}

// Interface guards
var (
	_ layer4.ConnMatcher    = (*RemoteIpList)(nil)
	_ caddy.Provisioner     = (*RemoteIpList)(nil)
	_ caddyfile.Unmarshaler = (*RemoteIpList)(nil)
)
