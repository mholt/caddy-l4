// Copyright 2021 contrun
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

package l4proxyprotocol

import (
	"errors"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mastercactapus/proxyprotocol"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MatchPROXYProtocol{})
}

// MatchPROXYProtocol is able to match PROXY protocol connections.
type MatchPROXYProtocol struct {
	// Note by default, we allow all client ips.
	AllowedRanges []string `json:"allowed_ranges,omitempty"`

	allowedSubnets []*net.IPNet
	logger         *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (MatchPROXYProtocol) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.proxyprotocol",
		New: func() caddy.Module { return new(MatchPROXYProtocol) },
	}
}

func (m MatchPROXYProtocol) isIPAllowed(ip net.IP) bool {
	if len(m.allowedSubnets) == 0 {
		return true
	}
	for _, n := range m.allowedSubnets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Provision sets up the module.
func (t *MatchPROXYProtocol) Provision(ctx caddy.Context) error {
	t.logger = ctx.Logger(t)
	cidrs, err := layer4.GetCIDRsFromStrings(t.AllowedRanges)
	if err != nil {
		return err
	}
	t.allowedSubnets = cidrs
	return nil
}

// Match returns true if the connection is a PROXY protocol handshake.
// Then saves the terminated proxy protocol to `terminated_proxy_connection`.
func (m MatchPROXYProtocol) Match(cx *layer4.Connection) (bool, error) {
	// We use `cx.Conn` instead of `cx` here as proxyprotocol already only peeks into the packet.
	conn := proxyprotocol.NewConn(cx, time.Time{})
	// TODO: Figure out if this call will block when there is not enough data.
	_, err := conn.ProxyHeader()
	if err != nil {
		m.logger.Debug("matching PROXY protocol", zap.Error(err))
		var headerErr *proxyprotocol.InvalidHeaderErr
		if errors.As(err, &headerErr) {
			return false, nil
		}
		return false, err
	}

	clientIP, err := layer4.GetClientIP(cx)
	if err != nil {
		return false, err
	}
	if m.isIPAllowed(clientIP) {
		m.logger.Debug("matched PROXY protocol", zap.String("clientIP", clientIP.String()))
		cx.SetVar("terminated_proxy_connection", conn)
		return true, nil
	}

	return false, nil
}

// Interface guards
var (
	_ layer4.ConnMatcher = (*MatchPROXYProtocol)(nil)
	_ caddy.Provisioner  = (*MatchPROXYProtocol)(nil)
)
