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

package l4proxyprotocol

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mastercactapus/proxyprotocol"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a connection handler that accepts the PROXY protocol.
type Handler struct {
	// How long to wait for the PROXY protocol header to be received.
	// Defaults to zero, which means timeout is disabled.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// An optional list of CIDR ranges to allow/require PROXY headers from.
	Allow []string `json:"allow,omitempty"`

	rules  []proxyprotocol.Rule
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.proxy_protocol",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the module.
func (h *Handler) Provision(ctx caddy.Context) error {
	for _, s := range h.Allow {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("invalid subnet '%s': %w", s, err)
		}
		h.rules = append(h.rules, proxyprotocol.Rule{Timeout: time.Duration(h.Timeout), Subnet: n})
	}
	h.tidyRules()

	h.logger = ctx.Logger(h)
	return nil
}

// tidyRules removes duplicate subnet rules, and use the lowest non-zero timeout.
//
// This is basically a copy of `Listener.SetFilter` from the proxyprotocol package.
func (h *Handler) tidyRules() {
	rules := h.rules
	sort.Slice(rules, func(i, j int) bool {
		iOnes, iBits := rules[i].Subnet.Mask.Size()
		jOnes, jBits := rules[j].Subnet.Mask.Size()
		if iOnes != jOnes {
			return iOnes > jOnes
		}
		if iBits != jBits {
			return iBits > jBits
		}
		if rules[i].Timeout != rules[j].Timeout {
			if rules[j].Timeout == 0 {
				return true
			}
			return rules[i].Timeout < rules[j].Timeout
		}
		return rules[i].Timeout < rules[j].Timeout
	})

	if len(rules) > 0 {
		// dedup
		last := rules[0]
		nf := rules[1:1]
		for _, f := range rules[1:] {
			if last.Subnet.String() == f.Subnet.String() {
				continue
			}

			last = f
			nf = append(nf, f)
		}
	}
}

// newConn creates a new connection which will handle the PROXY protocol. It
// will return nil if the remote IP does not match the allowable CIDR ranges.
//
// This is basically a copy of `Listener.Accept` from the proxyprotocol package.
func (h *Handler) newConn(cx *layer4.Connection) *proxyprotocol.Conn {
	nc := func(t time.Duration) *proxyprotocol.Conn {
		if t == 0 {
			return proxyprotocol.NewConn(cx, time.Time{})
		}
		return proxyprotocol.NewConn(cx, time.Now().Add(t))
	}

	if len(h.rules) == 0 {
		return nc(time.Duration(h.Timeout))
	}

	var remoteIP net.IP
	switch r := cx.RemoteAddr().(type) {
	case *net.TCPAddr:
		remoteIP = r.IP
	case *net.UDPAddr:
		remoteIP = r.IP
	default:
		return nil
	}

	for _, r := range h.rules {
		if r.Subnet.Contains(remoteIP) {
			return nc(r.Timeout)
		}
	}

	return nil
}

// Handle handles the connections.
func (h *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	conn := h.newConn(cx)
	if conn == nil {
		h.logger.Debug("untrusted party not allowed",
			zap.String("remote", cx.RemoteAddr().String()),
			zap.Strings("allow", h.Allow),
		)
		return next.Handle(cx)
	}

	if _, err := conn.ProxyHeader(); err != nil {
		return fmt.Errorf("parsing the PROXY header: %v", err)
	}
	h.logger.Debug("received the PROXY header",
		zap.String("remote", conn.RemoteAddr().String()),
		zap.String("local", conn.LocalAddr().String()),
	)

	// Set conn as a custom variable on cx.
	cx.SetVar("l4.proxy_protocol.conn", conn)

	return next.Handle(cx.Wrap(conn))
}

// GetConn gets the connection which holds the information received from the PROXY protocol.
func GetConn(cx *layer4.Connection) net.Conn {
	if val := cx.GetVar("l4.proxy_protocol.conn"); val != nil {
		return val.(net.Conn)
	}
	return cx.Conn
}

// Interface guards
var (
	_ caddy.Provisioner  = (*Handler)(nil)
	_ layer4.NextHandler = (*Handler)(nil)
)
