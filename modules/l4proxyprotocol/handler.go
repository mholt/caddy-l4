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
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/pires/go-proxyproto"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&Handler{})
}

// Handler is a connection handler that accepts the PROXY protocol.
type Handler struct {
	// How long to wait for the PROXY protocol header to be received.
	// Defaults to zero, which means timeout is disabled.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// An optional list of CIDR ranges to allow/require PROXY headers from.
	Allow []string `json:"allow,omitempty"`
	allow []netip.Prefix

	// Deny is an optional list of CIDR ranges to
	// deny PROXY headers from.
	Deny []string `json:"deny,omitempty"`
	deny []netip.Prefix

	// FallbackPolicy specifies the policy to use if the downstream
	// IP address is not in the Allow list nor is in the Deny list.
	//
	// NOTE: The generated docs which describe the value of this
	// field is wrong because of how this type unmarshals JSON in a
	// custom way. The field expects a string, not a number.
	//
	// Accepted values are: IGNORE, USE, REJECT, REQUIRE, SKIP
	//
	// - IGNORE: address from PROXY header, but accept connection
	//
	// - USE: address from PROXY header
	//
	// - REJECT: connection when PROXY header is sent
	//   Note: even though the first read on the connection returns an error if
	//   a PROXY header is present, subsequent reads do not. It is the task of
	//   the code using the connection to handle that case properly.
	//
	// - REQUIRE: connection to send PROXY header, reject if not present
	//   Note: even though the first read on the connection returns an error if
	//   a PROXY header is not present, subsequent reads do not. It is the task
	//   of the code using the connection to handle that case properly.
	//
	// - SKIP: accepts a connection without requiring the PROXY header.
	//   Note: an example usage can be found in the SkipProxyHeaderForCIDR
	//   function.
	//
	// Default: IGNORE
	//
	// Policy definitions are here: https://pkg.go.dev/github.com/pires/go-proxyproto#Policy
	FallbackPolicy Policy `json:"fallback_policy,omitempty"`

	policy proxyproto.PolicyFunc
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.proxy_protocol",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the module.
func (h *Handler) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	for _, allowCIDR := range h.Allow {
		allowCIDR = repl.ReplaceAll(allowCIDR, "")
		ipnet, err := netip.ParsePrefix(allowCIDR)
		if err != nil {
			return err
		}
		h.allow = append(h.allow, ipnet)
	}
	for _, cidr := range h.Deny {
		cidr = repl.ReplaceAll(cidr, "")
		ipnet, err := netip.ParsePrefix(cidr)
		if err != nil {
			return err
		}
		h.deny = append(h.deny, ipnet)
	}

	h.policy = proxyproto.PolicyFunc(func(upstream net.Addr) (proxyproto.Policy, error) {
		// trust in-memory pipes
		if upstream.Network() == "pipe" {
			return proxyproto.REQUIRE, nil
		}
		// trust unix sockets
		if network := upstream.Network(); caddy.IsUnixNetwork(network) || caddy.IsFdNetwork(network) {
			return proxyproto.USE, nil
		}
		ret := h.FallbackPolicy
		host, _, err := net.SplitHostPort(upstream.String())
		if err != nil {
			return proxyproto.REJECT, err
		}

		ip, err := netip.ParseAddr(host)
		if err != nil {
			return proxyproto.REJECT, err
		}
		for _, ipnet := range h.deny {
			if ipnet.Contains(ip) {
				return proxyproto.REJECT, nil
			}
		}
		for _, ipnet := range h.allow {
			if ipnet.Contains(ip) {
				ret = PolicyUSE
				break
			}
		}
		return policyToGoProxyPolicy[ret], nil
	})

	h.logger = ctx.Logger(h)
	return nil
}

// newConn creates a new connection which will handle the PROXY protocol.
func (h *Handler) newConn(cx *layer4.Connection) *proxyproto.Conn {
	// Check policy
	policy, err := h.policy(cx.RemoteAddr())
	if err != nil {
		h.logger.Debug("policy check failed", zap.Error(err))
		return nil
	}
	if policy == proxyproto.REJECT {
		h.logger.Debug("connection rejected by policy")
		return nil
	}

	// Create connection with timeout option
	var opts []func(*proxyproto.Conn)
	if h.Timeout > 0 {
		opts = append(opts, proxyproto.SetReadHeaderTimeout(time.Duration(h.Timeout)))
	}

	return proxyproto.NewConn(cx, opts...)
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

	header := conn.ProxyHeader()
	if header == nil {
		// No proxy header was present, but that might be okay depending on policy
		h.logger.Debug("no PROXY header received")

		// check the policy again for the `REQUIRE` case
		policy, err := h.policy(cx.RemoteAddr())
		if err != nil {
			h.logger.Debug("policy check in handler failed", zap.Error(err))
			return nil
		}
		if policy == proxyproto.REQUIRE {
			h.logger.Debug("connection rejected in handler by policy")
			return errors.New("PROXY header required but not received")
		}
	} else {
		h.logger.Debug("received PROXY header")
	}
	h.logger.Debug("connection established",
		zap.String("remote", conn.RemoteAddr().String()),
		zap.String("local", conn.LocalAddr().String()),
	)

	// Set conn as a custom variable on cx.
	cx.SetVar("l4.proxy_protocol.conn", conn)

	return next.Handle(cx.Wrap(conn))
}

// UnmarshalCaddyfile sets up the Handler from Caddyfile tokens. Syntax:
//
//	proxy_protocol {
//		allow <ranges...>
//		timeout <duration>
//	}
//
// proxy_protocol
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	var hasTimeout bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "allow":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			for d.NextArg() {
				val := d.Val()
				if val == "private_ranges" {
					h.Allow = append(h.Allow, caddyhttp.PrivateRangesCIDR()...)
					continue
				}
				h.Allow = append(h.Allow, val)
			}
		case "deny":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			for d.NextArg() {
				val := d.Val()
				if val == "private_ranges" {
					h.Deny = append(h.Deny, caddyhttp.PrivateRangesCIDR()...)
					continue
				}
				h.Deny = append(h.Deny, val)
			}
		case "fallback_policy":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p, err := parsePolicy(d.Val())
			if err != nil {
				return d.WrapErr(err)
			}
			h.FallbackPolicy = p
		case "timeout":
			if hasTimeout {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			d.NextArg()
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing %s option '%s' duration: %v", wrapper, optionName, err)
			}
			h.Timeout, hasTimeout = caddy.Duration(dur), true
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	return nil
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
	_ caddy.Provisioner     = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ layer4.NextHandler    = (*Handler)(nil)
)
