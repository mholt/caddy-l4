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

package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4tls"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a handler that can proxy connections.
type Handler struct {
	Upstreams []*Upstream `json:"upstreams,omitempty"`

	logger *zap.Logger
}

// Upstream represents a proxy upstream.
type Upstream struct {
	// The network address to dial. Supports placeholders; does not support port ranges.
	Dial []string `json:"dial,omitempty"`

	// Set this field to enable TLS to the upstream.
	TLS *reverseproxy.TLSConfig `json:"tls,omitempty"` // TODO: kind of a weird import but ok

	peers     []*peer
	tlsConfig *tls.Config
}

func (u *Upstream) provision(ctx caddy.Context) error {
	for _, dialAddr := range u.Dial {
		addr, err := caddy.ParseNetworkAddress(dialAddr)
		if err != nil {
			return err
		}
		if addr.PortRangeSize() != 1 {
			return fmt.Errorf("%s: port ranges not supported", dialAddr)
		}
		// TODO: UsagePool for global state
		u.peers = append(u.peers, &peer{
			address: addr,
		})
	}
	if len(u.peers) == 0 {
		return fmt.Errorf("no peers defined in upstream")
	}

	if u.TLS != nil {
		var err error
		u.tlsConfig, err = u.TLS.MakeTLSClientConfig(ctx)
		if err != nil {
			return fmt.Errorf("making TLS client config: %v", err)
		}
	}

	return nil
}

type peer struct {
	address caddy.NetworkAddress
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (p *Handler) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger(p)

	if len(p.Upstreams) == 0 {
		return fmt.Errorf("no upstreams defined")
	}
	for i, ups := range p.Upstreams {
		err := ups.provision(ctx)
		if err != nil {
			return fmt.Errorf("upstream %d: %v", i, err)
		}
	}

	// TODO: load balancing policies

	return nil
}

// Handle handles the downstream connection.
func (p Handler) Handle(down *layer4.Connection, _ layer4.Handler) error {
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	// TODO: get next upstream from LB policy
	upstream := p.Upstreams[0]

	// establish all upstream connections
	var upConns []net.Conn
	for _, peer := range upstream.peers {
		var up net.Conn
		var err error

		hostPort := repl.ReplaceAll(peer.address.JoinHostPort(0), "")
		if upstream.TLS == nil {
			up, err = net.Dial(peer.address.Network, hostPort)
		} else {
			// the prepared config could be nil if user enabled but did not customize TLS,
			// in which case we adopt the downstream client's TLS ClientHello for ours;
			// i.e. by default, make the client's TLS config as transparent as possible
			tlsCfg := upstream.tlsConfig
			if tlsCfg == nil {
				tlsCfg = new(tls.Config)
				if chi, ok := down.GetVar("tls_client_hello").(l4tls.ClientHelloInfo); ok {
					chi.FillTLSClientConfig(tlsCfg)
				}
			}
			up, err = tls.Dial(peer.address.Network, hostPort, tlsCfg)
		}
		if err != nil {
			return err
		}
		defer up.Close()
		upConns = append(upConns, up)
	}

	// every time we read from downstream, we write
	// the same to each upstream; this is half of
	// the proxy duplex
	var downTee io.Reader = down.Conn
	for _, up := range upConns {
		downTee = io.TeeReader(downTee, up)
	}

	// when we are done and have closed connections, set this
	// flag to 1 so that we don't report errors unnecessarily
	var done int32

	for _, up := range upConns {
		go func(up net.Conn) {
			_, err := io.Copy(down.Conn, up)
			if err != nil && atomic.LoadInt32(&done) == 0 {
				p.logger.Error("upstream connection",
					zap.String("local_address", up.LocalAddr().String()),
					zap.String("remote_address", up.RemoteAddr().String()),
					zap.Error(err),
				)
			}
		}(up)
	}

	// read from downstream until connection is closed
	// TODO: this is kinda weird, writing into discard; could be avoided if we used io.Pipe - see _gitignore/oldtee.go.txt
	io.Copy(ioutil.Discard, downTee)
	atomic.StoreInt32(&done, 1)

	return nil
}

// Interface guard
var _ layer4.NextHandler = (*Handler)(nil)
