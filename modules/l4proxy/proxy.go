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

package l4proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mastercactapus/proxyprotocol"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4tls"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a handler that can proxy connections.
type Handler struct {
	// Upstreams is the list of backends to proxy to.
	Upstreams UpstreamPool `json:"upstreams,omitempty"`

	// Health checks update the status of backends, whether they are
	// up or down. Down backends will not be proxied to.
	HealthChecks *HealthChecks `json:"health_checks,omitempty"`

	// Load balancing distributes load/connections between backends.
	LoadBalancing *LoadBalancing `json:"load_balancing,omitempty"`

	// Specifies the version of the Proxy Protocol header to add, either "v1" or "v2".
	// Ref: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
	ProxyProtocol string `json:"proxy_protocol,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.ctx = ctx
	h.logger = ctx.Logger(h)

	// start by loading modules
	if h.LoadBalancing != nil && h.LoadBalancing.SelectionPolicyRaw != nil {
		mod, err := ctx.LoadModule(h.LoadBalancing, "SelectionPolicyRaw")
		if err != nil {
			return fmt.Errorf("loading load balancing selection policy: %s", err)
		}
		h.LoadBalancing.SelectionPolicy = mod.(Selector)
	}

	if h.ProxyProtocol != "" && h.ProxyProtocol != "v1" && h.ProxyProtocol != "v2" {
		return fmt.Errorf("proxy_protocol: \"%s\" should be empty, or one of \"v1\" \"v2\"", h.ProxyProtocol)
	}

	// prepare upstreams
	if len(h.Upstreams) == 0 {
		return fmt.Errorf("no upstreams defined")
	}
	for i, ups := range h.Upstreams {
		err := ups.provision(ctx, h)
		if err != nil {
			return fmt.Errorf("upstream %d: %v", i, err)
		}
	}

	// health checks
	if h.HealthChecks != nil {
		// set defaults on passive health checks, if necessary
		if h.HealthChecks.Passive != nil {
			if h.HealthChecks.Passive.FailDuration > 0 && h.HealthChecks.Passive.MaxFails == 0 {
				h.HealthChecks.Passive.MaxFails = 1
			}
		}

		// if active health checks are enabled, configure them and start a worker
		if h.HealthChecks.Active != nil {
			h.HealthChecks.Active.logger = h.logger.Named("health_checker.active")

			if h.HealthChecks.Active.Timeout == 0 {
				h.HealthChecks.Active.Timeout = caddy.Duration(5 * time.Second)
			}
			if h.HealthChecks.Active.Interval == 0 {
				h.HealthChecks.Active.Interval = caddy.Duration(30 * time.Second)
			}

			go h.activeHealthChecker()
		}
	}

	// set up load balancing; it must not be nil, even if there's just one backend
	if h.LoadBalancing == nil {
		h.LoadBalancing = new(LoadBalancing)
	}
	if h.LoadBalancing.SelectionPolicy == nil {
		h.LoadBalancing.SelectionPolicy = RandomSelection{}
	}
	if h.LoadBalancing.TryDuration > 0 && h.LoadBalancing.TryInterval == 0 {
		// a non-zero try_duration with a zero try_interval
		// will always spin the CPU for try_duration if the
		// upstream is local or low-latency; avoid that by
		// defaulting to a sane wait period between attempts
		h.LoadBalancing.TryInterval = caddy.Duration(250 * time.Millisecond)
	}

	return nil
}

// Handle handles the downstream connection.
func (h Handler) Handle(down *layer4.Connection, _ layer4.Handler) error {
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	start := time.Now()

	var upConns []net.Conn
	var proxyErr error

	for {
		// choose an available upstream
		upstream := h.LoadBalancing.SelectionPolicy.Select(h.Upstreams, down)
		if upstream == nil {
			if proxyErr == nil {
				proxyErr = fmt.Errorf("no upstreams available")
			}
			if !h.LoadBalancing.tryAgain(h.ctx, start) {
				return proxyErr
			}
			continue
		}

		// establish all upstream connections
		upConns, proxyErr = h.dialPeers(upstream, repl, down)
		if proxyErr != nil {
			// we might be able to try again
			if !h.LoadBalancing.tryAgain(h.ctx, start) {
				return proxyErr
			}
			continue
		}

		break
	}

	// make sure upstream connections all get closed
	defer func() {
		for _, conn := range upConns {
			conn.Close()
		}
	}()

	// finally, proxy the connection
	h.proxy(down, upConns)

	return nil
}

func (h *Handler) dialPeers(upstream *Upstream, repl *caddy.Replacer, down *layer4.Connection) ([]net.Conn, error) {
	var upConns []net.Conn

	for _, p := range upstream.peers {
		hostPort := repl.ReplaceAll(p.address.JoinHostPort(0), "")

		var up net.Conn
		var err error

		if upstream.TLS == nil {
			up, err = net.Dial(p.address.Network, hostPort)
		} else {
			// the prepared config could be nil if user enabled but did not customize TLS,
			// in which case we adopt the downstream client's TLS ClientHello for ours;
			// i.e. by default, make the client's TLS config as transparent as possible
			tlsCfg := upstream.tlsConfig
			if tlsCfg == nil {
				tlsCfg = new(tls.Config)
				if hellos := l4tls.GetClientHelloInfos(down); len(hellos) > 0 {
					hellos[0].FillTLSClientConfig(tlsCfg)
				}
			}
			up, err = tls.Dial(p.address.Network, hostPort, tlsCfg)
		}
		h.logger.Debug("dial upstream",
			zap.String("remote", down.RemoteAddr().String()),
			zap.String("upstream", hostPort),
			zap.Error(err))

		// Add Proxy header
		if err == nil && h.ProxyProtocol == "v1" {
			var h proxyprotocol.HeaderV1
			h.FromConn(down.Conn, false)
			_, err = h.WriteTo(up)
		} else if err == nil && h.ProxyProtocol == "v2" {
			var h proxyprotocol.HeaderV2
			h.FromConn(down.Conn, false)
			_, err = h.WriteTo(up)
		}

		if err != nil {
			h.countFailure(p)
			for _, conn := range upConns {
				conn.Close()
			}
			return nil, err
		}

		upConns = append(upConns, up)
	}

	return upConns, nil
}

// proxy proxies the downstream connection to all upstream connections.
func (h *Handler) proxy(down *layer4.Connection, upConns []net.Conn) {
	// every time we read from downstream, we write
	// the same to each upstream; this is half of
	// the proxy duplex
	var downTee io.Reader = down
	for _, up := range upConns {
		downTee = io.TeeReader(downTee, up)
	}

	// when we are done and have closed connections, set this
	// flag to 1 so that we don't report errors unnecessarily
	var done int32

	for _, up := range upConns {
		go func(up net.Conn) {
			_, err := io.Copy(down, up)
			if err != nil && atomic.LoadInt32(&done) == 0 {
				h.logger.Error("upstream connection",
					zap.String("local_address", up.LocalAddr().String()),
					zap.String("remote_address", up.RemoteAddr().String()),
					zap.Error(err),
				)
			}
		}(up)
	}

	// read from downstream until connection is closed;
	// TODO: this pumps the reader, but writing into discard is a weird way to do it; could be avoided if we used io.Pipe - see _gitignore/oldtee.go.txt
	io.Copy(ioutil.Discard, downTee)
	atomic.StoreInt32(&done, 1)
}

// countFailure is used with passive health checks. It
// remembers 1 failure for upstream for the configured
// duration. If passive health checks are disabled or
// failure expiry is 0, this is a no-op.
func (h *Handler) countFailure(p *peer) {
	// only count failures if passive health checking is enabled
	// and if failures are configured have a non-zero expiry
	if h.HealthChecks == nil || h.HealthChecks.Passive == nil {
		return
	}
	failDuration := time.Duration(h.HealthChecks.Passive.FailDuration)
	if failDuration == 0 {
		return
	}

	// count failure immediately
	err := p.countFail(1)
	if err != nil {
		h.HealthChecks.Passive.logger.Error("could not count failure",
			zap.String("peer_address", p.address.String()),
			zap.Error(err))
		return
	}

	// forget it later
	go func(failDuration time.Duration) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[PANIC] health check failure forgetter: %v\n%s", err, debug.Stack())
			}
		}()
		time.Sleep(failDuration)
		err := p.countFail(-1)
		if err != nil {
			h.HealthChecks.Passive.logger.Error("could not forget failure",
				zap.String("peer_address", p.address.String()),
				zap.Error(err))
		}
	}(failDuration)
}

// Cleanup cleans up the resources made by h during provisioning.
func (h *Handler) Cleanup() error {
	// remove hosts from our config from the pool
	for _, upstream := range h.Upstreams {
		for _, dialAddr := range upstream.Dial {
			peers.Delete(dialAddr)
		}
	}
	return nil
}

// peers is the global repository for peers that are
// currently in use by active configuration(s). This
// allows the state of remote hosts to be preserved
// through config reloads.
var peers = caddy.NewUsagePool()

// Interface guards
var (
	_ layer4.NextHandler = (*Handler)(nil)
	_ caddy.Provisioner  = (*Handler)(nil)
	_ caddy.CleanerUpper = (*Handler)(nil)
)
