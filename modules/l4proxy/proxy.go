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
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mastercactapus/proxyprotocol"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4proxyprotocol"
	"github.com/mholt/caddy-l4/modules/l4tls"
)

func init() {
	caddy.RegisterModule(&Handler{})
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

	proxyProtocolVersion uint8

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
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

	repl := caddy.NewReplacer()
	proxyProtocol := repl.ReplaceAll(h.ProxyProtocol, "")
	if proxyProtocol == "v1" {
		h.proxyProtocolVersion = 1
	} else if proxyProtocol == "v2" {
		h.proxyProtocolVersion = 2
	} else if proxyProtocol != "" {
		return fmt.Errorf("proxy_protocol: \"%s\" should be empty, or one of \"v1\" \"v2\"", proxyProtocol)
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
		h.LoadBalancing.SelectionPolicy = &RandomSelection{}
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
func (h *Handler) Handle(down *layer4.Connection, _ layer4.Handler) error {
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
			_ = conn.Close()
		}
	}()

	// finally, proxy the connection
	h.proxy(down, upConns)

	return nil
}

// packetProxyProtocolConn sends every message prepended with proxy protocol
type packetProxyProtocolConn struct {
	net.Conn
	header io.WriterTo // both of the pp header types implement this interface
}

func (pp *packetProxyProtocolConn) Write(p []byte) (int, error) {
	// TODO: pool the buffer
	buf := new(bytes.Buffer)
	// send pp and payload in a single message
	_, _ = pp.header.WriteTo(buf)
	buf.Write(p)
	_, err := buf.WriteTo(pp.Conn)
	if err != nil {
		return 0, err
	}
	return len(p), nil
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

		// Send the PROXY protocol header.
		if err == nil {
			downConn := l4proxyprotocol.GetConn(down)
			var header io.WriterTo
			switch h.proxyProtocolVersion {
			case 1:
				var h proxyprotocol.HeaderV1
				h.FromConn(downConn, false)
				header = h
			case 2:
				var h proxyprotocol.HeaderV2
				h.FromConn(downConn, false)
				header = h
			}

			// Only write the PROXY protocol header if it's not nil
			if header != nil {
				// for packet connection, prepend each message with pp
				// unix connections always implement this interface while not necessarily in datagram mode
				// ignore it unless the unix socket is in datagram mode
				if _, ok := up.(net.PacketConn); ok && (!caddy.IsUnixNetwork(p.address.Network) || p.address.Network == "unixgram") {
					// only v2 supports UDP addresses
					if v2, ok := header.(proxyprotocol.HeaderV2); ok {
						la, _ := v2.Dest.(*net.UDPAddr)
						ra, _ := v2.Src.(*net.UDPAddr)
						// for UDP, local address maybe net.IPv6zero or net.IPv4zero if listener address is not specified
						if la != nil && ra != nil && la.IP.IsUnspecified() {
							// TODO: extract real local address using golang.org/x/net
							la = &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: la.Port, Zone: la.Zone}
							v2.Dest = la
							// header is not updated automatically, a value not a pointer
							header = v2
						}
					}
					up = &packetProxyProtocolConn{
						Conn:   up,
						header: header,
					}
				} else {
					_, err = header.WriteTo(up)
				}
			}
		}

		if err != nil {
			h.countFailure(p)
			for _, conn := range upConns {
				_ = conn.Close()
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

	var wg sync.WaitGroup
	var downClosed atomic.Bool

	for _, up := range upConns {
		wg.Add(1)

		go func(up net.Conn) {
			defer wg.Done()

			if _, err := io.Copy(down, up); err != nil {
				// If the downstream connection has been closed, we can assume this is
				// the reason io.Copy() errored.  That's normal operation for UDP
				// connections after idle timeout, so don't log an error in that case.
				if !downClosed.Load() {
					h.logger.Error("upstream connection",
						zap.String("local_address", up.LocalAddr().String()),
						zap.String("remote_address", up.RemoteAddr().String()),
						zap.Error(err),
					)
				}
			}
		}(up)
	}

	downConnClosedCh := make(chan struct{}, 1)

	go func() {
		// read from downstream until connection is closed;
		// TODO: this pumps the reader, but writing into discard is a weird way to do it; could be avoided if we used io.Pipe - see _gitignore/oldtee.go.txt
		_, _ = io.Copy(io.Discard, downTee)
		downConnClosedCh <- struct{}{}

		// Shut down the writing side of all upstream connections, in case
		// that the downstream connection is half closed. (issue #40)
		//
		// UDP connections meanwhile don't implement CloseWrite(), but in order
		// to ensure io.Copy() in the per-upstream goroutines (above) returns,
		// we need to close the socket.  This will cause io.Copy() return an
		// error, which in this particular case is expected, so we signal the
		// intentional closure by setting this flag.
		downClosed.Store(true)
		for _, up := range upConns {
			if conn, ok := up.(closeWriter); ok {
				_ = conn.CloseWrite()
			} else {
				_ = up.Close()
			}
		}
	}()

	// wait for reading from all upstream connections
	wg.Wait()

	// Shut down the writing side of the downstream connection, in case that
	// the upstream connections are all half closed.
	if downConn, ok := down.Conn.(closeWriter); ok {
		_ = downConn.CloseWrite()
	}

	// Wait for reading from the downstream connection, if possible.
	<-downConnClosedCh
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
			_, _ = peers.Delete(dialAddr)
		}
	}
	return nil
}

// UnmarshalCaddyfile sets up the Handler from Caddyfile tokens. Syntax:
//
//	proxy [<upstreams...>] {
//		# active health check options
//		health_interval <duration>
//		health_port <int>
//		health_timeout <duration>
//
//		# passive health check options
//		fail_duration <duration>
//		max_fails <int>
//		unhealthy_connection_count <int>
//
//		# load balancing options
//		lb_policy <name> [<args...>]
//		lb_try_duration <duration>
//		lb_try_interval <duration>
//
//		proxy_protocol <v1|v2>
//
//		# multiple upstream options are supported
//		upstream [<args...>] {
//			...
//		}
//		upstream [<args...>]
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Treat all same-line options as upstream addresses
	for d.NextArg() {
		h.Upstreams = append(h.Upstreams, &Upstream{Dial: []string{d.Val()}})
	}

	var (
		hasHealthInterval, hasHealthPort, hasHealthTimeout  bool // active health check options
		hasFailDuration, hasMaxFails, hasUnhealthyConnCount bool // passive health check options
		hasLBPolicy, hasLBTryDuration, hasLBTryInterval     bool // load balancing options
		hasProxyProtocol                                    bool
	)
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "health_interval":
			if hasHealthInterval {
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
			if h.HealthChecks == nil {
				h.HealthChecks = &HealthChecks{Active: &ActiveHealthChecks{}}
			} else if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = &ActiveHealthChecks{}
			}
			h.HealthChecks.Active.Interval, hasHealthInterval = caddy.Duration(dur), true
		case "health_port":
			if hasHealthPort {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			d.NextArg()
			val, err := strconv.ParseInt(d.Val(), 10, 32)
			if err != nil {
				return d.Errf("parsing %s option '%s': %v", wrapper, optionName, err)
			}
			if h.HealthChecks == nil {
				h.HealthChecks = &HealthChecks{Active: &ActiveHealthChecks{}}
			} else if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = &ActiveHealthChecks{}
			}
			h.HealthChecks.Active.Port, hasHealthPort = int(val), true
		case "health_timeout":
			if hasHealthTimeout {
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
			if h.HealthChecks == nil {
				h.HealthChecks = &HealthChecks{Active: &ActiveHealthChecks{}}
			} else if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = &ActiveHealthChecks{}
			}
			h.HealthChecks.Active.Timeout, hasHealthTimeout = caddy.Duration(dur), true
		case "fail_duration":
			if hasFailDuration {
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
			if h.HealthChecks == nil {
				h.HealthChecks = &HealthChecks{Passive: &PassiveHealthChecks{}}
			} else if h.HealthChecks.Passive == nil {
				h.HealthChecks.Passive = &PassiveHealthChecks{}
			}
			h.HealthChecks.Passive.FailDuration, hasFailDuration = caddy.Duration(dur), true
		case "max_fails":
			if hasMaxFails {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			d.NextArg()
			val, err := strconv.ParseInt(d.Val(), 10, 32)
			if err != nil {
				return d.Errf("parsing %s option '%s': %v", wrapper, optionName, err)
			}
			if h.HealthChecks == nil {
				h.HealthChecks = &HealthChecks{Passive: &PassiveHealthChecks{}}
			} else if h.HealthChecks.Passive == nil {
				h.HealthChecks.Passive = &PassiveHealthChecks{}
			}
			h.HealthChecks.Passive.MaxFails, hasMaxFails = int(val), true
		case "unhealthy_connection_count":
			if hasUnhealthyConnCount {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			d.NextArg()
			val, err := strconv.ParseInt(d.Val(), 10, 32)
			if err != nil {
				return d.Errf("parsing %s option '%s': %v", wrapper, optionName, err)
			}
			if h.HealthChecks == nil {
				h.HealthChecks = &HealthChecks{Passive: &PassiveHealthChecks{}}
			} else if h.HealthChecks.Passive == nil {
				h.HealthChecks.Passive = &PassiveHealthChecks{}
			}
			h.HealthChecks.Passive.UnhealthyConnectionCount, hasUnhealthyConnCount = int(val), true
		case "lb_policy":
			if hasLBPolicy {
				return d.Errf("duplicate proxy load_balancing option '%s'", optionName)
			}
			if !d.NextArg() {
				return d.ArgErr()
			}
			policyName := d.Val()

			unm, err := caddyfile.UnmarshalModule(d, "layer4.proxy.selection_policies."+policyName)
			if err != nil {
				return err
			}
			us, ok := unm.(Selector)
			if !ok {
				return d.Errf("policy module '%s' is not an upstream selector", policyName)
			}
			policyRaw := caddyconfig.JSON(us, nil)

			policyRaw, err = layer4.SetModuleNameInline("policy", policyName, policyRaw)
			if err != nil {
				return d.Errf("re-encoding module '%s' configuration: %v", policyName, err)
			}
			if h.LoadBalancing == nil {
				h.LoadBalancing = &LoadBalancing{}
			}
			h.LoadBalancing.SelectionPolicyRaw, hasLBPolicy = policyRaw, true
		case "lb_try_duration":
			if hasLBTryDuration {
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
			if h.LoadBalancing == nil {
				h.LoadBalancing = &LoadBalancing{}
			}
			h.LoadBalancing.TryDuration, hasLBTryDuration = caddy.Duration(dur), true
		case "lb_try_interval":
			if hasLBTryInterval {
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
			if h.LoadBalancing == nil {
				h.LoadBalancing = &LoadBalancing{}
			}
			h.LoadBalancing.TryInterval, hasLBTryInterval = caddy.Duration(dur), true
		case "proxy_protocol":
			if hasProxyProtocol {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			_, h.ProxyProtocol, hasProxyProtocol = d.NextArg(), d.Val(), true
		case "upstream":
			u := &Upstream{}
			if err := u.UnmarshalCaddyfile(d.NewFromNextSegment()); err != nil {
				return err
			}
			h.Upstreams = append(h.Upstreams, u)
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

// peers is the global repository for peers that are
// currently in use by active configuration(s). This
// allows the state of remote hosts to be preserved
// through config reloads.
var peers = caddy.NewUsagePool()

// Interface guards
var (
	_ caddy.CleanerUpper    = (*Handler)(nil)
	_ caddy.Provisioner     = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ layer4.NextHandler    = (*Handler)(nil)
)

// Used to properly shutdown half-closed connections (see PR #73).
// Implemented by net.TCPConn, net.UnixConn, tls.Conn, qtls.Conn.
type closeWriter interface {
	// CloseWrite shuts down the writing side of the connection.
	CloseWrite() error
}

// Ensure we notice if CloseWrite changes for these important connections
var (
	_ closeWriter = (*net.TCPConn)(nil)
	_ closeWriter = (*net.UnixConn)(nil)
	_ closeWriter = (*tls.Conn)(nil)
)
