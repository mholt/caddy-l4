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
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

// UpstreamPool is a collection of upstreams.
type UpstreamPool []*Upstream

// Upstream represents a proxy upstream.
type Upstream struct {
	// The network addresses to dial. Supports placeholders, but not port
	// ranges currently (each address must be exactly 1 socket).
	Dial []string `json:"dial,omitempty"`

	// Set this field to enable TLS to the upstream.
	TLS *reverseproxy.TLSConfig `json:"tls,omitempty"`

	// How many connections this upstream is allowed to
	// have before being marked as unhealthy (if > 0).
	MaxConnections int `json:"max_connections,omitempty"`

	peers             []*peer
	tlsConfig         *tls.Config
	healthCheckPolicy *PassiveHealthChecks
}

func (u *Upstream) provision(ctx caddy.Context, h *Handler) error {
	for _, dialAddr := range u.Dial {
		// parse and validate address
		addr, err := caddy.ParseNetworkAddress(dialAddr)
		if err != nil {
			return err
		}
		if addr.PortRangeSize() != 1 {
			return fmt.Errorf("%s: port ranges not currently supported", dialAddr)
		}

		// create or load peer info
		p := &peer{address: addr}
		existingPeer, loaded := peers.LoadOrStore(dialAddr, p)
		if loaded {
			p = existingPeer.(*peer)
		}
		u.peers = append(u.peers, p)
	}

	// set up TLS client
	if u.TLS != nil {
		var err error
		u.tlsConfig, err = u.TLS.MakeTLSClientConfig(ctx)
		if err != nil {
			return fmt.Errorf("making TLS client config: %v", err)
		}
	}

	// if the passive health checker has a non-zero UnhealthyConnectionCount
	// but the upstream has no MaxConnections set (they are the same thing,
	// but the passive health checker is a default value for for upstreams
	// without MaxConnections), copy the value into this upstream, since the
	// value in the upstream (MaxConnections) is what is used during
	// availability checks
	if h.HealthChecks != nil && h.HealthChecks.Passive != nil {
		h.HealthChecks.Passive.logger = h.logger.Named("health_checker.passive")
		if h.HealthChecks.Passive.UnhealthyConnectionCount > 0 &&
			u.MaxConnections == 0 {
			u.MaxConnections = h.HealthChecks.Passive.UnhealthyConnectionCount
		}
	}

	// upstreams need independent access to the passive
	// health check policy because passive health checks
	// run without access to h.
	if h.HealthChecks != nil {
		u.healthCheckPolicy = h.HealthChecks.Passive
	}

	return nil
}

// available returns true if the remote host
// is available to receive connections. This is
// the method that should be used by selection
// policies, etc. to determine if a backend
// is usable at the moment.
func (u *Upstream) available() bool {
	return u.healthy() && !u.full()
}

// healthy returns true if the remote host
// is currently known to be healthy or "up".
// It consults the circuit breaker, if any.
func (u *Upstream) healthy() bool {
	for _, p := range u.peers {
		if !p.healthy() {
			return false
		}
	}
	if u.healthCheckPolicy != nil && u.healthCheckPolicy.MaxFails > 0 {
		for _, p := range u.peers {
			if atomic.LoadInt32(&p.fails) >= int32(u.healthCheckPolicy.MaxFails) {
				return false
			}
		}
	}
	return true
}

// full returns true if any of the peers cannot
// receive more connections at this time.
func (u *Upstream) full() bool {
	if u.MaxConnections == 0 {
		return false
	}
	for _, p := range u.peers {
		if p.getNumConns() >= u.MaxConnections {
			return true
		}
	}
	return false
}

// totalConns returns the total number of active connections
// to this upstream (across all peers).
func (u *Upstream) totalConns() int {
	var totalConns int
	for _, p := range u.peers {
		totalConns += p.getNumConns()
	}
	return totalConns
}

// peer holds the state for a singular proxy backend;
// must not be copied, because peers are singular
// (even if there is more than 1 instance of a config,
// that does not duplicate the actual backend).
type peer struct {
	numConns  int32
	unhealthy int32
	fails     int32
	address   caddy.NetworkAddress
}

// getNumConns returns the number of active connections with the peer.
func (p *peer) getNumConns() int {
	return int(atomic.LoadInt32(&p.numConns))
}

// healthy returns true if the peer is not unhealthy.
func (p *peer) healthy() bool {
	return atomic.LoadInt32(&p.unhealthy) == 0
}

// countConn mutates the active connection count by
// delta. It returns an error if the adjustment fails.
func (p *peer) countConn(delta int) error {
	result := atomic.AddInt32(&p.numConns, int32(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

// countFail mutates the recent failures count by
// delta. It returns an error if the adjustment fails.
func (p *peer) countFail(delta int) error {
	result := atomic.AddInt32(&p.fails, int32(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

// setHealthy sets the upstream has healthy or unhealthy
// and returns true if the new value is different.
func (p *peer) setHealthy(healthy bool) (bool, error) {
	var unhealthy, compare int32 = 1, 0
	if healthy {
		unhealthy, compare = 0, 1
	}
	swapped := atomic.CompareAndSwapInt32(&p.unhealthy, compare, unhealthy)
	return swapped, nil
}
