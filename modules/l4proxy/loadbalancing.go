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
	"encoding/json"
	"fmt"
	"hash/fnv"
	weakrand "math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

// LoadBalancing has parameters related to load balancing.
type LoadBalancing struct {
	// A selection policy is how to choose an available backend.
	// The default policy is random selection.
	SelectionPolicyRaw json.RawMessage `json:"selection,omitempty" caddy:"namespace=layer4.proxy.selection_policies inline_key=policy"`

	// How long to try selecting available backends for each connection
	// if the next available host is down. By default, this retry is
	// disabled. Clients will wait for up to this long while the load
	// balancer tries to find an available upstream host.
	TryDuration caddy.Duration `json:"try_duration,omitempty"`

	// How long to wait between selecting the next host from the pool. Default
	// is 250ms. Only relevant when a connection to an upstream host fails. Be
	// aware that setting this to 0 with a non-zero try_duration can cause the
	// CPU to spin if all backends are down and latency is very low.
	TryInterval caddy.Duration `json:"try_interval,omitempty"`

	SelectionPolicy Selector `json:"-"`
}

// tryAgain takes the time that the handler was initially invoked
// and returns true if another attempt should be made at proxying the
// connection. If true is returned, it has already blocked long enough
// before the next retry (i.e. no more sleeping is needed). If false
// is returned, the handler should stop trying to proxy the connection.
func (lb LoadBalancing) tryAgain(ctx caddy.Context, start time.Time) bool {
	// if we've tried long enough, break
	if time.Since(start) >= time.Duration(lb.TryDuration) {
		return false
	}

	// otherwise, wait and try the next available host
	select {
	case <-time.After(time.Duration(lb.TryInterval)):
		return true
	case <-ctx.Done():
		return false
	}
}

// Selector selects an available upstream from the pool.
type Selector interface {
	Select(UpstreamPool, *layer4.Connection) *Upstream
}

func init() {
	caddy.RegisterModule(RandomSelection{})
	caddy.RegisterModule(RandomChoiceSelection{})
	caddy.RegisterModule(LeastConnSelection{})
	caddy.RegisterModule(RoundRobinSelection{})
	caddy.RegisterModule(FirstSelection{})
	caddy.RegisterModule(IPHashSelection{})

	weakrand.Seed(time.Now().UTC().UnixNano())
}

// RandomSelection is a policy that selects
// an available host at random.
type RandomSelection struct{}

// CaddyModule returns the Caddy module information.
func (RandomSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.proxy.selection_policies.random",
		New: func() caddy.Module { return new(RandomSelection) },
	}
}

// Select returns an available host, if any.
func (r RandomSelection) Select(pool UpstreamPool, conn *layer4.Connection) *Upstream {
	// use reservoir sampling because the number of available
	// hosts isn't known: https://en.wikipedia.org/wiki/Reservoir_sampling
	var randomHost *Upstream
	var count int
	for _, upstream := range pool {
		if !upstream.available() {
			continue
		}
		// (n % 1 == 0) holds for all n, therefore a
		// upstream will always be chosen if there is at
		// least one available
		count++
		if (weakrand.Int() % count) == 0 {
			randomHost = upstream
		}
	}
	return randomHost
}

// RandomChoiceSelection is a policy that selects
// two or more available hosts at random, then
// chooses the one with the least load.
type RandomChoiceSelection struct {
	// The size of the sub-pool created from the larger upstream pool. The default value
	// is 2 and the maximum at selection time is the size of the upstream pool.
	Choose int `json:"choose,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (RandomChoiceSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.proxy.selection_policies.random_choose",
		New: func() caddy.Module { return new(RandomChoiceSelection) },
	}
}

// Provision sets up r.
func (r *RandomChoiceSelection) Provision(ctx caddy.Context) error {
	if r.Choose == 0 {
		r.Choose = 2
	}
	return nil
}

// Validate ensures that r's configuration is valid.
func (r RandomChoiceSelection) Validate() error {
	if r.Choose < 2 {
		return fmt.Errorf("choose must be at least 2")
	}
	return nil
}

// Select returns an available host, if any.
func (r RandomChoiceSelection) Select(pool UpstreamPool, _ *layer4.Connection) *Upstream {
	k := r.Choose
	if k > len(pool) {
		k = len(pool)
	}
	choices := make([]*Upstream, k)
	for i, upstream := range pool {
		if !upstream.available() {
			continue
		}
		j := weakrand.Intn(i + 1)
		if j < k {
			choices[j] = upstream
		}
	}
	return leastConns(choices)
}

// LeastConnSelection is a policy that selects the upstream
// with the least active connections. If multiple upstreams
// have the same fewest number, one is chosen randomly.
type LeastConnSelection struct{}

// CaddyModule returns the Caddy module information.
func (LeastConnSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.proxy.selection_policies.least_conn",
		New: func() caddy.Module { return new(LeastConnSelection) },
	}
}

// Select selects the up host with the least number of connections in the
// pool. If more than one host has the same least number of connections,
// one of the hosts is chosen at random.
func (LeastConnSelection) Select(pool UpstreamPool, _ *layer4.Connection) *Upstream {
	var best *Upstream
	var count int
	leastConns := -1

	for _, upstream := range pool {
		if !upstream.available() {
			continue
		}
		totalConns := upstream.totalConns()
		if leastConns == -1 || totalConns < leastConns {
			leastConns = totalConns
			count = 0
		}

		// among hosts with same least connections, perform a reservoir
		// sample: https://en.wikipedia.org/wiki/Reservoir_sampling
		if totalConns == leastConns {
			count++
			if (weakrand.Int() % count) == 0 {
				best = upstream
			}
		}
	}

	return best
}

// RoundRobinSelection is a policy that selects
// a host based on round-robin ordering.
type RoundRobinSelection struct {
	robin uint32
}

// CaddyModule returns the Caddy module information.
func (RoundRobinSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.proxy.selection_policies.round_robin",
		New: func() caddy.Module { return new(RoundRobinSelection) },
	}
}

// Select returns an available host, if any.
func (r *RoundRobinSelection) Select(pool UpstreamPool, _ *layer4.Connection) *Upstream {
	n := uint32(len(pool))
	if n == 0 {
		return nil
	}
	for i := uint32(0); i < n; i++ {
		atomic.AddUint32(&r.robin, 1)
		host := pool[r.robin%n]
		if host.available() {
			return host
		}
	}
	return nil
}

// FirstSelection is a policy that selects
// the first available host.
type FirstSelection struct{}

// CaddyModule returns the Caddy module information.
func (FirstSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.proxy.selection_policies.first",
		New: func() caddy.Module { return new(FirstSelection) },
	}
}

// Select returns an available host, if any.
func (FirstSelection) Select(pool UpstreamPool, _ *layer4.Connection) *Upstream {
	for _, host := range pool {
		if host.available() {
			return host
		}
	}
	return nil
}

// IPHashSelection is a policy that selects a host
// based on hashing the remote IP of the connection.
type IPHashSelection struct{}

// CaddyModule returns the Caddy module information.
func (IPHashSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.proxy.selection_policies.ip_hash",
		New: func() caddy.Module { return new(IPHashSelection) },
	}
}

// Select returns an available host, if any.
func (IPHashSelection) Select(pool UpstreamPool, conn *layer4.Connection) *Upstream {
	remoteAddr := conn.Conn.RemoteAddr().String()
	clientIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		clientIP = remoteAddr
	}
	return hostByHashing(pool, clientIP)
}

// leastConns returns the upstream with the
// least number of active connections to it.
// If more than one upstream has the same
// least number of active connections, then
// one of those is chosen at random.
func leastConns(upstreams []*Upstream) *Upstream {
	if len(upstreams) == 0 {
		return nil
	}
	var best []*Upstream
	var bestReqs int
	for _, upstream := range upstreams {
		reqs := upstream.totalConns()
		if reqs == 0 {
			return upstream
		}
		if reqs <= bestReqs {
			bestReqs = reqs
			best = append(best, upstream)
		}
	}
	if len(best) == 0 {
		return nil
	}
	return best[weakrand.Intn(len(best))]
}

// hostByHashing returns an available host
// from pool based on a hashable string s.
func hostByHashing(pool []*Upstream, s string) *Upstream {
	poolLen := uint32(len(pool))
	if poolLen == 0 {
		return nil
	}
	index := hash(s) % poolLen
	for i := uint32(0); i < poolLen; i++ {
		index += i
		upstream := pool[index%poolLen]
		if upstream.available() {
			return upstream
		}
	}
	return nil
}

// hash calculates a fast hash based on s.
func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// Interface guards
var (
	_ Selector = (*RandomSelection)(nil)
	_ Selector = (*RandomChoiceSelection)(nil)
	_ Selector = (*LeastConnSelection)(nil)
	_ Selector = (*RoundRobinSelection)(nil)
	_ Selector = (*FirstSelection)(nil)
	_ Selector = (*IPHashSelection)(nil)

	_ caddy.Validator   = (*RandomChoiceSelection)(nil)
	_ caddy.Provisioner = (*RandomChoiceSelection)(nil)
)
