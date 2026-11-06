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
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&SRVUpstreams{})
	caddy.RegisterModule(&AUpstreams{})
	caddy.RegisterModule(&AAAAUpstreams{})
}

// UpstreamSource gets the list of upstreams to proxy to dynamically, instead of
// from a static configuration, so the backend set can be discovered (e.g. from
// DNS) rather than hard-coded. It is given the connection's replacer for
// placeholder expansion (and nothing connection-specific), so the same source
// can also be polled by the active health checker, which has no connection.
type UpstreamSource interface {
	GetUpstreams(*caddy.Replacer) (UpstreamPool, error)
}

// SRVUpstreams discovers upstreams from DNS SRV records, so the upstream set
// does not have to be restated in config when DNS already publishes it. Results
// are cached and refreshed periodically.
//
// Each configured source owns its cache and the peer-pool references for the
// addresses it currently resolves to: a reference is taken when an address
// first appears and released when it drops out of the results or when the
// source is cleaned up (on config reload), so peers do not accumulate as the
// backend set churns. Note: active health checks only run on
// statically-configured upstreams; passive health checking and connection
// counting still apply to dynamically-discovered ones. Because the lookup runs
// while the source's lock is held, a slow resolver delays the connections
// served by this source while a refresh is in flight.
type SRVUpstreams struct {
	// The service label of the SRV record (the "_service" part).
	Service string `json:"service,omitempty"`

	// The protocol label of the SRV record, "tcp" or "udp" (the "_proto" part).
	Proto string `json:"proto,omitempty"`

	// The name label; or, if service and proto are empty, the entire domain
	// name to look up.
	Name string `json:"name,omitempty"`

	// The interval at which to refresh the SRV lookup. Results are cached
	// between lookups. Default: 1m.
	Refresh caddy.Duration `json:"refresh,omitempty"`

	// If > 0 and a lookup fails, keep using the cached results instead of
	// returning an error. Note that each failed refresh pushes the window
	// forward, so while the lookup keeps failing the last good results are
	// served for as long as the failures continue, not just for one grace
	// period after they were fetched. Default: 0.
	GracePeriod caddy.Duration `json:"grace_period,omitempty"`

	// Specific network to dial the discovered upstreams on (e.g. "tcp4"); the
	// SRV record only provides host and port. Defaults to "tcp".
	DialNetwork string `json:"dial_network,omitempty"`

	logger    *zap.Logger
	lookupSRV func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)

	resolved dnsResolved
}

// CaddyModule returns the Caddy module information.
func (*SRVUpstreams) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.proxy.upstreams.srv",
		New: func() caddy.Module { return new(SRVUpstreams) },
	}
}

// Provision sets up the SRV upstream source.
func (su *SRVUpstreams) Provision(ctx caddy.Context) error {
	su.logger = ctx.Logger()
	if su.Refresh == 0 {
		su.Refresh = caddy.Duration(time.Minute)
	}
	// Validate proto early so a typo is caught at provision rather than at the
	// first lookup. A placeholder is left for per-connection expansion.
	if su.Proto != "" && !strings.Contains(su.Proto, "{") {
		switch su.Proto {
		case "tcp", "udp":
		default:
			return fmt.Errorf("srv upstreams: proto must be tcp or udp, got %q", su.Proto)
		}
	}
	if su.lookupSRV == nil {
		su.lookupSRV = net.DefaultResolver.LookupSRV
	}
	return nil
}

// GetUpstreams resolves the SRV record (using cached results when fresh) and
// returns one upstream per record.
func (su *SRVUpstreams) GetUpstreams(repl *caddy.Replacer) (UpstreamPool, error) {
	addr, service, proto, name := su.expandedAddr(repl)

	if pool, ok := su.resolved.fresh(time.Duration(su.Refresh)); ok {
		return pool, nil
	}

	su.resolved.mu.Lock()
	defer su.resolved.mu.Unlock()
	if pool, ok := su.resolved.freshLocked(time.Duration(su.Refresh)); ok {
		return pool, nil
	}

	_, records, err := su.lookupSRV(context.Background(), service, proto, name)
	if err != nil && len(records) == 0 {
		// LookupSRV may return some records plus an error for invalid names;
		// only treat it as fatal when nothing usable came back.
		if pool, ok := su.resolved.serveStale(su.GracePeriod, su.Refresh); ok {
			if c := su.logger.Check(zap.ErrorLevel, "SRV lookup failed; using stale cache"); c != nil {
				c.Write(zap.String("addr", addr), zap.Error(err))
			}
			return pool, nil
		}
		return nil, fmt.Errorf("looking up SRV %s: %v", addr, err)
	}

	dialAddrs := make([]string, 0, len(records))
	for _, rec := range records {
		dialAddr := net.JoinHostPort(rec.Target, strconv.Itoa(int(rec.Port)))
		if su.DialNetwork != "" {
			dialAddr = su.DialNetwork + "/" + dialAddr
		}
		dialAddrs = append(dialAddrs, dialAddr)
	}
	return su.resolved.refreshLocked(dialAddrs, su.logger), nil
}

// expandedAddr expands placeholders in the SRV labels and returns the RFC 2782
// address plus the individual service/proto/name used for the lookup. When both
// Service and Proto are empty, Name is treated as the full domain to look up.
func (su *SRVUpstreams) expandedAddr(repl *caddy.Replacer) (addr, service, proto, name string) {
	name = repl.ReplaceAll(su.Name, "")
	if su.Service == "" && su.Proto == "" {
		return name, "", "", name
	}
	service = repl.ReplaceAll(su.Service, "")
	proto = repl.ReplaceAll(su.Proto, "")
	return fmt.Sprintf("_%s._%s.%s", service, proto, name), service, proto, name
}

// Cleanup releases the peer-pool references this source holds. It is called by
// Caddy when the config is unloaded.
func (su *SRVUpstreams) Cleanup() error {
	su.resolved.cleanup()
	return nil
}

// UnmarshalCaddyfile sets up the SRVUpstreams from Caddyfile tokens. Syntax:
//
//	srv [<name>] {
//		service <service>
//		proto <tcp|udp>
//		name <name>
//		refresh <duration>
//		grace_period <duration>
//		dial_network <network>
//	}
func (su *SRVUpstreams) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	if d.NextArg() {
		su.Name = d.Val()
	}
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		option := d.Val()
		switch option {
		case "service":
			if !d.NextArg() {
				return d.ArgErr()
			}
			su.Service = d.Val()
		case "proto":
			if !d.NextArg() {
				return d.ArgErr()
			}
			su.Proto = d.Val()
		case "name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			su.Name = d.Val()
		case "refresh":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing %s option '%s': %v", wrapper, option, err)
			}
			su.Refresh = caddy.Duration(dur)
		case "grace_period":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing %s option '%s': %v", wrapper, option, err)
			}
			su.GracePeriod = caddy.Duration(dur)
		case "dial_network":
			if !d.NextArg() {
				return d.ArgErr()
			}
			su.DialNetwork = d.Val()
		default:
			return d.Errf("unrecognized %s option '%s'", wrapper, option)
		}
	}
	return nil
}

// dnsResolved is the per-source cache for a DNS-based upstream source. It holds
// the last resolved pool with its freshness and the peer-pool references the
// source currently owns (one per dial address in the pool). Keeping this
// per-source rather than in a package-global map means two sources looking up
// the same name with different options (e.g. dial_network) cannot collide, and
// the references can be released deterministically on cleanup.
type dnsResolved struct {
	mu        sync.RWMutex
	freshness time.Time
	pool      UpstreamPool
	refs      map[string]*peer // dial address -> referenced peer
}

// fresh returns the cached pool if it is still fresh, taking only a read lock.
func (r *dnsResolved) fresh(refresh time.Duration) (UpstreamPool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.freshLocked(refresh)
}

func (r *dnsResolved) freshLocked(refresh time.Duration) (UpstreamPool, bool) {
	if !r.freshness.IsZero() && time.Since(r.freshness) < refresh {
		return r.pool, true
	}
	return nil, false
}

// serveStale extends the freshness window by the grace period and returns the
// last good pool, if there is one and grace is enabled. The caller holds the
// write lock.
func (r *dnsResolved) serveStale(grace, refresh caddy.Duration) (UpstreamPool, bool) {
	if grace > 0 && r.pool != nil {
		r.freshness = time.Now().Add(time.Duration(grace) - time.Duration(refresh))
		return r.pool, true
	}
	return nil, false
}

// refreshLocked reconciles the held references to dialAddrs (taking a reference
// for each newly-appearing address and releasing it for each one that dropped
// out), caches the resulting pool as fresh, and returns it. The caller holds
// the write lock.
func (r *dnsResolved) refreshLocked(dialAddrs []string, logger *zap.Logger) UpstreamPool {
	if r.refs == nil {
		r.refs = make(map[string]*peer, len(dialAddrs))
	}

	want := make(map[string]struct{}, len(dialAddrs))
	pool := make(UpstreamPool, 0, len(dialAddrs))
	for _, dialAddr := range dialAddrs {
		p, ok := r.refs[dialAddr]
		if !ok {
			address, err := parseAddress(dialAddr)
			if err != nil {
				if c := logger.Check(zap.WarnLevel, "skipping invalid upstream address"); c != nil {
					c.Write(zap.String("target", dialAddr), zap.Error(err))
				}
				continue
			}
			np := &peer{dialAddr: dialAddr, address: address}
			existing, loaded := peers.LoadOrStore(dialAddr, np)
			if loaded {
				np = existing.(*peer)
			}
			p = np
			r.refs[dialAddr] = p
		}
		want[dialAddr] = struct{}{}
		pool = append(pool, &Upstream{Dial: []string{dialAddr}, peers: []*peer{p}})
	}

	// release references for addresses that are no longer in the results
	for dialAddr := range r.refs {
		if _, ok := want[dialAddr]; !ok {
			_, _ = peers.Delete(dialAddr)
			delete(r.refs, dialAddr)
		}
	}

	r.pool = pool
	r.freshness = time.Now()
	return pool
}

// cleanup releases every peer-pool reference the source holds and resets the
// cache. It is idempotent.
func (r *dnsResolved) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for dialAddr := range r.refs {
		_, _ = peers.Delete(dialAddr)
	}
	r.refs = nil
	r.pool = nil
	r.freshness = time.Time{}
}

// ipUpstreams is the shared implementation behind the `a` and `aaaa` dynamic
// upstream sources, which differ only in the DNS record type they resolve:
// `a` yields IPv4 (A) addresses and `aaaa` yields IPv6 (AAAA) addresses. Since
// plain address records carry no port, every discovered address uses the
// configured Port. This fits clusters where all members share a port (e.g. a
// Postgres cluster on 5432 published behind a single name). Results are cached
// and refreshed; see SRVUpstreams for the per-source caching, reference
// tracking and active-health-check caveats.
type ipUpstreams struct {
	// The domain name to look up.
	Name string `json:"name,omitempty"`

	// The port to use for every discovered address.
	Port string `json:"port,omitempty"`

	// The interval at which to refresh the lookup. Results are cached between
	// lookups. Default: 1m.
	Refresh caddy.Duration `json:"refresh,omitempty"`

	// If > 0 and a lookup fails, keep using the cached results instead of
	// returning an error. As with the srv source, each failed refresh pushes
	// the window forward, so the last good results are served for as long as
	// the failures continue. Default: 0.
	GracePeriod caddy.Duration `json:"grace_period,omitempty"`

	// Specific network to dial the discovered upstreams on (e.g. "tcp4").
	// Defaults to "tcp".
	DialNetwork string `json:"dial_network,omitempty"`

	// network is the IP network passed to the resolver: "ip4" for A records or
	// "ip6" for AAAA records. The concrete source sets it in Provision; it is
	// not part of the JSON config.
	network  string
	logger   *zap.Logger
	lookupIP func(ctx context.Context, network, host string) ([]net.IP, error)

	resolved dnsResolved
}

// provision validates the source and records which IP network (A vs AAAA) it
// resolves. network must be "ip4" or "ip6".
func (u *ipUpstreams) provision(ctx caddy.Context, network string) error {
	u.network = network
	u.logger = ctx.Logger()
	if u.Refresh == 0 {
		u.Refresh = caddy.Duration(time.Minute)
	}
	if u.Port == "" {
		return fmt.Errorf("%s upstreams: port is required", recordLabel(network))
	}
	if u.lookupIP == nil {
		u.lookupIP = net.DefaultResolver.LookupIP
	}
	return nil
}

// GetUpstreams resolves the name's addresses for this source's record type
// (using cached results when fresh) and returns one upstream per address, all
// on the configured port.
func (u *ipUpstreams) GetUpstreams(repl *caddy.Replacer) (UpstreamPool, error) {
	name := repl.ReplaceAll(u.Name, "")
	port := repl.ReplaceAll(u.Port, "")

	if pool, ok := u.resolved.fresh(time.Duration(u.Refresh)); ok {
		return pool, nil
	}

	u.resolved.mu.Lock()
	defer u.resolved.mu.Unlock()
	if pool, ok := u.resolved.freshLocked(time.Duration(u.Refresh)); ok {
		return pool, nil
	}

	ips, err := u.lookupIP(context.Background(), u.network, name)
	if err != nil {
		if pool, ok := u.resolved.serveStale(u.GracePeriod, u.Refresh); ok {
			if c := u.logger.Check(zap.ErrorLevel, "lookup failed; using stale cache"); c != nil {
				c.Write(zap.String("record", recordLabel(u.network)), zap.String("name", name), zap.Error(err))
			}
			return pool, nil
		}
		return nil, fmt.Errorf("looking up %s %s: %v", recordLabel(u.network), name, err)
	}

	dialAddrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		dialAddr := net.JoinHostPort(ip.String(), port)
		if u.DialNetwork != "" {
			dialAddr = u.DialNetwork + "/" + dialAddr
		}
		dialAddrs = append(dialAddrs, dialAddr)
	}
	return u.resolved.refreshLocked(dialAddrs, u.logger), nil
}

// Cleanup releases the peer-pool references this source holds. It is called by
// Caddy when the config is unloaded.
func (u *ipUpstreams) Cleanup() error {
	u.resolved.cleanup()
	return nil
}

// UnmarshalCaddyfile sets up the source from Caddyfile tokens. Syntax:
//
//	<a|aaaa> [<name>] {
//		name <name>
//		port <port>
//		refresh <duration>
//		grace_period <duration>
//		dial_network <network>
//	}
func (u *ipUpstreams) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	if d.NextArg() {
		u.Name = d.Val()
	}
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		option := d.Val()
		switch option {
		case "name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			u.Name = d.Val()
		case "port":
			if !d.NextArg() {
				return d.ArgErr()
			}
			u.Port = d.Val()
		case "refresh":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing %s option '%s': %v", wrapper, option, err)
			}
			u.Refresh = caddy.Duration(dur)
		case "grace_period":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing %s option '%s': %v", wrapper, option, err)
			}
			u.GracePeriod = caddy.Duration(dur)
		case "dial_network":
			if !d.NextArg() {
				return d.ArgErr()
			}
			u.DialNetwork = d.Val()
		default:
			return d.Errf("unrecognized %s option '%s'", wrapper, option)
		}
	}
	return nil
}

// recordLabel maps an IP network ("ip4"/"ip6") to its DNS record / source name.
func recordLabel(network string) string {
	if network == "ip6" {
		return "aaaa"
	}
	return "a"
}

// AUpstreams discovers upstreams from a name's DNS A records (IPv4). For AAAA
// (IPv6) records, use the sibling aaaa source.
type AUpstreams struct {
	ipUpstreams
}

// CaddyModule returns the Caddy module information.
func (*AUpstreams) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.proxy.upstreams.a",
		New: func() caddy.Module { return new(AUpstreams) },
	}
}

// Provision sets up the A (IPv4) upstream source.
func (au *AUpstreams) Provision(ctx caddy.Context) error {
	return au.provision(ctx, "ip4")
}

// AAAAUpstreams discovers upstreams from a name's DNS AAAA records (IPv6). For
// A (IPv4) records, use the sibling a source.
type AAAAUpstreams struct {
	ipUpstreams
}

// CaddyModule returns the Caddy module information.
func (*AAAAUpstreams) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.proxy.upstreams.aaaa",
		New: func() caddy.Module { return new(AAAAUpstreams) },
	}
}

// Provision sets up the AAAA (IPv6) upstream source.
func (au *AAAAUpstreams) Provision(ctx caddy.Context) error {
	return au.provision(ctx, "ip6")
}

// Interface guards
var (
	_ UpstreamSource        = (*SRVUpstreams)(nil)
	_ caddy.Provisioner     = (*SRVUpstreams)(nil)
	_ caddy.CleanerUpper    = (*SRVUpstreams)(nil)
	_ caddyfile.Unmarshaler = (*SRVUpstreams)(nil)

	_ UpstreamSource        = (*AUpstreams)(nil)
	_ caddy.Provisioner     = (*AUpstreams)(nil)
	_ caddy.CleanerUpper    = (*AUpstreams)(nil)
	_ caddyfile.Unmarshaler = (*AUpstreams)(nil)

	_ UpstreamSource        = (*AAAAUpstreams)(nil)
	_ caddy.Provisioner     = (*AAAAUpstreams)(nil)
	_ caddy.CleanerUpper    = (*AAAAUpstreams)(nil)
	_ caddyfile.Unmarshaler = (*AAAAUpstreams)(nil)
)
