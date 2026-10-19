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
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func srvWith(name string, recs []*net.SRV, err error, calls *int) *SRVUpstreams {
	return &SRVUpstreams{
		Name:    name,
		Refresh: caddy.Duration(time.Minute),
		logger:  zap.NewNop(),
		lookupSRV: func(context.Context, string, string, string) (string, []*net.SRV, error) {
			if calls != nil {
				*calls++
			}
			return "", recs, err
		},
	}
}

func TestSRVGetUpstreamsDiscoversRecords(t *testing.T) {
	recs := []*net.SRV{
		{Target: "db1.example.", Port: 5432},
		{Target: "db2.example.", Port: 5433},
	}
	calls := 0
	su := srvWith("srv-discover.test", recs, nil, &calls)

	pool, err := su.GetUpstreams(caddy.NewReplacer())
	if err != nil {
		t.Fatalf("getUpstreams: %v", err)
	}
	if len(pool) != 2 {
		t.Fatalf("pool length = %d, want 2", len(pool))
	}
	want := []string{"db1.example.:5432", "db2.example.:5433"}
	for i, w := range want {
		if pool[i].Dial[0] != w {
			t.Errorf("dial[%d] = %q, want %q", i, pool[i].Dial[0], w)
		}
		if len(pool[i].peers) != 1 {
			t.Errorf("upstream %d has %d peers, want 1", i, len(pool[i].peers))
		}
	}
	if calls != 1 {
		t.Errorf("lookup calls = %d, want 1", calls)
	}
}

func TestSRVGetUpstreamsCaches(t *testing.T) {
	calls := 0
	su := srvWith("srv-cache.test", []*net.SRV{{Target: "x.", Port: 1}}, nil, &calls)
	repl := caddy.NewReplacer()

	if _, err := su.GetUpstreams(repl); err != nil {
		t.Fatal(err)
	}
	if _, err := su.GetUpstreams(repl); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("lookup calls = %d, want 1 (second call should hit cache)", calls)
	}
}

func TestSRVGetUpstreamsLookupError(t *testing.T) {
	su := srvWith("srv-error.test", nil, errors.New("dns boom"), nil)
	if _, err := su.GetUpstreams(caddy.NewReplacer()); err == nil {
		t.Fatal("expected an error when lookup fails and nothing is cached")
	}
}

func TestSRVExpandedAddr(t *testing.T) {
	repl := caddy.NewReplacer()

	su := &SRVUpstreams{Service: "postgres", Proto: "tcp", Name: "db.local"}
	addr, service, proto, name := su.expandedAddr(repl)
	if addr != "_postgres._tcp.db.local" {
		t.Errorf("addr = %q, want _postgres._tcp.db.local", addr)
	}
	if service != "postgres" || proto != "tcp" || name != "db.local" {
		t.Errorf("parts = %q/%q/%q", service, proto, name)
	}

	// service+proto empty: Name is the full domain
	suName := &SRVUpstreams{Name: "_custom._tcp.svc"}
	addr2, _, _, name2 := suName.expandedAddr(repl)
	if addr2 != "_custom._tcp.svc" || name2 != "_custom._tcp.svc" {
		t.Errorf("name-only addr = %q, name = %q", addr2, name2)
	}
}

func TestUnmarshalCaddyfileDynamicSRV(t *testing.T) {
	d := caddyfile.NewTestDispenser("proxy {\n" +
		"\tdynamic srv {\n" +
		"\t\tservice postgres\n" +
		"\t\tproto tcp\n" +
		"\t\tname db.local\n" +
		"\t\trefresh 30s\n" +
		"\t}\n" +
		"}")
	h := new(Handler)
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(h.DynamicUpstreamsRaw) == 0 {
		t.Fatal("DynamicUpstreamsRaw was not set")
	}
	var m map[string]any
	if err := json.Unmarshal(h.DynamicUpstreamsRaw, &m); err != nil {
		t.Fatalf("decoding DynamicUpstreamsRaw: %v", err)
	}
	if m["source"] != "srv" {
		t.Errorf("source = %v, want srv", m["source"])
	}
	if m["service"] != "postgres" || m["name"] != "db.local" {
		t.Errorf("parsed fields wrong: %v", m)
	}
}

func TestUnmarshalCaddyfileDynamicErrors(t *testing.T) {
	cases := map[string]string{
		"missing source": "proxy {\n\tdynamic\n}",
		"unknown source": "proxy {\n\tdynamic nope\n}",
		"bad srv option": "proxy {\n\tdynamic srv {\n\t\tbogus x\n\t}\n}",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			h := new(Handler)
			if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatalf("expected an error for %q, got nil", name)
			}
		})
	}
}

func ipsFromStrings(addrs []string) []net.IP {
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, net.ParseIP(a))
	}
	return ips
}

// ipSourceWith builds an A (network "ip4") or AAAA (network "ip6") source whose
// resolver returns the given addresses.
func ipSourceWith(network, name, port string, addrs []string, err error, calls *int) *ipUpstreams {
	return &ipUpstreams{
		Name:    name,
		Port:    port,
		Refresh: caddy.Duration(time.Minute),
		network: network,
		logger:  zap.NewNop(),
		lookupIP: func(context.Context, string, string) ([]net.IP, error) {
			if calls != nil {
				*calls++
			}
			return ipsFromStrings(addrs), err
		},
	}
}

func aWith(name, port string, addrs []string, err error, calls *int) *ipUpstreams {
	return ipSourceWith("ip4", name, port, addrs, err, calls)
}

func TestAGetUpstreamsDiscoversAddresses(t *testing.T) {
	calls := 0
	au := aWith("db.a-discover.test", "5432", []string{"10.0.0.1", "10.0.0.2"}, nil, &calls)

	pool, err := au.GetUpstreams(caddy.NewReplacer())
	if err != nil {
		t.Fatalf("GetUpstreams: %v", err)
	}
	if len(pool) != 2 {
		t.Fatalf("pool length = %d, want 2", len(pool))
	}
	want := []string{"10.0.0.1:5432", "10.0.0.2:5432"}
	for i, w := range want {
		if pool[i].Dial[0] != w {
			t.Errorf("dial[%d] = %q, want %q", i, pool[i].Dial[0], w)
		}
	}
	if calls != 1 {
		t.Errorf("lookup calls = %d, want 1", calls)
	}
}

func TestAGetUpstreamsCaches(t *testing.T) {
	calls := 0
	au := aWith("db.a-cache.test", "5432", []string{"10.0.0.9"}, nil, &calls)
	repl := caddy.NewReplacer()

	if _, err := au.GetUpstreams(repl); err != nil {
		t.Fatal(err)
	}
	if _, err := au.GetUpstreams(repl); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("lookup calls = %d, want 1 (second call should hit cache)", calls)
	}
}

func TestAAAAGetUpstreamsDiscoversAddresses(t *testing.T) {
	calls := 0
	au := ipSourceWith("ip6", "db.aaaa-discover.test", "5432", []string{"2001:db8::1", "2001:db8::2"}, nil, &calls)

	pool, err := au.GetUpstreams(caddy.NewReplacer())
	if err != nil {
		t.Fatalf("GetUpstreams: %v", err)
	}
	if len(pool) != 2 {
		t.Fatalf("pool length = %d, want 2", len(pool))
	}
	want := []string{"[2001:db8::1]:5432", "[2001:db8::2]:5432"}
	for i, w := range want {
		if pool[i].Dial[0] != w {
			t.Errorf("dial[%d] = %q, want %q", i, pool[i].Dial[0], w)
		}
	}
	if calls != 1 {
		t.Errorf("lookup calls = %d, want 1", calls)
	}
}

// TestAAndAAAADoNotShareCacheEntries guards the record type being part of the
// cache key: the a and aaaa sources share one cache, so the same name:port must
// not let one serve the other's addresses.
func TestAAndAAAADoNotShareCacheEntries(t *testing.T) {
	const name, port = "db.ab-collide.test", "5432"
	a := ipSourceWith("ip4", name, port, []string{"10.0.0.1"}, nil, nil)
	aaaa := ipSourceWith("ip6", name, port, []string{"2001:db8::1"}, nil, nil)
	repl := caddy.NewReplacer()

	aPool, err := a.GetUpstreams(repl)
	if err != nil {
		t.Fatalf("a GetUpstreams: %v", err)
	}
	aaaaPool, err := aaaa.GetUpstreams(repl)
	if err != nil {
		t.Fatalf("aaaa GetUpstreams: %v", err)
	}
	if aPool[0].Dial[0] != "10.0.0.1:5432" {
		t.Errorf("a dial = %q, want 10.0.0.1:5432", aPool[0].Dial[0])
	}
	if aaaaPool[0].Dial[0] != "[2001:db8::1]:5432" {
		t.Errorf("aaaa dial = %q, want [2001:db8::1]:5432 (a's cached entry leaked)", aaaaPool[0].Dial[0])
	}
}

func TestUnmarshalCaddyfileDynamicA(t *testing.T) {
	d := caddyfile.NewTestDispenser("proxy {\n" +
		"\tdynamic a {\n" +
		"\t\tname db.local\n" +
		"\t\tport 5432\n" +
		"\t\trefresh 15s\n" +
		"\t}\n" +
		"}")
	h := new(Handler)
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(h.DynamicUpstreamsRaw, &m); err != nil {
		t.Fatalf("decoding DynamicUpstreamsRaw: %v", err)
	}
	if m["source"] != "a" {
		t.Errorf("source = %v, want a", m["source"])
	}
	if m["name"] != "db.local" || m["port"] != "5432" {
		t.Errorf("parsed fields wrong: %v", m)
	}
}

func TestUnmarshalCaddyfileDynamicAAAA(t *testing.T) {
	d := caddyfile.NewTestDispenser("proxy {\n" +
		"\tdynamic aaaa {\n" +
		"\t\tname db.local\n" +
		"\t\tport 5432\n" +
		"\t\trefresh 15s\n" +
		"\t}\n" +
		"}")
	h := new(Handler)
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(h.DynamicUpstreamsRaw, &m); err != nil {
		t.Fatalf("decoding DynamicUpstreamsRaw: %v", err)
	}
	if m["source"] != "aaaa" {
		t.Errorf("source = %v, want aaaa", m["source"])
	}
	if m["name"] != "db.local" || m["port"] != "5432" {
		t.Errorf("parsed fields wrong: %v", m)
	}
}

// expire resets a per-source cache so the next GetUpstreams re-resolves,
// deterministically. Forcing staleness via a tiny Refresh instead is unreliable
// on a platform with a coarse monotonic clock (Windows), where time.Since can
// read 0 between two rapid calls so the entry still counts as fresh and the
// refresh is skipped.
func expire(r *dnsResolved) {
	r.mu.Lock()
	r.freshness = time.Time{}
	r.mu.Unlock()
}

func TestSRVGracePeriodServesStale(t *testing.T) {
	failing := false
	su := &SRVUpstreams{
		Name:        "srv-grace-cov.test",
		Refresh:     caddy.Duration(time.Minute),
		GracePeriod: caddy.Duration(time.Hour),
		logger:      zaptest.NewLogger(t), // enabled, so the grace-path log line runs
		lookupSRV: func(context.Context, string, string, string) (string, []*net.SRV, error) {
			if failing {
				return "", nil, errors.New("dns boom")
			}
			return "", []*net.SRV{{Target: "a.example.", Port: 1}}, nil
		},
	}
	repl := caddy.NewReplacer()
	if _, err := su.GetUpstreams(repl); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	failing = true
	expire(&su.resolved) // force the next lookup to run (and fail)
	pool, err := su.GetUpstreams(repl)
	if err != nil {
		t.Fatalf("grace period should suppress the error: %v", err)
	}
	if len(pool) != 1 {
		t.Errorf("expected the stale cached pool to be served, got %d", len(pool))
	}
}

func TestAGracePeriodServesStale(t *testing.T) {
	failing := false
	au := &ipUpstreams{
		Name:        "a-grace-cov.test",
		Port:        "5432",
		Refresh:     caddy.Duration(time.Minute),
		GracePeriod: caddy.Duration(time.Hour),
		network:     "ip4",
		logger:      zaptest.NewLogger(t), // enabled, so the grace-path log line runs
		lookupIP: func(context.Context, string, string) ([]net.IP, error) {
			if failing {
				return nil, errors.New("dns boom")
			}
			return []net.IP{net.ParseIP("10.0.0.1")}, nil
		},
	}
	repl := caddy.NewReplacer()
	if _, err := au.GetUpstreams(repl); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	failing = true
	expire(&au.resolved) // force the next lookup to run (and fail)
	pool, err := au.GetUpstreams(repl)
	if err != nil {
		t.Fatalf("grace period should suppress the error: %v", err)
	}
	if len(pool) != 1 {
		t.Errorf("expected the stale cached pool to be served, got %d", len(pool))
	}
}

func TestIPSkipsInvalidAddress(t *testing.T) {
	// a non-numeric port makes the dial address unparseable; it must be skipped
	// rather than added to the pool. An enabled logger is used so the "skipping"
	// log line is exercised too.
	au := &ipUpstreams{
		Name:    "skip.test",
		Port:    "notaport",
		network: "ip4",
		Refresh: caddy.Duration(time.Minute),
		logger:  zaptest.NewLogger(t),
		lookupIP: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.0.0.1")}, nil
		},
	}
	pool, err := au.GetUpstreams(caddy.NewReplacer())
	if err != nil {
		t.Fatalf("GetUpstreams: %v", err)
	}
	if len(pool) != 0 {
		t.Fatalf("pool length = %d, want 0 (invalid address must be skipped)", len(pool))
	}
}

// TestSRVReleasesDroppedPeerReferences guards the fix for the peer-pool
// reference leak: a stable address keeps exactly one reference across
// refreshes (no per-refresh increment), an address that drops out of the
// results has its reference released, and Cleanup releases what remains.
func TestSRVReleasesDroppedPeerReferences(t *testing.T) {
	stable := &net.SRV{Target: "stable.ref-test.", Port: 7101}
	gone := &net.SRV{Target: "gone.ref-test.", Port: 7102}
	records := []*net.SRV{stable, gone}
	su := &SRVUpstreams{
		Name:    "ref-test.svc",
		Refresh: caddy.Duration(time.Minute),
		logger:  zap.NewNop(),
		lookupSRV: func(context.Context, string, string, string) (string, []*net.SRV, error) {
			return "", records, nil
		},
	}
	repl := caddy.NewReplacer()

	const stableAddr, goneAddr = "stable.ref-test.:7101", "gone.ref-test.:7102"

	// Make sure no references survive this test even if an assertion fails, so
	// the shared peer pool stays clean for other tests.
	t.Cleanup(func() {
		_, _ = peers.Delete(stableAddr)
		_, _ = peers.Delete(goneAddr)
	})

	if _, err := su.GetUpstreams(repl); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if n, ok := peers.References(stableAddr); !ok || n != 1 {
		t.Fatalf("stable refs = %d (present=%v), want 1", n, ok)
	}
	if n, ok := peers.References(goneAddr); !ok || n != 1 {
		t.Fatalf("gone refs = %d (present=%v), want 1", n, ok)
	}

	// second target drops out of the results
	records = []*net.SRV{stable}
	expire(&su.resolved)
	if _, err := su.GetUpstreams(repl); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if n, ok := peers.References(stableAddr); !ok || n != 1 {
		t.Fatalf("stable refs after refresh = %d (present=%v), want 1 (no per-refresh leak)", n, ok)
	}
	if n, ok := peers.References(goneAddr); ok {
		t.Fatalf("dropped target still referenced after refresh: refs=%d", n)
	}

	// cleanup releases the remaining reference
	if err := su.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n, ok := peers.References(stableAddr); ok {
		t.Fatalf("stable target still referenced after cleanup: refs=%d", n)
	}
}

func TestSRVProvisionValidatesProto(t *testing.T) {
	cases := []struct {
		proto   string
		wantErr bool
	}{
		{"tcp", false},
		{"udp", false},
		{"", false},
		{"{env.PROTO}", false}, // placeholder is validated later, not at provision
		{"sctp", true},
		{"TCP", true}, // case-sensitive
	}
	for _, c := range cases {
		t.Run(c.proto, func(t *testing.T) {
			su := &SRVUpstreams{Name: "x", Proto: c.proto}
			err := su.Provision(caddy.Context{})
			if (err != nil) != c.wantErr {
				t.Fatalf("proto %q: err=%v, wantErr=%v", c.proto, err, c.wantErr)
			}
			if !c.wantErr && su.Refresh != caddy.Duration(time.Minute) {
				t.Errorf("refresh not defaulted: %v", time.Duration(su.Refresh))
			}
		})
	}
}

func TestIPUpstreamsProvision(t *testing.T) {
	t.Run("a sets ip4 and defaults refresh", func(t *testing.T) {
		au := &AUpstreams{}
		au.Port = "5432"
		if err := au.Provision(caddy.Context{}); err != nil {
			t.Fatalf("provision: %v", err)
		}
		if au.network != "ip4" {
			t.Errorf("network = %q, want ip4", au.network)
		}
		if au.Refresh != caddy.Duration(time.Minute) {
			t.Errorf("refresh not defaulted: %v", time.Duration(au.Refresh))
		}
	})
	t.Run("aaaa sets ip6", func(t *testing.T) {
		au := &AAAAUpstreams{}
		au.Port = "5432"
		if err := au.Provision(caddy.Context{}); err != nil {
			t.Fatalf("provision: %v", err)
		}
		if au.network != "ip6" {
			t.Errorf("network = %q, want ip6", au.network)
		}
	})
	// Port is required; the error names the record type (exercises recordLabel
	// for both "a" and "aaaa").
	t.Run("a requires port", func(t *testing.T) {
		if err := (&AUpstreams{}).Provision(caddy.Context{}); err == nil {
			t.Fatal("expected an error when port is missing")
		}
	})
	t.Run("aaaa requires port", func(t *testing.T) {
		if err := (&AAAAUpstreams{}).Provision(caddy.Context{}); err == nil {
			t.Fatal("expected an error when port is missing")
		}
	})
}

func TestIPUpstreamsCleanupReleasesReferences(t *testing.T) {
	au := ipSourceWith("ip4", "db.aclean.test", "5533", []string{"10.1.2.3"}, nil, nil)
	const addr = "10.1.2.3:5533"
	t.Cleanup(func() { _, _ = peers.Delete(addr) })

	if _, err := au.GetUpstreams(caddy.NewReplacer()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := peers.References(addr); !ok {
		t.Fatal("expected a reference after resolve")
	}
	if err := au.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n, ok := peers.References(addr); ok {
		t.Errorf("reference not released by Cleanup: refs=%d", n)
	}
}

func TestUnmarshalCaddyfileDynamicSRVAllOptions(t *testing.T) {
	d := caddyfile.NewTestDispenser("proxy {\n" +
		"\tdynamic srv the-arg-name {\n" +
		"\t\tservice pg\n" +
		"\t\tproto tcp\n" +
		"\t\tname db.local\n" +
		"\t\trefresh 2m\n" +
		"\t\tgrace_period 30s\n" +
		"\t\tdial_network tcp4\n" +
		"\t}\n" +
		"}")
	h := new(Handler)
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(h.DynamicUpstreamsRaw, &m); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	for k, want := range map[string]string{
		"source": "srv", "service": "pg", "proto": "tcp",
		"name": "db.local", "dial_network": "tcp4",
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v", k, m[k], want)
		}
	}
	// caddy.Duration marshals to integer nanoseconds.
	for k, want := range map[string]float64{
		"refresh": float64(2 * time.Minute), "grace_period": float64(30 * time.Second),
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v", k, m[k], want)
		}
	}
}

func TestUnmarshalCaddyfileDynamicAAllOptions(t *testing.T) {
	d := caddyfile.NewTestDispenser("proxy {\n" +
		"\tdynamic a the-arg-name {\n" +
		"\t\tname db.local\n" +
		"\t\tport 5432\n" +
		"\t\trefresh 90s\n" +
		"\t\tgrace_period 10s\n" +
		"\t\tdial_network tcp4\n" +
		"\t}\n" +
		"}")
	h := new(Handler)
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(h.DynamicUpstreamsRaw, &m); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	for k, want := range map[string]string{
		"source": "a", "name": "db.local", "port": "5432", "dial_network": "tcp4",
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v", k, m[k], want)
		}
	}
	for k, want := range map[string]float64{
		"refresh": float64(90 * time.Second), "grace_period": float64(10 * time.Second),
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v", k, m[k], want)
		}
	}
}

func TestDialNetworkPrefixesDiscoveredAddresses(t *testing.T) {
	t.Run("srv", func(t *testing.T) {
		su := &SRVUpstreams{
			Name:        "dn-srv.test",
			Refresh:     caddy.Duration(time.Minute),
			DialNetwork: "tcp4",
			logger:      zap.NewNop(),
			lookupSRV: func(context.Context, string, string, string) (string, []*net.SRV, error) {
				return "", []*net.SRV{{Target: "h.example.", Port: 9}}, nil
			},
		}
		t.Cleanup(func() { _, _ = peers.Delete("tcp4/h.example.:9") })
		pool, err := su.GetUpstreams(caddy.NewReplacer())
		if err != nil {
			t.Fatalf("GetUpstreams: %v", err)
		}
		if len(pool) != 1 || pool[0].Dial[0] != "tcp4/h.example.:9" {
			t.Fatalf("dial = %v, want [tcp4/h.example.:9]", pool)
		}
	})
	t.Run("a", func(t *testing.T) {
		au := &ipUpstreams{
			Name:        "dn-a.test",
			Port:        "9",
			network:     "ip4",
			Refresh:     caddy.Duration(time.Minute),
			DialNetwork: "tcp4",
			logger:      zap.NewNop(),
			lookupIP: func(context.Context, string, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("10.9.9.9")}, nil
			},
		}
		t.Cleanup(func() { _, _ = peers.Delete("tcp4/10.9.9.9:9") })
		pool, err := au.GetUpstreams(caddy.NewReplacer())
		if err != nil {
			t.Fatalf("GetUpstreams: %v", err)
		}
		if len(pool) != 1 || pool[0].Dial[0] != "tcp4/10.9.9.9:9" {
			t.Fatalf("dial = %v, want [tcp4/10.9.9.9:9]", pool)
		}
	})
}

func TestIPLookupErrorWithoutGrace(t *testing.T) {
	au := ipSourceWith("ip4", "err-a.test", "5432", nil, errors.New("dns down"), nil)
	if _, err := au.GetUpstreams(caddy.NewReplacer()); err == nil {
		t.Fatal("expected an error when lookup fails and grace is disabled")
	}
}

func TestUnmarshalCaddyfileDynamicDNSErrors(t *testing.T) {
	cases := map[string]string{
		"srv unknown option":     "proxy {\n\tdynamic srv {\n\t\tbogus x\n\t}\n}",
		"srv bad refresh":        "proxy {\n\tdynamic srv {\n\t\trefresh notaduration\n\t}\n}",
		"srv bad grace":          "proxy {\n\tdynamic srv {\n\t\tgrace_period nope\n\t}\n}",
		"srv service no arg":     "proxy {\n\tdynamic srv {\n\t\tservice\n\t}\n}",
		"srv proto no arg":       "proxy {\n\tdynamic srv {\n\t\tproto\n\t}\n}",
		"srv name no arg":        "proxy {\n\tdynamic srv {\n\t\tname\n\t}\n}",
		"srv refresh no arg":     "proxy {\n\tdynamic srv {\n\t\trefresh\n\t}\n}",
		"srv grace no arg":       "proxy {\n\tdynamic srv {\n\t\tgrace_period\n\t}\n}",
		"srv dial_network noarg": "proxy {\n\tdynamic srv {\n\t\tdial_network\n\t}\n}",
		"srv too many args":      "proxy {\n\tdynamic srv a b\n}",
		"a unknown option":       "proxy {\n\tdynamic a {\n\t\tbogus x\n\t}\n}",
		"a bad refresh":          "proxy {\n\tdynamic a {\n\t\trefresh notaduration\n\t}\n}",
		"a bad grace":            "proxy {\n\tdynamic a {\n\t\tgrace_period nope\n\t}\n}",
		"a port no arg":          "proxy {\n\tdynamic a {\n\t\tport\n\t}\n}",
		"a name no arg":          "proxy {\n\tdynamic a {\n\t\tname\n\t}\n}",
		"a refresh no arg":       "proxy {\n\tdynamic a {\n\t\trefresh\n\t}\n}",
		"a grace no arg":         "proxy {\n\tdynamic a {\n\t\tgrace_period\n\t}\n}",
		"a dial_network no arg":  "proxy {\n\tdynamic a {\n\t\tdial_network\n\t}\n}",
		"a too many args":        "proxy {\n\tdynamic a x y\n}",
		"aaaa unknown option":    "proxy {\n\tdynamic aaaa {\n\t\tbogus x\n\t}\n}",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			h := new(Handler)
			if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatalf("expected an error for %q, got nil", name)
			}
		})
	}
}
