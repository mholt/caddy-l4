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
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
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

func aWith(name, port string, addrs []string, err error, calls *int) *AUpstreams {
	return &AUpstreams{
		Name:    name,
		Port:    port,
		Refresh: caddy.Duration(time.Minute),
		logger:  zap.NewNop(),
		lookupHost: func(context.Context, string) ([]string, error) {
			if calls != nil {
				*calls++
			}
			return addrs, err
		},
	}
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

func TestSRVGracePeriodServesStale(t *testing.T) {
	failing := false
	su := &SRVUpstreams{
		Name:        "srv-grace-cov.test",
		Refresh:     caddy.Duration(time.Nanosecond),
		GracePeriod: caddy.Duration(time.Hour),
		logger:      zap.NewNop(),
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
	failing = true // entry is already stale (refresh 1ns); next lookup fails
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
	au := &AUpstreams{
		Name:        "a-grace-cov.test",
		Port:        "5432",
		Refresh:     caddy.Duration(time.Nanosecond),
		GracePeriod: caddy.Duration(time.Hour),
		logger:      zap.NewNop(),
		lookupHost: func(context.Context, string) ([]string, error) {
			if failing {
				return nil, errors.New("dns boom")
			}
			return []string{"10.0.0.1"}, nil
		},
	}
	repl := caddy.NewReplacer()
	if _, err := au.GetUpstreams(repl); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	failing = true
	pool, err := au.GetUpstreams(repl)
	if err != nil {
		t.Fatalf("grace period should suppress the error: %v", err)
	}
	if len(pool) != 1 {
		t.Errorf("expected the stale cached pool to be served, got %d", len(pool))
	}
}

func TestNewDynamicUpstreamInvalid(t *testing.T) {
	// a non-numeric port makes ParseNetworkAddress fail
	if _, err := newDynamicUpstream("host:notaport"); err == nil {
		t.Fatal("expected an error for an invalid dial address")
	}
}

func TestSRVCacheBound(t *testing.T) {
	for i := 0; i < 101; i++ {
		su := srvWith(fmt.Sprintf("srv-bound-%d.test", i), []*net.SRV{{Target: "a.example.", Port: 1}}, nil, nil)
		if _, err := su.GetUpstreams(caddy.NewReplacer()); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	srvCacheMu.RLock()
	n := len(srvCache)
	srvCacheMu.RUnlock()
	if n > 100 {
		t.Errorf("srv cache not bounded: %d entries", n)
	}
}

func TestACacheBound(t *testing.T) {
	for i := 0; i < 101; i++ {
		au := aWith(fmt.Sprintf("a-bound-%d.test", i), "5432", []string{"10.0.0.1"}, nil, nil)
		if _, err := au.GetUpstreams(caddy.NewReplacer()); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	aCacheMu.RLock()
	n := len(aCache)
	aCacheMu.RUnlock()
	if n > 100 {
		t.Errorf("a cache not bounded: %d entries", n)
	}
}
