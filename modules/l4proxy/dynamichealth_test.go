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
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// erroringSource is an UpstreamSource whose GetUpstreams always fails.
type erroringSource struct{}

func (erroringSource) GetUpstreams(*caddy.Replacer) (UpstreamPool, error) {
	return nil, errors.New("discovery failed")
}

// countingListener accepts and closes connections on 127.0.0.1, counting them.
// Each accepted connection is one TCP active health check probe.
func countingListener(t *testing.T) (port string, accepted *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted = new(atomic.Int64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	_, port, err = net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port, accepted
}

// deadPort returns a loopback port nothing listens on.
func deadPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// streaks returns the peer's consecutive success/failure counters.
func streaks(p *peer) (successes, fails int) {
	p.activeHealthMu.Lock()
	defer p.activeHealthMu.Unlock()
	return p.consecSuccesses, p.consecFails
}

func dynamicHealthHandler(src UpstreamSource, active *ActiveHealthChecks) *Handler {
	active.Timeout = caddy.Duration(time.Second)
	active.logger = zap.NewNop()
	return &Handler{
		dynamicUpstreams: src,
		HealthChecks:     &HealthChecks{Active: active},
		logger:           zap.NewNop(),
	}
}

// A discovered peer that answers is actually probed, and the result goes
// through the same recordActiveCheck path as a static peer's.
func TestActiveHealthCheckProbesDynamicPeer(t *testing.T) {
	port, accepted := countingListener(t)
	au := aWith("live.dyn-health.test", port, []string{"127.0.0.1"}, nil, nil)
	t.Cleanup(func() { _ = au.Cleanup() })
	h := dynamicHealthHandler(au, &ActiveHealthChecks{Rise: 2})

	pool, err := au.GetUpstreams(caddy.NewReplacer())
	if err != nil || len(pool) != 1 || len(pool[0].peers) != 1 {
		t.Fatalf("expected one discovered peer, got %d (err %v)", len(pool), err)
	}
	p := pool[0].peers[0]

	h.doActiveHealthCheckForAllHosts()
	waitFor(t, "first probe recorded", func() bool { s, _ := streaks(p); return s == 1 })
	if got := accepted.Load(); got != 1 {
		t.Errorf("probes accepted = %d, want 1", got)
	}
	if !p.healthy() {
		t.Error("answering peer must stay healthy")
	}

	h.doActiveHealthCheckForAllHosts()
	waitFor(t, "second probe recorded", func() bool { s, _ := streaks(p); return s == 2 })
	if got := accepted.Load(); got != 2 {
		t.Errorf("probes accepted = %d, want 2", got)
	}
}

// A dead discovered peer is marked unhealthy only after health_fall
// consecutive failures, and a recovered one only after health_rise successes.
func TestActiveHealthCheckDynamicPeerFallAndRise(t *testing.T) {
	port := deadPort(t)
	au := aWith("flap.dyn-health.test", port, []string{"127.0.0.1"}, nil, nil)
	t.Cleanup(func() { _ = au.Cleanup() })
	h := dynamicHealthHandler(au, &ActiveHealthChecks{Fall: 2, Rise: 2})

	pool, err := au.GetUpstreams(caddy.NewReplacer())
	if err != nil || len(pool) != 1 {
		t.Fatalf("GetUpstreams: %v (%d upstreams)", err, len(pool))
	}
	p := pool[0].peers[0]
	if !p.healthy() {
		t.Fatal("peer should start healthy")
	}

	h.doActiveHealthCheckForAllHosts()
	waitFor(t, "first failure recorded", func() bool { _, f := streaks(p); return f == 1 })
	if !p.healthy() {
		t.Fatal("one failure < health_fall: peer must still be healthy")
	}

	h.doActiveHealthCheckForAllHosts()
	waitFor(t, "peer marked down", func() bool { return !p.healthy() })

	// bring the backend up on the very port the peer dials
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Skipf("cannot re-bind port %s: %v", port, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	h.doActiveHealthCheckForAllHosts()
	waitFor(t, "first success recorded", func() bool { s, _ := streaks(p); return s == 1 })
	if p.healthy() {
		t.Fatal("one success < health_rise: peer must still be down")
	}
	h.doActiveHealthCheckForAllHosts()
	waitFor(t, "peer marked up", func() bool { return p.healthy() })
}

// When discovery fails the pass must not panic or stop the static upstreams
// from being checked.
func TestActiveHealthCheckDynamicSourceError(t *testing.T) {
	port, accepted := countingListener(t)
	addr, err := parseAddress("127.0.0.1:" + port)
	if err != nil {
		t.Fatal(err)
	}
	sp := &peer{dialAddr: "127.0.0.1:" + port, address: addr}
	h := dynamicHealthHandler(erroringSource{}, &ActiveHealthChecks{})
	h.Upstreams = UpstreamPool{{Dial: []string{sp.dialAddr}, peers: []*peer{sp}}}

	h.doActiveHealthCheckForAllHosts()
	waitFor(t, "static peer probed", func() bool { return accepted.Load() == 1 })
}

// Static and dynamic upstreams are both checked in one pass.
func TestActiveHealthCheckStaticAndDynamic(t *testing.T) {
	dynPort, dynAccepted := countingListener(t)
	statPort, statAccepted := countingListener(t)
	au := aWith("both.dyn-health.test", dynPort, []string{"127.0.0.1"}, nil, nil)
	t.Cleanup(func() { _ = au.Cleanup() })

	addr, err := parseAddress("127.0.0.1:" + statPort)
	if err != nil {
		t.Fatal(err)
	}
	sp := &peer{dialAddr: "127.0.0.1:" + statPort, address: addr}
	h := dynamicHealthHandler(au, &ActiveHealthChecks{})
	h.Upstreams = UpstreamPool{{Dial: []string{sp.dialAddr}, peers: []*peer{sp}}}

	h.doActiveHealthCheckForAllHosts()
	waitFor(t, "both probed", func() bool { return dynAccepted.Load() == 1 && statAccepted.Load() == 1 })
}

// A peer reachable both statically and dynamically is probed once per pass, so
// health_rise/health_fall are not double-counted.
func TestActiveHealthCheckProbesSharedPeerOnce(t *testing.T) {
	port, accepted := countingListener(t)
	au := aWith("shared.dyn-health.test", port, []string{"127.0.0.1"}, nil, nil)
	t.Cleanup(func() { _ = au.Cleanup() })
	h := dynamicHealthHandler(au, &ActiveHealthChecks{Rise: 5})

	pool, err := au.GetUpstreams(caddy.NewReplacer())
	if err != nil || len(pool) != 1 {
		t.Fatalf("GetUpstreams: %v (%d upstreams)", err, len(pool))
	}
	p := pool[0].peers[0]
	h.Upstreams = UpstreamPool{{Dial: []string{p.dialAddr}, peers: []*peer{p}}}

	h.doActiveHealthCheckForAllHosts()
	waitFor(t, "probe recorded", func() bool { s, _ := streaks(p); return s >= 1 })
	time.Sleep(100 * time.Millisecond) // a duplicate probe would land by now
	if s, _ := streaks(p); s != 1 {
		t.Errorf("success streak = %d, want 1 (peer probed once)", s)
	}
	if got := accepted.Load(); got != 1 {
		t.Errorf("probes accepted = %d, want 1", got)
	}
}

// End to end: a provisioned handler with a dynamic source and active health
// checks has its background checker probe the discovered peer on every tick.
func TestProvisionedHandlerChecksDynamicPeersOnTimer(t *testing.T) {
	port, accepted := countingListener(t)
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	h := &Handler{
		DynamicUpstreamsRaw: []byte(`{"source":"a","name":"localhost","port":"` + port + `"}`),
		HealthChecks: &HealthChecks{Active: &ActiveHealthChecks{
			Interval: caddy.Duration(50 * time.Millisecond),
			Timeout:  caddy.Duration(time.Second),
		}},
	}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() { _ = h.Cleanup() })
	if len(h.Upstreams) != 0 {
		t.Fatalf("test needs an empty static list, got %d upstreams", len(h.Upstreams))
	}
	// the initial pass plus at least two ticks, all against the discovered peer
	waitFor(t, "repeated probes of the discovered peer", func() bool { return accepted.Load() >= 3 })
}
