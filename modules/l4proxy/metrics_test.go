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
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

func TestProxyMetricsConnections(t *testing.T) {
	m := newProxyMetrics(prometheus.NewRegistry())

	m.connectionOpened("up1")
	m.connectionOpened("up1")
	if got := testutil.ToFloat64(m.connectionsTotal.WithLabelValues("up1")); got != 2 {
		t.Errorf("connections_total = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.activeConns.WithLabelValues("up1")); got != 2 {
		t.Errorf("active_connections = %v, want 2", got)
	}

	m.connectionClosed("up1")
	if got := testutil.ToFloat64(m.activeConns.WithLabelValues("up1")); got != 1 {
		t.Errorf("active_connections after one close = %v, want 1", got)
	}
}

func TestProxyMetricsHealth(t *testing.T) {
	m := newProxyMetrics(prometheus.NewRegistry())

	m.setUpstreamHealthy("p1", true)
	if got := testutil.ToFloat64(m.upstreamHealthy.WithLabelValues("p1")); got != 1 {
		t.Errorf("upstream_healthy = %v, want 1", got)
	}
	m.setUpstreamHealthy("p1", false)
	if got := testutil.ToFloat64(m.upstreamHealthy.WithLabelValues("p1")); got != 0 {
		t.Errorf("upstream_healthy = %v, want 0", got)
	}
}

func TestProxyMetricsNilSafe(t *testing.T) {
	var m *proxyMetrics // a handler that was never provisioned
	m.connectionOpened("x")
	m.connectionClosed("x")
	m.setUpstreamHealthy("x", true)
}

// TestProxyMetricsDuplicateRegistration reproduces issue #445: multiple proxy
// handlers share one instance registry, so provisioning a second one must not
// panic on a duplicate collector registration, and both must share the same
// underlying collectors.
func TestProxyMetricsDuplicateRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()

	m1 := newProxyMetrics(reg)
	m2 := newProxyMetrics(reg) // previously panicked: "duplicate metrics collector registration attempted"

	m1.connectionOpened("up")
	m2.connectionOpened("up")

	// Both handlers write to the same registered collector.
	if got := testutil.ToFloat64(m1.connectionsTotal.WithLabelValues("up")); got != 2 {
		t.Errorf("connections_total = %v, want 2 (collectors must be shared)", got)
	}
	if m1.connectionsTotal != m2.connectionsTotal {
		t.Error("expected the second proxy handler to reuse the existing collector")
	}
}

func TestActiveHealthCheckUpdatesHealthMetricDown(t *testing.T) {
	addr, err := caddy.ParseNetworkAddress("127.0.0.1:1") // nothing listening
	if err != nil {
		t.Fatalf("parsing address: %v", err)
	}
	p := &peer{address: &addr, dialAddr: "127.0.0.1:1"}
	h := &Handler{
		metrics: newProxyMetrics(prometheus.NewRegistry()),
		HealthChecks: &HealthChecks{Active: &ActiveHealthChecks{
			Timeout: caddy.Duration(200 * time.Millisecond),
			logger:  zap.NewNop(),
		}},
	}
	h.metrics.setUpstreamHealthy(p.dialAddr, true) // pretend it was healthy

	if err := h.doActiveHealthCheck(&Upstream{peers: []*peer{p}}, p); err != nil {
		t.Fatalf("health check: %v", err)
	}
	if got := testutil.ToFloat64(h.metrics.upstreamHealthy.WithLabelValues(p.dialAddr)); got != 0 {
		t.Errorf("upstream_healthy after failed check = %v, want 0", got)
	}
}

func TestActiveHealthCheckUpdatesHealthMetricUp(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	addr, err := caddy.ParseNetworkAddress(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing address: %v", err)
	}
	p := &peer{address: &addr, dialAddr: ln.Addr().String()}
	h := &Handler{
		metrics: newProxyMetrics(prometheus.NewRegistry()),
		HealthChecks: &HealthChecks{Active: &ActiveHealthChecks{
			Timeout: caddy.Duration(time.Second),
			logger:  zap.NewNop(),
		}},
	}

	if err := h.doActiveHealthCheck(&Upstream{peers: []*peer{p}}, p); err != nil {
		t.Fatalf("health check: %v", err)
	}
	if got := testutil.ToFloat64(h.metrics.upstreamHealthy.WithLabelValues(p.dialAddr)); got != 1 {
		t.Errorf("upstream_healthy after successful check = %v, want 1", got)
	}
}
