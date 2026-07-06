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
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// proxyMetrics holds the Prometheus collectors for a proxy handler. They are
// registered against the instance's metrics registry (obtained from the Caddy
// context) so they reset cleanly across config reloads.
type proxyMetrics struct {
	connectionsTotal *prometheus.CounterVec
	activeConns      *prometheus.GaugeVec
	upstreamHealthy  *prometheus.GaugeVec
}

// registerOrExisting registers c on reg, or returns the already-registered
// equivalent collector if an identical one is present. Several proxy handlers
// in one config share the same instance registry, so the second and subsequent
// Provision calls must reuse the collectors instead of panicking on a duplicate
// registration (see issue #445).
func registerOrExisting[C prometheus.Collector](reg *prometheus.Registry, c C) C {
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(C); ok {
				return existing
			}
		}
		// Any other registration error means the metric is unusable; fall back to
		// the unregistered collector so recording is a harmless no-op rather than
		// crashing the whole server.
	}
	return c
}

// newProxyMetrics creates and registers the proxy metrics on reg, reusing any
// collectors already registered there by another proxy handler.
func newProxyMetrics(reg *prometheus.Registry) *proxyMetrics {
	const ns, sub = "caddy", "layer4_proxy"
	return &proxyMetrics{
		connectionsTotal: registerOrExisting(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "connections_total",
			Help:      "Total number of connections proxied, labeled by upstream.",
		}, []string{"upstream"})),
		activeConns: registerOrExisting(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "active_connections",
			Help:      "Number of connections currently being proxied, labeled by upstream.",
		}, []string{"upstream"})),
		upstreamHealthy: registerOrExisting(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "upstream_healthy",
			Help:      "Whether an upstream is currently healthy (1) or down (0), per active health checks.",
		}, []string{"upstream"})),
	}
}

// connectionOpened records the start of a proxied connection to upstream.
func (m *proxyMetrics) connectionOpened(upstream string) {
	if m == nil {
		return
	}
	m.connectionsTotal.WithLabelValues(upstream).Inc()
	m.activeConns.WithLabelValues(upstream).Inc()
}

// connectionClosed records the end of a proxied connection to upstream.
func (m *proxyMetrics) connectionClosed(upstream string) {
	if m == nil {
		return
	}
	m.activeConns.WithLabelValues(upstream).Dec()
}

// setUpstreamHealthy records an upstream's current health state.
func (m *proxyMetrics) setUpstreamHealthy(upstream string, healthy bool) {
	if m == nil {
		return
	}
	v := 0.0
	if healthy {
		v = 1.0
	}
	m.upstreamHealthy.WithLabelValues(upstream).Set(v)
}
