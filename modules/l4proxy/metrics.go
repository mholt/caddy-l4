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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// proxyMetrics holds the Prometheus collectors for a proxy handler. They are
// registered against the instance's metrics registry (obtained from the Caddy
// context) so they reset cleanly across config reloads.
type proxyMetrics struct {
	connectionsTotal *prometheus.CounterVec
	activeConns      *prometheus.GaugeVec
	upstreamHealthy  *prometheus.GaugeVec
}

// newProxyMetrics creates and registers the proxy metrics on reg.
func newProxyMetrics(reg *prometheus.Registry) *proxyMetrics {
	const ns, sub = "caddy", "layer4_proxy"
	return &proxyMetrics{
		connectionsTotal: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "connections_total",
			Help:      "Total number of connections proxied, labeled by upstream.",
		}, []string{"upstream"}),
		activeConns: promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "active_connections",
			Help:      "Number of connections currently being proxied, labeled by upstream.",
		}, []string{"upstream"}),
		upstreamHealthy: promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "upstream_healthy",
			Help:      "Whether an upstream is currently healthy (1) or down (0), per active health checks.",
		}, []string{"upstream"}),
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
