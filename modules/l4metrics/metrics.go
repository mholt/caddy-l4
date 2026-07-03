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

// Package l4metrics provides a passthrough handler that records per-connection
// traffic metrics (connection count and bytes received/sent) to Prometheus.
package l4metrics

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&Handler{})
}

// Handler is a passthrough handler that records per-connection traffic metrics.
// It counts every connection that passes through it and, once the rest of the
// handler chain has finished, adds the connection's bytes received and sent to
// Prometheus counters. Place it early in a route so it wraps the whole chain;
// because layer4's byte accounting is kept on the underlying connection, the
// counts reflect the raw on-the-wire traffic even when a later handler (such as
// tls) terminates the connection.
type Handler struct {
	metrics *metrics
}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.metrics",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.metrics = newMetrics(ctx.GetMetricsRegistry())
	return nil
}

// Handle handles the connection, recording its traffic once the rest of the
// chain is done.
func (h *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	err := next.Handle(cx)
	// The chain has finished, so the byte counters are final and no longer being
	// mutated concurrently; it is safe to read them here.
	h.metrics.record(cx.BytesRead(), cx.BytesWritten())
	return err
}

// UnmarshalCaddyfile sets up the Handler from Caddyfile tokens. Syntax:
//
//	metrics
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed layer4 connection handler '%s': blocks are not supported", wrapper)
	}
	return nil
}

// metrics holds the Prometheus collectors for the metrics handler. They are
// registered against the instance's metrics registry (obtained from the Caddy
// context) so they reset cleanly across config reloads.
type metrics struct {
	connectionsTotal prometheus.Counter
	receivedBytes    prometheus.Counter
	sentBytes        prometheus.Counter
}

// newMetrics creates and registers the connection metrics on reg.
func newMetrics(reg *prometheus.Registry) *metrics {
	const ns, sub = "caddy", "layer4"
	return &metrics{
		connectionsTotal: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "connections_total",
			Help:      "Total number of connections handled through the metrics handler.",
		}),
		receivedBytes: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "received_bytes_total",
			Help:      "Total number of bytes received from clients through the metrics handler.",
		}),
		sentBytes: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "sent_bytes_total",
			Help:      "Total number of bytes sent to clients through the metrics handler.",
		}),
	}
}

// record adds one connection's traffic to the counters.
func (m *metrics) record(read, written uint64) {
	if m == nil {
		return
	}
	m.connectionsTotal.Inc()
	m.receivedBytes.Add(float64(read))
	m.sentBytes.Add(float64(written))
}

// Interface guards
var (
	_ caddy.Provisioner     = (*Handler)(nil)
	_ layer4.NextHandler    = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
)
