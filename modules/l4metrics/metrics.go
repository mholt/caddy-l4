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

// Package l4metrics provides a passthrough handler that records the traffic of
// the rest of a handler chain (connection count and bytes received/sent) to
// Prometheus, under a user-chosen tag.
package l4metrics

import (
	"errors"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&Handler{})
}

// Handler is a passthrough handler that records the traffic of the rest of the
// handler chain under a required tag. It snapshots the connection's byte
// counters when it starts and, once the rest of the chain has finished, adds the
// difference to Prometheus counters labeled with the tag. A handler placed after
// tls therefore measures the decrypted traffic, and one placed before tls
// measures the raw traffic. Values are recorded when the connection ends.
type Handler struct {
	// Tag labels the recorded metrics (the `tag` label). It is required.
	// Using the same tag in several places adds their numbers up.
	Tag string `json:"tag,omitempty"`

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
	if h.Tag == "" {
		return errors.New("metrics handler: tag is required")
	}
	h.metrics = newMetrics(ctx.GetMetricsRegistry(), h.Tag)
	return nil
}

// Handle handles the connection, recording the traffic of the rest of the chain
// once it is done.
func (h *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	startRead, startWritten := cx.TrafficSnapshot()
	err := next.Handle(cx)
	// The chain has finished, so the byte counters are final and no longer being
	// mutated concurrently; it is safe to read them here.
	endRead, endWritten := cx.TrafficSnapshot()
	h.metrics.record(delta(endRead, startRead), delta(endWritten, startWritten))
	return err
}

// delta returns end-start, or 0 if the counter went backwards.
func delta(end, start uint64) uint64 {
	if end < start {
		return 0
	}
	return end - start
}

// UnmarshalCaddyfile sets up the Handler from Caddyfile tokens. Syntax:
//
//	metrics <tag>
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// The tag is required
	if !d.NextArg() {
		return d.ArgErr()
	}
	h.Tag = d.Val()

	// No more same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed layer4 connection handler '%s': blocks are not supported", wrapper)
	}
	return nil
}

// metrics holds the Prometheus counters of one tagged metrics handler. The
// collectors are registered against the instance's metrics registry (obtained
// from the Caddy context) so they reset cleanly across config reloads, and are
// shared by all handlers; each handler records into its own tag's children.
type metrics struct {
	connectionsTotal prometheus.Counter
	receivedBytes    prometheus.Counter
	sentBytes        prometheus.Counter
}

// newMetrics creates and registers the handler metric families on reg, reusing
// any collectors already registered there by another metrics handler, and
// returns the counters for tag.
func newMetrics(reg *prometheus.Registry, tag string) *metrics {
	const ns, sub = "caddy", "layer4_handler"
	labels := []string{"tag"}
	connections := layer4.RegisterOrExisting(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "connections_total",
		Help:      "Total number of connections handled through the metrics handler, labeled by tag.",
	}, labels))
	received := layer4.RegisterOrExisting(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "received_bytes_total",
		Help:      "Total number of bytes received from clients through the metrics handler, labeled by tag.",
	}, labels))
	sent := layer4.RegisterOrExisting(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "sent_bytes_total",
		Help:      "Total number of bytes sent to clients through the metrics handler, labeled by tag.",
	}, labels))
	return &metrics{
		connectionsTotal: connections.WithLabelValues(tag),
		receivedBytes:    received.WithLabelValues(tag),
		sentBytes:        sent.WithLabelValues(tag),
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
