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

package l4tls

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4metrics"
)

// counterValue returns the value of the counter family name with the given tag.
func counterValue(t *testing.T, reg *prometheus.Registry, name, tag string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "tag" && l.GetValue() == tag {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	t.Fatalf("no series %s{tag=%q}", name, tag)
	return 0
}

// TestMetricsAfterTLSMeasuresDecryptedTraffic runs a real TLS handshake over
// loopback TCP through the chain metrics<raw> -> tls -> metrics<plain> -> echo
// and checks that the handler after tls counts only the plaintext, while the
// one before it counts the raw wire bytes (handshake and TLS framing included).
func TestMetricsAfterTLSMeasuresDecryptedTraffic(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	raw, plain := &l4metrics.Handler{Tag: "raw"}, &l4metrics.Handler{Tag: "plain"}
	if err := raw.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if err := plain.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	tlsHandler := newTestHandler(t, 10*time.Second)

	const request, reply = "hello, plaintext!", "pong" // 17 and 4 bytes

	terminal := layer4.HandlerFunc(func(cx *layer4.Connection) error {
		if _, err := io.ReadFull(cx, make([]byte, len(request))); err != nil {
			return err
		}
		_, err := cx.Write([]byte(reply))
		return err
	})
	chain := layer4.HandlerFunc(func(cx *layer4.Connection) error {
		return raw.Handle(cx, layer4.HandlerFunc(func(cx *layer4.Connection) error {
			return tlsHandler.Handle(cx, layer4.HandlerFunc(func(cx *layer4.Connection) error {
				return plain.Handle(cx, terminal)
			}))
		}))
	})

	client, cx := tcpDownstream(t)
	done := make(chan error, 1)
	go func() { done <- chain.Handle(cx) }()

	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}) //nolint:gosec // test-only self-signed cert
	if _, err := tc.Write([]byte(request)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if _, err := io.ReadFull(tc, make([]byte, len(reply))); err != nil {
		t.Fatalf("client read: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("chain: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("chain did not finish")
	}

	reg := ctx.GetMetricsRegistry()
	const recv, sent = "caddy_layer4_handler_received_bytes_total", "caddy_layer4_handler_sent_bytes_total"
	if got := counterValue(t, reg, recv, "plain"); got != float64(len(request)) {
		t.Errorf("plain received = %v, want %d (decrypted)", got, len(request))
	}
	if got := counterValue(t, reg, sent, "plain"); got != float64(len(reply)) {
		t.Errorf("plain sent = %v, want %d (decrypted)", got, len(reply))
	}
	// the raw handler sees the ClientHello, Finished, record headers and AEAD
	// tags on top of the plaintext, in both directions
	if got := counterValue(t, reg, recv, "raw"); got <= float64(len(request)) {
		t.Errorf("raw received = %v, want more than the %d plaintext bytes", got, len(request))
	}
	if got := counterValue(t, reg, sent, "raw"); got <= float64(len(reply)) {
		t.Errorf("raw sent = %v, want more than the %d plaintext bytes (ServerHello, certificate...)", got, len(reply))
	}
}
