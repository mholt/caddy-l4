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

package l4metrics

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

func TestMetricsRecord(t *testing.T) {
	m := newMetrics(prometheus.NewRegistry())

	m.record(100, 40)
	m.record(20, 10)

	if got := testutil.ToFloat64(m.connectionsTotal); got != 2 {
		t.Errorf("connections_total = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.receivedBytes); got != 120 {
		t.Errorf("received_bytes_total = %v, want 120", got)
	}
	if got := testutil.ToFloat64(m.sentBytes); got != 50 {
		t.Errorf("sent_bytes_total = %v, want 50", got)
	}
}

func TestMetricsNilSafe(t *testing.T) {
	var m *metrics // a handler that was never provisioned
	m.record(1, 2)
}

// TestMetricsDuplicateRegistration guards against the panic seen in issue #445:
// multiple metrics handlers share one instance registry, so a second one must
// reuse the existing collectors instead of panicking on a duplicate.
func TestMetricsDuplicateRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()

	m1 := newMetrics(reg)
	m2 := newMetrics(reg) // must not panic

	m1.record(10, 5)
	m2.record(20, 7)

	if got := testutil.ToFloat64(m1.connectionsTotal); got != 2 {
		t.Errorf("connections_total = %v, want 2 (collectors must be shared)", got)
	}
	if got := testutil.ToFloat64(m1.receivedBytes); got != 30 {
		t.Errorf("received_bytes_total = %v, want 30", got)
	}
	if m1.connectionsTotal != m2.connectionsTotal {
		t.Error("expected the second handler to reuse the existing collector")
	}
}

func TestProvision(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	h := new(Handler)
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if h.metrics == nil {
		t.Fatal("expected metrics to be set after Provision")
	}
}

// TestHandleRecordsTraffic drives a connection through the handler and checks
// that the received/sent byte counts and the connection count are recorded.
func TestHandleRecordsTraffic(t *testing.T) {
	h := &Handler{metrics: newMetrics(prometheus.NewRegistry())}

	client, server := net.Pipe()
	defer client.Close()
	cx := layer4.WrapConnection(server, []byte{}, zap.NewNop())

	// The next handler reads 4 bytes from the client and writes 2 bytes back.
	next := layer4.HandlerFunc(func(cx *layer4.Connection) error {
		buf := make([]byte, 4)
		if _, err := io.ReadFull(cx, buf); err != nil {
			return err
		}
		_, err := cx.Write([]byte("hi"))
		return err
	})

	go func() {
		_, _ = client.Write([]byte("ping"))
		reply := make([]byte, 2)
		_, _ = io.ReadFull(client, reply)
	}()

	if err := h.Handle(cx, next); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if got := testutil.ToFloat64(h.metrics.connectionsTotal); got != 1 {
		t.Errorf("connections_total = %v, want 1", got)
	}
	if got := testutil.ToFloat64(h.metrics.receivedBytes); got != 4 {
		t.Errorf("received_bytes_total = %v, want 4", got)
	}
	if got := testutil.ToFloat64(h.metrics.sentBytes); got != 2 {
		t.Errorf("sent_bytes_total = %v, want 2", got)
	}
}

// TestHandlePropagatesError verifies the next handler's error is returned while
// the connection is still recorded.
func TestHandlePropagatesError(t *testing.T) {
	h := &Handler{metrics: newMetrics(prometheus.NewRegistry())}

	_, server := net.Pipe()
	cx := layer4.WrapConnection(server, []byte{}, zap.NewNop())

	boom := errors.New("downstream failed")
	next := layer4.HandlerFunc(func(*layer4.Connection) error { return boom })

	if err := h.Handle(cx, next); !errors.Is(err, boom) {
		t.Fatalf("Handle error = %v, want %v", err, boom)
	}
	if got := testutil.ToFloat64(h.metrics.connectionsTotal); got != 1 {
		t.Errorf("connections_total = %v, want 1 (recorded even on error)", got)
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	t.Run("bare", func(t *testing.T) {
		d := caddyfile.NewTestDispenser(`metrics`)
		if err := (&Handler{}).UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("args rejected", func(t *testing.T) {
		d := caddyfile.NewTestDispenser(`metrics extra`)
		if err := (&Handler{}).UnmarshalCaddyfile(d); err == nil {
			t.Fatal("expected an error for arguments")
		}
	})

	t.Run("block rejected", func(t *testing.T) {
		d := caddyfile.NewTestDispenser("metrics {\n\tfoo\n}")
		if err := (&Handler{}).UnmarshalCaddyfile(d); err == nil {
			t.Fatal("expected an error for a block")
		}
	})
}
