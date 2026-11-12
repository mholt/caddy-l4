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
	m := newMetrics(prometheus.NewRegistry(), "t")

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

// TestMetricNamesAndTagLabel pins the exported family names and the tag label,
// which are hard to change once dashboards depend on them.
func TestMetricNamesAndTagLabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	newMetrics(reg, "edge").record(1, 2)

	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{
		"caddy_layer4_handler_connections_total":    1,
		"caddy_layer4_handler_received_bytes_total": 1,
		"caddy_layer4_handler_sent_bytes_total":     2,
	}
	if len(families) != len(want) {
		t.Fatalf("got %d families, want %d", len(families), len(want))
	}
	for _, mf := range families {
		v, ok := want[mf.GetName()]
		if !ok {
			t.Errorf("unexpected family %q", mf.GetName())
			continue
		}
		ms := mf.GetMetric()
		if len(ms) != 1 || len(ms[0].GetLabel()) != 1 ||
			ms[0].GetLabel()[0].GetName() != "tag" || ms[0].GetLabel()[0].GetValue() != "edge" {
			t.Errorf("%s: want exactly one series labeled tag=\"edge\", got %v", mf.GetName(), ms)
			continue
		}
		if got := ms[0].GetCounter().GetValue(); got != v {
			t.Errorf("%s = %v, want %v", mf.GetName(), got, v)
		}
	}
}

// TestMetricsDuplicateRegistration guards against the panic seen in issue #445:
// multiple metrics handlers share one instance registry, so a second one must
// reuse the existing collectors instead of panicking on a duplicate. Handlers
// with the same tag add up; different tags stay separate.
func TestMetricsDuplicateRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()

	m1 := newMetrics(reg, "a")
	m2 := newMetrics(reg, "a") // must not panic
	m3 := newMetrics(reg, "b")

	m1.record(10, 5)
	m2.record(20, 7)
	m3.record(1, 1)

	if got := testutil.ToFloat64(m1.connectionsTotal); got != 2 {
		t.Errorf("connections_total{a} = %v, want 2 (collectors must be shared)", got)
	}
	if got := testutil.ToFloat64(m1.receivedBytes); got != 30 {
		t.Errorf("received_bytes_total{a} = %v, want 30", got)
	}
	if got := testutil.ToFloat64(m3.receivedBytes); got != 1 {
		t.Errorf("received_bytes_total{b} = %v, want 1 (tags must not mix)", got)
	}
}

func TestProvision(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	h := &Handler{Tag: "t"}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if h.metrics == nil {
		t.Fatal("expected metrics to be set after Provision")
	}

	// a second handler in the same context must not panic on duplicates
	if err := (&Handler{Tag: "u"}).Provision(ctx); err != nil {
		t.Fatalf("second Provision: %v", err)
	}
}

func TestProvisionRequiresTag(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := (&Handler{}).Provision(ctx); err == nil {
		t.Fatal("expected an error for an empty tag")
	}
}

// TestHandleRecordsTraffic drives a connection through the handler and checks
// that the received/sent byte counts and the connection count are recorded.
func TestHandleRecordsTraffic(t *testing.T) {
	h := &Handler{Tag: "t", metrics: newMetrics(prometheus.NewRegistry(), "t")}

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

// TestHandleMeasuresDelta checks that a handler placed after an earlier stage
// only counts the traffic of the stages after it, not what the earlier stage
// already read and wrote.
func TestHandleMeasuresDelta(t *testing.T) {
	h := &Handler{Tag: "t", metrics: newMetrics(prometheus.NewRegistry(), "t")}

	client, server := net.Pipe()
	defer client.Close()
	cx := layer4.WrapConnection(server, []byte{}, zap.NewNop())

	go func() {
		_, _ = client.Write([]byte("HELLO-"))       // earlier stage: 6 bytes
		_, _ = io.ReadFull(client, make([]byte, 3)) // earlier stage's reply: 3 bytes
		_, _ = client.Write([]byte("ping"))         // measured: 4 bytes
		_, _ = io.ReadFull(client, make([]byte, 2)) // measured reply: 2 bytes
	}()

	// the earlier stage (e.g. a handshake) runs before the metrics handler
	if _, err := io.ReadFull(cx, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	if _, err := cx.Write([]byte("ack")); err != nil {
		t.Fatal(err)
	}

	next := layer4.HandlerFunc(func(cx *layer4.Connection) error {
		if _, err := io.ReadFull(cx, make([]byte, 4)); err != nil {
			return err
		}
		_, err := cx.Write([]byte("hi"))
		return err
	})
	if err := h.Handle(cx, next); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if got := testutil.ToFloat64(h.metrics.receivedBytes); got != 4 {
		t.Errorf("received_bytes_total = %v, want 4 (delta, not 10)", got)
	}
	if got := testutil.ToFloat64(h.metrics.sentBytes); got != 2 {
		t.Errorf("sent_bytes_total = %v, want 2 (delta, not 5)", got)
	}
}

// TestHandlePropagatesError verifies the next handler's error is returned while
// the connection is still recorded.
func TestHandlePropagatesError(t *testing.T) {
	h := &Handler{Tag: "t", metrics: newMetrics(prometheus.NewRegistry(), "t")}

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
	t.Run("tag", func(t *testing.T) {
		d := caddyfile.NewTestDispenser(`metrics edge`)
		h := &Handler{}
		if err := h.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.Tag != "edge" {
			t.Errorf("Tag = %q, want %q", h.Tag, "edge")
		}
	})

	t.Run("bare rejected", func(t *testing.T) {
		d := caddyfile.NewTestDispenser(`metrics`)
		if err := (&Handler{}).UnmarshalCaddyfile(d); err == nil {
			t.Fatal("expected an error for a missing tag")
		}
	})

	t.Run("extra args rejected", func(t *testing.T) {
		d := caddyfile.NewTestDispenser(`metrics a b`)
		if err := (&Handler{}).UnmarshalCaddyfile(d); err == nil {
			t.Fatal("expected an error for extra arguments")
		}
	})

	t.Run("block rejected", func(t *testing.T) {
		d := caddyfile.NewTestDispenser("metrics edge {\n\tfoo\n}")
		if err := (&Handler{}).UnmarshalCaddyfile(d); err == nil {
			t.Fatal("expected an error for a block")
		}
	})
}
