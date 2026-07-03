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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func TestPeerTrackUntrackCloseConns(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()

	p := &peer{}
	p.trackConn(a)
	if got := len(p.openConns); got != 1 {
		t.Fatalf("tracked conns = %d, want 1", got)
	}

	// untrack removes without closing
	p.untrackConn(a)
	if got := len(p.openConns); got != 0 {
		t.Fatalf("after untrack = %d, want 0", got)
	}

	// re-track, then closeOpenConns closes and clears
	p.trackConn(a)
	p.closeOpenConns()
	if got := len(p.openConns); got != 0 {
		t.Fatalf("after closeOpenConns = %d, want 0", got)
	}
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := a.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected a read error on the closed connection")
	}
}

func newDeadPeer(t *testing.T) *peer {
	t.Helper()
	addr, err := caddy.ParseNetworkAddress("127.0.0.1:1") // nothing listening on port 1
	if err != nil {
		t.Fatalf("parsing address: %v", err)
	}
	return &peer{address: &addr}
}

func activeCheckHandler(closeOnUnhealthy bool) *Handler {
	return &Handler{
		HealthChecks: &HealthChecks{
			Active: &ActiveHealthChecks{
				Timeout:          caddy.Duration(200 * time.Millisecond),
				CloseIfUnhealthy: closeOnUnhealthy,
				logger:           zap.NewNop(),
			},
		},
	}
}

func TestActiveHealthCheckClosesConnsWhenEnabled(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()

	p := newDeadPeer(t)
	p.trackConn(a)

	h := activeCheckHandler(true)
	if err := h.doActiveHealthCheck(&Upstream{peers: []*peer{p}}, p); err != nil {
		t.Fatalf("health check: %v", err)
	}
	if p.healthy() {
		t.Fatal("peer should be unhealthy after a failed dial")
	}
	if got := len(p.openConns); got != 0 {
		t.Fatalf("open conns = %d, want 0 (should have been closed)", got)
	}
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := a.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the tracked connection to be closed")
	}
}

func TestActiveHealthCheckKeepsConnsWhenDisabled(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	p := newDeadPeer(t)
	p.trackConn(a)

	h := activeCheckHandler(false)
	if err := h.doActiveHealthCheck(&Upstream{peers: []*peer{p}}, p); err != nil {
		t.Fatalf("health check: %v", err)
	}
	if p.healthy() {
		t.Fatal("peer should be unhealthy after a failed dial")
	}
	if got := len(p.openConns); got != 1 {
		t.Fatalf("open conns = %d, want 1 (option disabled, must not close)", got)
	}
}

func TestUnmarshalCaddyfileCloseConnections(t *testing.T) {
	h := new(Handler)
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser("proxy localhost:1 {\n\tclose_if_unhealthy\n}")); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if h.HealthChecks == nil || h.HealthChecks.Active == nil || !h.HealthChecks.Active.CloseIfUnhealthy {
		t.Fatal("expected Active.CloseIfUnhealthy = true")
	}

	h2 := new(Handler)
	if err := h2.UnmarshalCaddyfile(caddyfile.NewTestDispenser("proxy localhost:1 {\n\tclose_if_unhealthy yes\n}")); err == nil {
		t.Fatal("expected an error when close_if_unhealthy has an argument")
	}

	h3 := new(Handler)
	if err := h3.UnmarshalCaddyfile(caddyfile.NewTestDispenser("proxy localhost:1 {\n\tclose_if_unhealthy\n\tclose_if_unhealthy\n}")); err == nil {
		t.Fatal("expected an error when close_if_unhealthy is specified twice")
	}
}
