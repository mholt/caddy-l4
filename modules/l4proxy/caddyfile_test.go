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
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfileFull(t *testing.T) {
	d := caddyfile.NewTestDispenser(`proxy localhost:5432 udp/localhost:5433 {
		health_interval 5s
		health_port 8008
		health_timeout 2s
		fail_duration 30s
		max_fails 3
		unhealthy_connection_count 10
		lb_policy round_robin
		lb_try_duration 10s
		lb_try_interval 1s
		proxy_protocol v2
		upstream localhost:5434
	}`)

	h := new(Handler)
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}

	if len(h.Upstreams) != 3 {
		t.Fatalf("Upstreams = %d, want 3 (2 inline + 1 upstream block)", len(h.Upstreams))
	}

	if h.HealthChecks == nil || h.HealthChecks.Active == nil || h.HealthChecks.Passive == nil {
		t.Fatal("expected both active and passive health checks to be configured")
	}
	a := h.HealthChecks.Active
	if a.Interval != caddy.Duration(5*time.Second) {
		t.Errorf("active Interval = %v, want 5s", time.Duration(a.Interval))
	}
	if a.Port != 8008 {
		t.Errorf("active Port = %d, want 8008", a.Port)
	}
	if a.Timeout != caddy.Duration(2*time.Second) {
		t.Errorf("active Timeout = %v, want 2s", time.Duration(a.Timeout))
	}

	p := h.HealthChecks.Passive
	if p.FailDuration != caddy.Duration(30*time.Second) {
		t.Errorf("passive FailDuration = %v, want 30s", time.Duration(p.FailDuration))
	}
	if p.MaxFails != 3 {
		t.Errorf("passive MaxFails = %d, want 3", p.MaxFails)
	}
	if p.UnhealthyConnectionCount != 10 {
		t.Errorf("passive UnhealthyConnectionCount = %d, want 10", p.UnhealthyConnectionCount)
	}

	if h.LoadBalancing == nil {
		t.Fatal("expected load balancing to be configured")
	}
	if len(h.LoadBalancing.SelectionPolicyRaw) == 0 {
		t.Error("expected a selection policy to be set")
	}
	if h.LoadBalancing.TryDuration != caddy.Duration(10*time.Second) {
		t.Errorf("TryDuration = %v, want 10s", time.Duration(h.LoadBalancing.TryDuration))
	}
	if h.LoadBalancing.TryInterval != caddy.Duration(1*time.Second) {
		t.Errorf("TryInterval = %v, want 1s", time.Duration(h.LoadBalancing.TryInterval))
	}

	if h.ProxyProtocol != "v2" {
		t.Errorf("ProxyProtocol = %q, want v2", h.ProxyProtocol)
	}
}

func TestUnmarshalCaddyfileErrors(t *testing.T) {
	cases := map[string]string{
		"duplicate health_interval": "proxy localhost:1 {\n\thealth_interval 5s\n\thealth_interval 6s\n}",
		"bad health_interval":       "proxy localhost:1 {\n\thealth_interval nope\n}",
		"bad health_port":           "proxy localhost:1 {\n\thealth_port nope\n}",
		"bad max_fails":             "proxy localhost:1 {\n\tmax_fails nope\n}",
		"duplicate lb_try_duration": "proxy localhost:1 {\n\tlb_try_duration 1s\n\tlb_try_duration 2s\n}",
		"unknown lb_policy":         "proxy localhost:1 {\n\tlb_policy does_not_exist\n}",
		"unknown directive":         "proxy localhost:1 {\n\tnope 1\n}",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			h := new(Handler)
			if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatalf("expected an error for %q, got nil", name)
			}
		})
	}
}
