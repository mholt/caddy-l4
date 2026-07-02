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
	"go.uber.org/zap"
)

func TestRecordActiveCheckThresholds(t *testing.T) {
	p := &peer{}

	// fall=3: three consecutive failures are required to mark unhealthy.
	if mark, _ := p.recordActiveCheck(false, 2, 3); mark {
		t.Fatal("1 failure must not mark with fall=3")
	}
	if mark, _ := p.recordActiveCheck(false, 2, 3); mark {
		t.Fatal("2 failures must not mark with fall=3")
	}
	if mark, healthy := p.recordActiveCheck(false, 2, 3); !mark || healthy {
		t.Fatalf("3 failures must mark unhealthy; got mark=%v healthy=%v", mark, healthy)
	}

	// A success resets the failure streak; rise=2 requires two successes.
	if mark, _ := p.recordActiveCheck(true, 2, 3); mark {
		t.Fatal("1 success must not mark with rise=2")
	}
	if mark, healthy := p.recordActiveCheck(true, 2, 3); !mark || !healthy {
		t.Fatalf("2 successes must mark healthy; got mark=%v healthy=%v", mark, healthy)
	}

	// A failure resets the success streak again.
	if mark, _ := p.recordActiveCheck(false, 2, 3); mark {
		t.Fatal("1 failure after recovery must not mark with fall=3")
	}
}

func TestRecordActiveCheckDefaultsToSingle(t *testing.T) {
	p := &peer{}
	if mark, healthy := p.recordActiveCheck(false, 0, 0); !mark || healthy {
		t.Fatalf("a single failure must mark unhealthy with defaults; mark=%v healthy=%v", mark, healthy)
	}
	if mark, healthy := p.recordActiveCheck(true, 0, 0); !mark || !healthy {
		t.Fatalf("a single success must mark healthy with defaults; mark=%v healthy=%v", mark, healthy)
	}
}

func TestActiveHealthCheckFallThreshold(t *testing.T) {
	addr, err := caddy.ParseNetworkAddress("127.0.0.1:1") // nothing listening on port 1
	if err != nil {
		t.Fatalf("parsing address: %v", err)
	}
	p := &peer{address: &addr}
	h := &Handler{HealthChecks: &HealthChecks{Active: &ActiveHealthChecks{
		Timeout: caddy.Duration(200 * time.Millisecond),
		Fall:    2,
		logger:  zap.NewNop(),
	}}}
	up := &Upstream{peers: []*peer{p}}

	if err := h.doActiveHealthCheck(up, p); err != nil {
		t.Fatalf("check 1: %v", err)
	}
	if !p.healthy() {
		t.Fatal("peer should still be healthy after 1 failure with fall=2")
	}
	if err := h.doActiveHealthCheck(up, p); err != nil {
		t.Fatalf("check 2: %v", err)
	}
	if p.healthy() {
		t.Fatal("peer should be unhealthy after 2 failures with fall=2")
	}
}

func TestUnmarshalCaddyfileRiseFall(t *testing.T) {
	d := caddyfile.NewTestDispenser("proxy localhost:1 {\n\thealth_fall 3\n\thealth_rise 2\n}")
	h := new(Handler)
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if h.HealthChecks.Active.Fall != 3 {
		t.Errorf("Fall = %d, want 3", h.HealthChecks.Active.Fall)
	}
	if h.HealthChecks.Active.Rise != 2 {
		t.Errorf("Rise = %d, want 2", h.HealthChecks.Active.Rise)
	}

	cases := map[string]string{
		"duplicate health_fall": "proxy localhost:1 {\n\thealth_fall 1\n\thealth_fall 2\n}",
		"bad health_rise":       "proxy localhost:1 {\n\thealth_rise nope\n}",
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
