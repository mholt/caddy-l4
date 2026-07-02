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

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func healthyUpstream(weight int) *Upstream {
	return &Upstream{Weight: weight, peers: []*peer{{}}}
}

func TestWeightedRoundRobinDistribution(t *testing.T) {
	pool := UpstreamPool{healthyUpstream(1), healthyUpstream(2), healthyUpstream(3)}
	w := new(WeightedRoundRobinSelection)

	const cycles = 100 // total weight is 6, so each full cycle is 6 selections
	counts := map[*Upstream]int{}
	for range 6 * cycles {
		u := w.Select(pool, nil)
		if u == nil {
			t.Fatal("unexpected nil selection")
		}
		counts[u]++
	}

	// Smooth weighted round-robin is exactly proportional over a full period.
	want := map[*Upstream]int{pool[0]: 1 * cycles, pool[1]: 2 * cycles, pool[2]: 3 * cycles}
	for u, c := range want {
		if counts[u] != c {
			t.Errorf("upstream weight %d: got %d selections, want %d", u.Weight, counts[u], c)
		}
	}
}

func TestWeightedRoundRobinDefaultsToOne(t *testing.T) {
	// Unset weight (0) is treated as 1, so two upstreams split evenly.
	pool := UpstreamPool{healthyUpstream(0), healthyUpstream(0)}
	w := new(WeightedRoundRobinSelection)

	counts := map[*Upstream]int{}
	for range 200 {
		counts[w.Select(pool, nil)]++
	}
	if counts[pool[0]] != 100 || counts[pool[1]] != 100 {
		t.Errorf("even split expected, got %d / %d", counts[pool[0]], counts[pool[1]])
	}
}

func TestWeightedRoundRobinSkipsUnavailable(t *testing.T) {
	up := healthyUpstream(1)
	down := healthyUpstream(5)
	down.peers[0].setHealthy(false)

	pool := UpstreamPool{up, down}
	w := new(WeightedRoundRobinSelection)
	for range 10 {
		if got := w.Select(pool, nil); got != up {
			t.Fatalf("expected only the available upstream to be selected, got %v", got)
		}
	}
}

func TestWeightedRoundRobinAllDownReturnsNil(t *testing.T) {
	u := healthyUpstream(1)
	u.peers[0].setHealthy(false)
	w := new(WeightedRoundRobinSelection)
	if got := w.Select(UpstreamPool{u}, nil); got != nil {
		t.Fatalf("expected nil when all upstreams are down, got %v", got)
	}
}

func TestUnmarshalCaddyfileWeighted(t *testing.T) {
	d := caddyfile.NewTestDispenser("proxy {\n" +
		"\tlb_policy weighted_round_robin\n" +
		"\tupstream localhost:5432 {\n" +
		"\t\tweight 3\n" +
		"\t}\n" +
		"}")
	h := new(Handler)
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(h.Upstreams) != 1 {
		t.Fatalf("upstreams = %d, want 1", len(h.Upstreams))
	}
	if h.Upstreams[0].Weight != 3 {
		t.Errorf("Weight = %d, want 3", h.Upstreams[0].Weight)
	}
	if h.LoadBalancing == nil || len(h.LoadBalancing.SelectionPolicyRaw) == 0 {
		t.Error("expected weighted_round_robin selection policy to be set")
	}
}

func TestUnmarshalCaddyfileWeightErrors(t *testing.T) {
	cases := map[string]string{
		"bad weight":       "proxy {\n\tupstream localhost:1 {\n\t\tweight nope\n\t}\n}",
		"duplicate weight": "proxy {\n\tupstream localhost:1 {\n\t\tweight 1\n\t\tweight 2\n\t}\n}",
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
