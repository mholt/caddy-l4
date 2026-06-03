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
	"errors"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// erroringSource is an UpstreamSource whose GetUpstreams always fails.
type erroringSource struct{}

func (erroringSource) GetUpstreams(*caddy.Replacer) (UpstreamPool, error) {
	return nil, errors.New("discovery failed")
}

// TestActiveHealthCheckDynamicSourceError exercises the path where the dynamic
// upstream source returns an error during a health-check pass: it must be
// logged and swallowed (no panic).
func TestActiveHealthCheckDynamicSourceError(t *testing.T) {
	h := &Handler{
		dynamicUpstreams: erroringSource{},
		HealthChecks: &HealthChecks{Active: &ActiveHealthChecks{
			Timeout: caddy.Duration(200 * time.Millisecond),
			logger:  zap.NewNop(),
		}},
	}
	// Must not panic; the error from the source is logged and ignored.
	h.doActiveHealthCheckForAllHosts()
}

// TestActiveHealthCheckMarksDynamicUpstream verifies that the active health
// checker also checks dynamically-discovered upstreams: a discovered peer that
// cannot be dialed must be marked unhealthy.
func TestActiveHealthCheckMarksDynamicUpstream(t *testing.T) {
	// dynamic source returns a single dead address (nothing listens on port 1)
	au := aWith("db.dyn-health.test", "1", []string{"127.0.0.1"}, nil, nil)

	h := &Handler{
		dynamicUpstreams: au,
		HealthChecks: &HealthChecks{
			Active: &ActiveHealthChecks{
				Timeout: caddy.Duration(200 * time.Millisecond),
				logger:  zap.NewNop(),
			},
		},
	}

	// resolve once so we hold the same peer the checker will mark (the cache
	// returns the same pool/peer pointers)
	pool, err := au.GetUpstreams(caddy.NewReplacer())
	if err != nil {
		t.Fatalf("GetUpstreams: %v", err)
	}
	if len(pool) != 1 || len(pool[0].peers) != 1 {
		t.Fatalf("expected exactly one discovered peer, got %d upstreams", len(pool))
	}
	p := pool[0].peers[0]
	if !p.healthy() {
		t.Fatal("peer should start healthy")
	}

	h.doActiveHealthCheckForAllHosts()

	// the check runs in a goroutine; wait for it to mark the peer down
	var down bool
	for range 100 {
		if !p.healthy() {
			down = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !down {
		t.Fatal("dynamically-discovered dead peer was not marked unhealthy")
	}
}
