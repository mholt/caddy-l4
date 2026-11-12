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
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestSourcesRejectPlaceholders(t *testing.T) {
	newA := func(name, port string) *AUpstreams {
		au := &AUpstreams{}
		au.Name, au.Port = name, port
		return au
	}
	newAAAA := func(name, port string) *AAAAUpstreams {
		au := &AAAAUpstreams{}
		au.Name, au.Port = name, port
		return au
	}
	cases := map[string]caddy.Provisioner{
		"srv name":    &SRVUpstreams{Name: "{l4.tls.server_name}.svc"},
		"srv service": &SRVUpstreams{Name: "x", Service: "{svc}"},
		"srv proto":   &SRVUpstreams{Name: "x", Proto: "{env.P}"},
		"a name":      newA("{l4.tls.server_name}", "5432"),
		"a port":      newA("x", "{env.PORT}"),
		"aaaa name":   newAAAA("{host}", "5432"),
		"aaaa port":   newAAAA("x", "{env.PORT}"),
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			err := src.Provision(caddy.Context{})
			if err == nil || !strings.Contains(err.Error(), "placeholders") {
				t.Fatalf("expected a placeholder error, got %v", err)
			}
		})
	}
}

// The cap is fixed (independent of refresh) because the lookup holds the lock.
func TestLookupContextBound(t *testing.T) {
	ctx, cancel := lookupContext()
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("lookup context has no deadline")
	}
	if d := time.Until(dl); d > lookupTimeout || d < lookupTimeout-time.Second {
		t.Errorf("bound = %v, want about %v", d, lookupTimeout)
	}
}

func TestLookupsReceiveDeadline(t *testing.T) {
	var gotSRV bool
	su := srvWith("srv-deadline.test", nil, nil, nil)
	su.lookupSRV = func(ctx context.Context, _, _, _ string) (string, []*net.SRV, error) {
		_, gotSRV = ctx.Deadline()
		return "", []*net.SRV{{Target: "x.", Port: 1}}, nil
	}
	t.Cleanup(func() { _ = su.Cleanup() })
	if _, err := su.GetUpstreams(caddy.NewReplacer()); err != nil {
		t.Fatal(err)
	}
	if !gotSRV {
		t.Error("SRV lookup context has no deadline")
	}

	var gotIP bool
	au := aWith("a-deadline.test", "5432", nil, nil, nil)
	au.lookupIP = func(ctx context.Context, _, _ string) ([]net.IP, error) {
		_, gotIP = ctx.Deadline()
		return ipsFromStrings([]string{"10.9.9.9"}), nil
	}
	t.Cleanup(func() { _ = au.Cleanup() })
	if _, err := au.GetUpstreams(caddy.NewReplacer()); err != nil {
		t.Fatal(err)
	}
	if !gotIP {
		t.Error("IP lookup context has no deadline")
	}
}

// A discovered peer that reaches max_fails must stop being selected: the
// passive policy has to reach the upstreams the source builds.
func TestDynamicPeerHonoursMaxFails(t *testing.T) {
	au := aWith("a-maxfails.test", "5601", []string{"10.7.7.1", "10.7.7.2"}, nil, nil)
	t.Cleanup(func() { _ = au.Cleanup() })
	var src passivePolicyAware = au
	src.setPassivePolicy(&PassiveHealthChecks{MaxFails: 2})

	pool, err := au.GetUpstreams(caddy.NewReplacer())
	if err != nil {
		t.Fatal(err)
	}
	if len(pool) != 2 {
		t.Fatalf("pool length = %d, want 2", len(pool))
	}
	first := new(FirstSelection)
	if got := first.Select(pool, nil); got != pool[0] {
		t.Fatalf("before failures: selected %v, want the first upstream", got)
	}

	pool[0].peers[0].fails.Store(2) // reaches max_fails
	if got := first.Select(pool, nil); got != pool[1] {
		t.Fatalf("after max_fails: selected %v, want the second upstream", got)
	}
	pool[1].peers[0].fails.Store(2)
	if got := first.Select(pool, nil); got != nil {
		t.Fatalf("all peers at max_fails: selected %v, want nil", got)
	}
}

func TestSRVPeerHonoursMaxFails(t *testing.T) {
	su := srvWith("srv-maxfails.test", []*net.SRV{{Target: "mf.example.", Port: 7}}, nil, nil)
	t.Cleanup(func() { _ = su.Cleanup() })
	su.setPassivePolicy(&PassiveHealthChecks{MaxFails: 1})
	pool, err := su.GetUpstreams(caddy.NewReplacer())
	if err != nil {
		t.Fatal(err)
	}
	pool[0].peers[0].fails.Store(1)
	if pool[0].available() {
		t.Error("srv-discovered peer at max_fails should be unavailable")
	}
}

// Handler.Provision must hand the passive policy to the loaded dynamic source.
func TestHandlerProvisionWiresPassivePolicy(t *testing.T) {
	provision := func(hc *HealthChecks) *AUpstreams {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		t.Cleanup(cancel)
		h := &Handler{
			DynamicUpstreamsRaw: []byte(`{"source":"a","name":"wire.test","port":"5700"}`),
			HealthChecks:        hc,
		}
		if err := h.Provision(ctx); err != nil {
			t.Fatalf("provision: %v", err)
		}
		au, ok := h.dynamicUpstreams.(*AUpstreams)
		if !ok {
			t.Fatalf("dynamic source is %T, want *AUpstreams", h.dynamicUpstreams)
		}
		return au
	}

	policy := &PassiveHealthChecks{MaxFails: 3}
	if got := provision(&HealthChecks{Passive: policy}).resolved.passive; got != policy {
		t.Errorf("passive policy = %v, want the handler's policy", got)
	}
	// no health checks configured: provisioning succeeds and no policy is set
	if got := provision(nil).resolved.passive; got != nil {
		t.Errorf("passive policy = %v, want nil", got)
	}
}

// Without a passive policy, failures are not counted against a peer.
func TestDynamicPeerWithoutPolicyIgnoresFails(t *testing.T) {
	au := aWith("a-nopolicy.test", "5602", []string{"10.7.8.1"}, nil, nil)
	t.Cleanup(func() { _ = au.Cleanup() })
	pool, err := au.GetUpstreams(caddy.NewReplacer())
	if err != nil {
		t.Fatal(err)
	}
	pool[0].peers[0].fails.Store(99)
	if !pool[0].healthy() {
		t.Error("upstream without a policy should stay healthy")
	}
}
