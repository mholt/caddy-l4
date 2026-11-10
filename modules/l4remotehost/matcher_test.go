// Copyright 2026 ChrisJr404
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

package l4remotehost

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

var (
	_ net.Conn = &dummyConn{}
	_ net.Addr = dummyAddr{}
)

type dummyAddr struct {
	ip      string
	network string
}

func (da dummyAddr) Network() string { return da.network }
func (da dummyAddr) String() string  { return da.ip }

type dummyConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (dc *dummyConn) RemoteAddr() net.Addr { return dc.remoteAddr }

// stubLookup replaces the package reverse-DNS lookup for the duration of the test.
func stubLookup(t *testing.T, names []string, err error) {
	t.Helper()
	orig := lookupAddr
	t.Cleanup(func() { lookupAddr = orig })
	lookupAddr = func(_ context.Context, _ string) ([]string, error) {
		return names, err
	}
}

func matchOn(t *testing.T, hosts, ptrNames []string, lookupErr error, remoteIP string) bool {
	t.Helper()
	stubLookup(t, ptrNames, lookupErr)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	m := &MatchRemoteHost{Hosts: hosts}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("provision: %v", err)
	}

	cx := &layer4.Connection{
		Conn:    &dummyConn{remoteAddr: dummyAddr{ip: remoteIP + ":12345", network: "tcp"}},
		Context: context.Background(),
		Logger:  zap.NewNop(),
	}

	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	return matched
}

func TestExactMatch(t *testing.T) {
	if !matchOn(t, []string{"host.example.com"}, []string{"host.example.com."}, nil, "192.0.2.10") {
		t.Error("expected exact host name to match")
	}
}

func TestExactNoMatch(t *testing.T) {
	if matchOn(t, []string{"host.example.com"}, []string{"other.example.com."}, nil, "192.0.2.10") {
		t.Error("expected non-listed host name not to match")
	}
}

func TestCaseInsensitive(t *testing.T) {
	if !matchOn(t, []string{"Host.Example.COM"}, []string{"HOST.example.com"}, nil, "192.0.2.10") {
		t.Error("expected match to be case insensitive")
	}
}

func TestWildcardMatch(t *testing.T) {
	if !matchOn(t, []string{"*.example.com"}, []string{"web-1.example.com."}, nil, "192.0.2.10") {
		t.Error("expected wildcard to match a subdomain")
	}
}

func TestWildcardDoesNotMatchApex(t *testing.T) {
	if matchOn(t, []string{"*.example.com"}, []string{"example.com."}, nil, "192.0.2.10") {
		t.Error("expected wildcard not to match the apex domain")
	}
}

func TestMultipleNamesAnyMatches(t *testing.T) {
	names := []string{"alias.internal.", "web-1.example.com."}
	if !matchOn(t, []string{"web-1.example.com"}, names, nil, "192.0.2.10") {
		t.Error("expected a match when any returned PTR name matches")
	}
}

func TestLookupErrorIsNotAMatch(t *testing.T) {
	if matchOn(t, []string{"host.example.com"}, nil, errors.New("no such host"), "192.0.2.10") {
		t.Error("expected a failed reverse lookup to be treated as no match")
	}
}

func TestInvalidRemoteIP(t *testing.T) {
	stubLookup(t, nil, nil)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	m := &MatchRemoteHost{Hosts: []string{"host.example.com"}}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("provision: %v", err)
	}

	cx := &layer4.Connection{
		Conn:    &dummyConn{remoteAddr: dummyAddr{ip: "not-an-ip", network: "tcp"}},
		Context: context.Background(),
		Logger:  zap.NewNop(),
	}

	if _, err := m.Match(cx); err == nil {
		t.Error("expected an error for an unparseable remote address")
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`remote_host host.example.com *.internal`)
	m := new(MatchRemoteHost)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{"host.example.com", "*.internal"}
	if len(m.Hosts) != len(want) {
		t.Fatalf("got %d hosts, want %d", len(m.Hosts), len(want))
	}
	for i := range want {
		if m.Hosts[i] != want[i] {
			t.Errorf("host[%d] = %q, want %q", i, m.Hosts[i], want[i])
		}
	}
}

func TestUnmarshalCaddyfileNoArgs(t *testing.T) {
	d := caddyfile.NewTestDispenser(`remote_host`)
	m := new(MatchRemoteHost)
	if err := m.UnmarshalCaddyfile(d); err == nil {
		t.Error("expected an error when no host names are given")
	}
}
