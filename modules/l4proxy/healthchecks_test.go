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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func httpHealthHandler(uri string, expect int) *Handler {
	return &Handler{
		HealthChecks: &HealthChecks{
			Active: &ActiveHealthChecks{
				URI:          uri,
				ExpectStatus: expect,
				Timeout:      caddy.Duration(2 * time.Second),
				logger:       zap.NewNop(),
			},
		},
	}
}

func TestActiveHTTPHealthCheckHealthyOnExpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/primary" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	h := httpHealthHandler("/primary", 0) // 0 => default 200
	p := &peer{}
	if _, err := p.setHealthy(false); err != nil { // start unhealthy
		t.Fatalf("seeding unhealthy: %v", err)
	}

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	if err := h.doActiveHTTPHealthCheck(p, hostPort, time.Second); err != nil {
		t.Fatalf("health check returned error: %v", err)
	}
	if !p.healthy() {
		t.Fatal("peer should be healthy after 200 on /primary")
	}
}

func TestActiveHTTPHealthCheckUnhealthyOnWrongStatus(t *testing.T) {
	// Mimics a replica: Patroni's /primary returns 503 when not the leader.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	h := httpHealthHandler("/primary", 0)
	p := &peer{} // starts healthy

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	if err := h.doActiveHTTPHealthCheck(p, hostPort, time.Second); err != nil {
		t.Fatalf("health check returned error: %v", err)
	}
	if p.healthy() {
		t.Fatal("peer should be unhealthy after 503 on /primary")
	}
}

func TestActiveHTTPHealthCheckUnhealthyOnDial(t *testing.T) {
	h := httpHealthHandler("/primary", 0)
	p := &peer{} // starts healthy

	// Port 1 is not listening: the GET must fail and mark the peer down.
	if err := h.doActiveHTTPHealthCheck(p, "127.0.0.1:1", 200*time.Millisecond); err != nil {
		t.Fatalf("health check returned error: %v", err)
	}
	if p.healthy() {
		t.Fatal("peer should be unhealthy when the connection is refused")
	}
}

func TestStatusCodeMatches(t *testing.T) {
	cases := []struct {
		status, expect int
		want           bool
	}{
		{200, 200, true},
		{503, 200, false},
		{204, 2, true},  // class match
		{299, 2, true},  // class match
		{301, 2, false}, // class mismatch
		{301, 3, true},  // class match
	}
	for _, c := range cases {
		if got := statusCodeMatches(c.status, c.expect); got != c.want {
			t.Errorf("statusCodeMatches(%d, %d) = %v, want %v", c.status, c.expect, got, c.want)
		}
	}
}

func TestParseStatusCode(t *testing.T) {
	ok := map[string]int{"200": 200, "404": 404, "2xx": 2, "5xx": 5}
	for in, want := range ok {
		got, err := parseStatusCode(in)
		if err != nil {
			t.Errorf("parseStatusCode(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseStatusCode(%q) = %d, want %d", in, got, want)
		}
	}
	for _, in := range []string{"", "abc", "9xx", "xxx", "2x"} {
		if _, err := parseStatusCode(in); err == nil {
			t.Errorf("parseStatusCode(%q): expected error, got nil", in)
		}
	}
}

func TestActiveHTTPHealthCheckStatusClass(t *testing.T) {
	// expect_status 2 (any 2xx); server returns 204.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	h := httpHealthHandler("/primary", 2)
	p := &peer{}
	if _, err := p.setHealthy(false); err != nil {
		t.Fatalf("seeding unhealthy: %v", err)
	}

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	if err := h.doActiveHTTPHealthCheck(p, hostPort, time.Second); err != nil {
		t.Fatalf("health check returned error: %v", err)
	}
	if !p.healthy() {
		t.Fatal("peer should be healthy after 204 with expect_status 2 (2xx class)")
	}
}

func TestActiveHTTPSHealthCheck(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/primary" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	h := httpHealthHandler("/primary", 0)
	h.HealthChecks.Active.HTTPS = true
	h.HealthChecks.Active.TLSSkipVerify = true // httptest uses a self-signed cert
	p := &peer{}
	if _, err := p.setHealthy(false); err != nil {
		t.Fatalf("seeding unhealthy: %v", err)
	}

	hostPort := strings.TrimPrefix(srv.URL, "https://")
	if err := h.doActiveHTTPHealthCheck(p, hostPort, time.Second); err != nil {
		t.Fatalf("https health check returned error: %v", err)
	}
	if !p.healthy() {
		t.Fatal("peer should be healthy after 200 over HTTPS on /primary")
	}
}

func TestActiveHTTPHealthCheckBadURI(t *testing.T) {
	// A control character makes the request URL invalid, so building the
	// request fails and the error is surfaced (rather than marking unhealthy).
	h := httpHealthHandler("/\x7f", 0)
	p := &peer{}
	if err := h.doActiveHTTPHealthCheck(p, "127.0.0.1:9", time.Second); err == nil {
		t.Fatal("expected an error building the request for an invalid URI")
	}
}

func TestUnmarshalCaddyfileHTTPHealthCheck(t *testing.T) {
	d := caddyfile.NewTestDispenser(`proxy localhost:5432 {
		health_uri /primary
		health_status 2xx
		health_https
		health_tls_skip_verify
	}`)
	h := new(Handler)
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if h.HealthChecks == nil || h.HealthChecks.Active == nil {
		t.Fatal("expected active health checks to be configured")
	}
	a := h.HealthChecks.Active
	if a.URI != "/primary" {
		t.Errorf("URI = %q, want /primary", a.URI)
	}
	if a.ExpectStatus != 2 {
		t.Errorf("ExpectStatus = %d, want 2", a.ExpectStatus)
	}
	if !a.HTTPS {
		t.Error("HTTPS = false, want true")
	}
	if !a.TLSSkipVerify {
		t.Error("TLSSkipVerify = false, want true")
	}
}

func TestUnmarshalCaddyfileHTTPHealthCheckErrors(t *testing.T) {
	cases := map[string]string{
		"duplicate health_uri":   "proxy localhost:5432 {\n\thealth_uri /a\n\thealth_uri /b\n}",
		"bad health_status":      "proxy localhost:5432 {\n\thealth_status nope\n}",
		"health_uri missing arg": "proxy localhost:5432 {\n\thealth_uri\n}",
		"health_https with arg":  "proxy localhost:5432 {\n\thealth_https yes\n}",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			h := new(Handler)
			if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatalf("expected error for %q, got nil", name)
			}
		})
	}
}
