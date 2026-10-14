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

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestActiveHTTPHealthCheckSendsHeadersAndHost(t *testing.T) {
	var gotHeader, gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Probe")
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := httpHealthHandler("/primary", 0)
	h.HealthChecks.Active.Headers = http.Header{
		"X-Probe": {"weft"},
		"Host":    {"db.internal"},
	}
	p := &peer{}

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	if err := h.doActiveHTTPHealthCheck(p, hostPort, time.Second); err != nil {
		t.Fatalf("health check: %v", err)
	}
	if gotHeader != "weft" {
		t.Errorf("X-Probe header = %q, want weft", gotHeader)
	}
	if gotHost != "db.internal" {
		t.Errorf("Host = %q, want db.internal", gotHost)
	}
	if !p.healthy() {
		t.Error("peer should be healthy")
	}
}

func TestActiveHTTPHealthCheckExpectBodyMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"role":"master","state":"running"}`))
	}))
	defer srv.Close()

	h := httpHealthHandler("/primary", 0)
	h.HealthChecks.Active.ExpectBody = `"role":"master"`
	p := &peer{}
	if _, err := p.setHealthy(false); err != nil {
		t.Fatalf("seeding unhealthy: %v", err)
	}

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	if err := h.doActiveHTTPHealthCheck(p, hostPort, time.Second); err != nil {
		t.Fatalf("health check: %v", err)
	}
	if !p.healthy() {
		t.Fatal("peer should be healthy when the body matches expect_body")
	}
}

func TestActiveHTTPHealthCheckExpectBodyMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"role":"replica"}`))
	}))
	defer srv.Close()

	h := httpHealthHandler("/primary", 0)
	h.HealthChecks.Active.ExpectBody = `"role":"master"`
	p := &peer{} // starts healthy

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	if err := h.doActiveHTTPHealthCheck(p, hostPort, time.Second); err != nil {
		t.Fatalf("health check: %v", err)
	}
	if p.healthy() {
		t.Fatal("peer should be unhealthy when the body does not match expect_body")
	}
}

func TestActiveHTTPHealthCheckBadExpectBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := httpHealthHandler("/primary", 0)
	h.HealthChecks.Active.ExpectBody = "(["
	p := &peer{}

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	if err := h.doActiveHTTPHealthCheck(p, hostPort, time.Second); err == nil {
		t.Fatal("expected an error compiling an invalid expect_body regexp")
	}
}

func TestUnmarshalCaddyfileHeadersAndExpectBody(t *testing.T) {
	d := caddyfile.NewTestDispenser("proxy localhost:5432 {\n" +
		"\thealth_uri /primary\n" +
		"\thealth_header X-Probe weft\n" +
		"\thealth_header Host db.internal\n" +
		"\thealth_expect_body running\n" +
		"}")
	h := new(Handler)
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	a := h.HealthChecks.Active
	if a.Headers.Get("X-Probe") != "weft" {
		t.Errorf("X-Probe = %q, want weft", a.Headers.Get("X-Probe"))
	}
	if a.Headers.Get("Host") != "db.internal" {
		t.Errorf("Host = %q, want db.internal", a.Headers.Get("Host"))
	}
	if a.ExpectBody != "running" {
		t.Errorf("ExpectBody = %q, want running", a.ExpectBody)
	}
}

func TestUnmarshalCaddyfileHeadersAndExpectBodyErrors(t *testing.T) {
	cases := map[string]string{
		"health_header missing value":  "proxy localhost:1 {\n\thealth_header onlyname\n}",
		"duplicate health_expect_body": "proxy localhost:1 {\n\thealth_expect_body a\n\thealth_expect_body b\n}",
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
