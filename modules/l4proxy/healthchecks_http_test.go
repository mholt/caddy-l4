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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// httpCheckFixture is a handler with a single upstream, provisioned for HTTP
// active health checks against the given server address.
type httpCheckFixture struct {
	h    *Handler
	up   *Upstream
	p    *peer
	logs *observer.ObservedLogs
}

func newHTTPCheckFixture(t *testing.T, serverURL string, a *ActiveHealthChecks, up *Upstream) *httpCheckFixture {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := caddy.ParseNetworkAddress(u.Host)
	if err != nil {
		t.Fatalf("parsing %q: %v", u.Host, err)
	}
	p := &peer{address: &addr, dialAddr: u.Host}
	if up == nil {
		up = new(Upstream)
	}
	up.Dial = []string{u.Host}
	up.peers = []*peer{p}

	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)
	if a.Timeout == 0 {
		a.Timeout = caddy.Duration(2 * time.Second)
	}
	a.logger = logger
	h := &Handler{
		logger:    logger,
		metrics:   newProxyMetrics(prometheus.NewRegistry()),
		Upstreams: []*Upstream{up},
		HealthChecks: &HealthChecks{
			Active: a,
		},
	}
	if err := a.provision(h); err != nil {
		t.Fatalf("provisioning active health checks: %v", err)
	}
	t.Cleanup(a.closeIdleConnections)
	return &httpCheckFixture{h: h, up: up, p: p, logs: logs}
}

func (f *httpCheckFixture) check(t *testing.T) {
	t.Helper()
	if err := f.h.doActiveHealthCheck(f.up, f.p); err != nil {
		t.Fatalf("doActiveHealthCheck: %v", err)
	}
}

func (f *httpCheckFixture) count(msg string) int {
	return f.logs.FilterMessage(msg).Len()
}

func statusServer(status *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
}

func TestHealthURIValidatedAtProvision(t *testing.T) {
	for _, bad := range []string{"primary", "http://example.com/primary", "//example.com/x", "/bad%zz"} {
		a := &ActiveHealthChecks{URI: bad}
		if err := a.provision(&Handler{}); err == nil {
			t.Errorf("provision accepted uri %q", bad)
		}
		input := "proxy localhost:5432 {\n\thealth_uri " + bad + "\n}"
		if err := new(Handler).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
			t.Errorf("Caddyfile accepted health_uri %q", bad)
		}
	}
	a := &ActiveHealthChecks{URI: "/primary?role=leader"}
	if err := a.provision(&Handler{}); err != nil {
		t.Fatalf("valid uri rejected: %v", err)
	}
	a.closeIdleConnections()

	// An HTTP-only option without uri is a misconfiguration, not silently ignored.
	if err := (&ActiveHealthChecks{ExpectBody: "x"}).provision(&Handler{}); err == nil {
		t.Error("expect_body without uri accepted")
	}
	// The HTTP probe cannot run against a non-TCP upstream.
	udpAddr, _ := caddy.ParseNetworkAddress("udp/127.0.0.1:53")
	h := &Handler{Upstreams: []*Upstream{{peers: []*peer{{address: &udpAddr}}}}}
	if err := (&ActiveHealthChecks{URI: "/x"}).provision(h); err == nil {
		t.Error("uri accepted for a UDP upstream")
	}
}

func TestHTTPCheckStatus(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	srv := statusServer(&status)
	defer srv.Close()

	cases := []struct {
		name    string
		expect  int
		status  int32
		healthy bool
	}{
		{"default accepts 204", 0, 204, true},
		{"default rejects 301 without redirects", 0, 301, false},
		{"default rejects 503", 0, 503, false},
		{"exact match", 204, 204, true},
		{"exact mismatch", 200, 204, false},
		{"class match", 2, 299, true},
		{"class mismatch", 2, 301, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status.Store(tc.status)
			f := newHTTPCheckFixture(t, srv.URL, &ActiveHealthChecks{URI: "/primary", ExpectStatus: tc.expect}, nil)
			f.check(t)
			if got := f.p.healthy(); got != tc.healthy {
				t.Errorf("healthy = %v, want %v", got, tc.healthy)
			}
		})
	}
}

func TestHTTPCheckSchemeAndTrustFromUpstreamTLS(t *testing.T) {
	var gotTLS atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTLS.Store(r.TLS != nil)
	})
	tlsSrv := httptest.NewTLSServer(handler)
	defer tlsSrv.Close()
	plainSrv := httptest.NewServer(handler)
	defer plainSrv.Close()

	provisionTLS := func(t *testing.T, cfg *reverseproxy.TLSConfig) *Upstream {
		t.Helper()
		up := &Upstream{TLS: cfg}
		var err error
		if up.tlsConfig, err = cfg.MakeTLSClientConfig(caddy.Context{}); err != nil {
			t.Fatalf("making TLS client config: %v", err)
		}
		return up
	}

	t.Run("https with insecure_skip_verify", func(t *testing.T) {
		gotTLS.Store(false)
		up := provisionTLS(t, &reverseproxy.TLSConfig{InsecureSkipVerify: true})
		f := newHTTPCheckFixture(t, tlsSrv.URL, &ActiveHealthChecks{URI: "/"}, up)
		f.check(t)
		if !f.p.healthy() || !gotTLS.Load() {
			t.Errorf("healthy = %v, tls = %v; want a healthy check over TLS", f.p.healthy(), gotTLS.Load())
		}
	})
	t.Run("https verifies the certificate like the proxy does", func(t *testing.T) {
		up := provisionTLS(t, &reverseproxy.TLSConfig{})
		f := newHTTPCheckFixture(t, tlsSrv.URL, &ActiveHealthChecks{URI: "/"}, up)
		f.check(t)
		if f.p.healthy() {
			t.Error("self-signed certificate was trusted without insecure_skip_verify")
		}
	})
	t.Run("no upstream TLS means plain http", func(t *testing.T) {
		gotTLS.Store(true)
		f := newHTTPCheckFixture(t, plainSrv.URL, &ActiveHealthChecks{URI: "/"}, nil)
		f.check(t)
		if !f.p.healthy() || gotTLS.Load() {
			t.Errorf("healthy = %v, tls = %v; want a healthy plain HTTP check", f.p.healthy(), gotTLS.Load())
		}
	})
	t.Run("no upstream TLS against a TLS server fails", func(t *testing.T) {
		f := newHTTPCheckFixture(t, tlsSrv.URL, &ActiveHealthChecks{URI: "/"}, nil)
		f.check(t)
		if f.p.healthy() {
			t.Error("plain HTTP check of a TLS server passed")
		}
	})
	t.Run("upstream TLS against a plain server fails", func(t *testing.T) {
		up := provisionTLS(t, &reverseproxy.TLSConfig{InsecureSkipVerify: true})
		f := newHTTPCheckFixture(t, plainSrv.URL, &ActiveHealthChecks{URI: "/"}, up)
		f.check(t)
		if f.p.healthy() {
			t.Error("TLS check of a plain HTTP server passed")
		}
	})
	t.Run("https and tls_skip_verify are gone", func(t *testing.T) {
		for _, opt := range []string{"health_https", "health_tls_skip_verify"} {
			input := "proxy localhost:5432 {\n\t" + opt + "\n}"
			if err := new(Handler).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Errorf("%s still accepted", opt)
			}
		}
	})
}

func TestHTTPCheckExpectBodyAndMaxSize(t *testing.T) {
	var body atomic.Value
	body.Store("role: primary")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer srv.Close()

	cases := []struct {
		name    string
		body    string
		regexp  string
		maxSize int64
		healthy bool
	}{
		{"match", "role: primary", `primary`, 0, true},
		{"mismatch", "role: replica", `primary`, 0, false},
		{"anchored regexp", "role: primary", `^role: (primary|leader)$`, 0, true},
		{"match beyond max_size is not seen", "xxxxxxxxxxprimary", `primary`, 5, false},
		{"match within max_size", "primaryxxxxxxxxxx", `primary`, 7, true},
		{"no expect_body ignores body", "anything", ``, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body.Store(tc.body)
			f := newHTTPCheckFixture(t, srv.URL, &ActiveHealthChecks{URI: "/", ExpectBody: tc.regexp, MaxSize: tc.maxSize}, nil)
			f.check(t)
			if got := f.p.healthy(); got != tc.healthy {
				t.Errorf("healthy = %v, want %v", got, tc.healthy)
			}
		})
	}

	t.Run("bad expect_body rejected at provision", func(t *testing.T) {
		if err := (&ActiveHealthChecks{URI: "/", ExpectBody: "("}).provision(&Handler{}); err == nil {
			t.Error("invalid regular expression accepted")
		}
		input := "proxy localhost:5432 {\n\thealth_body (\n}"
		if err := new(Handler).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
			t.Error("Caddyfile accepted an invalid health_body")
		}
	})
}

// TestHTTPCheckRequestHeadersMethodBody covers the request building ported
// from mainline, which is the feature of the folded "request headers and
// body matching" change.
func TestHTTPCheckRequestHeadersMethodBody(t *testing.T) {
	type seen struct {
		method, host, header, uri, body string
	}
	var mu sync.Mutex
	var got seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = seen{r.Method, r.Host, r.Header.Get("X-Role"), r.URL.RequestURI(), string(b)}
		mu.Unlock()
	}))
	defer srv.Close()

	f := newHTTPCheckFixture(t, srv.URL, &ActiveHealthChecks{
		URI:     "/health?deep=1",
		Method:  http.MethodPost,
		Body:    `{"check":"primary"}`,
		Headers: http.Header{"x-role": {"leader"}, "Host": {"db.internal"}},
	}, nil)
	f.check(t)

	mu.Lock()
	defer mu.Unlock()
	want := seen{http.MethodPost, "db.internal", "leader", "/health?deep=1", `{"check":"primary"}`}
	if got != want {
		t.Errorf("server saw %+v, want %+v", got, want)
	}
	if !f.p.healthy() {
		t.Error("peer unhealthy after a 200 response")
	}

	// Caddyfile forms, 1:1 with mainline.
	input := "proxy localhost:5432 {\n\thealth_uri /p\n\thealth_status 2xx\n\thealth_method POST\n" +
		"\thealth_request_body hi\n\thealth_body ok\n\thealth_follow_redirects\n" +
		"\thealth_headers {\n\t\tX-Role leader\n\t\tHost db.internal\n\t}\n}"
	h := new(Handler)
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	a := h.HealthChecks.Active
	if a.URI != "/p" || a.ExpectStatus != 2 || a.Method != "POST" || a.Body != "hi" || a.ExpectBody != "ok" ||
		!a.FollowRedirects || a.Headers.Get("X-Role") != "leader" || a.Headers["Host"][0] != "db.internal" {
		t.Errorf("unexpected active health checks: %+v", a)
	}
}

func TestHTTPCheckRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/new", http.StatusFound)
	})
	mux.HandleFunc("/new", func(http.ResponseWriter, *http.Request) {})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := newHTTPCheckFixture(t, srv.URL, &ActiveHealthChecks{URI: "/old"}, nil)
	f.check(t)
	if f.p.healthy() {
		t.Error("redirect was followed without follow_redirects")
	}
	f = newHTTPCheckFixture(t, srv.URL, &ActiveHealthChecks{URI: "/old", FollowRedirects: true}, nil)
	f.check(t)
	if !f.p.healthy() {
		t.Error("redirect was not followed with follow_redirects")
	}
}

// The HTTP result must go through recordActiveCheck, i.e. honor fall and rise.
func TestHTTPCheckHonorsRiseFall(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	srv := statusServer(&status)
	defer srv.Close()
	f := newHTTPCheckFixture(t, srv.URL, &ActiveHealthChecks{URI: "/", Fall: 2, Rise: 2}, nil)

	status.Store(503)
	f.check(t)
	if !f.p.healthy() {
		t.Fatal("one failure marked the peer unhealthy with fall=2")
	}
	f.check(t)
	if f.p.healthy() {
		t.Fatal("two failures did not mark the peer unhealthy with fall=2")
	}

	status.Store(200)
	f.check(t)
	if f.p.healthy() {
		t.Fatal("one success marked the peer healthy with rise=2")
	}
	f.check(t)
	if !f.p.healthy() {
		t.Fatal("two successes did not mark the peer healthy with rise=2")
	}
}

// close_if_unhealthy and the health metric must apply to HTTP results too.
func TestHTTPCheckClosesConnsAndSetsMetric(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	srv := statusServer(&status)
	defer srv.Close()
	f := newHTTPCheckFixture(t, srv.URL, &ActiveHealthChecks{URI: "/", CloseIfUnhealthy: true}, nil)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	f.p.trackConn(server)

	f.check(t)
	if got := testutil.ToFloat64(f.h.metrics.upstreamHealthy.WithLabelValues(f.p.dialAddr)); got != 1 {
		t.Errorf("health metric = %v after a healthy check, want 1", got)
	}

	status.Store(503)
	f.check(t)
	if got := testutil.ToFloat64(f.h.metrics.upstreamHealthy.WithLabelValues(f.p.dialAddr)); got != 0 {
		t.Errorf("health metric = %v after a failed check, want 0", got)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("tracked connection was not closed by close_if_unhealthy: read error %v", err)
	}
}

func TestHTTPCheckLogsOnlyOnStateChange(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	srv := statusServer(&status)
	defer srv.Close()
	f := newHTTPCheckFixture(t, srv.URL, &ActiveHealthChecks{URI: "/"}, nil)

	for range 3 {
		f.check(t)
	}
	if n := f.count("host is up"); n != 0 {
		t.Errorf("'host is up' logged %d times for a peer that never went down", n)
	}
	status.Store(500)
	for range 3 {
		f.check(t)
	}
	if n := f.count("host is down"); n != 1 {
		t.Errorf("'host is down' logged %d times over 3 failed checks, want 1", n)
	}
	status.Store(200)
	for range 3 {
		f.check(t)
	}
	if n := f.count("host is up"); n != 1 {
		t.Errorf("'host is up' logged %d times over 3 good checks, want 1", n)
	}
}

func TestHTTPCheckDialHonorsLocalAddressAndResolverPreference(t *testing.T) {
	var mu sync.Mutex
	var remote string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		remote = r.RemoteAddr
		mu.Unlock()
	}))
	defer srv.Close()

	t.Run("local_address", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		src := l.Addr().String()
		_ = l.Close()
		up := &Upstream{localAddrs: []string{src}}
		f := newHTTPCheckFixture(t, srv.URL, &ActiveHealthChecks{URI: "/"}, up)
		f.check(t)
		mu.Lock()
		defer mu.Unlock()
		if !f.p.healthy() || remote != src {
			t.Errorf("healthy = %v, server saw %q; want a check from %q", f.p.healthy(), remote, src)
		}
	})
	t.Run("resolver_preference", func(t *testing.T) {
		// The server only listens on IPv4, so ipv6_only must fail the check.
		up := &Upstream{ResolverPreference: "ipv6_only"}
		f := newHTTPCheckFixture(t, srv.URL, &ActiveHealthChecks{URI: "/"}, up)
		f.check(t)
		if f.p.healthy() {
			t.Error("resolver_preference ipv6_only did not apply to the HTTP check")
		}
		up = &Upstream{ResolverPreference: "ipv4_only"}
		f = newHTTPCheckFixture(t, srv.URL, &ActiveHealthChecks{URI: "/"}, up)
		f.check(t)
		if !f.p.healthy() {
			t.Error("resolver_preference ipv4_only failed against an IPv4 server")
		}
	})
}

// One dedicated transport serves all checks (connections are reused), it
// ignores proxy environment variables, and Cleanup closes its idle connections.
func TestHTTPCheckTransport(t *testing.T) {
	var conns atomic.Int32
	var closed atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			conns.Add(1)
		case http.StateClosed:
			closed.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	f := newHTTPCheckFixture(t, srv.URL, &ActiveHealthChecks{URI: "/"}, nil)
	a := f.h.HealthChecks.Active
	if a.transport == nil || a.transport.Proxy != nil {
		t.Fatalf("transport = %+v, want a dedicated transport with Proxy nil", a.transport)
	}
	if a.httpClient.Transport != http.RoundTripper(a.transport) {
		t.Error("client does not use the dedicated transport")
	}
	for range 3 {
		f.check(t)
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("3 checks opened %d connections, want 1 (reused by one transport)", n)
	}
	if err := f.h.Cleanup(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if closed.Load() != 1 {
		t.Errorf("Cleanup left the idle connection open (closed=%d)", closed.Load())
	}
}

func TestHTTPCheckUnreachableUpstream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listens any more
	f := newHTTPCheckFixture(t, url, &ActiveHealthChecks{URI: "/", Timeout: caddy.Duration(500 * time.Millisecond)}, nil)
	f.check(t)
	if f.p.healthy() {
		t.Error("peer healthy although nothing listens")
	}
	if f.count("host is down") != 1 {
		t.Errorf("expected exactly one 'host is down' log, got %d", f.count("host is down"))
	}
}
