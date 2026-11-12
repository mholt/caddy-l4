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
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// HealthChecks configures active and passive health checks.
type HealthChecks struct {
	// Active health checks run in the background on a timer. To
	// minimally enable active health checks, set the interval; the
	// default probe is a raw TCP dial. Set uri to probe over HTTP
	// instead (see the fields below), which lets the proxy follow
	// an application-level signal such as a primary-election endpoint.
	// The HTTP probe uses TLS if, and only if, the upstream has TLS
	// enabled, and trusts the upstream exactly as proxied connections do.
	Active *ActiveHealthChecks `json:"active,omitempty"`

	// Passive health checks monitor proxied connections for errors or timeouts.
	// To minimally enable passive health checks, specify at least an empty
	// config object.
	Passive *PassiveHealthChecks `json:"passive,omitempty"`
}

// ActiveHealthChecks holds configuration related to active health
// checks (that is, health checks which occur independently in a
// background goroutine).
//
// The HTTP fields (uri, headers, method, body, follow_redirects, max_size,
// expect_status and expect_body) and their semantics are ported from
// caddyhttp/reverseproxy.ActiveHealthChecks in Caddy, and are kept as close
// to it as possible so that this copy can be dropped in favor of the
// original when the two are merged.
type ActiveHealthChecks struct {
	// The port to use (if different from the upstream's dial
	// address) for health checks.
	Port int `json:"port,omitempty"`

	// The URI (path and query) to request for an HTTP health check, e.g.
	// "/primary". It must start with "/". When set, each check performs an
	// HTTP request against the upstream (on Port if configured, otherwise the
	// dial port) instead of a raw TCP dial. HTTPS is used if, and only if,
	// the upstream has TLS enabled; the upstream's TLS settings (including
	// insecure_skip_verify) are applied to the probe.
	URI string `json:"uri,omitempty"`

	// HTTP headers to set on health check requests. A "Host" entry sets the
	// request's Host. Only used when URI is set.
	Headers http.Header `json:"headers,omitempty"`

	// The HTTP method to use for health checks (default "GET").
	Method string `json:"method,omitempty"`

	// The body to send with the health check request.
	Body string `json:"body,omitempty"`

	// Whether to follow HTTP redirects in response to active health checks (default off).
	FollowRedirects bool `json:"follow_redirects,omitempty"`

	// The maximum response body to download from the backend
	// during a health check.
	MaxSize int64 `json:"max_size,omitempty"`

	// The HTTP status code to expect from a healthy backend. A value below
	// 100 is a status class, e.g. 2 matches any 2xx response. If unset, any
	// 2xx response is healthy.
	ExpectStatus int `json:"expect_status,omitempty"`

	// A regular expression against which to match the response
	// body of a healthy backend.
	ExpectBody string `json:"expect_body,omitempty"`

	// How frequently to perform active health checks (default 30s).
	Interval caddy.Duration `json:"interval,omitempty"`

	// How long to wait for a connection to be established with
	// peer before considering it unhealthy (default 5s).
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// CloseIfUnhealthy, when true, force-closes a peer's currently open proxied
	// connections the moment an active health check marks it unhealthy, instead
	// of letting them run until they close on their own. This is useful for
	// failover, where clients should be moved off a backend as soon as it goes
	// down (e.g. a demoted database primary). Default false, preserving the
	// existing behavior.
	//
	// This applies to active health checks only: they provide a clear
	// healthy->unhealthy transition to hook onto. Passive health checking has no
	// equivalent transition event (a peer is simply considered down on demand
	// once its failure count crosses the threshold), so there is nothing to
	// trigger a close.
	CloseIfUnhealthy bool `json:"close_if_unhealthy,omitempty"`

	// Fall is the number of consecutive failed active health checks required
	// to mark an upstream unhealthy (default 1).
	Fall int `json:"fall,omitempty"`

	// Rise is the number of consecutive successful active health checks
	// required to mark an unhealthy upstream healthy again (default 1).
	Rise int `json:"rise,omitempty"`

	uri        *url.URL
	bodyRegexp *regexp.Regexp
	transport  *http.Transport
	httpClient *http.Client
	logger     *zap.Logger
}

// isHTTP reports whether the active health check probes over HTTP.
func (a *ActiveHealthChecks) isHTTP() bool {
	return a.URI != ""
}

// validateHealthURI checks the URI of an HTTP health check. It is called
// when parsing a Caddyfile and when provisioning, so a bad value is
// rejected up front instead of failing every single check.
func validateHealthURI(uri string) (*url.URL, error) {
	if !strings.HasPrefix(uri, "/") {
		return nil, fmt.Errorf("uri %q must start with '/'", uri)
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("uri %q: %v", uri, err)
	}
	if u.Scheme != "" || u.Host != "" {
		return nil, fmt.Errorf("uri %q must be a path and query only", uri)
	}
	return u, nil
}

// provision validates the HTTP probe configuration and builds, once per
// handler, the dedicated transport and client used by every HTTP check.
// It does nothing for plain TCP health checks.
func (a *ActiveHealthChecks) provision(h *Handler) error {
	if !a.isHTTP() {
		if len(a.Headers) > 0 || a.Method != "" || a.Body != "" || a.FollowRedirects ||
			a.MaxSize != 0 || a.ExpectStatus != 0 || a.ExpectBody != "" {
			return fmt.Errorf("headers, method, body, follow_redirects, max_size, expect_status and expect_body require uri")
		}
		return nil
	}
	var err error
	if a.uri, err = validateHealthURI(a.URI); err != nil {
		return err
	}

	// Canonicalize the header keys ahead of time, since
	// JSON unmarshaled headers may be incorrect
	cleaned := http.Header{}
	for key, hdrs := range a.Headers {
		for _, val := range hdrs {
			cleaned.Add(key, val)
		}
	}
	a.Headers = cleaned

	// If Method is not set, default to GET
	if a.Method == "" {
		a.Method = http.MethodGet
	}

	if a.ExpectBody != "" {
		a.bodyRegexp, err = regexp.Compile(a.ExpectBody)
		if err != nil {
			return fmt.Errorf("expect_body: compiling regular expression: %v", err)
		}
	}

	// The HTTP probe only makes sense against TCP upstreams.
	for i, ups := range h.Upstreams {
		for _, p := range ups.peers {
			if p.address == nil {
				continue
			}
			switch p.address.Network {
			case "tcp", "tcp4", "tcp6":
			default:
				return fmt.Errorf("uri: HTTP health checks require TCP upstreams; upstream %d has network %q", i, p.address.Network)
			}
		}
	}

	timeout := time.Duration(a.Timeout)
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	// Proxy is nil on purpose: HTTP(S)_PROXY in the environment must not
	// redirect health probes. Dialing goes through the proxy's own helpers so
	// that local_address and resolver_preference apply, and TLS comes from the
	// upstream; see healthCheckDialContext and healthCheckDialTLSContext.
	a.transport = &http.Transport{
		Proxy:          nil,
		DialContext:    h.healthCheckDialContext,
		DialTLSContext: h.healthCheckDialTLSContext,
		// Keep-alives are off on purpose: http.Transport pools connections by
		// scheme and host:port only, but TLS is applied per upstream in
		// healthCheckDialTLSContext. Two upstreams sharing a dial address with
		// different TLS settings must not reuse a connection handshaked with
		// the other's configuration, so every probe dials afresh. Checks are
		// infrequent, so the lost reuse is cheap.
		DisableKeepAlives: true,
	}
	a.httpClient = &http.Client{
		Timeout:   timeout,
		Transport: a.transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			if !a.FollowRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return nil
}

// closeIdleConnections releases the keep-alive connections of the HTTP probe.
func (a *ActiveHealthChecks) closeIdleConnections() {
	if a.transport != nil {
		a.transport.CloseIdleConnections()
	}
}

// PassiveHealthChecks holds configuration related to passive
// health checks (that is, health checks which occur during
// the normal flow of connection proxying).
type PassiveHealthChecks struct {
	// How long to remember a failed connection to a backend. A
	// duration > 0 enables passive health checking. Default 0.
	FailDuration caddy.Duration `json:"fail_duration,omitempty"`

	// The number of failed connections within the FailDuration window to
	// consider a backend as "down". Must be >= 1; default is 1. Requires
	// that FailDuration be > 0.
	MaxFails int `json:"max_fails,omitempty"`

	// Limits the number of simultaneous connections to a backend by
	// marking the backend as "down" if it has this many or more
	// concurrent connections.
	UnhealthyConnectionCount int `json:"unhealthy_connection_count,omitempty"`

	logger *zap.Logger
}

// activeHealthChecker runs active health checks on a
// regular basis and blocks until
// h.HealthChecks.Active.stopChan is closed.
func (h *Handler) activeHealthChecker() {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[PANIC] active health checks: %v\n%s", err, debug.Stack())
		}
	}()
	ticker := time.NewTicker(time.Duration(h.HealthChecks.Active.Interval))
	h.doActiveHealthCheckForAllHosts()
	for {
		select {
		case <-ticker.C:
			h.doActiveHealthCheckForAllHosts()
		case <-h.ctx.Done():
			ticker.Stop()
			return
		}
	}
}

// doActiveHealthCheckForAllHosts immediately performs a
// health checks for all upstream hosts configured by h.
func (h *Handler) doActiveHealthCheckForAllHosts() {
	for _, upstream := range h.Upstreams {
		go func(upstream *Upstream) {
			defer func() {
				if err := recover(); err != nil {
					log.Printf("[PANIC] active health check: %v\n%s", err, debug.Stack())
				}
			}()

			for _, p := range upstream.peers {
				err := h.doActiveHealthCheck(upstream, p)
				if err != nil {
					h.HealthChecks.Active.logger.Error("active health check failed",
						zap.String("peer", p.address.String()),
						zap.Error(err))
				}
			}
		}(upstream)
	}
}

// healthCheckParentContext returns the context health checks derive from, so
// that they are cancelled when the handler is shut down.
func (h *Handler) healthCheckParentContext() context.Context {
	if h.ctx.Context != nil {
		return h.ctx.Context
	}
	return context.Background()
}

// doActiveHealthCheck performs a health check to host which
// can be reached at address hostAddr. The health status of
// the host will be updated according to whether it passes
// the health check. An error is returned only if the health
// check fails to occur or if marking the host's health status
// fails.
//
// The probe is a raw TCP dial or, if a URI is configured, an HTTP request;
// either way the outcome goes through the same code below (rise/fall,
// close_if_unhealthy, metrics, logging on state change).
func (h *Handler) doActiveHealthCheck(upstream *Upstream, p *peer) error {
	if p.address == nil {
		return nil
	}
	addr := *p.address

	// adjust the port, if configured to be different
	if h.HealthChecks.Active.Port > 0 {
		addr.StartPort = uint(h.HealthChecks.Active.Port) //nolint:gosec // disable G115
		addr.EndPort = addr.StartPort
	}

	hostPort := addr.JoinHostPort(0)
	timeout := time.Duration(h.HealthChecks.Active.Timeout)

	ctx, cancel := context.WithTimeout(h.healthCheckParentContext(), timeout)
	defer cancel()

	var probeErr error
	if h.HealthChecks.Active.isHTTP() {
		probeErr = h.doActiveHTTPProbe(ctx, upstream, addr.Network, hostPort)
	} else {
		dialNetwork, localAddrs, err := h.healthCheckDialInfo(upstream, addr.Network, hostPort)
		if err != nil {
			return err
		}
		var conn net.Conn
		conn, probeErr = dialWithLocalAddrsContext(ctx, localAddrs, dialNetwork, hostPort)
		if probeErr == nil {
			_ = conn.Close()
		}
	}

	rise, fall := h.HealthChecks.Active.Rise, h.HealthChecks.Active.Fall
	if probeErr != nil {
		h.HealthChecks.Active.logger.Info("active health check failed",
			zap.String("address", addr.String()),
			zap.Duration("timeout", timeout),
			zap.Error(probeErr))
		if mark, healthy := p.recordActiveCheck(false, rise, fall); mark {
			swapped, err2 := p.setHealthy(healthy)
			if err2 != nil {
				return fmt.Errorf("marking unhealthy: %v (original error: %v)", err2, probeErr)
			}
			if swapped {
				h.HealthChecks.Active.logger.Info("host is down", zap.String("address", addr.String()))
			}
			if swapped && h.HealthChecks.Active.CloseIfUnhealthy {
				p.closeOpenConns()
			}
		}
		h.metrics.setUpstreamHealthy(p.dialAddr, false)
		return nil
	}

	// the probe succeeded
	if mark, healthy := p.recordActiveCheck(true, rise, fall); mark {
		swapped, err := p.setHealthy(healthy)
		if err != nil {
			return fmt.Errorf("marking healthy: %v", err)
		}
		if swapped {
			h.HealthChecks.Active.logger.Info("host is up", zap.String("address", addr.String()))
		}
	}
	h.metrics.setUpstreamHealthy(p.dialAddr, true)

	return nil
}

// healthCheckTarget tells the health check transport which upstream a request
// is for, so that its dial functions can apply that upstream's settings.
type healthCheckTarget struct {
	upstream *Upstream
	network  string
}

type healthCheckTargetKey struct{}

// doActiveHTTPProbe performs the HTTP request of an active health check and
// returns nil if the response satisfies the configured expectations, or an
// error saying why not.
//
// It is the transport-neutral part of the probe in Caddy's
// caddyhttp/reverseproxy/healthchecks.go (doActiveHealthCheck): build the
// request from uri/method/headers/body, then apply expect_status,
// expect_body and max_size. The scheme and TLS settings are not configured
// here: the scheme follows Upstream.TLS, and the transport trusts the
// upstream exactly like proxied connections do.
func (h *Handler) doActiveHTTPProbe(ctx context.Context, upstream *Upstream, network, hostPort string) error {
	a := h.HealthChecks.Active

	scheme := "http"
	if upstream.TLS != nil {
		scheme = "https"
	}
	u := &url.URL{
		Scheme:   scheme,
		Host:     hostPort,
		Path:     a.uri.Path,
		RawPath:  a.uri.RawPath,
		RawQuery: a.uri.RawQuery,
	}

	// replacer used for both body and headers. Only globals (env vars, system info, etc.) are available
	repl := caddy.NewReplacer()

	// if body is provided, create a reader for it, otherwise nil
	var requestBody io.Reader
	if a.Body != "" {
		// Only known placeholders are replaced: the body is often JSON, whose
		// braces would otherwise be read as placeholders and blanked.
		requestBody = strings.NewReader(repl.ReplaceKnown(a.Body, ""))
	}

	ctx = context.WithValue(ctx, healthCheckTargetKey{}, healthCheckTarget{upstream: upstream, network: network})
	req, err := http.NewRequestWithContext(ctx, a.Method, u.String(), requestBody)
	if err != nil {
		return fmt.Errorf("making request: %v", err)
	}

	// set headers, using replacer
	for key, vals := range a.Headers {
		key = repl.ReplaceAll(key, "")
		if key == "Host" {
			req.Host = repl.ReplaceAll(a.Headers.Get(key), "")
			continue
		}
		for _, val := range vals {
			req.Header.Add(key, repl.ReplaceKnown(val, ""))
		}
	}

	// do the request, being careful to tame the response body
	resp, err := a.httpClient.Do(req) //nolint:gosec // no SSRF: the target is a configured upstream
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	var body io.Reader = resp.Body
	if a.MaxSize > 0 {
		body = io.LimitReader(body, a.MaxSize)
	}
	defer func() {
		// drain any remaining body so connection could be reused
		_, _ = io.Copy(io.Discard, body)
		_ = resp.Body.Close()
	}()

	// if status code is outside criteria, mark down
	if a.ExpectStatus > 0 {
		if !statusCodeMatches(resp.StatusCode, a.ExpectStatus) {
			return fmt.Errorf("unexpected status code %d (expected %d)", resp.StatusCode, a.ExpectStatus)
		}
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status code %d out of tolerances", resp.StatusCode)
	}

	// if body does not match regex, mark down
	if a.bodyRegexp != nil {
		bodyBytes, err := io.ReadAll(body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		if !a.bodyRegexp.Match(bodyBytes) {
			return fmt.Errorf("response body failed expectations")
		}
	}

	return nil
}

// statusCodeMatches is a copy of caddyhttp.StatusCodeMatches: it reports
// whether actual satisfies configured, which is either an exact status code
// or, if below 100, a status class (e.g. 2 matches any 2xx response).
func statusCodeMatches(actual, configured int) bool {
	if actual == configured {
		return true
	}
	return configured < 100 &&
		actual >= configured*100 &&
		actual < (configured+1)*100
}

// healthCheckDialInfo resolves how a health check connection to hostPort
// must be dialed: the same way as proxied connections, i.e. honoring the
// upstream's resolver_preference and local_address.
func (h *Handler) healthCheckDialInfo(upstream *Upstream, network, hostPort string) (string, []net.Addr, error) {
	// Resolve the destination address family only when it will actually be used,
	// i.e. when the user has configured local_address or resolver_preference.
	// Otherwise skip it to avoid an extra DNS lookup per health check for hostname upstreams.
	var destFam int
	if len(upstream.localAddrs) > 0 || upstream.ResolverPreference != "" {
		var err error
		destFam, err = resolveDestFamily(network, hostPort, upstream.ResolverPreference)
		if err != nil {
			return "", nil, err
		}
	}
	// Narrow the dial network to match the resolved family so resolver_preference
	// is enforced at Dial time. When destFam == 0 (both new features unset) this
	// returns the network unchanged, preserving pre-PR health-check behavior.
	dialNetwork := narrowNetworkForFamily(network, destFam)
	return dialNetwork, buildLocalAddrs(upstream.localAddrs, dialNetwork, destFam, h.logger), nil
}

// healthCheckDialContext is the DialContext of the health check transport. It
// dials the upstream the request is for, as the proxy itself would.
func (h *Handler) healthCheckDialContext(ctx context.Context, _, hostPort string) (net.Conn, error) {
	t, ok := ctx.Value(healthCheckTargetKey{}).(healthCheckTarget)
	if !ok {
		return nil, fmt.Errorf("health check dial %s: no upstream in context", hostPort)
	}
	dialNetwork, localAddrs, err := h.healthCheckDialInfo(t.upstream, t.network, hostPort)
	if err != nil {
		return nil, err
	}
	return dialWithLocalAddrsContext(ctx, localAddrs, dialNetwork, hostPort)
}

// healthCheckDialTLSContext is the DialTLSContext of the health check
// transport. It uses the TLS client configuration of the upstream the request
// is for (so insecure_skip_verify, the trust pool, client certificates and the
// server name apply), defaulting the server name to the dialed host.
func (h *Handler) healthCheckDialTLSContext(ctx context.Context, _, hostPort string) (net.Conn, error) {
	t, ok := ctx.Value(healthCheckTargetKey{}).(healthCheckTarget)
	if !ok {
		return nil, fmt.Errorf("health check dial %s: no upstream in context", hostPort)
	}
	conn, err := h.healthCheckDialContext(ctx, "", hostPort)
	if err != nil {
		return nil, err
	}
	cfg := new(tls.Config)
	if t.upstream.tlsConfig != nil {
		cfg = t.upstream.tlsConfig.Clone()
	}
	// A server name with runtime placeholders (e.g. {l4.tls.server_name}) has no
	// value outside a proxied connection; fall back to the host being dialed.
	cfg.ServerName = caddy.NewReplacer().ReplaceAll(cfg.ServerName, "")
	if cfg.ServerName == "" {
		if host, _, splitErr := net.SplitHostPort(hostPort); splitErr == nil {
			cfg.ServerName = host
		}
	}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}
