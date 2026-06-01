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
	"regexp"
	"runtime/debug"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// HealthChecks configures active and passive health checks.
type HealthChecks struct {
	// Active health checks run in the background on a timer. To
	// minimally enable active health checks, set the interval; the
	// default probe is a raw TCP dial. Set uri to probe over HTTP
	// instead (matching expect_status), which lets the proxy follow
	// an application-level signal such as a primary-election endpoint.
	Active *ActiveHealthChecks `json:"active,omitempty"`

	// Passive health checks monitor proxied connections for errors or timeouts.
	// To minimally enable passive health checks, specify at least an empty
	// config object.
	Passive *PassiveHealthChecks `json:"passive,omitempty"`
}

// ActiveHealthChecks holds configuration related to active health
// checks (that is, health checks which occur independently in a
// background goroutine).
type ActiveHealthChecks struct {
	// The port to use (if different from the upstream's dial
	// address) for health checks.
	Port int `json:"port,omitempty"`

	// URI is the request path for an HTTP health check, e.g. "/primary".
	// When set, each check performs an HTTP GET against the upstream (on
	// Port if configured, otherwise the dial port) and the upstream is
	// considered healthy only if the response status matches ExpectStatus.
	// When empty, the check is a raw TCP dial (the default behavior).
	URI string `json:"uri,omitempty"`

	// ExpectStatus is the HTTP status code considered healthy for an HTTP
	// health check (default 200). A value below 100 is treated as a status
	// class, so e.g. 2 matches any 2xx response.
	ExpectStatus int `json:"expect_status,omitempty"`

	// HTTPS performs the HTTP health check over TLS.
	HTTPS bool `json:"https,omitempty"`

	// TLSSkipVerify disables TLS certificate verification for an HTTPS
	// health check (useful with self-signed certificates).
	TLSSkipVerify bool `json:"tls_skip_verify,omitempty"`

	// Headers are extra request headers to set on HTTP health check requests.
	// A "Host" entry sets the request's Host header. Only used when URI is set.
	Headers http.Header `json:"headers,omitempty"`

	// ExpectBody is a regular expression that the response body must match for
	// the upstream to be considered healthy, in addition to ExpectStatus. Only
	// used when URI is set; empty means the body is not inspected.
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

	logger         *zap.Logger
	expectBodyRe   *regexp.Regexp
	expectBodyOnce sync.Once
	expectBodyErr  error
}

// bodyRegexp lazily compiles ExpectBody once and caches the result.
func (a *ActiveHealthChecks) bodyRegexp() (*regexp.Regexp, error) {
	a.expectBodyOnce.Do(func() {
		if a.ExpectBody != "" {
			a.expectBodyRe, a.expectBodyErr = regexp.Compile(a.ExpectBody)
		}
	})
	return a.expectBodyRe, a.expectBodyErr
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

// doActiveHealthCheck performs a health check to host which
// can be reached at address hostAddr. The health status of
// the host will be updated according to whether it passes
// the health check. An error is returned only if the health
// check fails to occur or if marking the host's health status
// fails.
func (h *Handler) doActiveHealthCheck(upstream *Upstream, p *peer) error {
	addr := p.address
	if addr == nil {
		return nil
	}

	// adjust the port, if configured to be different
	if h.HealthChecks.Active.Port > 0 {
		addr.StartPort = uint(h.HealthChecks.Active.Port) //nolint:gosec // disable G115
		addr.EndPort = addr.StartPort
	}

	hostPort := addr.JoinHostPort(0)
	timeout := time.Duration(h.HealthChecks.Active.Timeout)

	// HTTP health check: GET the URI and match the response status. This lets
	// the proxy follow an application-level signal (e.g. Patroni's /primary,
	// which returns 200 only on the elected leader) instead of merely checking
	// that a TCP port accepts connections.
	if h.HealthChecks.Active.URI != "" {
		return h.doActiveHTTPHealthCheck(p, hostPort, timeout)
	}

	// Resolve the destination address family only when it will actually be used,
	// i.e. when the user has configured local_address or resolver_preference.
	// Otherwise skip it to avoid an extra DNS lookup per health check for hostname upstreams.
	var destFam int
	if len(upstream.localAddrs) > 0 || upstream.ResolverPreference != "" {
		var famErr error
		destFam, famErr = resolveDestFamily(addr.Network, hostPort, upstream.ResolverPreference)
		if famErr != nil {
			return famErr
		}
	}
	// Narrow the dial network to match the resolved family so resolver_preference
	// is enforced at Dial time. When destFam == 0 (both new features unset) this
	// returns addr.Network unchanged, preserving pre-PR health-check behavior.
	dialNetwork := narrowNetworkForFamily(addr.Network, destFam)
	localAddrs := buildLocalAddrs(upstream.localAddrs, dialNetwork, destFam, h.logger)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var conn net.Conn
	var err error
	if len(localAddrs) == 0 {
		var d net.Dialer
		d.Timeout = timeout
		conn, err = d.DialContext(ctx, dialNetwork, hostPort)
	} else {
		for _, la := range localAddrs {
			d := &net.Dialer{LocalAddr: la, Timeout: timeout}
			conn, err = d.DialContext(ctx, dialNetwork, hostPort)
			if err == nil {
				break
			}
		}
	}
	rise, fall := h.HealthChecks.Active.Rise, h.HealthChecks.Active.Fall
	if err != nil {
		h.HealthChecks.Active.logger.Info("active health check failed",
			zap.String("address", addr.String()),
			zap.Duration("timeout", timeout),
			zap.Error(err))
		if mark, healthy := p.recordActiveCheck(false, rise, fall); mark {
			swapped, err2 := p.setHealthy(healthy)
			if err2 != nil {
				return fmt.Errorf("marking unhealthy: %v (original error: %v)", err2, err)
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
	_ = conn.Close()

	// connection succeeded
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

// doActiveHTTPHealthCheck performs an HTTP GET against the peer at hostPort and
// marks it healthy only if the response status matches the configured
// ExpectStatus (default 200). It is used when ActiveHealthChecks.URI is set.
func (h *Handler) doActiveHTTPHealthCheck(p *peer, hostPort string, timeout time.Duration) error {
	scheme := "http"
	if h.HealthChecks.Active.HTTPS {
		scheme = "https"
	}
	u := scheme + "://" + hostPort + h.HealthChecks.Active.URI

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("building health check request: %v", err)
	}
	for k, vals := range h.HealthChecks.Active.Headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	if host := h.HealthChecks.Active.Headers.Get("Host"); host != "" {
		req.Host = host
	}

	client := &http.Client{Timeout: timeout}
	if h.HealthChecks.Active.HTTPS && h.HealthChecks.Active.TLSSkipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // explicitly opted in
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		h.HealthChecks.Active.logger.Info("host is down",
			zap.String("address", u),
			zap.Duration("timeout", timeout),
			zap.Error(err))
		// setHealthy never returns an error (it only reports whether the state
		// changed), so the result is intentionally ignored here.
		_, _ = p.setHealthy(false)
		return nil
	}
	// Read the body when we need to match it; otherwise drain a bounded amount
	// so the connection can be reused by keep-alive. Then close it.
	var body []byte
	if h.HealthChecks.Active.ExpectBody != "" {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // up to 1 MiB
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	}
	_ = resp.Body.Close()

	expect := h.HealthChecks.Active.ExpectStatus
	if expect == 0 {
		expect = http.StatusOK
	}
	if !statusCodeMatches(resp.StatusCode, expect) {
		h.HealthChecks.Active.logger.Info("host is down",
			zap.String("address", u),
			zap.Int("status", resp.StatusCode),
			zap.Int("expect_status", expect))
		_, _ = p.setHealthy(false)
		return nil
	}

	if h.HealthChecks.Active.ExpectBody != "" {
		re, err := h.HealthChecks.Active.bodyRegexp()
		if err != nil {
			return fmt.Errorf("compiling expect_body regexp: %v", err)
		}
		if re != nil && !re.Match(body) {
			h.HealthChecks.Active.logger.Info("host is down",
				zap.String("address", u),
				zap.String("reason", "response body did not match expect_body"))
			_, _ = p.setHealthy(false)
			return nil
		}
	}

	if swapped, _ := p.setHealthy(true); swapped {
		h.HealthChecks.Active.logger.Info("host is up", zap.String("address", u))
	}
	return nil
}

// statusCodeMatches reports whether status satisfies expect. If expect is below
// 100 it is treated as a status class (e.g. 2 matches any 2xx response);
// otherwise it must match exactly.
func statusCodeMatches(status, expect int) bool {
	if expect < 100 {
		return status/100 == expect
	}
	return status == expect
}
