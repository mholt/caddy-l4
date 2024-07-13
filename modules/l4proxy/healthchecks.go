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
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

// HealthChecks configures active and passive health checks.
type HealthChecks struct {
	// Active health checks run in the background on a timer. To
	// minimally enable active health checks, set either path or
	// port (or both).
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

	// How frequently to perform active health checks (default 30s).
	Interval caddy.Duration `json:"interval,omitempty"`

	// How long to wait for a connection to be established with
	// peer before considering it unhealthy (default 5s).
	Timeout caddy.Duration `json:"timeout,omitempty"`

	logger *zap.Logger
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
				err := h.doActiveHealthCheck(p)
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
func (h *Handler) doActiveHealthCheck(p *peer) error {
	addr := p.address

	// adjust the port, if configured to be different
	if h.HealthChecks.Active.Port > 0 {
		addr.StartPort = uint(h.HealthChecks.Active.Port)
		addr.EndPort = addr.StartPort
	}

	hostPort := addr.JoinHostPort(0)
	timeout := time.Duration(h.HealthChecks.Active.Timeout)

	conn, err := net.DialTimeout(addr.Network, hostPort, timeout)
	if err != nil {
		h.HealthChecks.Active.logger.Info("host is down",
			zap.String("address", addr.String()),
			zap.Duration("timeout", timeout),
			zap.Error(err))
		_, err2 := p.setHealthy(false)
		if err2 != nil {
			return fmt.Errorf("marking unhealthy: %v (original error: %v)", err2, err)
		}
		return nil
	}
	conn.Close()

	// connection succeeded, so mark as healthy
	swapped, err := p.setHealthy(true)
	if swapped {
		h.HealthChecks.Active.logger.Info("host is up", zap.String("address", addr.String()))
	}
	if err != nil {
		return fmt.Errorf("marking healthy: %v", err)
	}

	return nil
}

// UnmarshalCaddyfile sets up the HealthChecks from Caddyfile tokens. Syntax:
//
//	health_checks {
//		active {
//			...
//		}
//		passive {
//			...
//		}
//	}
//
// health_checks active <args>
func (hc *HealthChecks) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "active":
			ahc := ActiveHealthChecks{}
			err := ahc.UnmarshalCaddyfile(d.NewFromNextSegment())
			if err != nil {
				return err
			}
			hc.Active = &ahc
		case "passive":
			phc := PassiveHealthChecks{}
			err := phc.UnmarshalCaddyfile(d.NewFromNextSegment())
			if err != nil {
				return err
			}
			hc.Passive = &phc
		default:
			return d.ArgErr()
		}
	}

	return nil
}

// UnmarshalCaddyfile sets up the ActiveHealthChecks from Caddyfile tokens. Syntax:
//
//	active {
//		interval <duration>
//		port <int>
//		timeout <duration>
//	}
func (ahc *ActiveHealthChecks) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), "proxy health_checks "+d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	var hasInterval, hasPort, hasTimeout bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "interval":
			if hasInterval {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			d.NextArg()
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing %s option '%s' duration: %v", wrapper, optionName, err)
			}
			ahc.Interval, hasInterval = caddy.Duration(dur), true
		case "port":
			if hasPort {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			d.NextArg()
			val, err := strconv.ParseInt(d.Val(), 10, 32)
			if err != nil {
				return d.Errf("parsing %s option '%s': %v", wrapper, optionName, err)
			}
			ahc.Port, hasPort = int(val), true
		case "timeout":
			if hasTimeout {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			d.NextArg()
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing %s option '%s' duration: %v", wrapper, optionName, err)
			}
			ahc.Timeout, hasTimeout = caddy.Duration(dur), true
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	return nil
}

// UnmarshalCaddyfile sets up the PassiveHealthChecks from Caddyfile tokens. Syntax:
//
//	passive {
//		fail_duration <duration>
//		max_fails <int>
//		unhealthy_connection_count <int>
//	}
func (phc *PassiveHealthChecks) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), "proxy health_checks "+d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	var hasFailDuration, hasMaxFails, hasUnhealthyConnCount bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "fail_duration":
			if hasFailDuration {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			d.NextArg()
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing %s option '%s' duration: %v", wrapper, optionName, err)
			}
			phc.FailDuration, hasFailDuration = caddy.Duration(dur), true
		case "max_fails":
			if hasMaxFails {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			d.NextArg()
			val, err := strconv.ParseInt(d.Val(), 10, 32)
			if err != nil {
				return d.Errf("parsing %s option '%s': %v", wrapper, optionName, err)
			}
			phc.MaxFails, hasMaxFails = int(val), true
		case "unhealthy_connection_count":
			if hasUnhealthyConnCount {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			d.NextArg()
			val, err := strconv.ParseInt(d.Val(), 10, 32)
			if err != nil {
				return d.Errf("parsing %s option '%s': %v", wrapper, optionName, err)
			}
			phc.UnhealthyConnectionCount, hasUnhealthyConnCount = int(val), true
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*HealthChecks)(nil)
	_ caddyfile.Unmarshaler = (*ActiveHealthChecks)(nil)
	_ caddyfile.Unmarshaler = (*PassiveHealthChecks)(nil)
)
