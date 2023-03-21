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

package layer4

import (
	"fmt"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MatchIP{})
	caddy.RegisterModule(MatchLocalIP{})
}

// ConnMatcher is a type that can match a connection.
type ConnMatcher interface {
	// Match returns true if the given connection matches.
	// It should read from the connection as little as possible:
	// only as much as necessary to determine a match.
	Match(*Connection) (bool, error)
}

// MatcherSet is a set of matchers which
// must all match in order for the request
// to be matched successfully.
type MatcherSet []ConnMatcher

// Match returns true if the connection matches all matchers in mset
// or if there are no matchers. Any error terminates matching.
func (mset MatcherSet) Match(cx *Connection) (matched bool, err error) {
	for _, m := range mset {
		cx.record()
		matched, err = m.Match(cx)
		cx.rewind()
		if cx.Logger.Core().Enabled(zap.DebugLevel) {
			matcher := "unknown"
			if cm, ok := m.(caddy.Module); ok {
				matcher = cm.CaddyModule().String()
			}
			cx.Logger.Debug("matching",
				zap.String("remote", cx.RemoteAddr().String()),
				zap.Error(err),
				zap.String("matcher", matcher),
				zap.Bool("matched", matched),
			)
		}
		if !matched || err != nil {
			return
		}
	}
	matched = true
	return
}

// RawMatcherSets is a group of matcher sets in their
// raw JSON form.
type RawMatcherSets []caddy.ModuleMap

// MatcherSets is a group of matcher sets capable of checking
// whether a connection matches any of the sets.
type MatcherSets []MatcherSet

// AnyMatch returns true if the connection matches any of the matcher sets
// in mss or if there are no matchers, in which case the request always
// matches. Any error terminates matching.
func (mss MatcherSets) AnyMatch(cx *Connection) (matched bool, err error) {
	for _, m := range mss {
		matched, err = m.Match(cx)
		if matched || err != nil {
			return
		}
	}
	matched = len(mss) == 0
	return
}

// FromInterface fills ms from an interface{} value obtained from LoadModule.
func (mss *MatcherSets) FromInterface(matcherSets interface{}) error {
	for _, matcherSetIfaces := range matcherSets.([]map[string]interface{}) {
		var matcherSet MatcherSet
		for _, matcher := range matcherSetIfaces {
			connMatcher, ok := matcher.(ConnMatcher)
			if !ok {
				return fmt.Errorf("decoded module is not a ConnMatcher: %#v", matcher)
			}
			matcherSet = append(matcherSet, connMatcher)
		}
		*mss = append(*mss, matcherSet)
	}
	return nil
}

// MatchIP matches requests by remote IP (or CIDR range).
type MatchIP struct {
	Ranges []string `json:"ranges,omitempty"`

	cidrs []*net.IPNet
}

// CaddyModule returns the Caddy module information.
func (MatchIP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.ip",
		New: func() caddy.Module { return new(MatchIP) },
	}
}

// Provision parses m's IP ranges, either from IP or CIDR expressions.
func (m *MatchIP) Provision(_ caddy.Context) (err error) {
	m.cidrs, err = ParseNetworks(m.Ranges)
	if err != nil {
		return err
	}
	return nil
}

// Match returns true if the connection is from one of the designated IP ranges.
func (m MatchIP) Match(cx *Connection) (bool, error) {
	clientIP, err := m.getClientIP(cx)
	if err != nil {
		return false, fmt.Errorf("getting client IP: %v", err)
	}
	for _, ipRange := range m.cidrs {
		if ipRange.Contains(clientIP) {
			return true, nil
		}
	}
	return false, nil
}

func (m MatchIP) getClientIP(cx *Connection) (net.IP, error) {
	remote := cx.Conn.RemoteAddr().String()

	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote // OK; probably didn't have a port
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid client IP address: %s", ipStr)
	}

	return ip, nil
}

// MatchLocalIP matches requests by local IP (or CIDR range).
type MatchLocalIP struct {
	Ranges []string `json:"ranges,omitempty"`

	cidrs []*net.IPNet
}

// CaddyModule returns the Caddy module information.
func (MatchLocalIP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.local_ip",
		New: func() caddy.Module { return new(MatchLocalIP) },
	}
}

// Provision parses m's IP ranges, either from IP or CIDR expressions.
func (m *MatchLocalIP) Provision(ctx caddy.Context) error {
	for _, str := range m.Ranges {
		if strings.Contains(str, "/") {
			_, ipNet, err := net.ParseCIDR(str)
			if err != nil {
				return fmt.Errorf("parsing CIDR expression: %v", err)
			}
			m.cidrs = append(m.cidrs, ipNet)
		} else {
			ip := net.ParseIP(str)
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", str)
			}
			mask := len(ip) * 8
			m.cidrs = append(m.cidrs, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(mask, mask),
			})
		}
	}
	return nil
}

// Match returns true if the connection is from one of the designated IP ranges.
func (m MatchLocalIP) Match(cx *Connection) (bool, error) {
	localIP, err := m.getLocalIP(cx)
	if err != nil {
		return false, fmt.Errorf("getting local IP: %v", err)
	}
	for _, ipRange := range m.cidrs {
		if ipRange.Contains(localIP) {
			return true, nil
		}
	}
	return false, nil
}

func (m MatchLocalIP) getLocalIP(cx *Connection) (net.IP, error) {
	remote := cx.Conn.LocalAddr().String()

	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote // OK; probably didn't have a port
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid local IP address: %s", ipStr)
	}

	return ip, nil
}

// Interface guards
var (
	_ ConnMatcher       = (*MatchIP)(nil)
	_ caddy.Provisioner = (*MatchIP)(nil)
	_ ConnMatcher       = (*MatchLocalIP)(nil)
	_ caddy.Provisioner = (*MatchLocalIP)(nil)
)

// ParseNetworks parses a list of string IP addresses or CDIR subnets into a slice of net.IPNet's.
// It accepts for example ["127.0.0.1", "127.0.0.0/8", "::1", "2001:db8::/32"].
func ParseNetworks(networks []string) (ipNets []*net.IPNet, err error) {
	for _, str := range networks {
		if strings.Contains(str, "/") {
			_, ipNet, err := net.ParseCIDR(str)
			if err != nil {
				return nil, fmt.Errorf("parsing CIDR expression: %v", err)
			}
			ipNets = append(ipNets, ipNet)
		} else {
			ip := net.ParseIP(str)
			if ip == nil {
				return ipNets, fmt.Errorf("invalid IP address: %s", str)
			}
			mask := len(ip) * 8
			ipNets = append(ipNets, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(mask, mask),
			})
		}
	}
	return ipNets, nil
}
