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
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MatchIP{})
	caddy.RegisterModule(MatchLocalIP{})
	caddy.RegisterModule(MatchNot{})
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
	cidrs  []netip.Prefix
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

func (m MatchIP) getClientIP(cx *Connection) (netip.Addr, error) {
	remote := cx.Conn.RemoteAddr().String()

	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote // OK; probably didn't have a port
	}

	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid client IP address: %s", ipStr)
	}
	return ip, nil
}

// MatchLocalIP matches requests by local IP (or CIDR range).
type MatchLocalIP struct {
	Ranges []string `json:"ranges,omitempty"`

	cidrs []netip.Prefix
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
	ipnets, err := ParseNetworks(m.Ranges)
	if err != nil {
		return err
	}
	m.cidrs = ipnets
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

func (m MatchLocalIP) getLocalIP(cx *Connection) (netip.Addr, error) {
	remote := cx.Conn.LocalAddr().String()

	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote // OK; probably didn't have a port
	}

	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid local IP address: %s", ipStr)
	}
	return ip, nil
}

// MatchNot matches requests by negating the results of its matcher
// sets. A single "not" matcher takes one or more matcher sets. Each
// matcher set is OR'ed; in other words, if any matcher set returns
// true, the final result of the "not" matcher is false. Individual
// matchers within a set work the same (i.e. different matchers in
// the same set are AND'ed).
//
// NOTE: The generated docs which describe the structure of this
// module are wrong because of how this type unmarshals JSON in a
// custom way. The correct structure is:
//
// ```json
// [
//
//	{},
//	{}
//
// ]
// ```
//
// where each of the array elements is a matcher set, i.e. an
// object keyed by matcher name.
type MatchNot struct {
	MatcherSetsRaw []caddy.ModuleMap `json:"-" caddy:"namespace=layer4.matchers"`
	MatcherSets    []MatcherSet      `json:"-"`
}

// CaddyModule implements caddy.Module.
func (MatchNot) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.not",
		New: func() caddy.Module { return new(MatchNot) },
	}
}

// UnmarshalJSON satisfies json.Unmarshaler. It puts the JSON
// bytes directly into m's MatcherSetsRaw field.
func (m *MatchNot) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &m.MatcherSetsRaw)
}

// MarshalJSON satisfies json.Marshaler by marshaling
// m's raw matcher sets.
func (m MatchNot) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.MatcherSetsRaw)
}

// Provision loads the matcher modules to be negated.
func (m *MatchNot) Provision(ctx caddy.Context) error {
	matcherSets, err := ctx.LoadModule(m, "MatcherSetsRaw")
	if err != nil {
		return fmt.Errorf("loading matcher sets: %v", err)
	}
	for _, modMap := range matcherSets.([]map[string]any) {
		var ms MatcherSet
		for _, modIface := range modMap {
			ms = append(ms, modIface.(ConnMatcher))
		}
		m.MatcherSets = append(m.MatcherSets, ms)
	}
	return nil
}

// Match returns true if r matches m. Since this matcher negates
// the embedded matchers, false is returned if any of its matcher
// sets return true.
func (m MatchNot) Match(r *Connection) (bool, error) {
	for _, ms := range m.MatcherSets {
		match, err := ms.Match(r)
		if err != nil {
			return false, err
		}
		if match {
			return false, nil
		}
	}
	return true, nil
}

// Interface guards
var (
	_ caddy.Module      = (*MatchIP)(nil)
	_ ConnMatcher       = (*MatchIP)(nil)
	_ caddy.Provisioner = (*MatchIP)(nil)
	_ caddy.Module      = (*MatchLocalIP)(nil)
	_ ConnMatcher       = (*MatchLocalIP)(nil)
	_ caddy.Provisioner = (*MatchLocalIP)(nil)
	_ caddy.Module      = (*MatchNot)(nil)
	_ caddy.Provisioner = (*MatchNot)(nil)
	_ ConnMatcher       = (*MatchNot)(nil)
)

// ParseNetworks parses a list of string IP addresses or CDIR subnets into a slice of net.IPNet's.
// It accepts for example ["127.0.0.1", "127.0.0.0/8", "::1", "2001:db8::/32"].
func ParseNetworks(networks []string) (ipNets []netip.Prefix, err error) {
	for _, str := range networks {
		if strings.Contains(str, "/") {
			ipNet, err := netip.ParsePrefix(str)
			if err != nil {
				return nil, fmt.Errorf("parsing CIDR expression: %v", err)
			}
			ipNets = append(ipNets, ipNet)
			continue
		}

		addr, err := netip.ParseAddr(str)
		if err != nil {
			return nil, err
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		ipNets = append(ipNets, netip.PrefixFrom(addr, bits))
	}
	return ipNets, nil
}
