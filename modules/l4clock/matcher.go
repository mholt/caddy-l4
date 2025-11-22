// Copyright 2024 VNXME
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

package l4clock

import (
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchClock{})
}

// MatchClock is able to match any connections using the time when they are wrapped/matched.
type MatchClock struct {
	// After is a mandatory field that must have a value in 15:04:05 format representing the lowest valid time point.
	// Placeholders are supported and evaluated at provision. If Before is lower than After, their values are swapped
	// at provision.
	After string `json:"after,omitempty"`
	// Before is a mandatory field that must have a value in 15:04:05 format representing the highest valid time point
	// plus one second. Placeholders are supported and evaluated at provision. 00:00:00 is treated here as 24:00:00.
	// If Before is lower than After, their values are swapped at provision.
	Before string `json:"before,omitempty"`
	// Timezone is an optional field that may be an IANA time zone location (e.g. America/Los_Angeles), a fixed offset
	// to the east of UTC (e.g. +02, -03:30, or even +12:34:56) or Local (to use the system's local time zone).
	// If Timezone is empty, UTC is used by default.
	Timezone string `json:"timezone,omitempty"`

	location      *time.Location
	secondsAfter  int
	secondsBefore int
}

// CaddyModule returns the Caddy module information.
func (m *MatchClock) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.clock",
		New: func() caddy.Module { return new(MatchClock) },
	}
}

// Match returns true if the connection wrapping/matching occurs within m's time points.
func (m *MatchClock) Match(cx *layer4.Connection) (bool, error) {
	repl := cx.Context.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	t, known := repl.Get(timeKey)
	if !known {
		t = time.Now().UTC()
		repl.Set(timeKey, t)
	}
	secondsNow := timeToSeconds(t.(time.Time).In(m.location))
	if secondsNow >= m.secondsAfter && secondsNow < m.secondsBefore {
		return true, nil
	}
	return false, nil
}

// Provision parses m's time points and a time zone (UTC is used by default).
func (m *MatchClock) Provision(_ caddy.Context) (err error) {
	repl := caddy.NewReplacer()

	after := repl.ReplaceAll(m.After, "")
	if m.secondsAfter, err = timeParseSeconds(after, 0); err != nil {
		return
	}

	before := repl.ReplaceAll(m.Before, "")
	if m.secondsBefore, err = timeParseSeconds(before, 0); err != nil {
		return
	}

	// Treat secondsBefore of 00:00:00 as 24:00:00
	if m.secondsBefore == 0 {
		m.secondsBefore = 86400
	}

	// Swap time points, if secondsAfter is greater than secondsBefore
	if m.secondsBefore < m.secondsAfter {
		m.secondsAfter, m.secondsBefore = m.secondsBefore, m.secondsAfter
	}

	timezone := repl.ReplaceAll(m.Timezone, "")
	for _, layout := range tzLayouts {
		if len(layout) != len(timezone) {
			continue
		}
		if t, e := time.Parse(layout, timezone); e == nil {
			_, offset := t.Zone()
			m.location = time.FixedZone(timezone, offset)
			break
		}
	}
	if m.location == nil {
		if m.location, err = time.LoadLocation(timezone); err != nil {
			return
		}
	}

	return nil
}

// UnmarshalCaddyfile sets up the MatchClock from Caddyfile tokens. Syntax:
//
//	clock <time_after> <time_before> [<time_zone>]
//	clock <after|from> <time_after> [<time_zone>]
//	clock <before|till|to|until> <time_before> [<time_zone>]
//
// Note: MatchClock checks if time_now is greater than or equal to time_after AND less than time_before.
// The lowest value is 00:00:00. If time_before equals 00:00:00, it is treated as 24:00:00. If time_after is greater
// than time_before, they are swapped. Both "after 00:00:00" and "before 00:00:00" match all day. An IANA time zone
// location should be used as a value for time_zone. The system's local time zone may be used with "Local" value.
// If time_zone is empty, UTC is used.
func (m *MatchClock) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Only two or three same-line arguments are supported
	if d.CountRemainingArgs() < 2 || d.CountRemainingArgs() > 3 {
		return d.ArgErr()
	}

	_, first, _, second := d.NextArg(), d.Val(), d.NextArg(), d.Val()
	switch strings.ToLower(first) {
	case "before", "till", "to", "until":
		first = timeMin
	case "after", "from":
		first = timeMax
		second, first = first, second
	}
	m.After, m.Before = first, second

	if d.NextArg() {
		m.Timezone = d.Val()
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed %s matcher: blocks are not supported", wrapper)
	}

	return nil
}

const (
	timeKey    = "l4.conn.wrap_time"
	timeLayout = time.TimeOnly
	timeMax    = "00:00:00"
	timeMin    = "00:00:00"
)

var tzLayouts = [...]string{"-07", "-07:00", "-07:00:00"}

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchClock)(nil)
	_ caddyfile.Unmarshaler = (*MatchClock)(nil)
	_ layer4.ConnMatcher    = (*MatchClock)(nil)
)

// timeToSeconds gets time and returns the number of seconds passed from the beginning of the current day.
func timeToSeconds(t time.Time) int {
	hh, mm, ss := t.Clock()
	return hh*3600 + mm*60 + ss
}

// timeParseSeconds parses time string and returns seconds passed from the beginning of the current day.
func timeParseSeconds(src string, def int) (int, error) {
	if len(src) == 0 {
		return def, nil
	}
	t, err := time.Parse(timeLayout, src)
	if err != nil {
		return def, err
	}
	return timeToSeconds(t), nil
}
