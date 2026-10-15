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
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Unexpected error: %s\n", err)
	}
}

func Test_MatchClock_Match(t *testing.T) {
	type test struct {
		matcher     *MatchClock
		data        []byte
		shouldMatch bool
	}

	tNowMinus5Minutes := time.Now().UTC().Add(time.Minute * 5 * (-1)).Format(time.TimeOnly)
	tNowPlus5Minutes := time.Now().UTC().Add(time.Minute * 5).Format(time.TimeOnly)

	tests := []test{
		{matcher: &MatchClock{}, data: []byte{}, shouldMatch: true},
		{matcher: &MatchClock{After: tNowMinus5Minutes}, data: []byte{}, shouldMatch: true},
		{matcher: &MatchClock{Before: tNowPlus5Minutes}, data: []byte{}, shouldMatch: true},
		{matcher: &MatchClock{After: tNowMinus5Minutes, Before: tNowPlus5Minutes}, data: []byte{}, shouldMatch: true},
		// After > Before denotes an overnight window: [now+5m, 24:00:00) or [00:00:00, now-5m).
		// The current time sits in the excluded band around now, so this must not match.
		{matcher: &MatchClock{After: tNowPlus5Minutes, Before: tNowMinus5Minutes}, data: []byte{}, shouldMatch: false},

		{matcher: &MatchClock{After: tNowPlus5Minutes}, data: []byte{}, shouldMatch: false},
		{matcher: &MatchClock{Before: tNowMinus5Minutes}, data: []byte{}, shouldMatch: false},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for i, tc := range tests {
		func() {
			err := tc.matcher.Provision(ctx)
			assertNoError(t, err)

			in, out := net.Pipe()
			defer func() {
				_, _ = io.Copy(io.Discard, out)
				_ = out.Close()
			}()

			cx := layer4.WrapConnection(out, []byte{}, zap.NewNop())
			go func() {
				_, err := in.Write(tc.data)
				assertNoError(t, err)
				_ = in.Close()
			}()

			matched, err := tc.matcher.Match(cx)
			assertNoError(t, err)

			if matched != tc.shouldMatch {
				if tc.shouldMatch {
					t.Fatalf("test %d: matcher did not match | %+v\n", i, tc.matcher)
				} else {
					t.Fatalf("test %d: matcher should not match | %+v\n", i, tc.matcher)
				}
			}
		}()
	}
}

func Test_MatchClock_Provision(t *testing.T) {
	type test struct {
		name          string
		matcher       *MatchClock
		expectErr     bool
		secondsAfter  int
		secondsBefore int
		zoneName      string
		zoneOffset    int
	}

	tests := []test{
		{name: "same-day window", matcher: &MatchClock{After: "09:00:00", Before: "17:00:00"},
			secondsAfter: 9 * 3600, secondsBefore: 17 * 3600, zoneName: "UTC"},
		// An overnight window must be preserved as-is, not swapped.
		{name: "overnight window is not swapped", matcher: &MatchClock{After: "22:00:00", Before: "06:00:00"},
			secondsAfter: 22 * 3600, secondsBefore: 6 * 3600, zoneName: "UTC"},
		{name: "before 00:00:00 becomes 24:00:00", matcher: &MatchClock{After: "09:00:00", Before: "00:00:00"},
			secondsAfter: 9 * 3600, secondsBefore: secondsPerDay, zoneName: "UTC"},
		{name: "empty fields match all day", matcher: &MatchClock{},
			secondsAfter: 0, secondsBefore: secondsPerDay, zoneName: "UTC"},
		{name: "fixed offset east", matcher: &MatchClock{Timezone: "+02"},
			secondsAfter: 0, secondsBefore: secondsPerDay, zoneName: "+02", zoneOffset: 2 * 3600},
		{name: "fixed offset with minutes west", matcher: &MatchClock{Timezone: "-03:30"},
			secondsAfter: 0, secondsBefore: secondsPerDay, zoneName: "-03:30", zoneOffset: -(3*3600 + 30*60)},
		{name: "IANA location", matcher: &MatchClock{Timezone: "America/New_York"},
			secondsAfter: 0, secondsBefore: secondsPerDay, zoneName: "America/New_York"},
		{name: "invalid after", matcher: &MatchClock{After: "25:00:00"}, expectErr: true},
		{name: "invalid before", matcher: &MatchClock{Before: "12:60:00"}, expectErr: true},
		{name: "invalid timezone", matcher: &MatchClock{Timezone: "Nowhere/Land"}, expectErr: true},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.matcher.Provision(ctx)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected an error but got none | %+v", tc.matcher)
				}
				return
			}
			assertNoError(t, err)

			if tc.matcher.secondsAfter != tc.secondsAfter {
				t.Errorf("secondsAfter = %d, want %d", tc.matcher.secondsAfter, tc.secondsAfter)
			}
			if tc.matcher.secondsBefore != tc.secondsBefore {
				t.Errorf("secondsBefore = %d, want %d", tc.matcher.secondsBefore, tc.secondsBefore)
			}
			if tc.matcher.location == nil {
				t.Fatal("location was not set")
			}
			if tc.matcher.location.String() != tc.zoneName {
				t.Errorf("zone name = %q, want %q", tc.matcher.location.String(), tc.zoneName)
			}
			if tc.zoneOffset != 0 {
				ref := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).In(tc.matcher.location)
				if _, offset := ref.Zone(); offset != tc.zoneOffset {
					t.Errorf("zone offset = %d, want %d", offset, tc.zoneOffset)
				}
			}
		})
	}
}

func Test_MatchClock_UnmarshalCaddyfile(t *testing.T) {
	type test struct {
		name      string
		input     string
		expectErr bool
		after     string
		before    string
		timezone  string
	}

	tests := []test{
		{name: "two time points", input: `clock 09:00:00 17:00:00`,
			after: "09:00:00", before: "17:00:00"},
		{name: "two time points with timezone", input: `clock 09:00:00 17:00:00 America/New_York`,
			after: "09:00:00", before: "17:00:00", timezone: "America/New_York"},
		{name: "after keyword", input: `clock after 09:00:00`,
			after: "09:00:00", before: timeMin},
		{name: "from keyword", input: `clock from 09:00:00`,
			after: "09:00:00", before: timeMin},
		{name: "before keyword", input: `clock before 17:00:00`,
			after: timeMax, before: "17:00:00"},
		{name: "until keyword", input: `clock until 17:00:00`,
			after: timeMax, before: "17:00:00"},
		{name: "till keyword", input: `clock till 17:00:00`,
			after: timeMax, before: "17:00:00"},
		{name: "to keyword", input: `clock to 17:00:00`,
			after: timeMax, before: "17:00:00"},
		{name: "keyword with timezone", input: `clock after 09:00:00 America/New_York`,
			after: "09:00:00", before: timeMin, timezone: "America/New_York"},
		{name: "too few args", input: `clock 09:00:00`, expectErr: true},
		{name: "too many args", input: `clock 09:00:00 17:00:00 UTC extra`, expectErr: true},
		{name: "no args", input: `clock`, expectErr: true},
		{name: "blocks not supported", input: "clock 09:00:00 17:00:00 {\n\tfoo\n}", expectErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := new(MatchClock)
			err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected an error but got none | %+v", m)
				}
				return
			}
			assertNoError(t, err)

			if m.After != tc.after {
				t.Errorf("After = %q, want %q", m.After, tc.after)
			}
			if m.Before != tc.before {
				t.Errorf("Before = %q, want %q", m.Before, tc.before)
			}
			if m.Timezone != tc.timezone {
				t.Errorf("Timezone = %q, want %q", m.Timezone, tc.timezone)
			}
		})
	}
}
