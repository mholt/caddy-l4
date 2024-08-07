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
		{matcher: &MatchClock{After: tNowPlus5Minutes, Before: tNowMinus5Minutes}, data: []byte{}, shouldMatch: true},

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
