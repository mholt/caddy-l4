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

package l4regexp

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Unexpected error: %s\n", err)
	}
}

func Test_MatchRegexp_Match(t *testing.T) {
	type test struct {
		matcher     *MatchRegexp
		data        []byte
		shouldMatch bool
	}

	tests := []test{
		{matcher: &MatchRegexp{}, data: packet0123, shouldMatch: true},
		{matcher: &MatchRegexp{Pattern: ""}, data: packet0123, shouldMatch: true},
		{matcher: &MatchRegexp{Pattern: "12"}, data: packet0123, shouldMatch: true},
		{matcher: &MatchRegexp{Pattern: "^0123$"}, data: packet0123, shouldMatch: true},
		{matcher: &MatchRegexp{Pattern: "^012$"}, data: packet0123, shouldMatch: false},
		{matcher: &MatchRegexp{Pattern: "^0123$", Count: 5}, data: packet0123, shouldMatch: false},
		{matcher: &MatchRegexp{Pattern: "^012$", Count: 3}, data: packet0123, shouldMatch: true},
		{matcher: &MatchRegexp{Pattern: "^\\d+$"}, data: packet0123, shouldMatch: true},
		{matcher: &MatchRegexp{Pattern: "^\\d+$", Count: 0}, data: packet0123, shouldMatch: true},
		{matcher: &MatchRegexp{Pattern: "^\x30\x31\x32(\x33|\x34)$", Count: 0}, data: packet0123, shouldMatch: true},
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

var packet0123 = []byte{0x30, 0x31, 0x32, 0x33}
