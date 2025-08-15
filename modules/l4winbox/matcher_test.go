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

package l4winbox

import (
	"bytes"
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

func Test_MessageAuth_FromBytes_ToBytes(t *testing.T) {
	var msg *MessageAuth
	var err error
	for _, packet := range [][]byte{packetS1, packetS2, packetR1, packetR2} {
		msg = &MessageAuth{}
		if err = msg.FromBytes(packet); err != nil {
			t.Fatalf("Failed to parse MessageAuth from bytes: %s\n", err)
		}
		if !bytes.Equal(packet, msg.ToBytes()) {
			t.Fatalf("Bytes don't match.\nExpected: %x\nComposed: %x", packet, msg.ToBytes())
		}
	}
}

func Test_MatchWinbox_Match(t *testing.T) {
	type test struct {
		matcher     *MatchWinbox
		data        []byte
		shouldMatch bool
	}

	m0 := &MatchWinbox{}
	m1 := &MatchWinbox{Modes: []string{ModeStandard}}
	m2 := &MatchWinbox{Modes: []string{ModeRoMON}}
	m3 := &MatchWinbox{Username: "toms"}
	m4 := &MatchWinbox{UsernameRegexp: "^andris|edgars|juris$"}

	tests := []test{
		{matcher: m0, data: packetS1[:len(packetS1)-1], shouldMatch: false},
		{matcher: m0, data: packetS2[:len(packetS2)-1], shouldMatch: false},
		{matcher: m0, data: packetR1[:len(packetR1)-1], shouldMatch: false},
		{matcher: m0, data: packetR2[:len(packetR2)-1], shouldMatch: false},

		{matcher: m0, data: packetS1, shouldMatch: true},
		{matcher: m0, data: packetS2, shouldMatch: true},
		{matcher: m0, data: packetR1, shouldMatch: true},
		{matcher: m0, data: packetR2, shouldMatch: true},

		{matcher: m1, data: packetS1, shouldMatch: true},
		{matcher: m1, data: packetS2, shouldMatch: true},
		{matcher: m1, data: packetR1, shouldMatch: false},
		{matcher: m1, data: packetR2, shouldMatch: false},

		{matcher: m2, data: packetS1, shouldMatch: false},
		{matcher: m2, data: packetS2, shouldMatch: false},
		{matcher: m2, data: packetR1, shouldMatch: true},
		{matcher: m2, data: packetR2, shouldMatch: true},

		{matcher: m3, data: packetS1, shouldMatch: true},
		{matcher: m3, data: packetS2, shouldMatch: false},
		{matcher: m3, data: packetR1, shouldMatch: true},
		{matcher: m3, data: packetR2, shouldMatch: false},

		{matcher: m4, data: packetS1, shouldMatch: false},
		{matcher: m4, data: packetS2, shouldMatch: true},
		{matcher: m4, data: packetR1, shouldMatch: false},
		{matcher: m4, data: packetR2, shouldMatch: true},
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
					t.Fatalf("Test %d: matcher did not match | %+v\n", i, tc.matcher)
				} else {
					t.Fatalf("Test %d: matcher should not match | %+v\n", i, tc.matcher)
				}
			}
		}()
	}
}

// Packet examples
var (
	packetS1 = []byte{38, 6, 116, 111, 109, 115, 0, 16, 224, 171, 254, 156, 62, 32, 96, 105, 79, 183, 32, 18, 98, 154, 210, 88, 231, 107, 124, 235, 252, 112, 176, 226, 63, 148, 136, 155, 149, 250, 151, 0}
	packetS2 = []byte{40, 6, 97, 110, 100, 114, 105, 115, 0, 14, 185, 111, 184, 198, 199, 177, 230, 112, 205, 86, 92, 179, 165, 60, 173, 240, 56, 44, 175, 102, 201, 198, 26, 252, 174, 71, 206, 89, 58, 169, 17, 1}
	packetR1 = []byte{40, 6, 116, 111, 109, 115, 43, 114, 0, 65, 165, 44, 39, 101, 48, 138, 138, 139, 207, 103, 177, 231, 74, 148, 181, 203, 140, 104, 13, 19, 95, 116, 84, 172, 115, 20, 170, 6, 178, 163, 172, 0}
	packetR2 = []byte{42, 6, 97, 110, 100, 114, 105, 115, 43, 114, 0, 18, 158, 36, 11, 95, 8, 113, 35, 73, 92, 164, 206, 35, 223, 100, 63, 183, 98, 232, 182, 51, 93, 1, 56, 212, 183, 106, 169, 185, 69, 244, 81, 0}
)
