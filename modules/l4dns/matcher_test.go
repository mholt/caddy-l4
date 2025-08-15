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

package l4dns

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

func Test_MatchDNS_Match(t *testing.T) {
	type test struct {
		matcher       *MatchDNS
		data          []byte
		shouldMatch   bool
		shouldFakeTCP bool
	}

	tests := []test{
		{matcher: &MatchDNS{}, data: []byte{}, shouldMatch: false},

		{matcher: &MatchDNS{}, data: udpPacketAppleComA[:12], shouldMatch: false},
		{matcher: &MatchDNS{}, data: udpPacketGoogleComA[:14], shouldMatch: false},
		{matcher: &MatchDNS{}, data: tcpPacketAppleComA[:14], shouldMatch: false, shouldFakeTCP: true},
		{matcher: &MatchDNS{}, data: tcpPacketGoogleComA[:16], shouldMatch: false, shouldFakeTCP: true},

		{matcher: &MatchDNS{}, data: udpPacketAppleComA, shouldMatch: true},
		{matcher: &MatchDNS{}, data: udpPacketGoogleComA, shouldMatch: true},
		{matcher: &MatchDNS{}, data: tcpPacketAppleComA, shouldMatch: true, shouldFakeTCP: true},
		{matcher: &MatchDNS{}, data: tcpPacketGoogleComA, shouldMatch: true, shouldFakeTCP: true},

		{
			matcher: &MatchDNS{Allow: MatchDNSRules{&MatchDNSRule{Name: "example.com.", Type: "NS"}}},
			data:    tcpPacketExampleComA, shouldMatch: false, shouldFakeTCP: true,
		},
		{
			matcher: &MatchDNS{Allow: MatchDNSRules{&MatchDNSRule{Name: "example.com.", Type: "A", Class: "IN"}}},
			data:    tcpPacketExampleComA, shouldMatch: true, shouldFakeTCP: true,
		},
		{
			matcher: &MatchDNS{Allow: MatchDNSRules{&MatchDNSRule{TypeRegexp: "^(MX|NS)$"}}},
			data:    tcpPacketExampleComA, shouldMatch: false, shouldFakeTCP: true,
		},
		{
			matcher: &MatchDNS{Allow: MatchDNSRules{&MatchDNSRule{NameRegexp: "^(|[-0-9a-z]+\\.)example\\.com\\.$"}}},
			data:    tcpPacketExampleComA, shouldMatch: true, shouldFakeTCP: true,
		},

		{
			matcher: &MatchDNS{Deny: MatchDNSRules{&MatchDNSRule{Name: ".", Class: "IN"}}},
			data:    tcpPacketDotNS, shouldMatch: false, shouldFakeTCP: true,
		},
		{
			matcher: &MatchDNS{Deny: MatchDNSRules{&MatchDNSRule{Type: "A"}}},
			data:    tcpPacketDotNS, shouldMatch: true, shouldFakeTCP: true,
		},

		{matcher: &MatchDNS{
			Allow: MatchDNSRules{&MatchDNSRule{Name: "example.com.", Type: "A"}},
			Deny:  MatchDNSRules{&MatchDNSRule{Class: "IN"}},
		}, data: tcpPacketExampleComA, shouldMatch: false, shouldFakeTCP: true},
		{matcher: &MatchDNS{
			Allow: MatchDNSRules{&MatchDNSRule{Name: "example.com.", Type: "NS"}},
			Deny:  MatchDNSRules{&MatchDNSRule{Type: "MX"}},
		}, data: tcpPacketExampleComA, shouldMatch: true, shouldFakeTCP: true},
		{matcher: &MatchDNS{
			Allow:       MatchDNSRules{&MatchDNSRule{Name: "example.com.", Type: "NS"}},
			Deny:        MatchDNSRules{&MatchDNSRule{Type: "MX"}},
			DefaultDeny: true,
		}, data: tcpPacketExampleComA, shouldMatch: false, shouldFakeTCP: true},
		{matcher: &MatchDNS{
			Allow:       MatchDNSRules{&MatchDNSRule{Name: "example.com.", Type: "A"}},
			Deny:        MatchDNSRules{&MatchDNSRule{Class: "IN"}},
			PreferAllow: true,
		}, data: tcpPacketExampleComA, shouldMatch: true, shouldFakeTCP: true},
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

			if tc.shouldFakeTCP {
				out = &fakeTCPConn{Conn: out}
			}

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

type fakeTCPConn struct {
	net.Conn
}

func (c *fakeTCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

// Interface guard
var _ net.Conn = (*fakeTCPConn)(nil)

// Packet examples
var tcpPacketAppleComA = []byte{
	0, 27,
	126, 193, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	5, 97, 112, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, // apple.com (A, IN)
}

var udpPacketAppleComA = []byte{
	0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	5, 97, 112, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, // apple.com (A, IN)
}

var tcpPacketGoogleComA = []byte{
	0, 28,
	207, 90, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 5, 0, 1, // google.com. (A, IN)
}

var udpPacketGoogleComA = []byte{
	0, 11, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, // google.com. (A, IN)
}

var tcpPacketExampleComA = []byte{
	0, 29,
	101, 3, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, // example.com. (A, IN)
}

var tcpPacketDotNS = []byte{
	0, 17,
	213, 147, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	0, 0, 2, 0, 1, // . (NS, IN)
}
