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

package l4wireguard

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

func Test_MatchWireGuard_ProcessMessageInitiation(t *testing.T) {
	p := [][]byte{
		append(packet00000001, make([]byte, MessageInitiationBytesTotal-len(packet00000001))...),
		append(packet010077FF, make([]byte, MessageInitiationBytesTotal-len(packet010077FF))...),
	}
	for _, b := range p {
		func() {
			s := &MessageInitiation{}
			errFrom := s.FromBytes(b)
			assertNoError(t, errFrom)
			sb, errTo := s.ToBytes()
			assertNoError(t, errTo)
			if !bytes.Equal(b, sb) {
				t.Fatalf("test %T bytes processing: resulting bytes [% x] don't match original bytes [% x]", *s, b, sb)
			}
		}()
	}
}

func Test_MatchWireGuard_ProcessMessageData(t *testing.T) {
	p := [][]byte{
		append(packet00000004, make([]byte, MessageTransportBytesMin-len(packet00000001))...),
		append(packet00000004, make([]byte, MessageTransportBytesMin-len(packet00000001)+160)...),
	}
	for _, b := range p {
		func() {
			s := &MessageTransport{}
			errFrom := s.FromBytes(b)
			assertNoError(t, errFrom)
			sb, errTo := s.ToBytes()
			assertNoError(t, errTo)
			if !bytes.Equal(b, sb) {
				t.Fatalf("test %T bytes processing: resulting bytes [% x] don't match original bytes [% x]", *s, b, sb)
			}
		}()
	}
}

func Test_MatchWireGuard_Match(t *testing.T) {
	type test struct {
		matcher     *MatchWireGuard
		data        []byte
		shouldMatch bool
	}

	tests := []test{
		{matcher: &MatchWireGuard{}, data: packet00000001, shouldMatch: false},
		{matcher: &MatchWireGuard{}, data: append(packet00000001, make([]byte, MessageInitiationBytesTotal-len(packet00000001))...), shouldMatch: true},
		{matcher: &MatchWireGuard{}, data: append(packet00000001, make([]byte, MessageInitiationBytesTotal-len(packet00000001)+1)...), shouldMatch: false},

		{matcher: &MatchWireGuard{}, data: packet00000002, shouldMatch: false},
		{matcher: &MatchWireGuard{}, data: append(packet00000002, make([]byte, MessageInitiationBytesTotal-len(packet00000002))...), shouldMatch: false},
		{matcher: &MatchWireGuard{}, data: append(packet00000002, make([]byte, MessageResponseBytesTotal-len(packet00000002))...), shouldMatch: false},

		{matcher: &MatchWireGuard{}, data: packet00000003, shouldMatch: false},
		{matcher: &MatchWireGuard{}, data: append(packet00000003, make([]byte, MessageInitiationBytesTotal-len(packet00000003))...), shouldMatch: false},
		{matcher: &MatchWireGuard{}, data: append(packet00000003, make([]byte, MessageCookieReplyBytesTotal-len(packet00000003))...), shouldMatch: false},

		{matcher: &MatchWireGuard{}, data: packet00000004, shouldMatch: false},
		{matcher: &MatchWireGuard{}, data: append(packet00000004, make([]byte, MessageInitiationBytesTotal-len(packet00000004))...), shouldMatch: false},
		{matcher: &MatchWireGuard{}, data: append(packet00000004, make([]byte, MessageTransportBytesMin-len(packet00000004))...), shouldMatch: true},

		{matcher: &MatchWireGuard{}, data: packet010077FF, shouldMatch: false},
		{matcher: &MatchWireGuard{}, data: append(packet010077FF, make([]byte, MessageInitiationBytesTotal-len(packet010077FF))...), shouldMatch: false},
		{matcher: &MatchWireGuard{Zero: 4285988864}, data: append(packet010077FF, make([]byte, MessageInitiationBytesTotal-len(packet010077FF))...), shouldMatch: true},
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

var (
	packet00000001 = []byte{uint8(MessageTypeInitiation), 0x00, 0x00, 0x00}
	packet00000002 = []byte{uint8(MessageTypeResponse), 0x00, 0x00, 0x00}
	packet00000003 = []byte{uint8(MessageTypeCookieReply), 0x00, 0x00, 0x00}
	packet00000004 = []byte{uint8(MessageTypeTransport), 0x00, 0x00, 0x00}
	packet010077FF = []byte{uint8(MessageTypeInitiation), 0x00, 0x77, 0xFF}
)
