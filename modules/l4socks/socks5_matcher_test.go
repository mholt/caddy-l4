package l4socks

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func TestSocks5Matcher_Match(t *testing.T) {
	curlSocks5Example1 := []byte{0x05, 0x02, 0x00, 0x01}
	curlSocks5Example2 := []byte{0x05, 0x03, 0x00, 0x01, 0x02}
	firefoxSocks5Example := []byte{0x05, 0x01, 0x00}

	type test struct {
		matcher     *Socks5Matcher
		data        []byte
		shouldMatch bool
	}

	tests := []test{
		// match with defaults
		{matcher: &Socks5Matcher{}, data: curlSocks5Example1, shouldMatch: true},
		{matcher: &Socks5Matcher{}, data: curlSocks5Example2, shouldMatch: true},
		{matcher: &Socks5Matcher{}, data: firefoxSocks5Example, shouldMatch: true},
		{matcher: &Socks5Matcher{}, data: []byte("Hello World"), shouldMatch: false},

		// match only no auth
		{matcher: &Socks5Matcher{AuthMethods: []uint16{0}}, data: curlSocks5Example1, shouldMatch: false},
		{matcher: &Socks5Matcher{AuthMethods: []uint16{0}}, data: curlSocks5Example2, shouldMatch: false},
		{matcher: &Socks5Matcher{AuthMethods: []uint16{0}}, data: firefoxSocks5Example, shouldMatch: true},

		// match custom auth
		{matcher: &Socks5Matcher{AuthMethods: []uint16{129}}, data: curlSocks5Example1, shouldMatch: false},
		{matcher: &Socks5Matcher{AuthMethods: []uint16{129}}, data: firefoxSocks5Example, shouldMatch: false},
		{matcher: &Socks5Matcher{AuthMethods: []uint16{129}}, data: []byte{0x05, 0x01, 0x81}, shouldMatch: true},
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
