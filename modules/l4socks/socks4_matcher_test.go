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

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Unexpected error: %s\n", err)
	}
}

func TestSocks4Matcher_Match(t *testing.T) {
	curlSocks4Example1 := []byte{0x04, 0x01, 0x00, 0x50, 0x5d, 0xb8, 0xd8, 0x22, 0x00}
	curlSocks4Example2 := []byte{0x04, 0x01, 0x01, 0xbb, 0xa5, 0xe3, 0x14, 0xcf, 0x00}

	curlSocks4aExample1 := []byte{0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67, 0x00}
	curlSocks4aExample2 := []byte{0x04, 0x01, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x63, 0x61, 0x64, 0x64, 0x79, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x00}

	type test struct {
		matcher     *Socks4Matcher
		data        []byte
		shouldMatch bool
	}

	tests := []test{
		// match with defaults
		{matcher: &Socks4Matcher{}, data: curlSocks4Example1, shouldMatch: true},
		{matcher: &Socks4Matcher{}, data: curlSocks4aExample1, shouldMatch: true},
		{matcher: &Socks4Matcher{}, data: curlSocks4Example2, shouldMatch: true},
		{matcher: &Socks4Matcher{}, data: curlSocks4aExample2, shouldMatch: true},
		{matcher: &Socks4Matcher{}, data: []byte("Hello World"), shouldMatch: false},

		// match only BIND
		{matcher: &Socks4Matcher{Commands: []string{"BIND"}}, data: curlSocks4Example1, shouldMatch: false},
		{matcher: &Socks4Matcher{Commands: []string{"BIND"}}, data: curlSocks4aExample1, shouldMatch: false},

		// match destination ip
		{matcher: &Socks4Matcher{Networks: []string{"127.0.0.1"}}, data: curlSocks4Example1, shouldMatch: false},
		{matcher: &Socks4Matcher{Networks: []string{"127.0.0.1"}}, data: curlSocks4Example2, shouldMatch: false},

		{matcher: &Socks4Matcher{Networks: []string{"165.227.0.0/8"}}, data: curlSocks4Example1, shouldMatch: false},
		{matcher: &Socks4Matcher{Networks: []string{"165.227.0.0/8"}}, data: curlSocks4Example2, shouldMatch: true},

		{matcher: &Socks4Matcher{Networks: []string{"165.227.0.0/8", "::1"}}, data: curlSocks4Example1, shouldMatch: false},
		{matcher: &Socks4Matcher{Networks: []string{"165.227.0.0/8", "::1"}}, data: curlSocks4Example2, shouldMatch: true},

		{matcher: &Socks4Matcher{Networks: []string{"127.0.0.1"}}, data: curlSocks4aExample1, shouldMatch: false},
		{matcher: &Socks4Matcher{Networks: []string{"0.0.0.0/0"}}, data: curlSocks4aExample2, shouldMatch: true},

		// match destination port
		{matcher: &Socks4Matcher{Ports: []uint16{80, 1234}}, data: curlSocks4Example1, shouldMatch: true},
		{matcher: &Socks4Matcher{Ports: []uint16{80, 1234}}, data: curlSocks4Example2, shouldMatch: false},
		{matcher: &Socks4Matcher{Ports: []uint16{80, 1234}}, data: curlSocks4aExample1, shouldMatch: true},
		{matcher: &Socks4Matcher{Ports: []uint16{80, 1234}}, data: curlSocks4aExample2, shouldMatch: false},
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

func TestSocks4Matcher_InvalidCommand(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := &Socks4Matcher{Commands: []string{"Foo"}}
	err := handler.Provision(ctx)

	if err == nil || err.Error() != "unknown command \"Foo\" has to be one of [\"CONNECT\", \"BIND\"]" {
		t.Fatalf("Wrong error: %v\n", err)
	}
}
