package l4proxyprotocol

import (
	"encoding/hex"
	"io"
	"net"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

var (
	ProxyV1Example    = []byte("PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n")
	ProxyV2Example, _ = hex.DecodeString("0d0a0d0a000d0a515549540a2111000c7f0000017f000001b80701bb")
)

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Unexpected error: %s\n", err)
	}
}

func closePipe(wg *sync.WaitGroup, c1 net.Conn, c2 net.Conn) {
	wg.Wait()
	_ = c1.Close()
	_ = c2.Close()
}

func TestProxyProtocolMatchV1(t *testing.T) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	cx := layer4.WrapConnection(in, []byte{}, zap.NewNop())
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = out.Close() }()
		_, err := out.Write(ProxyV1Example)
		assertNoError(t, err)
	}()

	matcher := MatchProxyProtocol{}

	matched, err := matcher.Match(cx)
	assertNoError(t, err)

	if !matched {
		t.Fatalf("matcher did not match v1")
	}

	_, _ = io.Copy(io.Discard, in)
}

func TestProxyProtocolMatchV2(t *testing.T) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	cx := layer4.WrapConnection(in, []byte{}, zap.NewNop())
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = out.Close() }()
		_, err := out.Write(ProxyV2Example)
		assertNoError(t, err)
	}()

	matcher := MatchProxyProtocol{}

	matched, err := matcher.Match(cx)
	assertNoError(t, err)

	if !matched {
		t.Fatalf("matcher did not match v2")
	}

	_, _ = io.Copy(io.Discard, in)
}

func TestProxyProtocolMatchGarbage(t *testing.T) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	cx := layer4.WrapConnection(in, []byte{}, zap.NewNop())
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = out.Close() }()
		_, err := out.Write([]byte("Hello World Hello World Hello World Hello World"))
		assertNoError(t, err)
	}()

	matcher := MatchProxyProtocol{}

	matched, err := matcher.Match(cx)
	assertNoError(t, err)

	if matched {
		t.Fatalf("matcher did match garbage but should not")
	}

	_, _ = io.Copy(io.Discard, in)
}
