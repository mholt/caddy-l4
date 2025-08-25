package l4socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func replay(t *testing.T, handler *Socks5Handler, expectedError string, messages [][]byte) {
	t.Helper()
	in, out := net.Pipe()
	cx := layer4.WrapConnection(out, []byte{}, zap.NewNop())
	defer func() {
		_ = in.Close()
		_, _ = io.Copy(io.Discard, out)
		_ = out.Close()
		_ = cx.Close()
	}()

	go func() {
		err := handler.Handle(cx, nil)
		if expectedError != "" && err != nil && err.Error() != expectedError {
			t.Errorf("Unexpected error: %s\n", err)
		} else if expectedError != "" && err == nil {
			t.Errorf("Missing error: %s\n", expectedError)
		}
	}()

	for i := 0; i < len(messages); i += 2 {
		_, err := in.Write(messages[i])
		assertNoError(t, err)

		if i+1 < len(messages) {
			buf := make([]byte, len(messages[i+1]))
			_, err = io.ReadFull(in, buf)
			assertNoError(t, err)

			if !bytes.Equal(messages[i+1], buf) {
				t.Fatalf("Expected % x but received % x\n", messages[i+1], buf)
			}
		}
	}
}

func TestSocks5Handler_Defaults(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := &Socks5Handler{} // no config

	err := handler.Provision(ctx)
	assertNoError(t, err)

	// target for the socks handler to connect to (using free random port)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assertNoError(t, err)
	defer func() { _ = listener.Close() }()

	// transform random listening port into bytes
	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	assertNoError(t, err)
	port, err := strconv.ParseUint(portStr, 10, 16)
	assertNoError(t, err)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	replay(t, handler, "", [][]byte{
		{0x05, 0x01, 0x00}, // -> request no auth
		{0x05, 0x00},       // <- accept no auth
		{0x05, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, portBytes[0], portBytes[1]}, // -> CONNECT 127.0.0.1 [random port]
		{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01},                             // <- success (ignoring last 2 bytes containing random port)
	})

	replay(t, handler, "", [][]byte{
		{0x05, 0x01, 0x02}, // -> request auth with password
		{0x05, 0xff},       // <- NO ACCEPTABLE METHODS
	})

	replay(t, handler, "", [][]byte{
		{0x05, 0x01, 0x00}, // -> request no auth
		{0x05, 0x00},       // <- accept no auth
		{0x05, 0x02, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50}, // -> BIND 127.0.0.1 80
		{0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // <- connection not allowed by ruleset
	})
}

func TestSocks5Handler_Commands(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := &Socks5Handler{Commands: []string{"BIND"}} // only allow BIND

	err := handler.Provision(ctx)
	assertNoError(t, err)

	replay(t, handler, "bind to 127.0.0.1:80 blocked by rules", [][]byte{
		{0x05, 0x01, 0x00}, // -> request no auth
		{0x05, 0x00},       // <- accept no auth
		{0x05, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50}, // -> CONNECT 127.0.0.1 80
		{0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // <- connection not allowed by ruleset
	})

	replay(t, handler, "bind to 127.0.0.1:80 blocked by rules", [][]byte{
		{0x05, 0x01, 0x00}, // -> request no auth
		{0x05, 0x00},       // <- accept no auth
		{0x05, 0x03, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50}, // -> UDP ASSOCIATE 127.0.0.1 80
		{0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // <- connection not allowed by ruleset
	})

	replay(t, handler, "", [][]byte{
		{0x05, 0x01, 0x00}, // -> request no auth
		{0x05, 0x00},       // <- accept no auth
		{0x05, 0x02, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50}, // -> BIND 127.0.0.1 80
		{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // <- command not supported
	})
}

func TestSocks5Handler_Credentials(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := &Socks5Handler{Credentials: map[string]string{"alice": "alice", "bob": "bob"}}

	err := handler.Provision(ctx)
	assertNoError(t, err)

	replay(t, handler, "", [][]byte{
		{0x05, 0x01, 0x00}, // -> request no auth
		{0x05, 0xff},       // <- NO ACCEPTABLE METHODS
	})

	replay(t, handler, "", [][]byte{
		{0x05, 0x01, 0x02}, // -> request auth with password
		{0x05, 0x02},       // <- select auth with password
		{0x01, 0x05, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x05, 0x61, 0x6c, 0x69, 0x63, 0x65}, // -> send alice:alice
		{0x01, 0x00}, // <- accept user
	})

	replay(t, handler, "", [][]byte{
		{0x05, 0x02, 0x00, 0x02}, // -> request auth with password & no auth
		{0x05, 0x02},             // <- select auth with password
		{0x01, 0x03, 0x62, 0x6f, 0x62, 0x03, 0x62, 0x6f, 0x62}, // -> send bob:bob
		{0x01, 0x00}, // <- accept user
	})

	replay(t, handler, "", [][]byte{
		{0x05, 0x01, 0x02}, // -> request auth with password
		{0x05, 0x02},       // <- select auth with password
		{0x01, 0x05, 0x63, 0x61, 0x72, 0x6f, 0x6c, 0x05, 0x63, 0x61, 0x72, 0x6f, 0x6c}, // -> send carol:carol
		{0x01, 0x01}, // <- reject user
	})
}

func TestSocks5Handler_InvalidCommand(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := &Socks5Handler{Commands: []string{"Foo"}}
	err := handler.Provision(ctx)

	if err == nil || err.Error() != "unknown command \"Foo\" has to be one of [\"CONNECT\", \"ASSOCIATE\", \"BIND\"]" {
		t.Fatalf("Wrong error: %v\n", err)
	}
}
