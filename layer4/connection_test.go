package layer4

import (
	"bytes"
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func TestConnection_FreezeAndUnfreeze(t *testing.T) {
	in, out := net.Pipe()
	defer func() { _ = in.Close() }()
	defer func() { _ = out.Close() }()

	cx := WrapConnection(out, []byte{}, zap.NewNop())
	defer func() { _ = cx.Close() }()

	matcherData := []byte("foo")
	consumeData := []byte("bar")

	buf := make([]byte, len(matcherData))

	go func() {
		_, _ = in.Write(matcherData)
		_, _ = in.Write(consumeData)
	}()

	// prefetch like server handler would
	err := cx.prefetch()
	if err != nil {
		t.Fatal(err)
	}

	// 1st matcher
	cx.freeze()

	n, err := cx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(matcherData) {
		t.Fatalf("expected to read %d bytes but got %d", len(matcherData), n)
	}
	if !bytes.Equal(matcherData, buf) {
		t.Fatalf("expected %s but received %s", matcherData, buf)
	}

	cx.unfreeze()

	// 2nd matcher (reads same data)

	cx.freeze()

	n, err = cx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(matcherData) {
		t.Fatalf("expected to read %d bytes but got %d", len(matcherData), n)
	}
	if !bytes.Equal(matcherData, buf) {
		t.Fatalf("expected %s but received %s", matcherData, buf)
	}

	cx.unfreeze()

	// 1st consumer (no freeze call)

	n, err = cx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(matcherData) {
		t.Fatalf("expected to read %d bytes but got %d", len(matcherData), n)
	}
	if !bytes.Equal(matcherData, buf) {
		t.Fatalf("expected %s but received %s", matcherData, buf)
	}

	// 2nd consumer (reads other data)

	n, err = cx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(consumeData) {
		t.Fatalf("expected to read %d bytes but got %d", len(consumeData), n)
	}
	if !bytes.Equal(consumeData, buf) {
		t.Fatalf("expected %s but received %s", consumeData, buf)
	}
}

func TestConnection_AddrPartPlaceholders(t *testing.T) {
	for i, tc := range []struct {
		local, remote          net.Addr
		localHost, localPort   string
		remoteHost, remotePort string
	}{
		{
			local:     &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50001},
			remote:    &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 61234},
			localHost: "10.0.0.1", localPort: "50001",
			remoteHost: "192.0.2.7", remotePort: "61234",
		},
		{
			local:     &net.UDPAddr{IP: net.IPv6zero, Port: 3478},
			remote:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 5000},
			localHost: "::", localPort: "3478",
			remoteHost: "2001:db8::1", remotePort: "5000",
		},
	} {
		cx := WrapConnection(&dummyConn{localAddr: tc.local, remoteAddr: tc.remote}, []byte{}, zap.NewNop())
		repl := cx.Context.Value(ReplacerCtxKey).(*caddy.Replacer)
		for ph, want := range map[string]string{
			"{l4.conn.local_host}":  tc.localHost,
			"{l4.conn.local_port}":  tc.localPort,
			"{l4.conn.remote_host}": tc.remoteHost,
			"{l4.conn.remote_port}": tc.remotePort,
		} {
			if got := repl.ReplaceAll(ph, "<empty>"); got != want {
				t.Errorf("test %d: %s = %q, want %q", i, ph, got, want)
			}
		}
		if got := repl.ReplaceAll("udp/10.0.1.68:{l4.conn.local_port}", ""); got != "udp/10.0.1.68:"+tc.localPort {
			t.Errorf("test %d: dial address = %q", i, got)
		}
	}

	// addresses without a port (e.g. pipes) leave the placeholders unset
	in, out := net.Pipe()
	defer func() { _ = in.Close() }()
	defer func() { _ = out.Close() }()
	repl := WrapConnection(out, []byte{}, zap.NewNop()).Context.Value(ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{l4.conn.local_port}", "<empty>"); got != "<empty>" {
		t.Errorf("pipe: {l4.conn.local_port} = %q, want unset", got)
	}
}
