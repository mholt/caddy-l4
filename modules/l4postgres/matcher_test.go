package l4postgres

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

// Example extends StartupMessage with utils to create example messages.
type example struct {
	startupMessage
}

// Bytes gets []byte from a struct as the raw protocol is similar to
// "user\u0000alice\u0000database\u0000stars_db"
func (x *example) Bytes() []byte {
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(x.Reader())
	return buf.Bytes()
}

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

var ExampleSSLRequest = func() []byte {
	x := &example{
		startupMessage: startupMessage{
			ProtocolVersion: sslRequestCode,
		},
	}
	return x.Bytes()
}

var ExampleStartupMessage = func() []byte {
	x := &example{
		startupMessage: startupMessage{
			ProtocolVersion: 196608, // v3.0
			Parameters: map[string]string{
				"user":     "alice",
				"database": "stars_db",
			},
		},
	}
	return x.Bytes()
}

func TestPostgresSSLMatch(t *testing.T) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	cx := layer4.WrapConnection(in, &bytes.Buffer{}, zap.NewNop())

	x := ExampleSSLRequest()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer out.Close()
		_, err := out.Write(x)
		assertNoError(t, err)
	}()

	matcher := MatchPostgresSSL{
		Required: true,
	}

	matched, err := matcher.Match(cx)
	assertNoError(t, err)

	if !matched {
		t.Fatalf("matcher did not match SSL")
	}

	_, _ = io.Copy(io.Discard, in)
}

func TestPostgresMatch(t *testing.T) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	cx := layer4.WrapConnection(in, &bytes.Buffer{}, zap.NewNop())

	x := ExampleStartupMessage()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer out.Close()
		_, err := out.Write(x)
		assertNoError(t, err)
	}()

	matcher := MatchPostgres{
		Users: map[string][]string{
			"alice": {},
		},
	}

	matched, err := matcher.Match(cx)
	assertNoError(t, err)

	if !matched {
		t.Fatalf("matcher did not match user")
	}

	_, _ = io.Copy(io.Discard, in)
}
