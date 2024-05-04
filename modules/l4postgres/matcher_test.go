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

// Reader allows any Example to be used in tests as data
type Reader interface {
	Read() ([]byte, error)
}

// Example extends StartupMessage with utils to create messages
type example struct {
	startupMessage
}

// Read gets []byte from an Example struct as the raw protocol is similar to
// "user\u0000alice\u0000database\u0000stars_db"
func (x *example) Read() ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(x.Reader())
	return buf.Bytes(), err
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

func matchTester(t *testing.T, matcher layer4.ConnMatcher, data []byte) (bool, error) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	cx := layer4.WrapConnection(in, &bytes.Buffer{}, zap.NewNop())

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer out.Close()
		_, err := out.Write(data)
		assertNoError(t, err)
	}()

	matched, err := matcher.Match(cx)

	_, _ = io.Copy(io.Discard, in)

	return matched, err
}

func Fatalf(t *testing.T, err error, matched bool, expect bool, explain string) {
	t.Helper()
	if matched != expect {
		if err != nil {
			t.Logf("Unexpected error: %s\n", err)
		}
		t.Fatalf("matcher did not match: returned %t != expected %t; %s", matched, expect, explain)
	}
}

func TestPostgres(t *testing.T) {
	t.Parallel() // marks as capable of running in parallel with other tests

	// ref: https://go.dev/wiki/TableDrivenTests
	tests := []struct {
		name    string
		matcher layer4.ConnMatcher
		data    Reader
		expect  bool
		explain string
	}{
		{
			name:    "rejects an empty StartupMessage",
			matcher: MatchPostgres{},
			data: &example{
				startupMessage: startupMessage{},
			},
			expect:  false,
			explain: "an empty Postgres StartupMessage has no version to check",
		},
		{
			name:    "allows any SSLRequest",
			matcher: MatchPostgres{},
			data: &example{
				startupMessage: startupMessage{
					ProtocolVersion: sslRequestCode,
				},
			},
			expect:  true,
			explain: "any Postgres SSLRequest should be accepted",
		},
		{
			name:    "allows any StartupMessage with a supported ProtocolVersion",
			matcher: MatchPostgres{},
			data: &example{
				startupMessage: startupMessage{
					ProtocolVersion: 196608, // v3.0
				},
			},
			expect:  true,
			explain: "any Postgres StartupMessage without parameters should be rejected",
		},
		{
			name:    "allows any StartupMessage with parameters",
			matcher: MatchPostgres{},
			data: &example{
				startupMessage: startupMessage{
					ProtocolVersion: 196608, // v3.0
					Parameters: map[string]string{
						"user":     "alice",
						"database": "stars_db",
					},
				},
			},
			expect:  true,
			explain: "any Postgres StartupMessage with parameters should be accepted",
		},
	}
	for _, tc := range tests {
		tc := tc // NOTE: /wiki/CommonMistakes#using-goroutines-on-loop-iterator-variables
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data, err := tc.data.Read()
			assertNoError(t, err)

			matched, err := matchTester(t, tc.matcher, data)
			Fatalf(t, err, matched, tc.expect, tc.explain)
		})
	}
}

func TestPostgresSSL(t *testing.T) {
	t.Parallel() // marks as capable of running in parallel with other tests

	// ref: https://go.dev/wiki/TableDrivenTests
	tests := []struct {
		name    string
		matcher layer4.ConnMatcher
		data    Reader
		expect  bool
		explain string
	}{
		{
			name:    "rejects an empty StartupMessage",
			matcher: MatchPostgresSSL{},
			data: &example{
				startupMessage: startupMessage{},
			},
			expect:  false,
			explain: "an empty Postgres StartupMessage has no version to check",
		},
		{
			name:    "implicitly requires SSL Requests",
			matcher: MatchPostgresSSL{},
			data: &example{
				startupMessage: startupMessage{
					ProtocolVersion: sslRequestCode,
				},
			},
			expect:  true,
			explain: "SSL is enabled",
		},
		{
			name: "explictly requires SSL Requests",
			matcher: MatchPostgresSSL{
				Disabled: false,
			},
			data: &example{
				startupMessage: startupMessage{
					ProtocolVersion: sslRequestCode,
				},
			},
			expect:  true,
			explain: "SSL is enabled",
		},
		{
			name:    "implicitly rejects non-SSL Requests",
			matcher: MatchPostgresSSL{},
			data: &example{
				startupMessage: startupMessage{
					ProtocolVersion: 196608,
				},
			},
			expect:  false,
			explain: "SSL is enabled",
		},
		{
			name: "explictly rejects non-SSL Requests",
			matcher: MatchPostgresSSL{
				Disabled: false,
			},
			data: &example{
				startupMessage: startupMessage{
					ProtocolVersion: 196608,
				},
			},
			expect:  false,
			explain: "SSL is enabled",
		},
		{
			name: "explictly requires non-SSL Requests",
			matcher: MatchPostgresSSL{
				Disabled: true,
			},
			data: &example{
				startupMessage: startupMessage{
					ProtocolVersion: 196608,
				},
			},
			expect:  true,
			explain: "SSL is disabled",
		},
		{
			name: "explictly rejects SSL Requests",
			matcher: MatchPostgresSSL{
				Disabled: true,
			},
			data: &example{
				startupMessage: startupMessage{
					ProtocolVersion: sslRequestCode,
				},
			},
			expect:  false,
			explain: "SSL is disabled",
		},
	}
	for _, tc := range tests {
		tc := tc // NOTE: /wiki/CommonMistakes#using-goroutines-on-loop-iterator-variables
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data, err := tc.data.Read()
			assertNoError(t, err)

			matched, err := matchTester(t, tc.matcher, data)
			Fatalf(t, err, matched, tc.expect, tc.explain)
		})
	}
}
