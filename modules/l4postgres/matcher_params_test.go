// Copyright 2020 Matthew Holt
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

package l4postgres

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

// runMatch feeds input to the matcher over an in-memory pipe and returns the result.
func runMatch(t *testing.T, m layer4.ConnMatcher, input []byte) (bool, error) {
	t.Helper()
	in, out := net.Pipe()
	defer func() {
		_, _ = io.Copy(io.Discard, out)
		_ = out.Close()
	}()
	cx := layer4.WrapConnection(out, []byte{}, zap.NewNop())
	go func() {
		_, _ = in.Write(input)
		_ = in.Close()
	}()
	return m.Match(cx)
}

func startup(params map[string]string) []byte {
	return buildStartupMessage(0x00030000, params)
}

func TestMatchPostgresUserDatabase(t *testing.T) {
	tests := []struct {
		name      string
		users     map[string][]string
		params    map[string]string
		wantMatch bool
	}{
		{
			name:      "user and database allowed",
			users:     map[string][]string{"alice": {"planets_db", "stars_db"}},
			params:    map[string]string{"user": "alice", "database": "planets_db"},
			wantMatch: true,
		},
		{
			name:      "user allowed but database not in list",
			users:     map[string][]string{"alice": {"planets_db"}},
			params:    map[string]string{"user": "alice", "database": "other_db"},
			wantMatch: false,
		},
		{
			name:      "unknown user",
			users:     map[string][]string{"alice": {"planets_db"}},
			params:    map[string]string{"user": "bob", "database": "planets_db"},
			wantMatch: false,
		},
		{
			name:      "user with empty database list matches any database",
			users:     map[string][]string{"alice": {}},
			params:    map[string]string{"user": "alice", "database": "anything"},
			wantMatch: true,
		},
		{
			name:      "user allowed, databases configured but none sent",
			users:     map[string][]string{"alice": {"planets_db"}},
			params:    map[string]string{"user": "alice"},
			wantMatch: true,
		},
		{
			name:      "wildcard user with allowed database",
			users:     map[string][]string{"*": {"public_db"}},
			params:    map[string]string{"database": "public_db"},
			wantMatch: true,
		},
		{
			name:      "wildcard user with disallowed database",
			users:     map[string][]string{"*": {"public_db"}},
			params:    map[string]string{"database": "secret_db"},
			wantMatch: false,
		},
		{
			name:      "wildcard user but no database sent",
			users:     map[string][]string{"*": {"public_db"}},
			params:    map[string]string{"client_encoding": "UTF8"},
			wantMatch: false,
		},
		{
			name:      "no user param and no wildcard configured",
			users:     map[string][]string{"alice": {"planets_db"}},
			params:    map[string]string{"database": "planets_db"},
			wantMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &MatchPostgres{User: tc.users}
			matched, err := runMatch(t, m, startup(tc.params))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if matched != tc.wantMatch {
				t.Fatalf("match = %v, want %v", matched, tc.wantMatch)
			}
		})
	}
}

// With a user filter configured, non-startup messages (SSLRequest) cannot match.
func TestMatchPostgresUserFilterRejectsSSLRequest(t *testing.T) {
	m := &MatchPostgres{User: map[string][]string{"alice": {"db"}}}
	matched, err := runMatch(t, m, buildSSLRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Fatal("an SSLRequest must not match when a user filter is configured")
	}
}

func TestMatchPostgresClient(t *testing.T) {
	tests := []struct {
		name      string
		clients   []string
		input     []byte
		wantMatch bool
	}{
		{
			name:      "matching application_name",
			clients:   []string{"psql", "TablePlus"},
			input:     startup(map[string]string{"application_name": "psql"}),
			wantMatch: true,
		},
		{
			name:      "non-matching application_name",
			clients:   []string{"psql"},
			input:     startup(map[string]string{"application_name": "pgadmin"}),
			wantMatch: false,
		},
		{
			name:      "missing application_name",
			clients:   []string{"psql"},
			input:     startup(map[string]string{"user": "alice"}),
			wantMatch: false,
		},
		{
			name:      "SSLRequest has no parameters",
			clients:   []string{"psql"},
			input:     buildSSLRequest(),
			wantMatch: false,
		},
		{
			name:      "not a postgres connection",
			clients:   []string{"psql"},
			input:     []byte("GET / HTTP/1.1\r\n\r\n"),
			wantMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &MatchPostgres{Client: tc.clients}
			matched, err := runMatch(t, m, tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if matched != tc.wantMatch {
				t.Fatalf("match = %v, want %v", matched, tc.wantMatch)
			}
		})
	}
}

func TestMatchPostgresTLS(t *testing.T) {
	tests := []struct {
		name      string
		tls       string
		input     []byte
		wantMatch bool
	}{
		{name: "require TLS, got SSLRequest", tls: tlsEnabled, input: buildSSLRequest(), wantMatch: true},
		{name: "require TLS, got startup", tls: tlsEnabled, input: startup(map[string]string{"user": "alice"}), wantMatch: false},
		{name: "reject TLS, got startup", tls: tlsDisabled, input: startup(map[string]string{"user": "alice"}), wantMatch: true},
		{name: "reject TLS, got SSLRequest", tls: tlsDisabled, input: buildSSLRequest(), wantMatch: false},
		{name: "indifferent, got SSLRequest", tls: tlsIndifferent, input: buildSSLRequest(), wantMatch: true},
		{name: "indifferent, got startup", tls: tlsIndifferent, input: startup(map[string]string{"user": "alice"}), wantMatch: true},
		{name: "not a postgres connection", tls: tlsEnabled, input: []byte("GET / HTTP/1.1\r\n\r\n"), wantMatch: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &MatchPostgres{TLS: tc.tls}
			matched, err := runMatch(t, m, tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if matched != tc.wantMatch {
				t.Fatalf("match = %v, want %v", matched, tc.wantMatch)
			}
		})
	}
}

// Combining constraints requires all of them to hold.
func TestMatchPostgresCombined(t *testing.T) {
	// tls disabled + a matching user must both hold on a plaintext startup.
	m := &MatchPostgres{
		TLS:  tlsDisabled,
		User: map[string][]string{"alice": {"planets_db"}},
	}
	ok, err := runMatch(t, m, startup(map[string]string{"user": "alice", "database": "planets_db"}))
	if err != nil || !ok {
		t.Fatalf("expected a match for tls=disabled + user alice: ok=%v err=%v", ok, err)
	}

	// tls enabled + a user filter can never match: an SSLRequest carries no params.
	m2 := &MatchPostgres{TLS: tlsEnabled, User: map[string][]string{"alice": {"planets_db"}}}
	if ok, err := runMatch(t, m2, buildSSLRequest()); err != nil || ok {
		t.Fatalf("tls=enabled + user filter must not match an SSLRequest: ok=%v err=%v", ok, err)
	}

	// user matches but client does not -> no match.
	m3 := &MatchPostgres{
		User:   map[string][]string{"alice": {}},
		Client: []string{"psql"},
	}
	if ok, err := runMatch(t, m3, startup(map[string]string{"user": "alice", "application_name": "pgadmin"})); err != nil || ok {
		t.Fatalf("mismatched client must fail the combined match: ok=%v err=%v", ok, err)
	}
}

func TestMatchPostgresProvision(t *testing.T) {
	for _, v := range []string{tlsIndifferent, tlsEnabled, tlsDisabled} {
		if err := (&MatchPostgres{TLS: v}).Provision(caddy.Context{}); err != nil {
			t.Errorf("tls=%q should provision cleanly: %v", v, err)
		}
	}
	if err := (&MatchPostgres{TLS: "bogus"}).Provision(caddy.Context{}); err == nil {
		t.Error("an invalid tls value must be rejected at provision")
	}
}

// TestValidateStartupMessageFormatEdgeCases covers the "reached end of data
// without a null terminator" branches, which the upstream matcher test suite
// does not exercise.
func TestValidateStartupMessageFormatEdgeCases(t *testing.T) {
	// A key that runs to the end of the payload with no null terminator.
	if validateStartupMessageFormat([]byte("abc")) {
		t.Error("a key without a null terminator must be invalid")
	}
	// A value that runs to the end of the payload with no null terminator.
	if validateStartupMessageFormat([]byte("key\x00value")) {
		t.Error("a value without a null terminator must be invalid")
	}
}

// errAfterConn returns data (across reads) and then a fixed error, to exercise
// the non-EOF read-error branches of readFirstMessage.
type errAfterConn struct {
	data []byte
	err  error
	pos  int
}

func (c *errAfterConn) Read(p []byte) (int, error) {
	if c.pos < len(c.data) {
		n := copy(p, c.data[c.pos:])
		c.pos += n
		return n, nil
	}
	return 0, c.err
}
func (c *errAfterConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *errAfterConn) Close() error                       { return nil }
func (c *errAfterConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (c *errAfterConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (c *errAfterConn) SetDeadline(_ time.Time) error      { return nil }
func (c *errAfterConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *errAfterConn) SetWriteDeadline(_ time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "127.0.0.1:0" }

func TestReadFirstMessageReadErrors(t *testing.T) {
	boom := errors.New("connection reset by peer")

	t.Run("error reading length", func(t *testing.T) {
		cx := layer4.WrapConnection(&errAfterConn{err: boom}, []byte{}, zap.NewNop())
		if _, _, ok, err := readFirstMessage(cx); ok || err == nil {
			t.Fatalf("expected (ok=false, err!=nil), got ok=%v err=%v", ok, err)
		}
	})

	t.Run("error reading payload", func(t *testing.T) {
		// A valid 4-byte length header announcing an 8-byte message, then an error.
		header := []byte{0x00, 0x00, 0x00, 0x08}
		cx := layer4.WrapConnection(&errAfterConn{data: header, err: boom}, []byte{}, zap.NewNop())
		if _, _, ok, err := readFirstMessage(cx); ok || err == nil {
			t.Fatalf("expected (ok=false, err!=nil), got ok=%v err=%v", ok, err)
		}
	})
}

func TestMatchPostgresUnmarshalCaddyfile(t *testing.T) {
	t.Run("full block", func(t *testing.T) {
		d := caddyfile.NewTestDispenser(`postgres {
			user alice planets_db stars_db
			user * public_db
			user alice extra_db
			client psql TablePlus
			tls enabled
		}`)
		m := &MatchPostgres{}
		if err := m.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := m.User["alice"]; len(got) != 3 || got[0] != "planets_db" || got[2] != "extra_db" {
			t.Fatalf("alice databases = %v, want [planets_db stars_db extra_db]", got)
		}
		if got := m.User["*"]; len(got) != 1 || got[0] != "public_db" {
			t.Fatalf("wildcard databases = %v, want [public_db]", got)
		}
		if len(m.Client) != 2 || m.Client[0] != "psql" || m.Client[1] != "TablePlus" {
			t.Fatalf("clients = %v, want [psql TablePlus]", m.Client)
		}
		if m.TLS != tlsEnabled {
			t.Fatalf("tls = %q, want %q", m.TLS, tlsEnabled)
		}
	})

	t.Run("tls disabled and wildcard", func(t *testing.T) {
		d := caddyfile.NewTestDispenser("postgres {\n\ttls disabled\n}")
		m := &MatchPostgres{}
		if err := m.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m.TLS != tlsDisabled {
			t.Fatalf("tls = %q, want %q", m.TLS, tlsDisabled)
		}

		d2 := caddyfile.NewTestDispenser("postgres {\n\ttls *\n}")
		m2 := &MatchPostgres{}
		if err := m2.UnmarshalCaddyfile(d2); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m2.TLS != tlsIndifferent {
			t.Fatalf("tls = %q, want indifferent", m2.TLS)
		}
	})

	t.Run("bare matcher", func(t *testing.T) {
		d := caddyfile.NewTestDispenser(`postgres`)
		if err := (&MatchPostgres{}).UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	errorCases := map[string]string{
		"args after wrapper":    `postgres extra`,
		"user without a name":   "postgres {\n\tuser\n}",
		"client without a name": "postgres {\n\tclient\n}",
		"tls without a value":   "postgres {\n\ttls\n}",
		"tls unknown value":     "postgres {\n\ttls maybe\n}",
		"tls with extra arg":    "postgres {\n\ttls enabled extra\n}",
		"tls specified twice":   "postgres {\n\ttls enabled\n\ttls disabled\n}",
		"unrecognized option":   "postgres {\n\tnonsense\n}",
	}
	for name, input := range errorCases {
		t.Run(name, func(t *testing.T) {
			if err := (&MatchPostgres{}).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatalf("expected an error for %q", name)
			}
		})
	}
}
