// Copyright (c) 2024 SICK AG
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

package l4fail2ban

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

// Setup dummy structs for test cases as in
// https://github.com/mholt/caddy-l4/blob/master/layer4/matchers_test.go
var _ net.Conn = &dummyConn{}
var _ net.Addr = dummyAddr{}

type dummyAddr struct {
	ip      string
	network string
}

// Network implements net.Addr.
func (da dummyAddr) Network() string {
	return da.network
}

// String implements net.Addr.
func (da dummyAddr) String() string {
	return da.ip
}

type dummyConn struct {
	net.Conn
	remoteAddr net.Addr
}

// RemoteAddr implements net.Conn.
func (dc *dummyConn) RemoteAddr() net.Addr {
	return dc.remoteAddr
}

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Unexpected error: %s\n", err)
	}
}

// Create a temporary directory and a ban file
func createBanFile(t *testing.T) (string, string) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "caddy-l4-fail2ban-test")
	assertNoError(t, err)

	banFile := path.Join(tempDir, "banned-ips")
	return tempDir, banFile
}

// Cleanup the temporary directory and the ban file
func cleanupBanFile(t *testing.T, tempDir string) {
	t.Helper()
	err := os.RemoveAll(tempDir)
	assertNoError(t, err)
}

// Test the Caddyfile unmarshaller
func TestFail2BanUnmarshaller(t *testing.T) {
	tempDir, banFile := createBanFile(t)
	defer cleanupBanFile(t, tempDir)

	dispenser := caddyfile.NewTestDispenser(fmt.Sprintf(`fail2ban %s`, banFile))

	matcher := Fail2Ban{}
	err := matcher.UnmarshalCaddyfile(dispenser)
	assertNoError(t, err)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err = matcher.Provision(ctx)
	assertNoError(t, err)

	// Wait for the banlist to be loaded by the matcher
	time.Sleep(100 * time.Millisecond)

	if matcher.Banfile != banFile {
		t.Fatalf("Expected %s, got %s", banFile, matcher.Banfile)
	}
}

// Test if a banned IP is matched
func TestFail2BanMatch(t *testing.T) {
	tempDir, banFile := createBanFile(t)
	defer cleanupBanFile(t, tempDir)

	os.WriteFile(banFile, []byte("127.0.0.99"), 0644)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	matcher := Fail2Ban{
		Banfile: banFile,
	}

	err := matcher.Provision(ctx)
	assertNoError(t, err)

	cx := &layer4.Connection{
		Conn: &dummyConn{
			remoteAddr: dummyAddr{ip: "127.0.0.99", network: "tcp"},
		},
		Logger: zap.NewNop(),
	}

	matched, err := matcher.Match(cx)
	assertNoError(t, err)

	if !matched {
		t.Fatalf("Matcher did not match")
	}
}

// Test if a non-banned IP is not matched
func TestFail2BanNoMatch(t *testing.T) {
	tempDir, banFile := createBanFile(t)
	defer cleanupBanFile(t, tempDir)

	os.WriteFile(banFile, []byte("127.0.0.1"), 0644)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	matcher := Fail2Ban{
		Banfile: banFile,
	}

	err := matcher.Provision(ctx)
	assertNoError(t, err)

	cx := &layer4.Connection{
		Conn: &dummyConn{
			remoteAddr: dummyAddr{ip: "127.0.0.99", network: "tcp"},
		},
		Logger: zap.NewNop(),
	}

	matched, err := matcher.Match(cx)
	assertNoError(t, err)

	if matched {
		t.Fatalf("Matcher did match")
	}
}
