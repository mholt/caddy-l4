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

package l4remoteiplist

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

// Setup dummy structs for test cases as in
// https://github.com/mholt/caddy-l4/blob/master/layer4/matchers_test.go
var (
	_ net.Conn = &dummyConn{}
	_ net.Addr = dummyAddr{}
)

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

// Create a temporary directory and a remote IP file
func createIPFile(t *testing.T) (string, string) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "caddy-l4-remoteiplist-test")
	assertNoError(t, err)

	remoteIPFile := filepath.Join(tempDir, "remote-ips")

	// Create the file
	file, err := os.Create(remoteIPFile)
	assertNoError(t, err)
	defer func() {
		_ = file.Close()
	}()

	return tempDir, remoteIPFile
}

// Cleanup the temporary directory and the remote IP file
func cleanupIPFile(t *testing.T, tempDir string) {
	t.Helper()
	err := os.RemoveAll(tempDir)
	assertNoError(t, err)
}

func wait() {
	time.Sleep(10 * time.Millisecond)
}

func appendToFile(t *testing.T, filename string, ip string) {
	// Append new IP to end of file
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0o600)
	assertNoError(t, err)
	defer func() {
		_ = f.Close()
	}()

	_, err = f.WriteString(ip + "\n")
	assertNoError(t, err)
}

// simple template for testing: write IP ipInFile to file and test against the IP ipInConnection
// expected result of the matcher is matchExpected
func simpleIPMatchTest(t *testing.T, ipInFile string, ipInConnection string, matchExpected bool) {
	tempDir, ipFile := createIPFile(t)
	defer cleanupIPFile(t, tempDir)

	appendToFile(t, ipFile, ipInFile)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	// Give some time to react to the context close
	defer wait()
	defer cancel()

	matcher := RemoteIPList{
		RemoteIPFile: ipFile,
	}

	err := matcher.Provision(ctx)
	assertNoError(t, err)
	wait()

	cx := &layer4.Connection{
		Conn: &dummyConn{
			remoteAddr: dummyAddr{ip: ipInConnection, network: "tcp"},
		},
		Logger: zap.NewNop(),
	}

	matched, err := matcher.Match(cx)
	assertNoError(t, err)

	if matched != matchExpected {
		t.Errorf("Matcher returned %t (expected was %t)", matched, matchExpected)
	}
}

// Test if a remote IPv4 address is matched
func TestRemoteIPv4Match(t *testing.T) {
	simpleIPMatchTest(t, "127.0.0.99", "127.0.0.99", true)
}

// Test if a remote IPv4 network is matched
func TestRemoteIPv4NetworkMatch(t *testing.T) {
	simpleIPMatchTest(t, "127.0.0.1/8", "127.0.0.99", true)
}

// Test if an IP that is not contained in the remote IP list is not matched
func TestRemoteIPv4NoMatch(t *testing.T) {
	simpleIPMatchTest(t, "127.0.0.1", "127.0.0.99", false)
}

// Test if a remote IPv6 address is matched
func TestRemoteIPv6Match(t *testing.T) {
	simpleIPMatchTest(t, "fd00::1", "fd00:0:0:0:0:0:0:1", true)
}

// Test if a remote IPv6 network is matched
func TestRemoteIPv6NetworkMatch(t *testing.T) {
	simpleIPMatchTest(t, "fd00::1/8", "fd00:0:0:0:0:0:0:99", true)
}

// Test if an IP that is not contained in the remote IP list is not matched
func TestRemoteIPv6NoMatch(t *testing.T) {
	simpleIPMatchTest(t, "fd00::1", "fd00::2", false)
}

// Test if an IP file only containing a comment is handled correctly
func TestNoMatch(t *testing.T) {
	simpleIPMatchTest(t, "// this is a comment", "127.0.0.1", false)
}

// Test if a remote IP is matched (added to the file after first match call)
func TestRemoteIPMatchDynamic(t *testing.T) {
	tempDir, ipFile := createIPFile(t)
	defer cleanupIPFile(t, tempDir)

	appendToFile(t, ipFile, "127.0.0.80")

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	// Give some time to react to the context close
	defer wait()
	defer cancel()

	matcher := RemoteIPList{
		RemoteIPFile: ipFile,
	}

	err := matcher.Provision(ctx)
	assertNoError(t, err)

	// Give the file system watcher some time to set up
	wait()

	cx := &layer4.Connection{
		Conn: &dummyConn{
			remoteAddr: dummyAddr{ip: "127.0.0.99", network: "tcp"},
		},
		Logger: zap.NewNop(),
	}

	// IP should not match
	matched, err := matcher.Match(cx)
	assertNoError(t, err)

	if matched {
		t.Error("Matcher did match")
	}

	appendToFile(t, ipFile, "127.0.0.99")

	// Allow some time to register the file change
	wait()

	// IP should match now
	matched, err = matcher.Match(cx)
	assertNoError(t, err)

	if !matched {
		t.Error("Matcher did not match")
	}
}

// Test if the matcher still works of no remote IP file exists
func TestNoRemoteIPFile(t *testing.T) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "caddy-l4-remoteiplist-test")
	assertNoError(t, err)
	defer cleanupIPFile(t, tempDir)

	ipFile := filepath.Join(tempDir, "remote-ips")

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	// Give some time to react to the context close
	defer wait()
	defer cancel()

	matcher := RemoteIPList{
		RemoteIPFile: ipFile,
	}

	err = matcher.Provision(ctx)
	assertNoError(t, err)
	wait()

	cx := &layer4.Connection{
		Conn: &dummyConn{
			remoteAddr: dummyAddr{ip: "127.0.0.99", network: "tcp"},
		},
		Logger: zap.NewNop(),
	}

	matched, err := matcher.Match(cx)
	assertNoError(t, err)

	if matched {
		t.Error("Matcher did match, although no remote IP file existed")
	}

	if _, err := os.Stat(ipFile); err == nil {
		t.Error("IP file does exist")
	}
}

// Test if the monitoring terminates properly on cleanup
func TestCleanup(t *testing.T) {
	tempDir, ipFile := createIPFile(t)
	defer cleanupIPFile(t, tempDir)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	// Give some time to react to the context close
	defer wait()
	defer cancel()

	matcher := RemoteIPList{
		RemoteIPFile: ipFile,
	}

	err := matcher.Provision(ctx)
	assertNoError(t, err)
	wait()

	// Cleanup matcher directly after provision
	err = matcher.Cleanup()
	assertNoError(t, err)
	wait()

	// Expect monitoring to have stopped
	if matcher.remoteIPList.isRunning.Load() {
		t.Errorf("Matcher is running although it was stopped")
	}
}
