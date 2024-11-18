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
	"path"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
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

// Create a temporary directory and a remote IP file
func createIpFile(t *testing.T) (string, string) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "caddy-l4-remoteiplist-test")
	assertNoError(t, err)

	remoteIpFile := path.Join(tempDir, "remote-ips")
	return tempDir, remoteIpFile
}

// Cleanup the temporary directory and the remote IP file
func cleanupIpFile(t *testing.T, tempDir string) {
	t.Helper()
	err := os.RemoveAll(tempDir)
	assertNoError(t, err)
}

func wait() {
	time.Sleep(10 * time.Millisecond)
}

// Test if the remote IP file gets created if it is not exiting
func TestRemoteIpFileCreation(t *testing.T) {
	tempDir, ipFile := createIpFile(t)
	defer cleanupIpFile(t, tempDir)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	// Give some time to react to the context close
	defer wait()
	defer cancel()

	matcher := RemoteIpList{
		RemoteIpFile: ipFile,
	}

	err := matcher.Provision(ctx)
	assertNoError(t, err)

	st, err := os.Lstat(ipFile)
	if err != nil || st.IsDir() {
		t.Error("File did not get created")
	}
}

// Test if a remote IPv4 address is matched
func TestRemoteIpv4Match(t *testing.T) {
	tempDir, ipFile := createIpFile(t)
	defer cleanupIpFile(t, tempDir)

	os.WriteFile(ipFile, []byte("127.0.0.99\n"), 0644)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	// Give some time to react to the context close
	defer wait()
	defer cancel()

	matcher := RemoteIpList{
		RemoteIpFile: ipFile,
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
		t.Error("Matcher did not match")
	}
}

// Test if a remote IPv6 address is matched
func TestRemoteIpv6Match(t *testing.T) {
	tempDir, ipFile := createIpFile(t)
	defer cleanupIpFile(t, tempDir)

	os.WriteFile(ipFile, []byte("fd00::1\n"), 0644)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	// Give some time to react to the context close
	defer wait()
	defer cancel()

	matcher := RemoteIpList{
		RemoteIpFile: ipFile,
	}

	err := matcher.Provision(ctx)
	assertNoError(t, err)

	cx := &layer4.Connection{
		Conn: &dummyConn{
			remoteAddr: dummyAddr{ip: "fd00:0:0:0:0:0:0:1", network: "tcp"},
		},
		Logger: zap.NewNop(),
	}

	matched, err := matcher.Match(cx)
	assertNoError(t, err)

	if !matched {
		t.Error("Matcher did not match")
	}
}

// Test if a remote IP is matched (added to the file after first match call)
func TestRemoteIpMatchDynamic(t *testing.T) {
	tempDir, ipFile := createIpFile(t)
	defer cleanupIpFile(t, tempDir)

	os.WriteFile(ipFile, []byte("127.0.0.80\n"), 0644)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	// Give some time to react to the context close
	defer wait()
	defer cancel()

	matcher := RemoteIpList{
		RemoteIpFile: ipFile,
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

	// Append new IP to end of file
	f, err := os.OpenFile(ipFile, os.O_APPEND|os.O_WRONLY, 0644)
	assertNoError(t, err)
	_, err = f.WriteString("127.0.0.99\n")
	assertNoError(t, err)
	f.Close()

	// Allow some time to register the file change
	wait()

	// IP should match now
	matched, err = matcher.Match(cx)
	assertNoError(t, err)

	if !matched {
		t.Error("Matcher did not match")
	}
}

// Test if an IP that is not contained in the remote IP list is not matched
func TestRemoteIpNoMatch(t *testing.T) {
	tempDir, ipFile := createIpFile(t)
	defer cleanupIpFile(t, tempDir)

	os.WriteFile(ipFile, []byte("127.0.0.1\n"), 0644)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	// Give some time to react to the context close
	defer wait()
	defer cancel()

	matcher := RemoteIpList{
		RemoteIpFile: ipFile,
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
