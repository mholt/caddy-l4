// Copyright 2026 Ingolf Gehrhardt
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

package l4audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/mholt/caddy-l4/layer4"
)

const recordTypeHandshake = 0x16

var (
	_ net.Conn = &dummyConn{}
	_ net.Addr = dummyAddr{}
)

type dummyAddr struct {
	network string
	address string
}

// Network implements net.Addr.
func (a dummyAddr) Network() string { return a.network }

// String implements net.Addr.
func (a dummyAddr) String() string { return a.address }

// dummyConn is a net.Conn with fixed addresses. The embedded net.Conn
// is nil: the handler and the test's next handler only ever read from
// the prefetched buffer.
type dummyConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

// Close implements net.Conn.
func (c *dummyConn) Close() error { return nil }

// LocalAddr implements net.Conn.
func (c *dummyConn) LocalAddr() net.Addr { return c.localAddr }

// RemoteAddr implements net.Conn.
func (c *dummyConn) RemoteAddr() net.Addr { return c.remoteAddr }

// SetDeadline implements net.Conn.
func (c *dummyConn) SetDeadline(time.Time) error { return nil }

// SetReadDeadline implements net.Conn.
func (c *dummyConn) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline implements net.Conn.
func (c *dummyConn) SetWriteDeadline(time.Time) error { return nil }

func testConnection(buf []byte) *layer4.Connection {
	return layer4.WrapConnection(&dummyConn{
		localAddr:  dummyAddr{network: "tcp", address: "127.0.0.1:443"},
		remoteAddr: dummyAddr{network: "tcp", address: "127.0.0.1:55000"},
	}, buf, zap.NewNop())
}

// generateClientHello returns the raw bytes of the TLS ClientHello
// record a real crypto/tls client sends for the given server name
// (an empty server name means: no SNI extension).
func generateClientHello(t *testing.T, serverName string) []byte {
	t.Helper()

	in, out := net.Pipe()
	defer func() { _ = in.Close() }()
	defer func() { _ = out.Close() }()

	client := tls.Client(in, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	handshake := make(chan error, 1)
	go func() { handshake <- client.Handshake() }()

	// read the record header and the record body the client wrote
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(out, hdr); err != nil {
		t.Fatalf("reading ClientHello record header: %v", err)
	}
	if hdr[0] != recordTypeHandshake {
		t.Fatalf("record type is %#x, want %#x (handshake)", hdr[0], recordTypeHandshake)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(out, body); err != nil {
		t.Fatalf("reading ClientHello record body: %v", err)
	}

	// unblock the client, which is waiting for a ServerHello
	_ = out.Close()
	<-handshake

	return append(hdr, body...)
}

func TestUnmarshalCaddyfile(t *testing.T) {
	for i, tc := range []struct {
		input       string
		wantVerdict string
		wantErr     string
	}{
		{input: "audit denied", wantVerdict: "denied"},
		{input: "audit allowed", wantVerdict: "allowed"},
		{input: "audit", wantErr: "expected exactly one argument"},
		{input: "audit a b", wantErr: "wrong argument count"},
		{input: "audit {\n	something\n}", wantErr: "blocks are not supported"},
		{input: "audit denied {\n	something\n}", wantErr: "blocks are not supported"},
		{input: "audit denied {\n}", wantVerdict: "denied"}, // empty block is tolerated, like `echo { }`
	} {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			h := new(Handler)
			err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("input %q: expected error containing %q, got nil", tc.input, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("input %q: expected error containing %q, got %q", tc.input, tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("input %q: UnmarshalCaddyfile: %v", tc.input, err)
			}
			if h.Verdict != tc.wantVerdict {
				t.Fatalf("input %q: Verdict is %q, want %q", tc.input, h.Verdict, tc.wantVerdict)
			}
		})
	}
}

func TestExtractSNI(t *testing.T) {
	hello := generateClientHello(t, "example.com")
	helloNoSNI := generateClientHello(t, "")

	for i, tc := range []struct {
		name   string
		buf    []byte
		want   string
		wantOK bool
	}{
		{
			name:   "ClientHello with SNI",
			buf:    hello,
			want:   "example.com",
			wantOK: true,
		},
		{
			name:   "ClientHello without SNI",
			buf:    helloNoSNI,
			want:   "",
			wantOK: true,
		},
		{
			name:   "non-TLS data",
			buf:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantOK: false,
		},
		{
			name:   "truncated record header",
			buf:    hello[:3],
			wantOK: false,
		},
		{
			name:   "truncated record body",
			buf:    hello[:10],
			wantOK: false,
		},
		{
			name:   "empty buffer",
			buf:    nil,
			wantOK: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sni, ok := extractSNI(tc.buf)
			if ok != tc.wantOK || sni != tc.want {
				t.Errorf("test %d: extractSNI() = (%q, %t), want (%q, %t)", i, sni, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestHandle(t *testing.T) {
	hello := generateClientHello(t, "allowed.example.com")
	helloNoSNI := generateClientHello(t, "")

	for i, tc := range []struct {
		name      string
		buf       []byte
		wantSNI   string
		wantDebug bool
	}{
		{
			name:    "TLS with SNI",
			buf:     hello,
			wantSNI: "allowed.example.com",
		},
		{
			name: "TLS without SNI",
			buf:  helloNoSNI,
		},
		{
			name:      "non-TLS data",
			buf:       []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantDebug: true,
		},
		{
			name:      "no buffered bytes",
			wantDebug: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			h := &Handler{
				Verdict: "denied",
				logger:  zap.New(core).Named("layer4.handlers.audit"),
			}
			cx := testConnection(tc.buf)

			nextCalled := false
			var got []byte
			err := h.Handle(cx, layer4.HandlerFunc(func(nextCx *layer4.Connection) error {
				nextCalled = true
				// the handler must not consume the buffered bytes
				got = make([]byte, len(tc.buf))
				_, err := io.ReadFull(nextCx, got)
				return err
			}))
			if err != nil {
				t.Fatalf("test %d: Handle: %v", i, err)
			}
			if !nextCalled {
				t.Fatal("handler did not call next")
			}
			if !bytes.Equal(got, tc.buf) {
				t.Fatalf("test %d: next handler got %d bytes, want the original %d bytes", i, len(got), len(tc.buf))
			}

			// exactly one audit record must be emitted, at INFO level
			entries := logs.FilterMessage("audit").All()
			if len(entries) != 1 {
				t.Fatalf("test %d: got %d audit records, want 1", i, len(entries))
			}
			entry := entries[0]
			if entry.Level != zapcore.InfoLevel {
				t.Errorf("test %d: audit record level is %s, want INFO", i, entry.Level)
			}
			if entry.LoggerName != "layer4.handlers.audit" {
				t.Errorf("test %d: audit record logger name is %q, want %q", i, entry.LoggerName, "layer4.handlers.audit")
			}

			want := map[string]any{
				"verdict": "denied",
				"network": "tcp",
				"local":   "127.0.0.1:443",
				"remote":  "127.0.0.1:55000",
			}
			if tc.wantSNI != "" {
				want["sni"] = tc.wantSNI
			}
			gotFields := entry.ContextMap()
			if len(gotFields) != len(want) {
				t.Fatalf("test %d: audit record has fields %v, want %v", i, gotFields, want)
			}
			for k, v := range want {
				if gotFields[k] != v {
					t.Errorf("test %d: audit record field %q is %v, want %v", i, k, gotFields[k], v)
				}
			}

			// a debug line explains why the sni field is missing
			debugs := logs.FilterMessage("no TLS ClientHello found in prefetched bytes").All()
			if (len(debugs) == 1) != tc.wantDebug {
				t.Errorf("test %d: got %d debug lines, wantDebug=%t", i, len(debugs), tc.wantDebug)
			}
		})
	}
}

func TestHandleWithoutLogger(t *testing.T) {
	// Handle must not panic if Provision was not called
	h := &Handler{Verdict: "denied"}
	cx := testConnection(generateClientHello(t, "example.com"))

	nextCalled := false
	err := h.Handle(cx, layer4.HandlerFunc(func(*layer4.Connection) error {
		nextCalled = true
		return nil
	}))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !nextCalled {
		t.Fatal("handler did not call next")
	}
}

func TestProvision(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	h := new(Handler)
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if h.logger == nil {
		t.Fatal("Provision did not set the logger")
	}
}
