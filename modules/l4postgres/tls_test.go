// Copyright 2024 Matthew Holt
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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSClientReoriginatesSSL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srvCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		// read the SSLRequest, reply 'S', then complete the TLS handshake
		buf := make([]byte, minMessageLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			srvErr <- err
			return
		}
		if binary.BigEndian.Uint32(buf[lenFieldSize:]) != sslRequestCode {
			srvErr <- err
			return
		}
		if _, err := conn.Write([]byte{'S'}); err != nil {
			srvErr <- err
			return
		}
		tlsConn := tls.Server(conn, srvCfg)
		if err := tlsConn.Handshake(); err != nil {
			srvErr <- err
			return
		}
		// echo one line to prove the encrypted channel works
		b := make([]byte, 4)
		_, _ = io.ReadFull(tlsConn, b)
		_, _ = tlsConn.Write(b)
		srvErr <- nil
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tlsConn, err := TLSClient(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	if err != nil {
		t.Fatalf("TLSClient: %v", err)
	}
	if _, err := tlsConn.Write([]byte("ping")); err != nil {
		t.Fatalf("write over TLS: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(tlsConn, got); err != nil {
		t.Fatalf("read over TLS: %v", err)
	}
	if string(got) != "ping" {
		t.Errorf("echo = %q, want ping", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

func TestTLSClientHandlesRefusal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, minMessageLen)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte{'N'}) // decline SSL
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := TLSClient(conn, &tls.Config{InsecureSkipVerify: true}); err == nil { //nolint:gosec // test
		t.Fatal("expected an error when the upstream replies 'N'")
	}
}

func sslRequest() []byte {
	b := make([]byte, minMessageLen)
	binary.BigEndian.PutUint32(b[:lenFieldSize], minMessageLen)
	binary.BigEndian.PutUint32(b[lenFieldSize:], sslRequestCode)
	return b
}

func TestPostgresTLSRepliesSAndContinues(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	cx := layer4.WrapConnection(server, []byte{}, zap.NewNop())

	nextCalled := make(chan struct{}, 1)
	errc := make(chan error, 1)
	go func() {
		h := &Handler{}
		errc <- h.Handle(cx, layer4.HandlerFunc(func(*layer4.Connection) error {
			nextCalled <- struct{}{}
			return nil
		}))
	}()

	// client sends SSLRequest, then must receive a single 'S'
	if _, err := client.Write(sslRequest()); err != nil {
		t.Fatalf("writing SSLRequest: %v", err)
	}
	reply := make([]byte, 1)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("reading reply: %v", err)
	}
	if reply[0] != 'S' {
		t.Fatalf("reply = %q, want 'S'", reply[0])
	}

	select {
	case <-nextCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("next handler was not called")
	}
	if err := <-errc; err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
}

func TestPostgresTLSRejectsNonSSLRequest(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	cx := layer4.WrapConnection(server, []byte{}, zap.NewNop())

	// a plaintext v3 startup message code (196608), not an SSLRequest
	msg := make([]byte, minMessageLen)
	binary.BigEndian.PutUint32(msg[:lenFieldSize], minMessageLen)
	binary.BigEndian.PutUint32(msg[lenFieldSize:], 196608)
	go func() { _, _ = client.Write(msg) }()

	h := &Handler{}
	err := h.Handle(cx, layer4.HandlerFunc(func(*layer4.Connection) error {
		t.Error("next handler must not be called for a non-SSLRequest")
		return nil
	}))
	if err == nil {
		t.Fatal("expected an error for a non-SSLRequest message")
	}
}

// dummyAddr satisfies net.Addr for the fake connection.
type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "test" }

// fakeConn is a net.Conn whose Read serves prepared bytes and whose Read/Write
// can be made to fail, for exercising error branches deterministically.
type fakeConn struct {
	r        *bytes.Reader
	readErr  error
	writeErr error
}

func (c *fakeConn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.r.Read(p)
}

func (c *fakeConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func wrapFake(c net.Conn) *layer4.Connection {
	return layer4.WrapConnection(c, []byte{}, zap.NewNop())
}

func TestPostgresTLSHandlerReadError(t *testing.T) {
	cx := wrapFake(&fakeConn{readErr: errors.New("boom")})
	err := (&Handler{}).Handle(cx, layer4.HandlerFunc(func(*layer4.Connection) error { return nil }))
	if err == nil {
		t.Fatal("expected an error when the SSLRequest cannot be read")
	}
}

func TestPostgresTLSHandlerWriteError(t *testing.T) {
	cx := wrapFake(&fakeConn{r: bytes.NewReader(sslRequest()), writeErr: errors.New("boom")})
	err := (&Handler{}).Handle(cx, layer4.HandlerFunc(func(*layer4.Connection) error {
		t.Error("next must not be called when replying 'S' fails")
		return nil
	}))
	if err == nil {
		t.Fatal("expected an error when the 'S' reply cannot be written")
	}
}

func TestTLSClientWriteError(t *testing.T) {
	if _, err := TLSClient(&fakeConn{writeErr: errors.New("boom")}, &tls.Config{}); err == nil {
		t.Fatal("expected an error when SSLRequest cannot be sent")
	}
}

func TestTLSClientReplyReadError(t *testing.T) {
	// write succeeds, but there is no reply to read
	if _, err := TLSClient(&fakeConn{r: bytes.NewReader(nil)}, &tls.Config{}); err == nil {
		t.Fatal("expected an error when the reply cannot be read")
	}
}

func TestTLSClientUnexpectedReply(t *testing.T) {
	if _, err := TLSClient(&fakeConn{r: bytes.NewReader([]byte{'X'})}, &tls.Config{}); err == nil {
		t.Fatal("expected an error for an unexpected reply byte")
	}
}

func TestTLSClientHandshakeError(t *testing.T) {
	// 'S' then non-TLS garbage so the client handshake fails
	conn := &fakeConn{r: bytes.NewReader([]byte{'S', 0xff, 0xff, 0xff, 0xff, 0xff})}
	if _, err := TLSClient(conn, &tls.Config{InsecureSkipVerify: true}); err == nil { //nolint:gosec // test
		t.Fatal("expected a TLS handshake error")
	}
}

func TestPostgresTLSHandlerUnmarshalCaddyfile(t *testing.T) {
	if err := (&Handler{}).UnmarshalCaddyfile(caddyfile.NewTestDispenser("postgres_tls")); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := (&Handler{}).UnmarshalCaddyfile(caddyfile.NewTestDispenser("postgres_tls extra")); err == nil {
		t.Fatal("expected an error for an unexpected argument")
	}
	if err := (&Handler{}).UnmarshalCaddyfile(caddyfile.NewTestDispenser("postgres_tls {\n\tfoo\n}")); err == nil {
		t.Fatal("expected an error for an unsupported block")
	}
}
