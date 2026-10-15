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

package l4tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
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

// newTestHandler returns a TLS handler serving a self-signed certificate,
// without the TLS app that Provision needs, and the given handshake timeout.
func newTestHandler(t *testing.T, handshakeTimeout time.Duration) *Handler {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	return &Handler{
		ConnectionPolicies: caddytls.ConnectionPolicies{{TLSConfig: cfg}},
		HandshakeTimeout:   caddy.Duration(handshakeTimeout),
		ctx:                caddy.Context{Context: context.Background()},
		logger:             zap.NewNop(),
	}
}

// tcpDownstream connects a real TCP client to a server end wrapped in a
// layer4.Connection, so deadlines behave like they do in production.
func tcpDownstream(t *testing.T) (net.Conn, *layer4.Connection) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialing downstream: %v", err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accepting downstream: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, layer4.WrapConnection(server, nil, zap.NewNop())
}

// handleAsync runs Handle in the background and returns its result channel.
func handleAsync(h *Handler, cx *layer4.Connection, next layer4.Handler) <-chan error {
	done := make(chan error, 1)
	go func() { done <- h.Handle(cx, next) }()
	return done
}

func waitHandle(t *testing.T, done <-chan error, d time.Duration) (error, bool) {
	t.Helper()
	select {
	case err := <-done:
		return err, true
	case <-time.After(d):
		return nil, false
	}
}

// stallAfterFirstWrite lets the first write (the ClientHello) through and
// blocks every later one, like a client that stops in the middle of the
// handshake.
type stallAfterFirstWrite struct {
	net.Conn
	wrote bool
	stop  chan struct{}
}

func (c *stallAfterFirstWrite) Write(b []byte) (int, error) {
	if c.wrote {
		<-c.stop
		return 0, io.ErrClosedPipe
	}
	c.wrote = true
	return c.Conn.Write(b)
}

func TestHandshakeTimeoutStalledClients(t *testing.T) {
	const timeout = 300 * time.Millisecond

	for name, client := range map[string]func(t *testing.T, c net.Conn){
		// connects and sends nothing
		"no ClientHello": func(t *testing.T, c net.Conn) {},
		// sends the header of a handshake record, but not the record itself
		"partial ClientHello": func(t *testing.T, c net.Conn) {
			if _, err := c.Write([]byte{0x16, 0x03, 0x01, 0x02, 0x00}); err != nil {
				t.Errorf("writing partial ClientHello: %v", err)
			}
		},
		// sends a complete ClientHello and never finishes the handshake
		"stall after ClientHello": func(t *testing.T, c net.Conn) {
			stalled := &stallAfterFirstWrite{Conn: c, stop: make(chan struct{})}
			t.Cleanup(func() { close(stalled.stop) })
			go func() {
				_ = tls.Client(stalled, &tls.Config{InsecureSkipVerify: true}).Handshake()
			}()
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHandler(t, timeout)
			c, cx := tcpDownstream(t)
			client(t, c)

			start := time.Now()
			done := handleAsync(h, cx, layer4.HandlerFunc(func(*layer4.Connection) error {
				t.Error("next handler called without a completed handshake")
				return nil
			}))
			err, returned := waitHandle(t, done, 5*time.Second)
			if !returned {
				t.Fatal("Handle kept waiting for a handshake past handshake_timeout")
			}
			if err == nil {
				t.Fatal("Handle returned no error for a handshake that did not complete")
			}
			if elapsed := time.Since(start); elapsed < timeout {
				t.Fatalf("Handle returned after %v, before handshake_timeout (%v)", elapsed, timeout)
			}
		})
	}
}

// TestHandshakeTimeoutClearedAfterHandshake: the timeout only applies to the
// handshake; once it completes, the connection may stay quiet for longer.
func TestHandshakeTimeoutClearedAfterHandshake(t *testing.T) {
	const timeout = 200 * time.Millisecond
	h := newTestHandler(t, timeout)
	c, cx := tcpDownstream(t)

	tlsClient := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
	clientErr := make(chan error, 1)
	go func() {
		if err := tlsClient.Handshake(); err != nil {
			clientErr <- err
			return
		}
		time.Sleep(3 * timeout)
		_, err := tlsClient.Write([]byte("hello"))
		clientErr <- err
	}()

	done := handleAsync(h, cx, layer4.HandlerFunc(func(cx *layer4.Connection) error {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(cx, buf); err != nil {
			return err
		}
		if string(buf) != "hello" {
			t.Errorf("read %q after the handshake; want %q", buf, "hello")
		}
		return nil
	}))
	err, returned := waitHandle(t, done, 5*time.Second)
	if !returned {
		t.Fatal("Handle did not return")
	}
	if err != nil {
		t.Fatalf("reading after a quiet period longer than handshake_timeout: %v", err)
	}
	if err := <-clientErr; err != nil {
		t.Fatalf("client: %v", err)
	}
}

// TestProvisionDefaultsHandshakeTimeout: without a handshake timeout, Provision
// sets the default one, so a client that never finishes the handshake is not
// kept forever.
func TestProvisionDefaultsHandshakeTimeout(t *testing.T) {
	// Provision needs the TLS app, which needs a running config
	cfg := `{"admin": {"disabled": true, "config": {"persist": false}},` +
		`"storage": {"module": "file_system", "root": ` + strconv.Quote(t.TempDir()) + `},` +
		`"apps": {"tls": {}}}`
	if err := caddy.Load([]byte(cfg), false); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	h := &Handler{}
	if err := h.Provision(caddy.ActiveContext()); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	if time.Duration(h.HandshakeTimeout) != HandshakeTimeoutDefault {
		t.Fatalf("handshake_timeout = %v; want %v", time.Duration(h.HandshakeTimeout), HandshakeTimeoutDefault)
	}
}

func TestProvisionRejectsNegativeHandshakeTimeout(t *testing.T) {
	h := &Handler{HandshakeTimeout: caddy.Duration(-time.Second)}
	err := h.Provision(caddy.Context{})
	if err == nil || !strings.Contains(err.Error(), "handshake_timeout") {
		t.Fatalf("expected a handshake_timeout error, got %v", err)
	}
}

func TestUnmarshalCaddyfileHandshakeTimeout(t *testing.T) {
	h := &Handler{}
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser("tls {\n\thandshake_timeout 5s\n}")); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if time.Duration(h.HandshakeTimeout) != 5*time.Second {
		t.Fatalf("handshake_timeout = %v; want 5s", time.Duration(h.HandshakeTimeout))
	}

	for name, input := range map[string]string{
		"duplicate handshake_timeout": "tls {\n\thandshake_timeout 1s\n\thandshake_timeout 2s\n}",
		"bad handshake_timeout":       "tls {\n\thandshake_timeout nope\n}",
		"missing handshake_timeout":   "tls {\n\thandshake_timeout\n}",
	} {
		t.Run(name, func(t *testing.T) {
			err := (&Handler{}).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
			if err == nil {
				t.Fatalf("expected an error for %q", input)
			}
		})
	}
}
