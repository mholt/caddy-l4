package l4proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/mholt/caddy-l4/layer4"
)

// selfSignedServerConfig returns a TLS server config with a throwaway certificate.
func selfSignedServerConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// tlsDownstream is tcpDownstream with TLS terminated on the server end, the way
// the tls handler wraps the connection before it reaches the proxy handler.
func tlsDownstream(t *testing.T, h *Handler) (*net.TCPConn, *tls.Conn, *layer4.Connection) {
	t.Helper()
	raw, cx := tcpDownstream(t, h)
	down := cx.Wrap(tls.Server(cx, selfSignedServerConfig(t)))
	return raw, tls.Client(raw, &tls.Config{InsecureSkipVerify: true}), down //nolint:gosec // test certificate
}

// readFIN reports whether the peer shut down the writing side of conn (TCP FIN)
// within the given time.
func readFIN(conn net.Conn, within time.Duration) error {
	_ = conn.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	switch {
	case n > 0:
		return errors.New("unexpected data instead of a TCP FIN")
	case errors.Is(err, io.EOF):
		return nil
	case errors.Is(err, os.ErrDeadlineExceeded):
		return errors.New("no TCP FIN: the connection stays open for writing")
	default:
		return err
	}
}

// TestHandleSendsFINToTLSDownstream: when the upstream finishes, the downstream
// gets the same TCP FIN with TLS terminated by the proxy as it gets without
// TLS. A TLS close_notify alone is invisible to anything that only sees TCP,
// such as a layer 4 load balancer in front of the proxy, so without the FIN the
// connection stays open until the client decides to close it.
func TestHandleSendsFINToTLSDownstream(t *testing.T) {
	up := listenTCP(t)
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("hello"))
		_ = c.Close()
	}()

	h := newTestProxy(t, up.Addr().String())
	raw, client, down := tlsDownstream(t, h)

	done := make(chan error, 1)
	go func() { done <- h.Handle(down, nil) }()

	got, err := io.ReadAll(client)
	if err != nil || string(got) != "hello" {
		t.Fatalf("reading through TLS = %q, %v; want %q and close_notify", got, err, "hello")
	}
	if err := readFIN(raw, 2*time.Second); err != nil {
		t.Fatal(err)
	}

	_ = raw.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return after the downstream connection was closed")
	}
}

// TestHandleSendsFINToTLSUpstream: the same holds towards a TLS upstream when
// the downstream half-closes first.
func TestHandleSendsFINToTLSUpstream(t *testing.T) {
	up := listenTCP(t)
	upResult := make(chan error, 1)
	go func() {
		raw, err := up.Accept()
		if err != nil {
			upResult <- err
			return
		}
		defer raw.Close()
		got, err := io.ReadAll(tls.Server(raw, selfSignedServerConfig(t)))
		if err != nil || string(got) != "ping" {
			upResult <- errors.New("upstream did not read the request followed by close_notify")
			return
		}
		upResult <- readFIN(raw, 2*time.Second)
	}()

	h := newTestProxy(t, up.Addr().String())
	h.Upstreams[0].TLS = &reverseproxy.TLSConfig{}
	h.Upstreams[0].tlsConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test certificate

	client, down := tcpDownstream(t, h)
	done := make(chan error, 1)
	go func() { done <- h.Handle(down, nil) }()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("writing to downstream: %v", err)
	}
	_ = client.CloseWrite()

	select {
	case err := <-upResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not finish reading")
	}

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return after both sides were closed")
	}
}
