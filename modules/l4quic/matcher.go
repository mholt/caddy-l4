// Copyright 2024 VNXME
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

package l4quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/quic-go/quic-go"

	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4tls"
)

func init() {
	caddy.RegisterModule(&MatchQUIC{})
}

// MatchQUIC is able to match QUIC connections. Its structure
// is different from the auto-generated documentation. This
// value should be a map of matcher names to their values.
type MatchQUIC struct {
	MatchersRaw caddy.ModuleMap `json:"-" caddy:"namespace=tls.handshake_match"`

	matchers []caddytls.ConnectionMatcher
	quicConf *quic.Config
	tlsConf  *tls.Config
}

// CaddyModule returns the Caddy module information.
func (m *MatchQUIC) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.quic",
		New: func() caddy.Module { return new(MatchQUIC) },
	}
}

// Match returns true if the connection looks like QUIC.
func (m *MatchQUIC) Match(cx *layer4.Connection) (bool, error) {
	// Check if the protocol is UDP
	if _, isUDP := cx.LocalAddr().(*net.UDPAddr); !isUDP {
		return false, nil
	}

	// Read one byte
	n := 1
	buf := make([]byte, n)
	_, err := io.ReadAtLeast(cx, buf, n)
	if err != nil {
		return false, err
	}

	// Ensure the second bit of the first byte is set, i.e. continue if
	// github.com/quic-go/quic-go/internal/wire.IsPotentialQUICPacket(buf[0]).
	qFirstByte := buf[0]
	if qFirstByte&QUICMagicBitValue == 0 {
		return false, nil
	}

	// Ensure the first bit of the first byte is set, i.e. continue if
	// github.com/quic-go/quic-go/internal/wire.IsLongHeaderPacket(buf[0]).
	// Note: this behaviour may be changed in the future if there are packets
	// that should be considered valid despite having the first bit unset.
	if qFirstByte&QUICLongHeaderBitValue == 0 {
		return false, nil
	}

	// Read the remaining bytes
	buf = make([]byte, QUICPacketBytesMax+1)
	buf[0] = qFirstByte
	n, err = io.ReadAtLeast(cx, buf[1:], 1)
	if err != nil || n < QUICPacketBytesMin-1 || n == QUICPacketBytesMax {
		return false, err
	}

	// Use a workaround to match ALPNs. This way quic.EarlyListener.Accept() exits on deadline
	// if it receives a packet having an ALPN other than those present in tls.Config.NextProtos.
	repl := cx.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)
	tlsConf := &tls.Config{Certificates: m.tlsConf.Certificates, MinVersion: tls.VersionTLS13}
	for _, matcher := range m.matchers {
		if alpnMatcher, ok := matcher.(*l4tls.MatchALPN); ok {
			for _, alpnValue := range *alpnMatcher {
				alpnValue = repl.ReplaceAll(alpnValue, "")
				if len(alpnValue) > 0 {
					tlsConf.NextProtos = append(tlsConf.NextProtos, alpnValue)
				}
			}
		}
	}

	// Create a new fakePacketConn pipe
	serverFPC, clientFPC := newFakePacketConnPipe(&fakePipeAddr{ID: newRand(), TS: time.Now()}, nil)
	defer func() { _ = serverFPC.Close() }()
	defer func() { _ = clientFPC.Close() }()

	// Create a new quic.Transport
	qTransport := quic.Transport{
		Conn: serverFPC,
	}

	// Launch a new quic.EarlyListener
	var qListener *quic.EarlyListener
	qListener, err = qTransport.ListenEarly(tlsConf, m.quicConf)
	if err != nil {
		return false, err
	}

	// Write the buffered bytes into the pipe
	_, err = clientFPC.WriteTo(buf[:n+1], nil)
	if err != nil {
		return false, nil
	}

	// Prepare a context with a deadline
	qContext, qCancel := context.WithDeadline(context.Background(), time.Now().Add(QUICAcceptTimeout))
	defer qCancel()

	// Accept a new quic.EarlyConnection
	var qConn *quic.Conn
	qConn, err = qListener.Accept(qContext)
	if err != nil {
		return false, nil
	}
	defer func() { _ = qListener.Close() }()

	// Obtain a quic.ConnectionState
	qState := qConn.ConnectionState()

	// Add values to the replacer
	repl.Set("l4.quic.tls.server_name", qState.TLS.ServerName)
	repl.Set("l4.quic.tls.version", qState.TLS.Version)
	repl.Set("l4.quic.version", qState.Version.String())

	// Fill a tls.ClientHelloInfo structure
	chi := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{qState.TLS.CipherSuite},
		ServerName:        qState.TLS.ServerName,
		SupportedCurves:   nil,
		SupportedPoints:   nil,
		SignatureSchemes:  nil,
		SupportedProtos:   []string{qState.TLS.NegotiatedProtocol}, // Empty if no ALPNs are provided
		SupportedVersions: []uint16{tls.VersionTLS13},              // Presumed to always be TLS 1.3
		Conn:              cx,
	}

	// Check TLS matchers if any
	for _, matcher := range m.matchers {
		// ALPN matching is implicitly done above when the QUIC listener is initialised,
		// as quic.EarlyConnection.ConnectionState().TLS.NegotiatedProtocol is only filled
		// when the client's ALPN matches one of the values set in tls.Config.NextProtos.
		if _, isMatchALPN := matcher.(*l4tls.MatchALPN); isMatchALPN {
			continue
		}

		// TODO: even though we have more data than the standard lib's
		// ClientHelloInfo lets us fill, the matcher modules we use do
		// not accept our own type; but the advantage of this is that
		// we can reuse TLS connection matchers from the tls app - but
		// it would be nice if we found a way to give matchers all
		// the information
		if !matcher.Match(chi) {
			return false, nil
		}
	}

	return true, nil
}

// Provision prepares m's internal structures.
func (m *MatchQUIC) Provision(ctx caddy.Context) error {
	// Load TLS matchers
	mods, err := ctx.LoadModule(m, "MatchersRaw")
	if err != nil {
		return fmt.Errorf("loading TLS matchers: %v", err)
	}
	for _, modAny := range mods.(map[string]any) {
		m.matchers = append(m.matchers, modAny.(caddytls.ConnectionMatcher))
	}

	// Generate a new private key
	var key *ecdsa.PrivateKey
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating a private key: %v", err)
	}

	// Compose a new x509 certificate template
	template := &x509.Certificate{
		SerialNumber: newRand(),
		Subject: pkix.Name{
			CommonName:   QUICCertificateCommonName,
			Organization: []string{QUICCertificateOrganization},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(QUICCertificateValidityPeriod),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{QUICCertificateSubjectAltName},
	}

	// Create a new x509 certificate
	var cert []byte
	cert, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("generating a x509 ceriticate: %v", err)
	}

	// Initialize a new TLS config
	m.tlsConf = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	}

	// Initialize a new QUIC config
	m.quicConf = &quic.Config{}

	return nil
}

// UnmarshalCaddyfile sets up the MatchQUIC from Caddyfile tokens. Syntax:
//
//	quic {
//		<matcher> [<args...>]
//		<matcher> [<args...>]
//	}
//	quic <matcher> [<args...>]
//	quic
func (m *MatchQUIC) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	matcherSet, err := l4tls.ParseCaddyfileNestedMatcherSet(d)
	if err != nil {
		return err
	}
	m.MatchersRaw = matcherSet

	return nil
}

// UnmarshalJSON satisfies the json.Unmarshaler interface.
func (m *MatchQUIC) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &m.MatchersRaw)
}

// MarshalJSON satisfies the json.Marshaler interface.
func (m *MatchQUIC) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.MatchersRaw)
}

// fakePipeAddr satisfies net.Addr and uses a random number and a timestamp
// to avoid panic in quic.connMultiplexer.AddConn() due to the same local address.
type fakePipeAddr struct {
	ID *big.Int
	TS time.Time
}

func (fpa fakePipeAddr) Network() string {
	return "pipe"
}

func (fpa fakePipeAddr) String() string {
	return fmt.Sprintf("fake_%v_%v", fpa.ID.String(), fpa.TS.UnixNano())
}

// fakePacketConn wraps around net.Conn and satisfies net.PacketConn.
type fakePacketConn struct {
	net.Conn

	Local  net.Addr
	Remote net.Addr
}

func (fpc *fakePacketConn) LocalAddr() net.Addr {
	if fpc.Local != nil {
		return fpc.Local
	}
	return fpc.Conn.LocalAddr()
}

func (fpc *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := fpc.Read(p)
	return n, fpc.RemoteAddr(), err
}

func (fpc *fakePacketConn) RemoteAddr() net.Addr {
	if fpc.Remote != nil {
		return fpc.Remote
	}
	return fpc.Conn.RemoteAddr()
}

func (fpc *fakePacketConn) SetReadBuffer(_ int) error {
	return nil
}

func (fpc *fakePacketConn) SetWriteBuffer(_ int) error {
	return nil
}

func (fpc *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return fpc.Write(p)
}

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchQUIC)(nil)
	_ caddyfile.Unmarshaler = (*MatchQUIC)(nil)
	_ layer4.ConnMatcher    = (*MatchQUIC)(nil)

	_ net.Addr = (*fakePipeAddr)(nil)

	_ net.PacketConn                         = (*fakePacketConn)(nil)
	_ interface{ SetReadBuffer(int) error }  = (*fakePacketConn)(nil)
	_ interface{ SetWriteBuffer(int) error } = (*fakePacketConn)(nil)
)

const (
	QUICAcceptTimeout = 100 * time.Millisecond

	QUICCertificateCommonName     = "layer4"
	QUICCertificateOrganization   = "caddy"
	QUICCertificateSubjectAltName = "*"
	QUICCertificateValidityPeriod = time.Hour * 24 * 365 * 20

	QUICLongHeaderBitValue uint8 = 0x80 // github.com/quic-go/quic-go/internal/wire.IsLongHeaderPacket()
	QUICMagicBitValue      uint8 = 0x40 // github.com/quic-go/quic-go/internal/wire.IsPotentialQUICPacket()

	QUICPacketBytesMax = 1452 // github.com/quic-go/quic-go/internal/protocol.MaxPacketBufferSize
	QUICPacketBytesMin = 1200 // github.com/quic-go/quic-go/internal/protocol.MinInitialPacketSize
)

func newFakePacketConnPipe(local, remote net.Addr) (*fakePacketConn, *fakePacketConn) {
	server, client := net.Pipe()
	serverFPC, clientFPC := &fakePacketConn{Conn: server}, &fakePacketConn{Conn: client}
	if local != nil || remote != nil {
		if local == nil {
			local = remote
		}
		if remote == nil {
			remote = local
		}
		serverFPC.Local, clientFPC.Remote = local, local
		serverFPC.Remote, clientFPC.Local = remote, remote
	}
	return serverFPC, clientFPC
}

func newRand() *big.Int {
	rnd, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	return rnd
}
