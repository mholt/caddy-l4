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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a connection handler that terminates TLS.
type Handler struct {
	ConnectionPolicies caddytls.ConnectionPolicies `json:"connection_policies,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.tls",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the module.
func (t *Handler) Provision(ctx caddy.Context) error {
	t.ctx = ctx
	t.logger = ctx.Logger(t)

	// ensure there is at least one policy, which will act as default
	if len(t.ConnectionPolicies) == 0 {
		t.ConnectionPolicies = append(t.ConnectionPolicies, new(caddytls.ConnectionPolicy))
	}

	err := t.ConnectionPolicies.Provision(ctx)
	if err != nil {
		return fmt.Errorf("setting up Handler connection policies: %v", err)
	}

	return nil
}

// Handle handles the connections.
func (t *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	// get the TLS config to use for this connection
	tlsCfg := t.ConnectionPolicies.TLSConfig(t.ctx)

	// capture the ClientHello info when the handshake is performed
	var clientHello ClientHelloInfo
	underlyingGetConfigForClient := tlsCfg.GetConfigForClient
	tlsCfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		clientHello.ClientHelloInfo = *hello
		return underlyingGetConfigForClient(hello)
	}

	// terminate TLS by performing the handshake (note that we pass
	// in cx, not cx.Conn; this is because we must read from the
	// connection to perform the handshake, and cx might have some
	// bytes already buffered need to be read first)
	tlsConn := tls.Server(cx, tlsCfg)
	err := tlsConn.Handshake()
	if err != nil {
		return err
	}
	t.logger.Debug("terminated TLS",
		zap.String("remote", cx.RemoteAddr().String()),
		zap.String("server_name", clientHello.ServerName),
	)

	// preserve this ClientHello info for later, if needed
	appendClientHello(cx, clientHello)

	// preserve the tls.ConnectionState for use in the http matcher
	connectionState := tlsConn.ConnectionState()
	appendConnectionState(cx, &connectionState)

	repl := cx.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)
	addTLSVarsToReplacer(repl, connectionState)

	// all future reads/writes will now be decrypted/encrypted
	// (tlsConn, which wraps cx, is wrapped into a new cx so
	// that future I/O succeeds... if we use the same cx, it'd
	// be wrapping itself, and we'd have nested read calls out
	// to the kernel, which creates a deadlock/hang; see #18)
	return next.Handle(cx.Wrap(tlsConn))
}

// FIXME: Should this perhaps be moved instead to caddytls?
func addTLSVarsToReplacer(repl *caddy.Replacer, cs tls.ConnectionState) {
	cert := getTLSPeerCert(cs)
	if cert == nil {
		return
	}
	repl.Map(func(key string) (interface{}, bool) {
		if !strings.HasPrefix(key, "l4.tls.") {
			return "", false
		}
		field := strings.ToLower(key[len("l4.tls."):])
		// subject alternate names (SANs)
		if strings.HasPrefix(field, "client.san.") {
			field = field[len("client.san."):]
			var fieldName string
			var fieldValue interface{}
			switch {
			case strings.HasPrefix(field, "dns_names"):
				fieldName = "dns_names"
				fieldValue = cert.DNSNames
			case strings.HasPrefix(field, "emails"):
				fieldName = "emails"
				fieldValue = cert.EmailAddresses
			case strings.HasPrefix(field, "ips"):
				fieldName = "ips"
				fieldValue = cert.IPAddresses
			case strings.HasPrefix(field, "uris"):
				fieldName = "uris"
				fieldValue = cert.URIs
			default:
				return nil, false
			}
			field = field[len(fieldName):]

			// if no index was specified, return the whole list
			if field == "" {
				return fieldValue, true
			}
			if len(field) < 2 || field[0] != '.' {
				return nil, false
			}
			field = field[1:] // trim '.' between field name and index

			// get the numeric index
			idx, err := strconv.Atoi(field)
			if err != nil || idx < 0 {
				return nil, false
			}

			// access the indexed element and return it
			switch v := fieldValue.(type) {
			case []string:
				if idx >= len(v) {
					return nil, true
				}
				return v[idx], true
			case []net.IP:
				if idx >= len(v) {
					return nil, true
				}
				return v[idx], true
			case []*url.URL:
				if idx >= len(v) {
					return nil, true
				}
				return v[idx], true
			}
		}
		// Break-out the client's Subject
		if strings.HasPrefix(field, "client.subject.") {
			field = field[len("client.subject."):]
			var fieldName string
			var fieldValue []string
			switch {
			case field == "common_name":
				// There can only be one.
				return cert.Subject.CommonName, true
			case strings.HasPrefix(field, "organizational_unit"):
				fieldName = "organizational_unit"
				fieldValue = cert.Subject.OrganizationalUnit
			case strings.HasPrefix(field, "organization"):
				fieldName = "organization"
				fieldValue = cert.Subject.Organization
			case strings.HasPrefix(field, "country"):
				fieldName = "country"
				fieldValue = cert.Subject.Country
			case strings.HasPrefix(field, "locality"):
				fieldName = "locality"
				fieldValue = cert.Subject.Locality
			case strings.HasPrefix(field, "province"):
				fieldName = "province"
				fieldValue = cert.Subject.Province
			default:
				return nil, false
			}
			field = field[len(fieldName):]

			// if no index was specified, return the whole list
			if field == "" {
				return fieldValue, true
			}
			if len(field) < 2 || field[0] != '.' {
				return nil, false
			}
			field = field[1:] // trim '.' between field name and index

			// get the numeric index
			idx, err := strconv.Atoi(field)
			if err != nil || idx < 0 {
				return nil, false
			}

			// access the indexed element and return it
			if idx >= len(fieldValue) {
				return nil, true
			}
			return fieldValue[idx], true
		}
		// Break-out the issuer's Subject
		if strings.HasPrefix(field, "client.issuer.") {
			field = field[len("client.issuer."):]
			var fieldName string
			var fieldValue []string
			switch {
			case field == "common_name":
				// There can only be one.
				return cert.Issuer.CommonName, true
			case strings.HasPrefix(field, "organizational_unit"):
				fieldName = "organizational_unit"
				fieldValue = cert.Issuer.OrganizationalUnit
			case strings.HasPrefix(field, "organization"):
				fieldName = "organization"
				fieldValue = cert.Issuer.Organization
			case strings.HasPrefix(field, "country"):
				fieldName = "country"
				fieldValue = cert.Issuer.Country
			case strings.HasPrefix(field, "locality"):
				fieldName = "locality"
				fieldValue = cert.Issuer.Locality
			case strings.HasPrefix(field, "province"):
				fieldName = "province"
				fieldValue = cert.Issuer.Province
			default:
				return nil, false
			}
			field = field[len(fieldName):]

			// if no index was specified, return the whole list
			if field == "" {
				return fieldValue, true
			}
			if len(field) < 2 || field[0] != '.' {
				return nil, false
			}
			field = field[1:] // trim '.' between field name and index

			// get the numeric index
			idx, err := strconv.Atoi(field)
			if err != nil || idx < 0 {
				return nil, false
			}

			// access the indexed element and return it
			if idx >= len(fieldValue) {
				return nil, true
			}
			return fieldValue[idx], true
		}
		// Remaining client mTLS fields
		switch field {
		case "client.fingerprint":
			return fmt.Sprintf("%x", sha256.Sum256(cert.Raw)), true
		case "client.public_key", "client.public_key_sha256":
			if cert.PublicKey == nil {
				return nil, true
			}
			pubKeyBytes, err := marshalPublicKey(cert.PublicKey)
			if err != nil {
				return nil, true
			}
			if strings.HasSuffix(field, "_sha256") {
				return fmt.Sprintf("%x", sha256.Sum256(pubKeyBytes)), true
			}
			return fmt.Sprintf("%x", pubKeyBytes), true
		case "client.issuer":
			return cert.Issuer, true
		case "client.serial":
			return cert.SerialNumber, true
		case "client.subject":
			return cert.Subject, true
		case "client.common_name":
			return cert.Subject.CommonName, true
		case "client.certificate_pem":
			block := pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
			return pem.EncodeToMemory(&block), true
		case "client.certificate_der_base64":
			return base64.StdEncoding.EncodeToString(cert.Raw), true
		default:
			return nil, false
		}
	})
}

func appendClientHello(cx *layer4.Connection, chi ClientHelloInfo) {
	var clientHellos []ClientHelloInfo
	if val := cx.GetVar("tls_client_hellos"); val != nil {
		clientHellos = val.([]ClientHelloInfo)
	}
	clientHellos = append(clientHellos, chi)
	cx.SetVar("tls_client_hellos", clientHellos)
}

// GetClientHelloInfos gets ClientHello information for all the terminated TLS connections.
func GetClientHelloInfos(cx *layer4.Connection) []ClientHelloInfo {
	var clientHellos []ClientHelloInfo
	if val := cx.GetVar("tls_client_hellos"); val != nil {
		clientHellos = val.([]ClientHelloInfo)
	}
	return clientHellos
}

func appendConnectionState(cx *layer4.Connection, cs *tls.ConnectionState) {
	var connectionStates []*tls.ConnectionState
	if val := cx.GetVar("tls_connection_states"); val != nil {
		connectionStates = val.([]*tls.ConnectionState)
	}
	connectionStates = append(connectionStates, cs)
	cx.SetVar("tls_connection_states", connectionStates)
}

// GetConnectionStates gets the tls.ConnectionState for all the terminated TLS connections.
func GetConnectionStates(cx *layer4.Connection) []*tls.ConnectionState {
	var connectionStates []*tls.ConnectionState
	if val := cx.GetVar("tls_connection_states"); val != nil {
		connectionStates = val.([]*tls.ConnectionState)
	}
	return connectionStates
}

// marshalPublicKey returns the byte encoding of pubKey.
func marshalPublicKey(pubKey interface{}) ([]byte, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return asn1.Marshal(key)
	case *ecdsa.PublicKey:
		return elliptic.Marshal(key.Curve, key.X, key.Y), nil
	case ed25519.PublicKey:
		return key, nil
	}
	return nil, fmt.Errorf("unrecognized public key type: %T", pubKey)
}

// getTLSPeerCert retrieves the first peer certificate from a TLS session.
// Returns nil if no peer cert is in use.
func getTLSPeerCert(cs tls.ConnectionState) *x509.Certificate {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	return cs.PeerCertificates[0]
}

// Interface guards
var (
	_ caddy.Provisioner  = (*Handler)(nil)
	_ layer4.NextHandler = (*Handler)(nil)
)
