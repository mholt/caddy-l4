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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&Handler{})
}

// Handler is a connection handler that terminates TLS.
type Handler struct {
	ConnectionPolicies caddytls.ConnectionPolicies `json:"connection_policies,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
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

	// add values to the replacer
	repl := cx.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)
	addTLSVarsToReplacer(repl, &connectionState)

	// all future reads/writes will now be decrypted/encrypted
	// (tlsConn, which wraps cx, is wrapped into a new cx so
	// that future I/O succeeds... if we use the same cx, it'd
	// be wrapping itself, and we'd have nested read calls out
	// to the kernel, which creates a deadlock/hang; see #18)
	return next.Handle(cx.Wrap(tlsConn))
}

// UnmarshalCaddyfile sets up the Handler from Caddyfile tokens. Syntax:
//
//	tls {
//		connection_policy {
//			...
//		}
//		connection_policy {
//			...
//		}
//	}
//	tls
func (t *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "connection_policy":
			cp := &caddytls.ConnectionPolicy{}
			if err := cp.UnmarshalCaddyfile(d.NewFromNextSegment()); err != nil {
				return err
			}
			t.ConnectionPolicies = append(t.ConnectionPolicies, cp)
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	return nil
}

// addTLSVarsToReplacer is an enhanced copy of caddyhttp.getReqTLSReplacement
func addTLSVarsToReplacer(repl *caddy.Replacer, cs *tls.ConnectionState) {
	if repl == nil || cs == nil {
		return
	}

	repl.Map(func(key string) (any, bool) {
		if !strings.HasPrefix(key, TLSReplPrefix) {
			return nil, false
		}

		field := strings.ToLower(key[len(TLSReplPrefix):])

		if strings.HasPrefix(field, "client.") {
			cert := getTLSPeerCert(cs)
			if cert == nil {
				return nil, false
			}

			field = field[len("client."):]

			// subject alternate names (SANs)
			if strings.HasPrefix(field, "san.") {
				field = field[len("san."):]

				var fieldName string
				var fieldValue any
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

			// subject and issuer
			for _, group := range []struct {
				prefix string
				values *pkix.Name
			}{
				{prefix: "subject.", values: &cert.Subject},
				{prefix: "issuer.", values: &cert.Issuer},
			} {
				if strings.HasPrefix(field, group.prefix) {
					field = field[len(group.prefix):]

					var fieldName string
					var fieldValue []string
					switch {
					case field == "common_name":
						// There can only be one.
						return group.values.CommonName, true
					case field == "serial":
						// There can only be one.
						return group.values.SerialNumber, true
					case strings.HasPrefix(field, "organizational_unit"):
						fieldName = "organizational_unit"
						fieldValue = group.values.OrganizationalUnit
					case strings.HasPrefix(field, "organization"):
						fieldName = "organization"
						fieldValue = group.values.Organization
					case strings.HasPrefix(field, "country"):
						fieldName = "country"
						fieldValue = group.values.Country
					case strings.HasPrefix(field, "locality"):
						fieldName = "locality"
						fieldValue = group.values.Locality
					case strings.HasPrefix(field, "province"):
						fieldName = "province"
						fieldValue = group.values.Province
					case strings.HasPrefix(field, "street_address"):
						fieldName = "street_address"
						fieldValue = group.values.StreetAddress
					case strings.HasPrefix(field, "postal_code"):
						fieldName = "postal_code"
						fieldValue = group.values.PostalCode
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
			}

			// remaining fields
			switch field {
			case "fingerprint":
				return fmt.Sprintf("%x", sha256.Sum256(cert.Raw)), true
			case "public_key", "public_key_sha256":
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
			case "issuer":
				return cert.Issuer, true
			case "serial":
				return cert.SerialNumber, true
			case "subject":
				return cert.Subject, true
			case "certificate_pem":
				block := pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
				return pem.EncodeToMemory(&block), true
			case "certificate_der_base64":
				return base64.StdEncoding.EncodeToString(cert.Raw), true
			default:
				return nil, false
			}
		}

		switch field {
		case "version":
			return caddytls.ProtocolName(cs.Version), true
		case "cipher_suite":
			return tls.CipherSuiteName(cs.CipherSuite), true
		case "resumed":
			return cs.DidResume, true
		case "proto":
			return cs.NegotiatedProtocol, true
		case "proto_mutual":
			// cs.NegotiatedProtocolIsMutual is deprecated - it's always true.
			return true, true
		case "server_name":
			return cs.ServerName, true
		case "ech":
			return cs.ECHAccepted, true
		}
		return nil, false
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
func marshalPublicKey(pubKey any) ([]byte, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return asn1.Marshal(key)
	case *ecdsa.PublicKey:
		e, err := key.ECDH()
		if err != nil {
			return nil, err
		}
		return e.Bytes(), nil
	case ed25519.PublicKey:
		return key, nil
	}
	return nil, fmt.Errorf("unrecognized public key type: %T", pubKey)
}

// getTLSPeerCert retrieves the first peer certificate from a TLS session.
// Returns nil if no peer cert is in use.
func getTLSPeerCert(cs *tls.ConnectionState) *x509.Certificate {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	return cs.PeerCertificates[0]
}

const TLSReplPrefix = layer4.AppReplPrefix + "tls."

// Interface guards
var (
	_ caddy.Provisioner     = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ layer4.NextHandler    = (*Handler)(nil)
)
