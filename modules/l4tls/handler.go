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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/big"

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
			if err := unmarshalCaddyfileConnectionPolicy(d.NewFromNextSegment(), cp); err != nil {
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

// Interface guards
var (
	_ caddy.Provisioner     = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ layer4.NextHandler    = (*Handler)(nil)
)

// TODO: move to https://github.com/caddyserver/caddy/tree/master/modules/caddytls/connpolicy.go
// unmarshalCaddyfileConnectionPolicy sets up the ConnectionPolicy from Caddyfile tokens. Syntax:
//
//	connection_policy {
//		alpn <values...>
//		cert_selection {
//			...
//		}
//		ciphers <cipher_suites...>
//		client_auth {
//			...
//		}
//		curves <curves...>
//		default_sni <server_name>
//		match {
//			...
//		}
//		protocols <min> [<max>]
//		# EXPERIMENTAL:
//		drop
//		fallback_sni <server_name>
//		insecure_secrets_log <log_file>
//	}
func unmarshalCaddyfileConnectionPolicy(d *caddyfile.Dispenser, cp *caddytls.ConnectionPolicy) error {
	_, wrapper := d.Next(), "tls "+d.Val()

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	var (
		hasCertSelection, hasClientAuth, hasDefaultSNI, hasDrop,
		hasFallbackSNI, hasInsecureSecretsLog, hasMatch, hasProtocols bool
	)
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "alpn":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			cp.ALPN = append(cp.ALPN, d.RemainingArgs()...)
		case "cert_selection":
			if hasCertSelection {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			p := &caddytls.CustomCertSelectionPolicy{}
			if err := unmarshalCaddyfileCertSelection(d.NewFromNextSegment(), p); err != nil {
				return err
			}
			cp.CertSelection, hasCertSelection = p, true
		case "client_auth":
			if hasClientAuth {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			ca := &caddytls.ClientAuthentication{}
			if err := ca.UnmarshalCaddyfile(d.NewFromNextSegment()); err != nil {
				return err
			}
			cp.ClientAuthentication, hasClientAuth = ca, true
		case "ciphers":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			cp.CipherSuites = append(cp.CipherSuites, d.RemainingArgs()...)
		case "curves":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			cp.Curves = append(cp.Curves, d.RemainingArgs()...)
		case "default_sni":
			if hasDefaultSNI {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, cp.DefaultSNI, hasDefaultSNI = d.NextArg(), d.Val(), true
		case "drop": // EXPERIMENTAL
			if hasDrop {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			cp.Drop, hasDrop = true, true
		case "fallback_sni": // EXPERIMENTAL
			if hasFallbackSNI {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, cp.FallbackSNI, hasFallbackSNI = d.NextArg(), d.Val(), true
		case "insecure_secrets_log": // EXPERIMENTAL
			if hasInsecureSecretsLog {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, cp.InsecureSecretsLog, hasInsecureSecretsLog = d.NextArg(), d.Val(), true
		case "match":
			if hasMatch {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			matcherSet, err := ParseCaddyfileNestedMatcherSet(d)
			if err != nil {
				return err
			}
			cp.MatchersRaw, hasMatch = matcherSet, true
		case "protocols":
			if hasProtocols {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() == 0 || d.CountRemainingArgs() > 2 {
				return d.ArgErr()
			}
			_, cp.ProtocolMin, hasProtocols = d.NextArg(), d.Val(), true
			if d.NextArg() {
				cp.ProtocolMax = d.Val()
			}
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

// TODO: move to https://github.com/caddyserver/caddy/tree/master/modules/caddytls/certselection.go
// unmarshalCaddyfileCertSelection sets up the CustomCertSelectionPolicy from Caddyfile tokens. Syntax:
//
//	cert_selection {
//		all_tags <values...>
//		any_tag <values...>
//		public_key_algorithm <dsa|ecdsa|rsa>
//		serial_number <big_integers...>
//		subject_organization <values...>
//	}
func unmarshalCaddyfileCertSelection(d *caddyfile.Dispenser, p *caddytls.CustomCertSelectionPolicy) error {
	_, wrapper := d.Next(), "tls connection_policy "+d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	var hasPublicKeyAlgorithm bool
	serialNumberStrings := make([]string, 0)
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "all_tags":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			p.AllTags = append(p.AllTags, d.RemainingArgs()...)
		case "any_tag":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			p.AnyTag = append(p.AnyTag, d.RemainingArgs()...)
		case "public_key_algorithm":
			if hasPublicKeyAlgorithm {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			d.NextArg()
			if err := p.PublicKeyAlgorithm.UnmarshalJSON([]byte(d.Val())); err != nil {
				return d.Errf("parsing %s option '%s': %v", wrapper, optionName, err)
			}
			hasPublicKeyAlgorithm = true
		case "serial_number":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			for d.NextArg() {
				val, bi := d.Val(), struct{ big.Int }{}
				_, ok := bi.SetString(val, 10)
				if !ok {
					return d.Errf("parsing %s option '%s': invalid big.int value %s", wrapper, optionName, val)
				}
				serialNumberStrings = append(serialNumberStrings, bi.String())
			}
		case "subject_organization":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			p.SubjectOrganization = append(p.SubjectOrganization, d.RemainingArgs()...)
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	// caddytls.bigInt struct is not exported. That's why we can't append directly to SerialNumber list above.
	// TODO: remove this workaround after the code is moved to caddyserver/caddy repo
	if len(serialNumberStrings) > 0 {
		serialNumbersRaw, err := json.Marshal(serialNumberStrings)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(serialNumbersRaw, &p.SerialNumber); err != nil {
			return err
		}
	}

	return nil
}
