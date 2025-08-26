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

package l4openvpn

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchOpenVPN{})
}

// MatchOpenVPN is able to match OpenVPN connections.
type MatchOpenVPN struct {
	// Modes contains a list of supported OpenVPN modes to match against incoming client reset messages:
	//
	//	- `plain` mode messages have no replay protection, authentication or encryption;
	//
	//	- `auth` mode messages have no encryption, but provide for replay protection and authentication
	//	with a pre-shared 2048-bit group key, a variable key direction, and plenty digest algorithms;
	//
	//	- 'crypt' mode messages feature replay protection, authentication and encryption with
	//	a pre-shared 2048-bit group key, a fixed key direction, and SHA-256 + AES-256-CTR algorithms;
	//
	//	- `crypt2` mode messages are essentially `crypt` messages with an individual 2048-bit client key
	//	used for authentication and encryption attached to client reset messages in a protected form
	//	(a 1024-bit server key is used for its authentication end encryption).
	//
	// Notes: Each mode shall only be present once in the list. Values in the list are case-insensitive.
	// If the list is empty, MatchOpenVPN will consider all modes as accepted and try them one by one.
	Modes []string `json:"modes,omitempty"`

	/*
	 *	Fields relevant to the auth, crypt and crypt2 modes:
	 */

	// IgnoreCrypto makes MatchOpenVPN skip decryption and authentication if set to true.
	//
	// Notes: IgnoreCrypto impacts the auth, crypt and crypt2 modes at once and makes sense only if/when
	// the relevant static keys are provided. If neither GroupKey nor GroupKeyFile is set, decryption
	// (if applicable) and authentication are automatically skipped in the auth and crypt modes only. If
	// neither ServerKey nor ServerKeyFile is provided, decryption and authentication are automatically
	// skipped in the crypt2 mode (unless there is a client key). If neither ClientKeys nor ClientKeyFiles
	// are provided, decryption and authentication are automatically skipped in the crypt2 mode (unless
	// there is a server key). In the crypt2 mode, when there is a client key and there is no server key,
	// decryption of a WrappedKey is impossible, and this part of the incoming message is authenticated by
	// comparing it with what has been included in the matching client key.
	IgnoreCrypto bool `json:"ignore_crypto,omitempty"`
	// IgnoreTimestamp makes MatchOpenVPN skip replay timestamps validation if set to true.
	//
	// Note: A 30-seconds time window is applicable by default, i.e. a timestamp of up to 15 seconds behind
	// or ahead of now is accepted.
	IgnoreTimestamp bool `json:"ignore_timestamp,omitempty"`

	/*
	 *	Fields relevant to the auth and crypt modes:
	 */

	// GroupKey contains a hex string representing a pre-shared 2048-bit group key. This key may be
	// present in OpenVPN config files inside `<tls-auth/>` or `<tls-crypt/>` blocks or generated with
	// `openvpn --genkey tls-auth|tls-crypt` command. No comments (starting with '#' or '-') are allowed.
	GroupKey string `json:"group_key,omitempty"`
	// GroupKeyFile is a path to a file containing a pre-shared 2048-bit group key which may be present
	// in OpenVPN config files after `tls-auth` or `tls-crypt` directives. It is the same key as the one
	// GroupKey introduces, so these fields are mutually exclusive. If both are set, GroupKey always takes
	// precedence. Any comments in the file (starting with '#' or '-') are ignored.
	GroupKeyFile string `json:"group_key_file,omitempty"`

	/*
	 *	Fields relevant to the auth mode only:
	 */

	// AuthDigest is a name of a digest algorithm used for authentication (HMAC generation and validation) of
	// the auth mode messages. If no value is provided, MatchOpenVPN will try all the algorithms it supports.
	//
	// Notes: OpenVPN binaries may support a larger number of digest algorithms thanks to the OpenSSL library
	// used under the hood. A few legacy and exotic digest algorithms are known to be missing, so IgnoreCrypto
	// may be set to true to ensure successful message matching if a desired digest algorithm isn't listed below.
	//
	// List of the supported digest algorithms:
	//	- MD5
	//	- SHA-1
	//	- SHA-224
	//	- SHA-256
	//	- SHA-384
	//	- SHA-512
	//	- SHA-512/224
	//	- SHA-512/256
	//	- SHA3-224
	//	- SHA3-256
	//	- SHA3-384
	//	- SHA3-512
	//	- BLAKE2s-256
	//	- BLAKE2b-512
	//	- SHAKE-128
	//	- SHAKE-256
	//
	// Note: Digest algorithm names are recognised in a number of popular notations, including lowercase.
	// Please, refer to the source code (AuthDigests variable in crypto.go) for details.
	AuthDigest string `json:"auth_digest,omitempty"`
	// GroupKeyDirection is a group key direction and may contain one of the following three values:
	//
	//	- `normal` means the server config has `tls-auth [...] 0` or `key-direction 0`,
	//	while the client configs have `tls-auth [...] 1` or `key-direction 1`;
	//
	//	- `inverse` means the server config has `tls-auth [...] 1` or `key-direction 1`,
	//	while the client config have `tls-auth [...] 0` or `key-direction 0`;
	//
	//	- `bidi` or `bidirectional` means key direction is omitted (e.g. `tls-auth [...]`)
	//	in both the server config and client configs.
	//
	// Notes: Values are case-insensitive. If no value is specified, the normal key direction is implied.
	// The inverse key direction is a violation of the OpenVPN official recommendations, and the bidi one
	// provides for a lower level of DoS and message replay attacks resilience.
	GroupKeyDirection string `json:"group_key_direction,omitempty"`

	/*
	 *	Fields relevant to the crypt2 mode only:
	 */

	// ClientKeys contains a list of base64 strings representing 2048-bit client keys (each one in a decrypted
	// form followed by an encrypted and authenticated form also known as WKc in the OpenVPN docs). These keys
	// may be present in OpenVPN client config files inside `<tls-crypt-v2/>` block or generated with `openvpn
	// --tls-crypt-v2 [server.key] --genkey tls-crypt-v2-client` command. No comments (starting with '#' or '-')
	// are allowed.
	ClientKeys []string `json:"client_keys,omitempty"`
	// ClientKeyFiles is a list of paths to files containing 2048-bit client key which may be present in OpenVPN
	// config files after `tls-crypt-v2` directive. These are the same keys as those ClientKeys introduce, but
	// these fields are complementary. If both are set, a joint list of client keys is created. Any comments in
	// the files (starting with '#' or '-') are ignored.
	ClientKeyFiles []string `json:"client_key_files,omitempty"`

	// ServerKey contains a base64 string representing a 1024-bit server key used only for authentication and
	// encryption of client keys. This key may be present in OpenVPN server config files inside `<tls-crypt-v2/>`
	// block or generated with `openvpn --genkey tls-crypt-v2-server` command. No comments (starting with '#'
	// or '-') are allowed.
	ServerKey string `json:"server_key,omitempty"`
	// ServerKeyFile is a path to a file containing a 1024-bit server key which may be present in OpenVPN
	// config files after `tls-crypt-v2` directive. It is the same key as the one ServerKey introduces, so
	// these fields are mutually exclusive. If both are set, ServerKey always takes precedence. Any comments
	// in the file (starting with '#' or '-') are ignored.
	ServerKeyFile string `json:"server_key_file,omitempty"`

	/*
	 *	Internal fields:
	 */

	acceptAuth   bool
	acceptCrypt  bool
	acceptCrypt2 bool
	acceptPlain  bool

	groupKeyAuth  *StaticKey
	groupKeyCrypt *StaticKey

	authDigest *AuthDigest
	lastDigest *AuthDigest

	clientKeys []*WrappedKey
	serverKey  *StaticKey
}

// CaddyModule returns the Caddy module information.
func (m *MatchOpenVPN) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.openvpn",
		New: func() caddy.Module { return new(MatchOpenVPN) },
	}
}

// Match returns true if the connection looks like OpenVPN.
func (m *MatchOpenVPN) Match(cx *layer4.Connection) (bool, error) {
	var err error
	var l, n int

	// Prepare a 3-byte buffer
	buf := make([]byte, LengthBytesTotal+OpcodeKeyIDBytesTotal)

	// Do TCP-specific reads and checks
	_, isTCP := cx.LocalAddr().(*net.TCPAddr)
	if isTCP {
		// Read 2 bytes containing the remaining bytes length
		_, err = io.ReadFull(cx, buf[:LengthBytesTotal])
		if err != nil {
			return false, err
		}

		// Validate the remaining bytes length
		l = int(binary.BigEndian.Uint16(buf[:LengthBytesTotal]))
		if l < MessagePlainBytesTotal || l > MessageCrypt2BytesMax {
			return false, nil
		}
	}

	// Read 1 byte containing MessageHeader
	_, err = io.ReadFull(cx, buf[LengthBytesTotal:])
	if err != nil {
		return false, err
	}

	// Parse MessageHeader
	hdr := &MessageHeader{}
	if err = hdr.FromBytes(buf[LengthBytesTotal:]); err != nil {
		return false, nil
	}

	// Validate MessageHeader.KeyID
	if hdr.KeyID > 0 {
		return false, nil
	}

	var mp *MessagePlain
	var ma *MessageAuth
	var mc *MessageCrypt
	var mr *MessageCrypt2

	if hdr.Opcode == OpcodeControlHardResetClientV2 && (m.acceptPlain || m.acceptAuth || m.acceptCrypt) {
		if isTCP {
			if l > MessageAuthBytesMax {
				return false, nil
			}

			buf = make([]byte, l-OpcodeKeyIDBytesTotal+1)
			n, err = io.ReadAtLeast(cx, buf, l-OpcodeKeyIDBytesTotal)
			if err != nil || n > l-OpcodeKeyIDBytesTotal {
				return false, err
			}
		} else {
			buf = make([]byte, MessageAuthBytesMaxHL+1)
			n, err = io.ReadAtLeast(cx, buf, 1)
			if err != nil || n < MessagePlainBytesTotalHL || n > MessageAuthBytesMaxHL {
				return false, err
			}
		}

		if m.acceptPlain {
			// Parse and validate MessagePlain
			mp = &MessagePlain{}
			err = mp.FromBytesHeadless(buf[:n], hdr)
			if err == nil && mp.Match() {
				return true, nil
			}
		}

		if m.acceptAuth {
			// Parse and validate MessageAuth
			ma = &MessageAuth{MessageTraitAuth: MessageTraitAuth{Digest: m.lastDigest}}
			err = ma.FromBytesHeadless(buf[:n], hdr)
			if err == nil && ma.Match(m.IgnoreTimestamp, m.IgnoreCrypto, m.authDigest, m.groupKeyAuth) {
				m.lastDigest = ma.Digest
				return true, nil
			}
		}

		if m.acceptCrypt {
			// Parse and validate MessageCrypt
			mc = &MessageCrypt{}
			err = mc.FromBytesHeadless(buf[:n], hdr)
			if err == nil && mc.Match(m.IgnoreTimestamp, m.IgnoreCrypto, nil, m.groupKeyCrypt) {
				return true, nil
			}
		}
	}

	if hdr.Opcode == OpcodeControlHardResetClientV3 && m.acceptCrypt2 {
		if isTCP {
			if l < MessageCrypt2BytesMin {
				return false, nil
			}

			buf = make([]byte, l-OpcodeKeyIDBytesTotal+1)
			n, err = io.ReadAtLeast(cx, buf, l-OpcodeKeyIDBytesTotal)
			if err != nil || n > l-OpcodeKeyIDBytesTotal {
				return false, err
			}
		} else {
			buf = make([]byte, MessageCrypt2BytesMaxHL+1)
			n, err = io.ReadAtLeast(cx, buf, 1)
			if err != nil || n < MessageCrypt2BytesMinHL || n > MessageCrypt2BytesMaxHL {
				return false, err
			}
		}

		// Parse and validate MessageCrypt2
		mr = &MessageCrypt2{}
		err = mr.FromBytesHeadless(buf[:n], hdr)
		if err == nil && mr.Match(m.IgnoreTimestamp, m.IgnoreCrypto, nil, m.serverKey, m.clientKeys) {
			return true, nil
		}
	}

	return false, nil
}

// Provision prepares m's internal structures.
func (m *MatchOpenVPN) Provision(_ caddy.Context) error {
	repl := caddy.NewReplacer()

	if len(m.Modes) > 0 {
		for _, mode := range m.Modes {
			mode = strings.ToLower(repl.ReplaceAll(mode, ""))
			switch mode {
			case ModeAuth:
				m.acceptAuth = true
			case ModeCrypt:
				m.acceptCrypt = true
			case ModeCrypt2:
				m.acceptCrypt2 = true
			case ModePlain:
				m.acceptPlain = true
			default:
				return ErrInvalidMode
			}
		}
	} else {
		m.acceptAuth, m.acceptCrypt, m.acceptCrypt2, m.acceptPlain = true, true, true, true
	}

	var gkdBidi, gkdInverse bool
	m.GroupKeyDirection = strings.ToLower(repl.ReplaceAll(m.GroupKeyDirection, ""))
	if len(m.GroupKeyDirection) > 0 {
		switch m.GroupKeyDirection {
		case GroupKeyDirectionBidi, GroupKeyDirectionBidi2:
			gkdBidi = true
		case GroupKeyDirectionInverse:
			gkdInverse = true
		case GroupKeyDirectionNormal:
			break
		default:
			return ErrInvalidGroupKeyDirection
		}
	}

	m.GroupKey = repl.ReplaceAll(m.GroupKey, "")
	if len(m.GroupKey) > 0 {
		sk := &StaticKey{}
		if err := sk.FromHex(m.GroupKey); err != nil {
			return err
		}
		if len(sk.KeyBytes) != StaticKeyBytesTotal {
			return ErrInvalidGroupKey
		}
		m.groupKeyAuth, m.groupKeyCrypt = &StaticKey{Bidi: gkdBidi, Inverse: gkdInverse, KeyBytes: sk.KeyBytes}, sk
	} else {
		m.GroupKeyFile = repl.ReplaceAll(m.GroupKeyFile, "")
		if len(m.GroupKeyFile) > 0 {
			sk := &StaticKey{}
			if err := sk.FromGroupKeyFile(m.GroupKeyFile); err != nil {
				return err
			}
			if len(sk.KeyBytes) != StaticKeyBytesTotal {
				return ErrInvalidGroupKey
			}
			m.groupKeyAuth, m.groupKeyCrypt = &StaticKey{Bidi: gkdBidi, Inverse: gkdInverse, KeyBytes: sk.KeyBytes}, sk
		}
	}

	m.AuthDigest = repl.ReplaceAll(m.AuthDigest, "")
	if len(m.AuthDigest) > 0 {
		m.authDigest = AuthDigestFindByName(m.AuthDigest)
		if m.authDigest == nil {
			return ErrInvalidAuthDigest
		}
	}

	m.ServerKey = repl.ReplaceAll(m.ServerKey, "")
	if len(m.ServerKey) > 0 {
		sk := &StaticKey{}
		if err := sk.FromBase64(m.ServerKey); err != nil {
			return err
		}
		if len(sk.KeyBytes) != StaticKeyBytesHalf {
			return ErrInvalidServerKey
		}
		m.serverKey = sk
	} else {
		m.ServerKeyFile = repl.ReplaceAll(m.ServerKeyFile, "")
		if len(m.ServerKeyFile) > 0 {
			sk := &StaticKey{}
			if err := sk.FromServerKeyFile(m.ServerKeyFile); err != nil {
				return err
			}
			if len(sk.KeyBytes) != StaticKeyBytesHalf {
				return ErrInvalidServerKey
			}
			m.serverKey = sk
		}
	}

	if len(m.ClientKeys) > 0 {
		for _, clientKey := range m.ClientKeys {
			clientKey = repl.ReplaceAll(clientKey, "")
			if len(clientKey) > 0 {
				ck := &WrappedKey{}
				if err := ck.FromBase64(clientKey); err != nil {
					return err
				}

				if len(ck.KeyBytes) != StaticKeyBytesTotal ||
					(m.serverKey != nil && !ck.DecryptAndAuthenticate(nil, m.serverKey)) {
					return ErrInvalidClientKey
				}

				m.clientKeys = append(m.clientKeys, ck)
			}
		}
	} else if len(m.ClientKeyFiles) > 0 {
		for _, clientKeyFile := range m.ClientKeyFiles {
			clientKeyFile = repl.ReplaceAll(clientKeyFile, "")
			if len(clientKeyFile) > 0 {
				ck := &WrappedKey{}
				if err := ck.FromClientKeyFile(clientKeyFile); err != nil {
					return err
				}

				if len(ck.KeyBytes) != StaticKeyBytesTotal ||
					(m.serverKey != nil && !ck.DecryptAndAuthenticate(nil, m.serverKey)) {
					return ErrInvalidClientKey
				}

				m.clientKeys = append(m.clientKeys, ck)
			}
		}
	}

	return nil
}

// UnmarshalCaddyfile sets up the MatchOpenVPN from Caddyfile tokens. Syntax:
//
//	openvpn {
//		modes <plain|auth|crypt|crypt2> [<...>]
//
//		ignore_crypto
//		ignore_timestamp
//
//		group_key <hex>
//		group_key_file <path>
//
//		auth_digest <digest>
//		group_key_direction <normal|inverse|bidi|bidirectional>
//
//		server_key <base64>
//		server_key_file <path>
//
//		client_key <base64>
//		client_key_file <path>
//	}
//	openvpn
//
// Note: multiple 'client_key' and 'client_key_file' options are allowed.
func (m *MatchOpenVPN) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line arguments are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	errDuplicate := func(optionName string) error {
		return d.Errf("duplicate %s option '%s'", wrapper, optionName)
	}

	errGroupKeyMutex := func() error {
		return d.Errf("%s options 'group_key' and `group_key_file` are mutually exclusive", wrapper)
	}

	errServerKeyMutex := func() error {
		return d.Errf("%s options 'server_key' and `server_key_file` are mutually exclusive", wrapper)
	}

	var hasAuthDigest, hasGroupKey, hasGroupKeyDirection, hasGroupKeyFile, hasIgnoreCrypto, hasIgnoreTimestamp,
		hasModes, hasServerKey, hasServerKeyFile bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "modes":
			if hasModes {
				return errDuplicate(optionName)
			}
			if d.CountRemainingArgs() == 0 || d.CountRemainingArgs() > 4 {
				return d.ArgErr()
			}
			m.Modes, hasModes = append(m.Modes, d.RemainingArgs()...), true
		case "ignore_crypto":
			if hasIgnoreCrypto {
				return errDuplicate(optionName)
			}
			if d.CountRemainingArgs() > 0 {
				return d.ArgErr()
			}
			m.IgnoreCrypto, hasIgnoreCrypto = true, true
		case "ignore_timestamp":
			if hasIgnoreTimestamp {
				return errDuplicate(optionName)
			}
			if d.CountRemainingArgs() > 0 {
				return d.ArgErr()
			}
			m.IgnoreTimestamp, hasIgnoreTimestamp = true, true
		case "group_key":
			if hasGroupKeyFile {
				return errGroupKeyMutex()
			}
			if hasGroupKey {
				return errDuplicate(optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, m.GroupKey, hasGroupKey = d.NextArg(), d.Val(), true
		case "group_key_file":
			if hasGroupKey {
				return errGroupKeyMutex()
			}
			if hasGroupKeyFile {
				return errDuplicate(optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, m.GroupKeyFile, hasGroupKeyFile = d.NextArg(), d.Val(), true
		case "auth_digest":
			if hasAuthDigest {
				return errDuplicate(optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, m.AuthDigest, hasAuthDigest = d.NextArg(), d.Val(), true
		case "group_key_direction":
			if hasGroupKeyDirection {
				return errDuplicate(optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, m.GroupKeyDirection, hasGroupKeyDirection = d.NextArg(), d.Val(), true
		case "server_key":
			if hasServerKeyFile {
				return errServerKeyMutex()
			}
			if hasServerKey {
				return errDuplicate(optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, m.ServerKey, hasServerKey = d.NextArg(), d.Val(), true
		case "server_key_file":
			if hasServerKey {
				return errServerKeyMutex()
			}
			if hasServerKeyFile {
				return errDuplicate(optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, m.ServerKeyFile, hasServerKeyFile = d.NextArg(), d.Val(), true
		case "client_key":
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			m.ClientKeys = append(m.ClientKeys, d.RemainingArgs()...)
		case "client_key_file":
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			m.ClientKeyFiles = append(m.ClientKeyFiles, d.RemainingArgs()...)
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': nested blocks are not supported", wrapper, optionName)
		}
	}

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchOpenVPN)(nil)
	_ caddyfile.Unmarshaler = (*MatchOpenVPN)(nil)
	_ layer4.ConnMatcher    = (*MatchOpenVPN)(nil)
)

var (
	ErrInvalidAuthDigest        = errors.New("invalid auth digest")
	ErrInvalidClientKey         = errors.New("invalid client key")
	ErrInvalidGroupKey          = errors.New("invalid group key")
	ErrInvalidGroupKeyDirection = errors.New("invalid group key direction")
	ErrInvalidMode              = errors.New("invalid mode")
	ErrInvalidServerKey         = errors.New("invalid server key")
)

const (
	GroupKeyDirectionBidi    = "bidi"
	GroupKeyDirectionBidi2   = "bidirectional"
	GroupKeyDirectionInverse = "inverse"
	GroupKeyDirectionNormal  = "normal"

	ModeAuth   = "auth"
	ModeCrypt  = "crypt"
	ModeCrypt2 = "crypt2"
	ModePlain  = "plain"
)
