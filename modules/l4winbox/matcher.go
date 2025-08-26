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

package l4winbox

import (
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchWinbox{})
}

// MatchWinbox matches any connections that look like those initiated by Winbox, a graphical tool developed
// by SIA Mikrotīkls, Latvia for their hardware and software routers management. As of v3.41 and v4.0 the tool
// used an undocumented proprietary protocol. This matcher is based on a number of recent studies describing
// RouterOS architecture and vulnerabilities, especially the ones published by Margin Research.
type MatchWinbox struct {
	// Modes contains a list of supported Winbox modes to match against incoming auth messages:.
	//
	//	- `standard` mode is a default one (it used to be called 'secure' mode in previous versions of Winbox);
	//
	//	- `romon` mode makes the destination router act as an agent so that its neighbour routers
	//	in isolated L2 segments could be reachable by the clients behind the agent.
	//
	// Notes: Each mode shall only be present once in the list. Values in the list are case-insensitive.
	// If the list is empty, MatchWinbox will consider all modes as acceptable.
	Modes []string `json:"modes,omitempty"`
	// Username is a plaintext username value to search for in the incoming connections. In Winbox it is what
	// the user types into the login field. According to the docs, it must start and end with an alphanumeric
	// character, but it can also include "_", ".", "#", "-", and "@" symbols. No maximum username length is
	// specified in the docs, so this matcher applies a reasonable limit of no more than 255 characters. If
	// Username contains at least one character, UsernameRegexp is ignored. If Username contains placeholders,
	// they are evaluated at match.
	Username string `json:"username,omitempty"`
	// UsernameRegexp is a username pattern to match the incoming connections against. This matcher verifies
	// that any username matches MessageAuthUsernameRegexp, so UsernameRegexp must not provide a wider pattern.
	// UsernameRegexp is only checked when Username is empty. If UsernameRegexp contains any placeholders, they
	// are evaluated at provision.
	UsernameRegexp string `json:"username_regexp,omitempty"`

	acceptStandard bool
	acceptRoMON    bool
	usernameRegexp *regexp.Regexp
}

// CaddyModule returns the Caddy module information.
func (m *MatchWinbox) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.winbox",
		New: func() caddy.Module { return new(MatchWinbox) },
	}
}

// Match returns true if the connection bytes match the regular expression.
func (m *MatchWinbox) Match(cx *layer4.Connection) (bool, error) {
	// Read a minimum number of bytes
	n := 2
	hdr := make([]byte, n)
	_, err := io.ReadFull(cx, hdr)
	if err != nil || hdr[0] < MessageAuthBytesMin-2 || hdr[1] != MessageChunkTypeAuth {
		return false, err
	}

	// Only allocate a larger buffer when the first chunk is full
	l := int(hdr[0])
	if l == MessageChunkBytesMax {
		l = MessageAuthBytesMax - 2
	}

	// Read the remaining bytes
	buf := make([]byte, 2+l+1)
	copy(buf[:2], hdr[:2])
	n, err = io.ReadAtLeast(cx, buf[2:], int(hdr[0]))
	if err != nil || n > l {
		return false, err
	}

	// Parse MessageAuth
	msg := &MessageAuth{}
	if err = msg.FromBytes(buf[:n+2]); err != nil {
		return false, nil
	}

	// Check the acceptable modes
	if msg.GetRoMON() {
		if !m.acceptRoMON {
			return false, nil
		}
	} else {
		if !m.acceptStandard {
			return false, nil
		}
	}

	// Replace placeholders in filters
	repl := cx.Context.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	userName := repl.ReplaceAll(m.Username, "")

	// Check a plaintext username, if provided
	if len(userName) > 0 && userName != msg.GetUsername() {
		return false, nil
	}

	// Check a username regexp, if provided
	if len(userName) == 0 && len(m.UsernameRegexp) > 0 && !m.usernameRegexp.MatchString(msg.GetUsername()) {
		return false, nil
	}

	// Add a username to the replacer
	repl.Set("l4.winbox.username", msg.GetUsername())

	return true, nil
}

// Provision prepares m's internal structures.
func (m *MatchWinbox) Provision(_ caddy.Context) (err error) {
	repl := caddy.NewReplacer()
	m.usernameRegexp, err = regexp.Compile(repl.ReplaceAll(m.UsernameRegexp, ""))
	if err != nil {
		return err
	}

	if len(m.Modes) > 0 {
		for _, mode := range m.Modes {
			mode = strings.ToLower(repl.ReplaceAll(mode, ""))
			switch mode {
			case ModeStandard:
				m.acceptStandard = true
			case ModeRoMON:
				m.acceptRoMON = true
			default:
				return ErrInvalidMode
			}
		}
	} else {
		m.acceptStandard, m.acceptRoMON = true, true
	}

	return nil
}

// UnmarshalCaddyfile sets up the MatchWinbox from Caddyfile tokens. Syntax:
//
//	winbox {
//		modes <standard|romon> [<...>]
//		username <value>
//		username_regexp <pattern>
//	}
//	winbox
//
// Note: username and username_regexp options are mutually exclusive.
func (m *MatchWinbox) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line argument are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	var hasModes, hasUsername bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "modes":
			if hasModes {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() == 0 || d.CountRemainingArgs() > 2 {
				return d.ArgErr()
			}
			m.Modes, hasModes = append(m.Modes, d.RemainingArgs()...), true
		case "username":
			if hasUsername {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, val := d.NextArg(), d.Val()
			m.Username, hasUsername = val, true
		case "username_regexp":
			if hasUsername {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, val := d.NextArg(), d.Val()
			m.UsernameRegexp, hasUsername = val, true
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

// MessageAuth is the first message the client sends to the server. It contains a plaintext username,
// an optional '+r' string concatenated to the username to request the RoMON mode, and a public key.
type MessageAuth struct {
	PublicKeyParity uint8
	PublicKeyBytes  []byte
	Username        string
}

// MessageChunk is a part of a bigger message. It may contain no more than 255 bytes.
type MessageChunk struct {
	Bytes  []byte
	Length uint8
	Type   uint8
}

func (msg *MessageAuth) DisableRoMON() {
	if msg.GetRoMON() {
		msg.Username = msg.Username[:len(msg.Username)-len(MessageAuthUsernameRoMONSuffix)]
	}
}

func (msg *MessageAuth) EnableRoMON() {
	if !msg.GetRoMON() {
		msg.Username = msg.Username + MessageAuthUsernameRoMONSuffix
	}
}

func (msg *MessageAuth) FromBytes(src []byte) error {
	l := len(src)
	if l < MessageAuthBytesMin {
		return ErrNotEnoughSourceBytes
	}

	var p int
	q := l/(MessageChunkBytesMax+2) + 1
	chunks := make([]*MessageChunk, 0, q)
	var chunk *MessageChunk
	for i := range q {
		chunk = &MessageChunk{}
		p = i * (MessageChunkBytesMax + 2)

		chunk.Length = src[p]
		if (q > 1 && i < q-1 && int(chunk.Length) != MessageChunkBytesMax) ||
			(l < p+2+int(chunk.Length)) || int(chunk.Length) < MessageChunkBytesMin {
			return ErrIncorrectSourceBytes
		}

		chunk.Type = src[p+1]
		if (i == 0 && chunk.Type != MessageChunkTypeAuth) || (i > 0 && chunk.Type != MessageChunkTypePrev) {
			return ErrIncorrectSourceBytes
		}

		chunk.Bytes = src[p+2 : p+2+int(chunk.Length)]
		chunks = append(chunks, chunk)
	}

	return msg.FromChunks(chunks)
}

func (msg *MessageAuth) FromChunks(chunks []*MessageChunk) error {
	l := 0
	for _, chunk := range chunks {
		switch chunk.Type {
		case MessageChunkTypeAuth, MessageChunkTypePrev:
			l += int(chunk.Length)
		default:
			return ErrIncorrectSourceBytes
		}
	}

	src := make([]byte, 0, l)
	for _, chunk := range chunks {
		src = append(src, chunk.Bytes[:min(int(chunk.Length), len(chunk.Bytes))]...)
	}

	var foundDelimiter bool
	for i, b := range src {
		if b == MessageChunkBytesDelimiter {
			msg.Username = string(src[:i])
			msg.PublicKeyBytes = src[i+1 : len(src)-1]
			msg.PublicKeyParity = src[len(src)-1]
			foundDelimiter = true
			break
		}
	}

	if !foundDelimiter || len(msg.Username) == 0 || len(msg.PublicKeyBytes) != MessageAuthPublicKeyBytesTotal ||
		msg.PublicKeyParity > 1 || !MessageAuthUsernameRegexp.MatchString(msg.GetUsername()) {
		return ErrIncorrectSourceBytes
	}
	return nil
}

func (msg *MessageAuth) GetPublicKey() ([]byte, uint8) {
	return msg.PublicKeyBytes, msg.PublicKeyParity
}

func (msg *MessageAuth) GetRoMON() bool {
	return strings.HasSuffix(msg.Username, MessageAuthUsernameRoMONSuffix)
}

func (msg *MessageAuth) GetUsername() string {
	if msg.GetRoMON() {
		return msg.Username[:len(msg.Username)-len(MessageAuthUsernameRoMONSuffix)]
	}
	return msg.Username
}

func (msg *MessageAuth) ToChunks() []*MessageChunk {
	l := len(msg.PublicKeyBytes) + len(msg.Username) + 2
	dst := make([]byte, 0, l)
	dst = append(dst, msg.Username...)
	dst = append(dst, MessageChunkBytesDelimiter)
	dst = append(dst, msg.PublicKeyBytes...)
	dst = append(dst, msg.PublicKeyParity)

	var p int
	q := l/MessageChunkBytesMax + 1
	chunks := make([]*MessageChunk, 0, q)
	var chunk *MessageChunk
	var ll int
	for i := range q {
		p = i * MessageChunkBytesMax
		ll = min(MessageChunkBytesMax, l-p)
		if ll == 0 {
			break
		}

		chunk = &MessageChunk{}
		chunk.Length = uint8(ll) //nolint:gosec // disable G115
		if i == 0 {
			chunk.Type = MessageChunkTypeAuth
		} else {
			chunk.Type = MessageChunkTypePrev
		}
		chunk.Bytes = dst[p : p+ll]
		chunks = append(chunks, chunk)
	}

	return chunks
}

func (msg *MessageAuth) ToBytes() []byte {
	chunks := msg.ToChunks()

	l := 0
	for _, chunk := range chunks {
		l += 2 + int(chunk.Length)
	}

	dst := make([]byte, 0, l)
	for _, chunk := range chunks {
		dst = append(dst, chunk.Length)
		dst = append(dst, chunk.Type)
		dst = append(dst, chunk.Bytes...)
	}

	return dst
}

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchWinbox)(nil)
	_ caddyfile.Unmarshaler = (*MatchWinbox)(nil)
	_ layer4.ConnMatcher    = (*MatchWinbox)(nil)
)

var (
	ErrInvalidMode          = errors.New("invalid mode")
	ErrIncorrectSourceBytes = errors.New("incorrect source bytes")
	ErrNotEnoughSourceBytes = errors.New("not enough source bytes")

	MessageAuthUsernameRegexp = regexp.MustCompile("^[0-9A-Za-z](?:[-#.0-9@A-Z_a-z]+[0-9A-Za-z])?$")
)

const (
	MessageAuthBytesMax            = 4 + MessageAuthUsernameBytesMax + 1 + MessageAuthPublicKeyBytesTotal + 1
	MessageAuthBytesMin            = 2 + MessageAuthUsernameBytesMin + 1 + MessageAuthPublicKeyBytesTotal + 1
	MessageAuthPublicKeyBytesTotal = 32
	MessageAuthUsernameBytesMax    = 255 // Assume nobody sets usernames longer than 255 characters
	MessageAuthUsernameBytesMin    = 1
	MessageAuthUsernameRoMONSuffix = "+r"
	MessageChunkBytesMin           = 1
	MessageChunkBytesMax           = 255

	MessageChunkBytesDelimiter uint8 = 0x00
	MessageChunkTypeAuth       uint8 = 0x06
	MessageChunkTypePrev       uint8 = 0xFF

	ModeStandard = "standard"
	ModeRoMON    = "romon"
)

// References:
//	https://help.mikrotik.com/docs/display/ROS/WinBox
//	https://help.mikrotik.com/docs/display/ROS/User
//	https://margin.re/2022/02/mikrotik-authentication-revealed/
//	https://margin.re/2022/06/pulling-mikrotik-into-the-limelight/
//	https://github.com/MarginResearch/FOISted
//	https://github.com/MarginResearch/mikrotik_authentication
//	https://github.com/MarginResearch/resources/blob/83e402a86370f7c3acf8bb3ad982c1fee89c9b53/documents/Pulling_MikroTik_into_the_Limelight.pdf
//	https://romhack.io/wp-content/uploads/sites/3/2023/09/RomHack-2023-Ting-Yu-Chen-NiN-9-Years-of-Overlooked-MikroTik-Pre-Auth-RCE.pdf
//	https://github.com/Cisco-Talos/Winbox_Protocol_Dissector
