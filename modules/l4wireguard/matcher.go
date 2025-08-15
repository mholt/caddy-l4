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

package l4wireguard

import (
	"bytes"
	"encoding/binary"
	"io"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchWireGuard{})
}

// MatchWireGuard is able to match WireGuard connections.
type MatchWireGuard struct {
	// Zero may be used to match reserved zero bytes of Type field when
	// they have non-zero values (e.g. for obfuscation purposes). E.g. it
	// may be set to 4,285,988,864 (0xFF770000) in order to match custom
	// handshake initiation messages starting with 0x010077FF byte sequence.
	// Note: any non-zero value is a violation of the WireGuard protocol.
	Zero uint32 `json:"zero,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (m *MatchWireGuard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.wireguard",
		New: func() caddy.Module { return new(MatchWireGuard) },
	}
}

// Match returns true if the connection looks like WireGuard.
func (m *MatchWireGuard) Match(cx *layer4.Connection) (bool, error) {
	// Read a number of bytes
	buf := make([]byte, MessageInitiationBytesTotal+1)
	n, err := io.ReadAtLeast(cx, buf, 1)
	if err != nil {
		return false, err
	}

	switch n {
	case MessageInitiationBytesTotal: // This is a handshake initiation message
		// Parse MessageInitiation
		msg := &MessageInitiation{}
		if err = msg.FromBytes(buf[:MessageInitiationBytesTotal]); err != nil {
			return false, nil
		}

		// Validate MessageInitiation
		if msg.Type != (m.Zero&ReservedZeroFilter)|MessageTypeInitiation {
			return false, nil
		}
	case MessageTransportBytesMin: // This is a keepalive message (with empty content)
		// Parse MessageTransport
		msg := &MessageTransport{}
		if err = msg.FromBytes(buf[:MessageTransportBytesMin]); err != nil {
			return false, nil
		}

		// Validate MessageTransport
		if msg.Type != (m.Zero&ReservedZeroFilter)|MessageTypeTransport {
			return false, nil
		}
	default: // This is anything else, can also be a valid non-empty transport message
		return false, nil
	}

	return true, nil
}

// Provision prepares m's internal structures.
func (m *MatchWireGuard) Provision(_ caddy.Context) error {
	return nil
}

// UnmarshalCaddyfile sets up the MatchWireGuard from Caddyfile tokens. Syntax:
//
//	wireguard [<zero>]
func (m *MatchWireGuard) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Only one same-line argument is supported
	if d.CountRemainingArgs() > 1 {
		return d.ArgErr()
	}

	if d.NextArg() {
		val, err := strconv.ParseUint(d.Val(), 10, 32)
		if err != nil {
			return d.Errf("parsing %s zero: %v", wrapper, err)
		}
		m.Zero = uint32(val)
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed %s option: blocks are not supported", wrapper)
	}

	return nil
}

// MessageInitiation is the first message
// which the initiator sends to the responder.
type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral [32]uint8
	Static    [32 + Poly1305TagSize]uint8
	Timestamp [12 + Poly1305TagSize]uint8
	MAC1      [16]uint8
	MAC2      [16]uint8
}

func (msg *MessageInitiation) FromBytes(src []byte) error {
	buf := bytes.NewBuffer(src)
	if err := binary.Read(buf, MessageBytesOrder, &msg.Type); err != nil {
		return err
	}
	if err := binary.Read(buf, MessageBytesOrder, &msg.Sender); err != nil {
		return err
	}
	if err := binary.Read(buf, MessageBytesOrder, &msg.Ephemeral); err != nil {
		return err
	}
	if err := binary.Read(buf, MessageBytesOrder, &msg.Static); err != nil {
		return err
	}
	if err := binary.Read(buf, MessageBytesOrder, &msg.Timestamp); err != nil {
		return err
	}
	if err := binary.Read(buf, MessageBytesOrder, &msg.MAC1); err != nil {
		return err
	}
	if err := binary.Read(buf, MessageBytesOrder, &msg.MAC2); err != nil {
		return err
	}
	return nil
}

func (msg *MessageInitiation) ToBytes() ([]byte, error) {
	dst := bytes.NewBuffer(make([]byte, 0, MessageInitiationBytesTotal))
	if err := binary.Write(dst, MessageBytesOrder, &msg.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, MessageBytesOrder, &msg.Sender); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, MessageBytesOrder, &msg.Ephemeral); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, MessageBytesOrder, &msg.Static); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, MessageBytesOrder, &msg.Timestamp); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, MessageBytesOrder, &msg.MAC1); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, MessageBytesOrder, &msg.MAC2); err != nil {
		return nil, err
	}
	return dst.Bytes(), nil
}

// MessageTransport is the message which the initiator and
// the responder exchange after a successful handshake.
type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []uint8
}

func (msg *MessageTransport) FromBytes(src []byte) error {
	buf := bytes.NewBuffer(src)
	if err := binary.Read(buf, MessageBytesOrder, &msg.Type); err != nil {
		return err
	}
	if err := binary.Read(buf, MessageBytesOrder, &msg.Receiver); err != nil {
		return err
	}
	if err := binary.Read(buf, MessageBytesOrder, &msg.Counter); err != nil {
		return err
	}
	if buf.Len() > 0 {
		msg.Content = append(msg.Content, buf.Bytes()...)
	}
	return nil
}

func (msg *MessageTransport) ToBytes() ([]byte, error) {
	dst := bytes.NewBuffer(make([]byte, 0, MessageTransportBytesMin-Poly1305TagSize+len(msg.Content)))
	if err := binary.Write(dst, MessageBytesOrder, &msg.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, MessageBytesOrder, &msg.Receiver); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, MessageBytesOrder, &msg.Counter); err != nil {
		return nil, err
	}
	return append(dst.Bytes(), msg.Content...), nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchWireGuard)(nil)
	_ caddyfile.Unmarshaler = (*MatchWireGuard)(nil)
	_ layer4.ConnMatcher    = (*MatchWireGuard)(nil)
)

var MessageBytesOrder = binary.LittleEndian

// Refs:
//
//	https://www.wireguard.com/protocol/
//	https://www.wireguard.com/papers/wireguard.pdf
//	https://github.com/pirate/wireguard-docs
//	https://github.com/WireGuard/wireguard-go/blob/master/device/noise-protocol.go
const (
	Poly1305TagSize int = 16

	MessageInitiationBytesTotal  int = 148
	MessageResponseBytesTotal    int = 92
	MessageCookieReplyBytesTotal int = 64
	MessageTransportBytesMin     int = 32

	MessageTypeInitiation  uint32 = 1
	MessageTypeResponse    uint32 = 2
	MessageTypeCookieReply uint32 = 3
	MessageTypeTransport   uint32 = 4

	ReservedZeroFilter = ^(uint32(0)) >> 8 << 8
)
