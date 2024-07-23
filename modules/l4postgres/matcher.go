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

// Package l4postgres allows the L4 multiplexing of Postgres connections
//
// With thanks to docs and code published at these links:
// ref: https://github.com/mholt/caddy-l4/blob/master/modules/l4ssh/matcher.go
// ref: https://github.com/rueian/pgbroker/blob/master/message/startup_message.go
// ref: https://github.com/traefik/traefik/blob/master/pkg/server/router/tcp/postgres.go
// ref: https://ivdl.co.za/2024/03/02/pretending-to-be-postgresql-part-one-1/
// ref: https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-STARTUPMESSAGE
// ref: https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-SSLREQUEST
package l4postgres

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(MatchPostgres{})
}

const (
	// Magic number to identify a SSLRequest message
	sslRequestCode = 80877103
	// byte size of the message length field
	initMessageSizeLength = 4
)

// Message provides readers for various types and
// updates the offset after each read
type message struct {
	data   []byte
	offset uint32
}

func (b *message) ReadUint32() (r uint32) {
	r = binary.BigEndian.Uint32(b.data[b.offset : b.offset+4])
	b.offset += 4
	return r
}

func (b *message) ReadString() (r string) {
	end := b.offset
	max := uint32(len(b.data))
	for ; end != max && b.data[end] != 0; end++ {
	}
	r = string(b.data[b.offset:end])
	b.offset = end + 1
	return r
}

// NewMessageFromBytes wraps the raw bytes of a message to enable processing
func newMessageFromBytes(b []byte) *message {
	return &message{data: b}
}

// StartupMessage contains the values parsed from the startup message
type startupMessage struct {
	ProtocolVersion uint32
	Parameters      map[string]string
}

// MatchPostgres is able to match Postgres connections.
type MatchPostgres struct{}

// CaddyModule returns the Caddy module information.
func (MatchPostgres) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.postgres",
		New: func() caddy.Module { return new(MatchPostgres) },
	}
}

// Match returns true if the connection looks like the Postgres protocol.
func (m MatchPostgres) Match(cx *layer4.Connection) (bool, error) {
	// Get bytes containing the message length
	head := make([]byte, initMessageSizeLength)
	if _, err := io.ReadFull(cx, head); err != nil {
		return false, err
	}

	// Get actual message length
	data := make([]byte, binary.BigEndian.Uint32(head)-initMessageSizeLength)
	if _, err := io.ReadFull(cx, data); err != nil {
		return false, err
	}

	b := newMessageFromBytes(data)

	// Check if it is a SSLRequest
	code := b.ReadUint32()
	if code == sslRequestCode {
		return true, nil
	}

	// Check supported protocol
	if majorVersion := code >> 16; majorVersion < 3 {
		return false, errors.New("pg protocol < 3.0 is not supported")
	}

	// Try parsing Postgres Params
	startup := &startupMessage{ProtocolVersion: code, Parameters: make(map[string]string)}
	for {
		k := b.ReadString()
		if k == "" {
			break
		}
		startup.Parameters[k] = b.ReadString()
	}
	// TODO(metafeather): match on param values: user, database, options, etc

	return len(startup.Parameters) > 0, nil
}

// UnmarshalCaddyfile sets up the MatchPostgres from Caddyfile tokens. Syntax:
//
//	postgres
func (m *MatchPostgres) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed layer4 connection matcher '%s': blocks are not supported", wrapper)
	}

	return nil
}

// Interface guards
var (
	_ layer4.ConnMatcher    = (*MatchPostgres)(nil)
	_ caddyfile.Unmarshaler = (*MatchPostgres)(nil)
)
