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
package l4postgres

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchPostgres{})
}

const (
	sslRequestCode    = 80877103  // Code for SSL request
	cancelRequestCode = 80877102  // Code for cancellation request
	lenFieldSize      = 4         // Size of message length field (bytes)
	minMessageLen     = 8         // Smallest valid message: SSLRequest (8 bytes)
	maxPayloadSize    = 16 * 1024 // Maximum reasonable payload size (16 KB)
)

// MatchPostgres is able to match Postgres connections.
type MatchPostgres struct{}

// CaddyModule returns the Caddy module information.
func (*MatchPostgres) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.postgres",
		New: func() caddy.Module { return new(MatchPostgres) },
	}
}

// Match returns true if the connection looks like the Postgres protocol.
func (m *MatchPostgres) Match(cx *layer4.Connection) (bool, error) {
	// Read message length (first 4 bytes)
	lenBytes := make([]byte, lenFieldSize)
	if _, err := io.ReadFull(cx, lenBytes); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil // Not enough data for PostgreSQL
		}
		return false, fmt.Errorf("reading message length: %w", err)
	}

	// Parse and validate message length
	msgLen := binary.BigEndian.Uint32(lenBytes)
	if msgLen < minMessageLen {
		return false, nil // Too small to be a valid PostgreSQL message
	}

	// Calculate and validate payload length
	payloadLen := msgLen - lenFieldSize
	if payloadLen > maxPayloadSize || payloadLen < 4 {
		return false, nil // Payload too large, reject to prevent DoS and need at least 4 bytes for the code/version
	}

	// Read the payload
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(cx, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil // Incomplete message
		}
		return false, fmt.Errorf("reading payload: %w", err)
	}

	// Check the first 4 bytes (code or protocol version)
	code := binary.BigEndian.Uint32(payload[:4])

	// Check for special message types
	switch code {
	case sslRequestCode:
		// SSLRequest is exactly 8 bytes (4 for length + 4 for code)
		return len(payload) == 4, nil

	case cancelRequestCode:
		// CancelRequest is 16 bytes (4 for length + 4 for code + 4 for pid + 4 for secret key)
		return len(payload) == 12, nil

	default:
		// Check if it's a startup message (protocol version)
		majorVersion := code >> 16
		if majorVersion != 3 {
			return false, nil // Only support protocol version 3
		}

		// Basic validation of parameters format
		return validateStartupMessageFormat(payload[4:]), nil
	}
}

// validateStartupMessageFormat checks if the payload has valid Postgres startup format
// using the same approach as handleStartupMessage
func validateStartupMessageFormat(data []byte) bool {
	pos := 0
	for pos < len(data) {
		// Read key
		keyEnd := pos
		for keyEnd < len(data) && data[keyEnd] != 0 {
			keyEnd++
		}

		// Check if we've reached the end without finding null terminator
		if keyEnd >= len(data) {
			return false
		}

		// Empty key means end of parameters
		if keyEnd == pos {
			// This should be the final null byte
			return pos == len(data)-1
		}

		// Skip the null terminator
		pos = keyEnd + 1

		// Read value
		valEnd := pos
		for valEnd < len(data) && data[valEnd] != 0 {
			valEnd++
		}

		// Check if we've reached the end without finding null terminator
		if valEnd >= len(data) {
			return false
		}

		// Skip the null terminator
		pos = valEnd + 1
	}
	return false
}

func (m *MatchPostgres) Provision(ctx caddy.Context) error {
	return nil
}

// UnmarshalCaddyfile sets up the matcher from Caddyfile tokens.
func (m *MatchPostgres) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed layer4 connection matcher '%s': blocks are not supported", wrapper)
	}
	return nil
}

//Refs
//
// https://github.com/mholt/caddy-l4/blob/master/modules/l4ssh/matcher.go
// https://github.com/rueian/pgbroker/blob/master/message/startup_message.go
// https://github.com/traefik/traefik/blob/master/pkg/server/router/tcp/postgres.go
// https://ivdl.co.za/2024/03/02/pretending-to-be-postgresql-part-one-1/
// https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-STARTUPMESSAGE
// https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-SSLREQUEST

// Interface guards
var (
	_ layer4.ConnMatcher    = (*MatchPostgres)(nil)
	_ caddyfile.Unmarshaler = (*MatchPostgres)(nil)
)
