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

// Package l4postgres allows the L4 multiplexing of Postgres connections.
//
// In addition to detecting a Postgres connection, the matchers can select on
// the contents of the StartupMessage the client sends first:
//
//   - postgres        also filters on the user/database pair;
//   - postgres_client filters on the application_name parameter;
//   - postgres_ssl     requires (or rejects) an SSLRequest.
package l4postgres

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchPostgres{})
	caddy.RegisterModule(&MatchPostgresClient{})
	caddy.RegisterModule(&MatchPostgresSSL{})
}

const (
	sslRequestCode    = 80877103  // Code for SSL request
	cancelRequestCode = 80877102  // Code for cancellation request
	lenFieldSize      = 4         // Size of message length field (bytes)
	minMessageLen     = 8         // Smallest valid message: SSLRequest (8 bytes)
	maxPayloadSize    = 16 * 1024 // Maximum reasonable payload size (16 KB)
)

// readFirstMessage reads and length-validates the first Postgres message on the
// connection, using DoS-safe bounds checks. It returns the message code (the
// first 4 bytes of the payload, i.e. an SSL/Cancel request code or the protocol
// version) together with the full payload (payload[:4] holds the code bytes).
//
// ok is false when the bytes on the wire cannot be a valid Postgres first
// message; callers should then return (false, nil). err is non-nil only for
// unexpected read errors (a short/closed connection is reported as ok=false,
// err=nil so it simply doesn't match).
func readFirstMessage(cx *layer4.Connection) (code uint32, payload []byte, ok bool, err error) {
	// Read message length (first 4 bytes)
	lenBytes := make([]byte, lenFieldSize)
	if _, err := io.ReadFull(cx, lenBytes); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, false, nil // Not enough data for PostgreSQL
		}
		return 0, nil, false, fmt.Errorf("reading message length: %w", err)
	}

	// Parse and validate message length
	msgLen := binary.BigEndian.Uint32(lenBytes)
	if msgLen < minMessageLen {
		return 0, nil, false, nil // Too small to be a valid PostgreSQL message
	}

	// Calculate and validate payload length
	payloadLen := msgLen - lenFieldSize
	if payloadLen > maxPayloadSize || payloadLen < 4 {
		// Payload too large (reject to prevent DoS) or too small to hold the
		// 4-byte code/version field.
		return 0, nil, false, nil
	}

	// Read the payload
	payload = make([]byte, payloadLen)
	if _, err := io.ReadFull(cx, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, false, nil // Incomplete message
		}
		return 0, nil, false, fmt.Errorf("reading payload: %w", err)
	}

	return binary.BigEndian.Uint32(payload[:4]), payload, true, nil
}

// classifyMessage reports which kind of Postgres first message the payload is.
// At most one of the returned booleans is true; all false means the bytes are
// not a recognized Postgres first message.
func classifyMessage(code uint32, payload []byte) (isSSL, isCancel, isStartup bool) {
	switch code {
	case sslRequestCode:
		// SSLRequest is exactly 8 bytes (4 for length + 4 for code)
		return len(payload) == 4, false, false
	case cancelRequestCode:
		// CancelRequest is 16 bytes (4 length + 4 code + 4 pid + 4 secret key)
		return false, len(payload) == 12, false
	default:
		// Otherwise the code is the protocol version; only v3 is supported
		if code>>16 != 3 {
			return false, false, false
		}
		return false, false, validateStartupMessageFormat(payload[4:])
	}
}

// MatchPostgres is able to match Postgres connections. Without any configuration
// it matches every well-formed Postgres first message (SSLRequest, CancelRequest
// or a protocol-3 StartupMessage). When the User map is set, only StartupMessages
// whose user (and, optionally, database) parameters satisfy the map will match.
//
// The User map is keyed by user name; the special key "*" matches any user that
// is not listed explicitly. Each value is the list of databases allowed for that
// user; an empty list allows any database.
type MatchPostgres struct {
	// User maps a Postgres user name to the databases it is allowed to use.
	// The special key "*" applies to any user not listed explicitly. An empty
	// (or nil) database list matches any database for that user.
	User map[string][]string `json:"user,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*MatchPostgres) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.postgres",
		New: func() caddy.Module { return new(MatchPostgres) },
	}
}

// Match returns true if the connection looks like the Postgres protocol and, when
// the User map is configured, the StartupMessage satisfies the user/database
// filter.
func (m *MatchPostgres) Match(cx *layer4.Connection) (bool, error) {
	code, payload, ok, err := readFirstMessage(cx)
	if err != nil || !ok {
		return false, err
	}

	isSSL, isCancel, isStartup := classifyMessage(code, payload)

	// Without a user/database filter, any well-formed Postgres first message
	// matches (this preserves the original detection behavior).
	if len(m.User) == 0 {
		return isSSL || isCancel || isStartup, nil
	}

	// The user/database filter only applies to StartupMessages, which are the
	// only kind that carry parameters. SSLRequest/CancelRequest cannot match.
	if !isStartup {
		return false, nil
	}

	return m.matchUserDatabase(parseStartupParameters(payload[4:])), nil
}

// matchUserDatabase applies the User map to the StartupMessage parameters.
func (m *MatchPostgres) matchUserDatabase(params map[string]string) bool {
	user, ok := params["user"]
	if !ok {
		// No user parameter: fall back to the wildcard entry, gated on the
		// database if one was sent.
		if databases, ok := m.User["*"]; ok {
			if db, ok := params["database"]; ok {
				return slices.Contains(databases, db)
			}
		}
		return false
	}

	databases, ok := m.User[user]
	if !ok {
		return false
	}

	// If specific databases are configured for this user, the connection's
	// database (when present) must be one of them.
	if len(databases) > 0 {
		if db, ok := params["database"]; ok {
			return slices.Contains(databases, db)
		}
	}

	return true
}

// MatchPostgresClient matches Postgres StartupMessages whose application_name
// parameter is one of the configured client names.
type MatchPostgresClient struct {
	// Client is the list of accepted application_name values.
	Client []string `json:"client,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*MatchPostgresClient) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.postgres_client",
		New: func() caddy.Module { return new(MatchPostgresClient) },
	}
}

// Match returns true if the connection is a Postgres StartupMessage whose
// application_name parameter is in the configured Client list.
func (m *MatchPostgresClient) Match(cx *layer4.Connection) (bool, error) {
	code, payload, ok, err := readFirstMessage(cx)
	if err != nil || !ok {
		return false, err
	}

	// Only StartupMessages carry an application_name; SSL/Cancel requests don't.
	if _, _, isStartup := classifyMessage(code, payload); !isStartup {
		return false, nil
	}

	name, ok := parseStartupParameters(payload[4:])["application_name"]
	if !ok {
		return false, nil
	}

	return slices.Contains(m.Client, name), nil
}

// MatchPostgresSSL matches on whether the Postgres connection began with an
// SSLRequest. By default it matches connections that request SSL; set Disabled
// to instead match connections that do not.
type MatchPostgresSSL struct {
	// Disabled inverts the match: when true, the matcher requires the absence
	// of an SSLRequest instead of its presence.
	Disabled bool `json:"disabled,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*MatchPostgresSSL) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.postgres_ssl",
		New: func() caddy.Module { return new(MatchPostgresSSL) },
	}
}

// Match returns true when the connection's SSL state matches the configuration:
// by default when it is an SSLRequest, or (with Disabled set) when it is not.
func (m *MatchPostgresSSL) Match(cx *layer4.Connection) (bool, error) {
	code, payload, ok, err := readFirstMessage(cx)
	if err != nil || !ok {
		return false, err
	}

	isSSL, _, _ := classifyMessage(code, payload)
	// Disabled=false -> match when SSL is requested.
	// Disabled=true  -> match when SSL is not requested.
	return isSSL != m.Disabled, nil
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

// parseStartupParameters extracts the key/value parameters from a StartupMessage
// payload (the bytes after the 4-byte protocol version). It assumes the payload
// has already been validated by validateStartupMessageFormat, so it does not
// need to guard against malformed input.
func parseStartupParameters(data []byte) map[string]string {
	params := make(map[string]string)
	pos := 0
	for pos < len(data) {
		keyEnd := pos
		for keyEnd < len(data) && data[keyEnd] != 0 {
			keyEnd++
		}
		// Empty key marks the end of the parameter list.
		if keyEnd == pos {
			break
		}
		key := string(data[pos:keyEnd])
		pos = keyEnd + 1

		valEnd := pos
		for valEnd < len(data) && data[valEnd] != 0 {
			valEnd++
		}
		params[key] = string(data[pos:valEnd])
		pos = valEnd + 1
	}
	return params
}

// UnmarshalCaddyfile sets up the matcher from Caddyfile tokens. Syntax:
//
//	postgres
//
//	postgres {
//		user <name> [<database>...]
//	}
//
// Repeated user lines accumulate; use "*" as the name to match any unlisted user.
func (m *MatchPostgres) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "user":
			if !d.NextArg() {
				return d.ArgErr()
			}
			name := d.Val()
			if m.User == nil {
				m.User = make(map[string][]string)
			}
			// Remaining args on the line (if any) are the allowed databases.
			m.User[name] = append(m.User[name], d.RemainingArgs()...)
		default:
			return d.Errf("malformed layer4 connection matcher '%s': unrecognized option '%s'", wrapper, d.Val())
		}
	}
	return nil
}

// UnmarshalCaddyfile sets up the matcher from Caddyfile tokens. Syntax:
//
//	postgres_client <name> [<name>...]
func (m *MatchPostgresClient) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name
	m.Client = append(m.Client, d.RemainingArgs()...)
	if len(m.Client) == 0 {
		return d.ArgErr()
	}
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed layer4 connection matcher '%s': blocks are not supported", wrapper)
	}
	return nil
}

// UnmarshalCaddyfile sets up the matcher from Caddyfile tokens. Syntax:
//
//	postgres_ssl [disabled]
func (m *MatchPostgresSSL) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name
	args := d.RemainingArgs()
	switch len(args) {
	case 0:
		// require SSL (default)
	case 1:
		if args[0] != "disabled" {
			return d.Errf("malformed layer4 connection matcher '%s': unrecognized argument '%s'", wrapper, args[0])
		}
		m.Disabled = true
	default:
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
	_ layer4.ConnMatcher    = (*MatchPostgresClient)(nil)
	_ caddyfile.Unmarshaler = (*MatchPostgresClient)(nil)
	_ layer4.ConnMatcher    = (*MatchPostgresSSL)(nil)
	_ caddyfile.Unmarshaler = (*MatchPostgresSSL)(nil)
)
