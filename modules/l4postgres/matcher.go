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
// Connections can be required to have SSL disabled.
// Non-SSL connections can also match on Message parameters.
//
// Example matcher configs:
//
//	{
//		"postgres": {}
//	}
//
//	{
//		"postgres": {
//			"users": {
//				"*": ["public_db"],
//				"alice": ["planets_db", "stars_db"]
//			}
//		}
//	}
//
//	{
//		"postgres_clients": ["psql", "TablePlus"]
//	}
//
//	{
//		"postgres_ssl": {
//			disabled: false
//	}
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
	"slices"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(MatchPostgres{})
	caddy.RegisterModule(MatchPostgresClients{})
	caddy.RegisterModule(MatchPostgresSSL{})
}

const (
	// Magic number to identify a SSLRequest message
	sslRequestCode = 80877103
)

// NewMessageFromConn create a message from the Connection
func newMessageFromConn(cx *layer4.Connection) (*message, error) {
	// Get bytes containing the message length
	head := make([]byte, lengthFieldSize)
	if _, err := io.ReadFull(cx, head); err != nil {
		return nil, err
	}

	// Get actual message length
	data := make([]byte, binary.BigEndian.Uint32(head)-lengthFieldSize)
	if _, err := io.ReadFull(cx, data); err != nil {
		return nil, err
	}

	return newMessageFromBytes(data), nil
}

// MatchPostgres is able to match Postgres connections
type MatchPostgres struct {
	Users   map[string][]string
	startup *startupMessage
}

// CaddyModule returns the Caddy module information.
func (MatchPostgres) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.postgres",
		New: func() caddy.Module { return new(MatchPostgres) },
	}
}

// Match returns true if the connection looks like the Postgres protocol, and
// can match `user` and `database` parameters
func (m MatchPostgres) Match(cx *layer4.Connection) (bool, error) {
	b, err := newMessageFromConn(cx)
	if err != nil {
		return false, err
	}

	m.startup = newStartupMessage(b)
	hasConfig := len(m.Users) > 0

	// Finish if this is a SSLRequest and there are no other matchers
	if m.startup.IsSSL() && !hasConfig {
		return true, nil
	}

	// Check supported protocol
	if !m.startup.IsSupported() {
		return false, errors.New("pg protocol < 3.0 is not supported")
	}

	// Finish if no more matchers are configured
	if !hasConfig {
		return true, nil
	}

	// Is there a user to check?
	user, ok := m.startup.Parameters["user"]
	if !ok {
		// Are there public databases to check?
		if databases, ok := m.Users["*"]; ok {
			if db, ok := m.startup.Parameters["database"]; ok {
				return slices.Contains(databases, db), nil
			}
		}
		return false, nil
	}

	databases, ok := m.Users[user]
	if !ok {
		return false, nil
	}

	// Are there databases to check?
	if len(databases) > 0 {
		if db, ok := m.startup.Parameters["database"]; ok {
			return slices.Contains(databases, db), nil
		}
	}

	return true, nil
}

// MatchPostgresClients is able to match Postgres connections that
// contain an `application_name` field
type MatchPostgresClients struct {
	Clients []string
	startup *startupMessage
}

// CaddyModule returns the Caddy module information.
func (MatchPostgresClients) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.postgres_clients",
		New: func() caddy.Module { return new(MatchPostgresClients) },
	}
}

// Match returns true if the connection looks like the Postgres protocol and
// passes any `application_name` parameter matchers
func (m MatchPostgresClients) Match(cx *layer4.Connection) (bool, error) {
	b, err := newMessageFromConn(cx)
	if err != nil {
		return false, err
	}

	m.startup = newStartupMessage(b)

	// Reject if this is a SSLRequest as it has no params
	if m.startup.IsSSL() {
		return false, nil
	}

	// Check supported protocol
	if !m.startup.IsSupported() {
		return false, errors.New("pg protocol < 3.0 is not supported")
	}

	// Is there a application_name to check?
	name, ok := m.startup.Parameters["application_name"]
	if !ok {
		return false, nil
	}

	// Check clients list
	return slices.Contains(m.Clients, name), nil
}

// MatchPostgresSSL is able to require/reject Postgres SSL connections.
type MatchPostgresSSL struct {
	Disabled bool
}

// CaddyModule returns the Caddy module information.
func (MatchPostgresSSL) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.postgres_ssl",
		New: func() caddy.Module { return new(MatchPostgresSSL) },
	}
}

// Match checks whether the connection is a Postgres SSL request.
func (m MatchPostgresSSL) Match(cx *layer4.Connection) (bool, error) {
	b, err := newMessageFromConn(cx)
	if err != nil {
		return false, err
	}

	code := b.ReadUint32()
	disabled := !isSSLRequest(code)

	// Enforce SSL enabled
	if !m.Disabled && !disabled {
		return true, nil
	}
	// Enforce SSL disabled
	if m.Disabled && disabled {
		return true, nil
	}
	return false, nil
}

// Interface guard
var _ layer4.ConnMatcher = (*MatchPostgres)(nil)
var _ layer4.ConnMatcher = (*MatchPostgresClients)(nil)
var _ layer4.ConnMatcher = (*MatchPostgresSSL)(nil)
