// Allows the L4 multiplexing of Postgres connections
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
	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(MatchPostgres{})
}

const (
	SSLRequestCode = 80877103
	InitMessageSizeLength = 4
)

// Message provides readers for various types and 
// updates the offset after each read
type Message struct{
	data []byte
	offset uint32
}

func (b *Message) ReadUint32() (r uint32) {
	r = binary.BigEndian.Uint32(b.data[b.offset : b.offset+4])
	b.offset += 4
	return r
}

func (b *Message) ReadString() (r string) {
	end := b.offset
	max := uint32(len(b.data))
	for ; end != max && b.data[end] != 0; end++ {
	}
	r = string(b.data[b.offset:end])
	b.offset = end + 1
	return r
}

func NewMessageFromBytes(b []byte) *Message {
	return &Message{data: b}
}

// StartupMessage contains the values parsed from the startup message
type StartupMessage struct {
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
	// Get message length bytes
	head := make([]byte, InitMessageSizeLength)
	if _, err := io.ReadFull(cx, head); err != nil {
		return false, err
	}

	// Get actual message length
	data := make([]byte, binary.BigEndian.Uint32(head)-InitMessageSizeLength)
	if _, err := io.ReadFull(cx, data); err != nil {
		return false, err
	}

	b := NewMessageFromBytes(data)

	// Check if a SSLRequest identified by magic number
	code := b.ReadUint32()
	if code == SSLRequestCode {
		return true, nil
	}

	// Check supported protocol
	if majorVersion := code >> 16; majorVersion < 3 {
		return false, errors.New("pg protocol < 3.0 is not supported")
	}	

	// Try parsing Postgres Params
	startup := &StartupMessage{ProtocolVersion: code, Parameters: make(map[string]string)}
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

// Interface guard
var _ layer4.ConnMatcher = (*MatchPostgres)(nil)
