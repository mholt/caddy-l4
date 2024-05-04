// ref: https://github.com/rueian/pgbroker/blob/master/message/util.go
package l4postgres

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	// byte size of the message length field
	lengthFieldSize = 4
)

// Message provides readers for various types and
// updates the offset after each read/write operation.
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

func (b *message) WriteByte(i byte) {
	b.data[b.offset] = i
	b.offset++
}

func (b *message) WriteByteN(i []byte) {
	for _, s := range i {
		b.WriteByte(s)
	}
}

func (b *message) WriteUint32(i uint32) {
	binary.BigEndian.PutUint32(b.data[b.offset:b.offset+4], i)
	b.offset += 4
}

func (b *message) WriteString(i string) {
	b.WriteByteN([]byte(i))
	b.WriteByte(0)
}

func (b *message) Length() int {
	return len(b.data)
}

func (b *message) Reader() io.Reader {
	length := make([]byte, lengthFieldSize)
	binary.BigEndian.PutUint32(length, uint32(b.Length()+lengthFieldSize))
	return io.MultiReader(
		bytes.NewReader(length),
		bytes.NewReader(b.data),
	)
}

func newMessage(len int) *message {
	return &message{data: make([]byte, len)}
}

// NewMessageFromBytes wraps the raw bytes of a message to enable processing
func newMessageFromBytes(b []byte) *message {
	return &message{data: b}
}

// StartupMessage contains the values parsed from the first message received.
// This should be either a SSLRequest or StartupMessage
type startupMessage struct {
	ProtocolVersion uint32
	Parameters      map[string]string
}

func (m *startupMessage) Reader() io.Reader {
	length := lengthFieldSize
	for k, v := range m.Parameters {
		length += len(k) + 1
		length += len(v) + 1
	}
	length += 1
	b := newMessage(length)
	b.WriteUint32(m.ProtocolVersion)
	for k, v := range m.Parameters {
		b.WriteString(k)
		b.WriteString(v)
	}
	b.WriteByte(0)
	return b.Reader()
}

// IsSSL confirms this is a SSLRequest
func (s startupMessage) IsSSL() bool {
	return isSSLRequest(s.ProtocolVersion)
}

// IsSupported confirms this is a supported version of Postgres
func (s startupMessage) IsSupported() bool {
	return isSupported(s.ProtocolVersion)
}

// NewStartupMessage creates a new startupMessage from the message bytes
func newStartupMessage(b *message) *startupMessage {
	return &startupMessage{
		ProtocolVersion: b.ReadUint32(),
		Parameters:      parseParameters(b),
	}
}

func isSSLRequest(code uint32) bool {
	return code == sslRequestCode
}

func isSupported(code uint32) bool {
	majorVersion := code >> 16
	return majorVersion >= 3
}

func parseParameters(b *message) map[string]string {
	params := make(map[string]string)
	for {
		k := b.ReadString()
		if k == "" {
			break
		}
		params[k] = b.ReadString()
	}
	return params
}
