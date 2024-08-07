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

package l4dns

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/miekg/dns"

	"github.com/mholt/caddy-l4/layer4"
)

func ReadBytes(cx *layer4.Connection) ([]byte, error) {
	// Determine whether the connection is TCP or not
	// Note: all non-TCP connections are treated as UDP,
	// i.e. having no length bytes prepending message bytes.
	_, isTCP := cx.LocalAddr().(*net.TCPAddr)

	// Read incoming DNS message bytes
	if isTCP {
		return ReadBytesFromTCP(cx)
	} else {
		return ReadBytesFromUDP(cx)
	}
}

func ReadBytesFromTCP(cx *layer4.Connection) ([]byte, error) {
	// Read the first 2 bytes as a big endian uint16 number and validate it
	// Note: these 2 bytes represent the length of the remaining part of the packet.
	var length uint16
	if err := binary.Read(cx, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length < dnsHeaderBytes {
		return nil, ErrBytesTooFew
	}

	// Read a minimum number of bytes
	buf := make([]byte, length+1)
	n, err := io.ReadFull(cx, buf[:dnsHeaderBytes])
	if err != nil {
		return nil, err
	}

	// Validate the bytes we have already read
	if !ValidateHeaderBytes(buf[:dnsHeaderBytes]) {
		return nil, ErrBytesBadHeader
	}

	// Read the remaining bytes
	n, err = io.ReadAtLeast(cx, buf[dnsHeaderBytes:], int(length-dnsHeaderBytes))
	if err != nil {
		return nil, err
	}

	// Validate the total message length
	// Note: if there is at least 1 extra byte, we can technically be sure, it isn't a DNS message.
	// This behaviour may be changed in the future if there are many false negative matches.
	if n > int(length-dnsHeaderBytes) {
		return nil, ErrBytesTooMany
	}

	return buf[:length], nil
}

func ReadBytesFromUDP(cx *layer4.Connection) ([]byte, error) {
	// Read a minimum number of bytes
	buf := make([]byte, dnsHeaderBytes)
	n, err := io.ReadFull(cx, buf)
	if err != nil {
		return nil, err
	}

	// Validate the bytes we have already read
	if !ValidateHeaderBytes(buf) {
		return nil, ErrBytesBadHeader
	}

	// Read the remaining bytes
	var nn int
	tmp := make([]byte, dns.MinMsgSize)
	for err == nil && n <= dns.MaxMsgSize {
		nn, err = io.ReadAtLeast(cx, tmp, 1)
		buf = append(buf, tmp[:nn]...)
		n += nn

		// Exit the loop when there are empty bytes in tmp
		if nn < len(tmp) {
			break
		}
	}

	// Validate the total message length
	if n > dns.MaxMsgSize {
		return nil, ErrBytesTooMany
	}

	return buf, nil
}

func ValidateHeaderBytes(bytes []byte) bool {
	return len(bytes) == int(dnsHeaderBytes) && validateHeaderFlags(binary.BigEndian.Uint16(bytes[2:4])) &&
		validateHeaderCounters(binary.BigEndian.Uint16(bytes[4:6]), binary.BigEndian.Uint16(bytes[6:8]),
			binary.BigEndian.Uint16(bytes[8:10]), binary.BigEndian.Uint16(bytes[10:12]))
}

// validateHeaderFlags returns true if the flags are valid for a DNS request message.
// Note: adapted from https://github.com/miekg/dns/blob/master/acceptfunc.go in August 2024.
func validateHeaderFlags(flags uint16) bool {
	return flags&(1<<15) == 0 && // it is a query
		flags&(1<<6) == 0 && // zero bit is empty
		int(flags&0xF) == dns.RcodeSuccess
}

// validateHeaderCounters returns true if the counters are valid for a DNS request message.
// Note: adapted from https://github.com/miekg/dns/blob/master/acceptfunc.go in August 2024.
func validateHeaderCounters(q, a, n, e uint16) bool {
	return q == 1 && a < 2 && n < 2 && e < 3
}

func WriteBytes(cx *layer4.Connection, data []byte) (int, error) {
	// Determine whether the connection is TCP or not
	// Note: all non-TCP connections are treated as UDP,
	// i.e. having no length bytes prepending message bytes.
	_, isTCP := cx.LocalAddr().(*net.TCPAddr)

	// Write outgoing DNS message bytes
	if isTCP {
		return WriteBytesToTCP(cx, data)
	} else {
		return WriteBytesToUDP(cx, data)
	}
}

func WriteBytesToTCP(cx *layer4.Connection, data []byte) (int, error) {
	// Validate the total message length
	length := len(data)
	if length < int(dnsHeaderBytes) {
		return 0, ErrBytesTooFew
	}
	if length > dns.MaxMsgSize {
		return 0, ErrBytesTooMany
	}

	// Copy the length to the first 2 bytes as a big endian uint16 number, then the remaining data bytes
	buf := make([]byte, 2+length)
	binary.BigEndian.PutUint16(buf, uint16(length))
	copy(buf[2:], data)

	return cx.Write(buf)
}

func WriteBytesToUDP(cx *layer4.Connection, data []byte) (int, error) {
	// Validate the total message length
	length := len(data)
	if length < int(dnsHeaderBytes) {
		return 0, ErrBytesTooFew
	}
	if length > dns.MaxMsgSize {
		return 0, ErrBytesTooMany
	}

	return cx.Write(data)
}

var (
	ErrBytesBadHeader = errors.New("bad header")
	ErrBytesTooFew    = errors.New("too few bytes")
	ErrBytesTooMany   = errors.New("too many bytes")
)
