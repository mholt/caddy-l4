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

package l4proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
var (
	headerV1Prefix = []byte("PROX") // intentional to not include "Y", see match() function for details
	headerV2Prefix = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
)

func init() {
	caddy.RegisterModule(MatchPROXY{})
}

type MatchPROXY struct{}

// CaddyModule returns the Caddy module information.
func (MatchPROXY) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.ProxyProtocol",
		New: func() caddy.Module { return new(MatchPROXY) },
	}
}

// Match returns true if the connection looks like it is using the Proxy Protocol.
func (m MatchPROXY) Match(cx *layer4.Connection) (bool, error) {
	p := make([]byte, 4)
	_, err := io.ReadFull(cx, p)
	if err != nil {
		return false, err
	}
	if bytes.Equal(p, headerV1Prefix) {
		return true, nil
	}

	buf := p[:]
	bufReader := bufio.NewReader(cx)
	for i := 1; i <= 8; i++ {
		// read the next 8 bytes, one byte at a time
		// since 5th byte being null is valid in v2 header
		// but is considered EOF by readers
		b, err := bufReader.ReadByte()
		if err == nil {
			buf = append(buf, b)
			continue
		}

		if !errors.Is(err, io.ErrUnexpectedEOF) {
			return false, err
		}

		// 4 bytes were already read, so i == 1 is the 5th byte
		if i != 1 {
			return false, err
		}

		buf = append(buf, 0x00)
	}

	if bytes.Equal(buf, headerV2Prefix) {
		return true, nil
	}

	return false, nil
}

// Interface guard
var _ layer4.ConnMatcher = (*MatchPROXY)(nil)
