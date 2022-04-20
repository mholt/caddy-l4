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

package l4proxyprotocol

import (
	"bytes"
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
var (
	headerV1Prefix = []byte("PROXY")
	headerV2Prefix = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
)

func init() {
	caddy.RegisterModule(MatchProxyProtocol{})
}

type MatchProxyProtocol struct{}

// CaddyModule returns the Caddy module information.
func (MatchProxyProtocol) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.proxy_protocol",
		New: func() caddy.Module { return new(MatchProxyProtocol) },
	}
}

// Match returns true if the connection looks like it is using the Proxy Protocol.
func (m MatchProxyProtocol) Match(cx *layer4.Connection) (bool, error) {
	buf := make([]byte, len(headerV2Prefix))
	_, err := io.ReadFull(cx, buf)
	if err != nil {
		return false, err
	}

	if bytes.HasPrefix(buf, headerV1Prefix) {
		return true, nil
	}
	if bytes.Equal(buf, headerV2Prefix) {
		return true, nil
	}

	return false, nil
}

// Interface guard
var _ layer4.ConnMatcher = (*MatchProxyProtocol)(nil)
