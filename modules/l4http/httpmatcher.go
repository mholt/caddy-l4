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

package l4http

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4tls"
)

func init() {
	caddy.RegisterModule(&MatchHTTP{})
}

// MatchHTTP is able to match HTTP connections. The auto-generated
// documentation for this type is wrong; instead of an object, it
// is [an array of matcher set objects](https://caddyserver.com/docs/json/apps/http/servers/routes/match/).
type MatchHTTP struct {
	MatcherSetsRaw caddyhttp.RawMatcherSets `json:"-" caddy:"namespace=http.matchers"`
	matcherSets    caddyhttp.MatcherSets
}

// CaddyModule returns the Caddy module information.
func (*MatchHTTP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.http",
		New: func() caddy.Module { return new(MatchHTTP) },
	}
}

// UnmarshalJSON satisfies the json.Unmarshaler interface.
func (m *MatchHTTP) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &m.MatcherSetsRaw)
}

// MarshalJSON satisfies the json.Marshaler interface.
func (m *MatchHTTP) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.MatcherSetsRaw)
}

// Provision sets up the handler.
func (m *MatchHTTP) Provision(ctx caddy.Context) error {
	matchersIface, err := ctx.LoadModule(m, "MatcherSetsRaw")
	if err != nil {
		return fmt.Errorf("loading matcher modules: %v", err)
	}
	err = m.matcherSets.FromInterface(matchersIface)
	if err != nil {
		return err
	}
	return nil
}

// Match returns true if the conn starts with an HTTP request.
func (m *MatchHTTP) Match(cx *layer4.Connection) (bool, error) {
	// TODO: do we need a more standardized way to amortize matchers? or at least to remember decoded results from previous matchers?
	req, ok := cx.GetVar("http_request").(*http.Request)
	if !ok {
		var err error

		data := cx.MatchingBytes()
		needMore, matched := m.isHttp(data)
		if needMore {
			if len(data) >= layer4.MaxMatchingBytes {
				return false, layer4.ErrMatchingBufferFull
			}
			return false, layer4.ErrConsumedAllPrefetchedBytes
		}
		if !matched {
			return false, nil
		}

		// use bufio reader which exactly matches the size of prefetched data,
		// to not trigger all bytes consumed error
		bufReader := bufio.NewReaderSize(cx, len(data))
		req, err = http.ReadRequest(bufReader)
		if err != nil {
			return false, err
		}

		// check if req is a http2 request made with prior knowledge and if so parse it
		err = m.handleHttp2WithPriorKnowledge(bufReader, req)
		if err != nil {
			return false, err
		}

		// if the tls handler was used before fill in the TLS field of the request
		// with the last aka innermost tls connection state
		if connectionStates := l4tls.GetConnectionStates(cx); len(connectionStates) > 0 {
			req.TLS = connectionStates[len(connectionStates)-1]
		}

		// in order to use request matchers, we have to populate the request context
		req = caddyhttp.PrepareRequest(req, caddy.NewReplacer(), nil, nil)

		// remember this for future use
		cx.SetVar("http_request", req)

		// also add values to the replacer (TODO: we could probably find a way to use the http app's replacer values)
		repl := cx.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)
		repl.Set("l4.http.host", req.Host)
	}

	// we have a valid HTTP request, so we can drill down further if there are
	// any more matchers configured
	return m.matcherSets.AnyMatchWithError(req)
}

// isHttp test if the buffered data looks like HTTP by looking at the first line.
// first boolean determines if more data is required
func (m *MatchHTTP) isHttp(data []byte) (bool, bool) {
	// try to find the end of a http request line, for example " HTTP/1.1\r\n"
	i := bytes.IndexByte(data, 0x0a) // find first new line
	if i < 10 {
		return true, false
	}
	// assume only \n line ending
	start := i - 9 // position of space in front of HTTP
	end := i - 3   // cut off version number "1.1" or "2.0"
	// if we got a correct \r\n line ending shift the calculated start & end to the left
	if data[i-1] == 0x0d {
		start -= 1
		end -= 1
	}
	return false, bytes.Equal(data[start:end], []byte(" HTTP/"))
}

// Parses information from a http2 request with prior knowledge (RFC 7540 Section 3.4)
func (m *MatchHTTP) handleHttp2WithPriorKnowledge(reader io.Reader, req *http.Request) error {
	// Does req contain a valid http2 magic?
	// https://github.com/golang/net/blob/a630d4f3e7a22f21271532b4b88e1693824a838f/http2/h2c/h2c.go#L74
	if req.Method != "PRI" || len(req.Header) != 0 || req.URL.Path != "*" || req.Proto != "HTTP/2.0" {
		return nil
	}

	const expectedBody = "SM\r\n\r\n"

	body := make([]byte, len(expectedBody))
	n, err := io.ReadFull(reader, body)
	if err != nil {
		return err
	}

	if string(body[:n]) != expectedBody {
		return nil
	}

	framer := http2.NewFramer(io.Discard, reader)

	// read the first 10 frames until we get a headers frame (skipping settings, window update & priority frames)
	var frame http2.Frame
	maxAttempts := 10
	for i := 0; i < maxAttempts; i++ {
		frame, err = framer.ReadFrame()
		if err != nil {
			return err
		}
		if frame.Header().Type == http2.FrameHeaders {
			maxAttempts = 0
			break
		}
	}
	if maxAttempts != 0 {
		return fmt.Errorf("failed to read a http2 headers frame after %d attempts", maxAttempts)
	}

	decoder := hpack.NewDecoder(4096, nil) // max table size 4096 from http2.initialHeaderTableSize
	headers, err := decoder.DecodeFull((frame.(*http2.HeadersFrame)).HeaderBlockFragment())
	if err != nil {
		return err
	}

	var scheme string
	var authority string
	var path string

	for _, h := range headers {
		switch h.Name {
		case ":method":
			req.Method = h.Value
		case ":path":
			path = h.Value
			req.RequestURI = h.Value
		case ":scheme":
			scheme = h.Value
		case ":authority":
			authority = h.Value
			req.Host = h.Value
		default:
			req.Header.Add(h.Name, h.Value)
		}
	}

	// According to http.Request.URL docs it only contains the value of RequestURI (so path only),
	// but we can fill in more information
	req.URL, err = url.Parse(fmt.Sprintf("%s://%s%s", scheme, authority, path))
	return err
}

// UnmarshalCaddyfile sets up the MatchHTTP from Caddyfile tokens. Syntax:
//
//	http {
//		<matcher> [<args...>]
//		not <matcher> [<args...>]
//		not {
//			<matcher> [<args...>]
//		}
//	}
//	http <matcher> [<args...>]
//	http not <matcher> [<args...>]
//
// Note: as per https://caddyserver.com/docs/json/apps/http/servers/routes/match/,
// matchers within a set are AND'ed together. Arguments of this http matcher constitute
// a single matcher set, thus no OR logic is supported. Instead, use multiple http matchers.
func (m *MatchHTTP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	matcherSet, err := caddyhttp.ParseCaddyfileNestedMatcherSet(d)
	if err != nil {
		return err
	}
	m.MatcherSetsRaw = append(m.MatcherSetsRaw, matcherSet)

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchHTTP)(nil)
	_ caddyfile.Unmarshaler = (*MatchHTTP)(nil)
	_ json.Marshaler        = (*MatchHTTP)(nil)
	_ json.Unmarshaler      = (*MatchHTTP)(nil)
	_ layer4.ConnMatcher    = (*MatchHTTP)(nil)
)
