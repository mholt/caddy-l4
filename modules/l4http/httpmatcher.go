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
	"encoding/json"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4tls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"io"
	"net/http"
	"net/url"
)

func init() {
	caddy.RegisterModule(MatchHTTP{})
}

// MatchHTTP is able to match HTTP connections. The auto-generated
// documentation for this type is wrong; instead of an object, it
// is an array of matcher set objects.
type MatchHTTP struct {
	MatcherSetsRaw caddyhttp.RawMatcherSets `json:"-" caddy:"namespace=http.matchers"`
	matcherSets    caddyhttp.MatcherSets
}

// CaddyModule returns the Caddy module information.
func (MatchHTTP) CaddyModule() caddy.ModuleInfo {
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
func (m MatchHTTP) MarshalJSON() ([]byte, error) {
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
func (m MatchHTTP) Match(cx *layer4.Connection) (bool, error) {
	// TODO: do we need a more standardized way to amortize matchers? or at least to remember decoded results from previous matchers?
	req, ok := cx.GetVar("http_request").(*http.Request)
	if !ok {
		var err error
		bufReader := bufio.NewReader(cx)
		req, err = http.ReadRequest(bufReader)
		if err != nil {
			// TODO: find a way to distinguish actual errors from mismatches
			return false, nil
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
	return m.matcherSets.AnyMatch(req), nil
}

// Parses information from a http2 request with prior knowledge (RFC 7540 Section 3.4)
func (m MatchHTTP) handleHttp2WithPriorKnowledge(reader io.Reader, req *http.Request) error {
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
	for i := 0; i < 10; i++ {
		frame, err = framer.ReadFrame()
		if err != nil {
			return err
		}
		if frame.Header().Type == http2.FrameHeaders {
			break
		}
	}

	if frame.Header().Type != http2.FrameHeaders {
		return fmt.Errorf("failed to read a http2 headers frame after 10 attempts")
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
		if h.Name == ":method" {
			req.Method = h.Value
		} else if h.Name == ":path" {
			path = h.Value
			req.RequestURI = h.Value
		} else if h.Name == ":scheme" {
			scheme = h.Value
		} else if h.Name == ":authority" {
			authority = h.Value
			req.Host = h.Value
		} else {
			req.Header.Add(h.Name, h.Value)
		}
	}

	// According to http.Request.URL docs it only contains the value of RequestURI (so path only),
	// but we can fill in more information
	req.URL, err = url.Parse(fmt.Sprintf("%s://%s%s", scheme, authority, path))
	return err
}

// Interface guards
var (
	_ layer4.ConnMatcher = (*MatchHTTP)(nil)
	_ caddy.Provisioner  = (*MatchHTTP)(nil)
	_ json.Marshaler     = (*MatchHTTP)(nil)
	_ json.Unmarshaler   = (*MatchHTTP)(nil)
)
