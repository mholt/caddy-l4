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
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/mholt/caddy-l4/layer4"
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
		req, err = http.ReadRequest(bufio.NewReader(cx))
		if err != nil {
			// TODO: find a way to distinguish actual errors from mismatches
			return false, nil
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

// Interface guards
var (
	_ layer4.ConnMatcher = (*MatchHTTP)(nil)
	_ caddy.Provisioner  = (*MatchHTTP)(nil)
	_ json.Marshaler     = (*MatchHTTP)(nil)
	_ json.Unmarshaler   = (*MatchHTTP)(nil)
)
