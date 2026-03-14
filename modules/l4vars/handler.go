// Copyright 2015 Matthew Holt and The Caddy Authors
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

package l4vars

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&HandleVars{})
}

// HandleVars is able to set custom context variables to
// have values that can be used in the Layer 4 connection handler
// chain. The primary way to access variables is with placeholders,
// which have the form: `{l4.vars.variable_name}`, or with
// the `vars` and `vars_regexp` connection matchers.
//
// The key is the variable name, and the value is the value of the
// variable. Both the name and value may use or contain placeholders.
type HandleVars map[string]any

// CaddyModule returns the Caddy module information.
func (*HandleVars) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.vars",
		New: func() caddy.Module { return new(HandleVars) },
	}
}

// Handle sets custom context variables for the connection.
func (h *HandleVars) Handle(cx *layer4.Connection, next layer4.Handler) error {
	repl := cx.Replacer()
	for k, v := range *h {
		keyExpanded := repl.ReplaceAll(k, "")
		if valStr, ok := v.(string); ok {
			v = repl.ReplaceAll(valStr, "")
		}
		cx.SetVar(keyExpanded, v)
	}
	return next.Handle(cx)
}

// UnmarshalCaddyfile sets up the HandleVars from Caddyfile tokens. Syntax:
//
//	vars [<variable> <value>] {
//	    <variable> <value>
//	    ...
//	}
func (h *HandleVars) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	if *h == nil {
		*h = make(HandleVars)
	}

	nextVar := func(headerLine bool) error {
		if headerLine {
			// header line is optional
			if !d.NextArg() {
				return nil
			}
		}
		varName := d.Val()

		if !d.NextArg() {
			return d.ArgErr()
		}
		varValue := d.ScalarVal()

		(*h)[varName] = varValue

		if d.NextArg() {
			return d.ArgErr()
		}
		return nil
	}

	if err := nextVar(true); err != nil {
		return err
	}
	for d.NextBlock(0) {
		if err := nextVar(false); err != nil {
			return err
		}
	}

	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*HandleVars)(nil)
	_ layer4.NextHandler    = (*HandleVars)(nil)
)
