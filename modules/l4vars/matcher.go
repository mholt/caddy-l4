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
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchVars{})
	caddy.RegisterModule(&MatchVarsRE{})
}

// MatchVars is able to match connections
// based on variables in the context or placeholder
// values. The key is the placeholder or name of the variable,
// and the values are possible values the variable can be in
// order to match (logical OR'ed).
//
// If the key is surrounded by `{ }`, it is assumed to be a
// placeholder. Otherwise, it will be considered a variable
// name.
//
// Placeholders in the keys are not expanded, but
// placeholders in the values are.
type MatchVars map[string][]string

// CaddyModule returns the Caddy module information.
func (*MatchVars) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.vars",
		New: func() caddy.Module { return new(MatchVars) },
	}
}

// Match returns true if the connection satisfies the applicable criteria,
// i.e. variables in the context or placeholder values have the given values.
func (m *MatchVars) Match(cx *layer4.Connection) (bool, error) {
	if len(*m) == 0 {
		return true, nil
	}

	vars := cx.Context.Value(layer4.VarsCtxKey).(map[string]any)
	repl := cx.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	var fromPlaceholder bool
	var matcherValExpanded, valExpanded, varStr string
	var varValue any
	for key, vals := range *m {
		if strings.HasPrefix(key, "{") &&
			strings.HasSuffix(key, "}") &&
			strings.Count(key, "{") == 1 {
			varValue, _ = repl.Get(strings.Trim(key, "{}"))
			fromPlaceholder = true
		} else {
			varValue = vars[key]
		}

		switch vv := varValue.(type) {
		case string:
			varStr = vv
		case fmt.Stringer:
			varStr = vv.String()
		case error:
			varStr = vv.Error()
		case nil:
			varStr = ""
		default:
			varStr = fmt.Sprintf("%v", vv)
		}

		// Only expand placeholders in values from literal variable names
		// (e.g. map outputs). Values resolved from placeholder keys are
		// already final and must not be re-expanded, as that would allow
		// user input like {env.SECRET} to be evaluated.
		valExpanded = varStr
		if !fromPlaceholder {
			valExpanded = repl.ReplaceAll(varStr, "")
		}

		// see if any of the values given in the matcher match the actual value
		for _, v := range vals {
			matcherValExpanded = repl.ReplaceAll(v, "")
			if valExpanded == matcherValExpanded {
				return true, nil
			}
		}
	}
	return false, nil
}

// UnmarshalCaddyfile sets up the MatchVars from Caddyfile tokens. Syntax:
//
//	vars <variable> <values...>
func (m *MatchVars) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if *m == nil {
		*m = make(map[string][]string)
	}
	// iterate to merge multiple matchers into one
	for d.Next() {
		var field string
		if !d.Args(&field) {
			return d.Errf("malformed vars matcher: expected field name")
		}
		vals := d.RemainingArgs()
		if len(vals) == 0 {
			return d.Errf("malformed vars matcher: expected at least one value to match against")
		}
		(*m)[field] = append((*m)[field], vals...)
		if d.NextBlock(0) {
			return d.Err("malformed vars matcher: blocks are not supported")
		}
	}
	return nil
}

// MatchVarsRE matches variables in the context or placeholder values against a given regular expression.
//
// Upon a match, it adds placeholders to the connection: `{l4.regexp.name.capture_group}`
// where `name` is the regular expression's name, and `capture_group` is either
// the named or positional capture group from the expression itself. If no name
// is given, then the placeholder omits the name: `{l4.regexp.capture_group}`
// (potentially leading to collisions).
type MatchVarsRE map[string]*layer4.MatchRegexp

// CaddyModule returns the Caddy module information.
func (*MatchVarsRE) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.vars_regexp",
		New: func() caddy.Module { return new(MatchVarsRE) },
	}
}

// Match returns true if the connection satisfies the applicable criteria,
// i.e. the context variables or placeholders match the given regular expressions.
func (m *MatchVarsRE) Match(cx *layer4.Connection) (bool, error) {
	vars := cx.Context.Value(layer4.VarsCtxKey).(map[string]any)
	repl := cx.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)
	var valExpanded, varStr string
	var varValue any
	var fromPlaceholder bool
	for key, val := range *m {
		if strings.HasPrefix(key, "{") &&
			strings.HasSuffix(key, "}") &&
			strings.Count(key, "{") == 1 {
			varValue, _ = repl.Get(strings.Trim(key, "{}"))
			fromPlaceholder = true
		} else {
			varValue = vars[key]
		}

		switch vv := varValue.(type) {
		case string:
			varStr = vv
		case fmt.Stringer:
			varStr = vv.String()
		case error:
			varStr = vv.Error()
		case nil:
			varStr = ""
		default:
			varStr = fmt.Sprintf("%v", vv)
		}

		// Only expand placeholders in values from literal variable names
		// (e.g. map outputs). Values resolved from placeholder keys are
		// already final and must not be re-expanded, as that would allow
		// user input like {env.SECRET} to be evaluated.
		valExpanded = varStr
		if !fromPlaceholder {
			valExpanded = repl.ReplaceAll(varStr, "")
		}
		if match := val.Match(valExpanded, repl); match {
			return match, nil
		}
	}
	return false, nil
}

// Provision compiles m's regular expressions.
func (m *MatchVarsRE) Provision(ctx caddy.Context) error {
	for _, rm := range *m {
		err := rm.Provision(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalCaddyfile sets up the MatchVarsRE from Caddyfile tokens. Syntax:
//
//	vars_regexp [<name>] <variable> <regexp>
func (m *MatchVarsRE) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if *m == nil {
		*m = make(map[string]*layer4.MatchRegexp)
	}
	// iterate to merge multiple matchers into one
	for d.Next() {
		var first, second, third string
		if !d.Args(&first, &second) {
			return d.ArgErr()
		}

		var name, field, val string
		if d.Args(&third) {
			name = first
			field = second
			val = third
		} else {
			field = first
			val = second
		}

		// Default to the named matcher's name, if no regexp name is provided
		if name == "" {
			name = d.GetContextString(caddyfile.MatcherNameCtxKey)
		}

		(*m)[field] = &layer4.MatchRegexp{Pattern: val, Name: name}
		if d.NextBlock(0) {
			return d.Err("malformed vars_regexp matcher: blocks are not supported")
		}
	}
	return nil
}

// Validate validates m's regular expressions.
func (m *MatchVarsRE) Validate() error {
	for _, rm := range *m {
		err := rm.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*MatchVars)(nil)
	_ caddyfile.Unmarshaler = (*MatchVarsRE)(nil)

	_ layer4.ConnMatcher = (*MatchVars)(nil)
	_ layer4.ConnMatcher = (*MatchVarsRE)(nil)
)
