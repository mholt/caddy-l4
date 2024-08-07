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
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&HandleDNS{})
}

// HandleDNS is a handler that serves DNS records.
type HandleDNS struct {
	// Cache contains the global DNS cache configuration.
	Cache json.RawMessage `json:"cache,omitempty" caddy:"namespace=layer4.handlers.dns.caches inline_key=name"`
	// Compress enables compression for response messages. By default, it is disabled.
	Compress bool `json:"compress,omitempty"`
	// Passthrough spawns a dns.Server instead of direct handling. By default, it is disabled.
	Passthrough bool `json:"pass_through,omitempty"`
	// Validate enables transaction signature validation for request messages. By default, it is disabled.
	Validate bool `json:"validate,omitempty"`
	// Zones contains raw DNS zone configurations. Each zone must have a unique pattern.
	Zones []json.RawMessage `json:"zones,omitempty" caddy:"namespace=layer4.handlers.dns.zones inline_key=name"`

	dis *Dispatcher
}

// CaddyModule returns the Caddy module information.
func (*HandleDNS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  NamespaceRoot,
		New: func() caddy.Module { return new(HandleDNS) },
	}
}

// Handle handles the DNS connection.
func (h *HandleDNS) Handle(cx *layer4.Connection, next layer4.Handler) (err error) {
	if h.Passthrough {
		return h.HandlePassthrough(cx, next)
	}
	return h.HandleSmart(cx, next)
}

// Provision prepares h's internal structures.
func (h *HandleDNS) Provision(ctx caddy.Context) error {
	// Fill the variables table in a context
	varMap := make(map[string]interface{})
	varMap[CacheCtxKey] = DefCache
	ctx = ctx.WithValue(layer4.VarsCtxKey, varMap)

	// Load cache if any and update the cache context value
	if len(h.Cache) > 0 {
		mod, err := ctx.LoadModule(h, "Cache")
		if err != nil {
			return fmt.Errorf("loading DNS cache: %v", err)
		}
		c, ok := mod.(Cache)
		if !ok {
			return fmt.Errorf("loading DNS cache module: expected Cache, got %T", mod)
		}
		varMap[CacheCtxKey] = c
	}

	// Initialize a Dispatcher
	h.dis = new(Dispatcher)

	// Load zones and register them with the Dispatcher
	mods, err := ctx.LoadModule(h, "Zones")
	if err != nil {
		return fmt.Errorf("loading DNS zones: %v", err)
	}
	for _, mod := range mods.([]interface{}) {
		z, ok := mod.(Zone)
		if !ok {
			return fmt.Errorf("loading DNS zone module: expected Zone, got %T", mod)
		}

		err = h.dis.RegisterZone(z)
		if err != nil {
			return fmt.Errorf("registering DNS zone: %v", err)
		}
	}

	return nil
}

// UnmarshalCaddyfile sets up the HandleDNS from Caddyfile tokens. Syntax:
//
//	dns {
//		cache <name> [<args...>] {
//			[<options...>]
//		}
//		compress
//		passthrough
//		validate
//		zone <name> [<args...>] {
//			[<options...>]
//		}
//	}
func (h *HandleDNS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	var hasCache, hasCompress, hasPassthrough, hasValidate bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "cache":
			if err := UnmarshalCaddyfileOptionModule(d, optionName, &h.Cache, &hasCache,
				NamespaceCaches,
				"name",
				func(name string, unm caddyfile.Unmarshaler) error {
					if _, ok := unm.(Cache); !ok {
						return fmt.Errorf("module '%s' is not a Cache; is %T", name, unm)
					}
					return nil
				},
			); err != nil {
				return err
			}
		case "compress":
			if err := UnmarshalCaddyfileOptionBool(d, optionName, &h.Compress, &hasCompress); err != nil {
				return err
			}
		case "passthrough":
			if err := UnmarshalCaddyfileOptionBool(d, optionName, &h.Passthrough, &hasPassthrough); err != nil {
				return err
			}
		case "validate":
			if err := UnmarshalCaddyfileOptionBool(d, optionName, &h.Validate, &hasValidate); err != nil {
				return err
			}
		case "zone":
			var (
				dup bool
				raw json.RawMessage
			)
			if err := UnmarshalCaddyfileOptionModule(d, optionName, &raw, &dup,
				NamespaceZones,
				"name",
				func(name string, unm caddyfile.Unmarshaler) error {
					if _, ok := unm.(Zone); !ok {
						return fmt.Errorf("module '%s' is not a Zone; is %T", name, unm)
					}
					return nil
				},
			); err != nil {
				return err
			}
			h.Zones = append(h.Zones, raw)
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed layer4 connection handler '%s': nested blocks are not supported", wrapper)
		}
	}

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*HandleDNS)(nil)
	_ caddyfile.Unmarshaler = (*HandleDNS)(nil)
	_ layer4.NextHandler    = (*HandleDNS)(nil)
)

const (
	NamespaceRoot      = "layer4.handlers.dns"
	NamespaceCaches    = NamespaceRoot + ".caches"
	NamespaceProviders = NamespaceRoot + ".providers"
	NamespaceUpstreams = NamespaceRoot + ".upstreams"
	NamespaceZones     = NamespaceRoot + ".zones"
)

func CaddyContextGetVars(ctx caddy.Context) (map[string]interface{}, error) {
	varMap, ok := ctx.Value(layer4.VarsCtxKey).(map[string]interface{})
	if varMap == nil || !ok {
		return nil, fmt.Errorf("getting '%s' from the context: nil or invalid type", layer4.VarsCtxKey)
	}
	return varMap, nil
}
