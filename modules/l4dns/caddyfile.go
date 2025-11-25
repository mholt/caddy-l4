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
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func UnmarshalCaddyfileOptionBool(d *caddyfile.Dispenser, name string, value *bool, dup *bool) error {
	if *dup {
		return d.Errf("duplicate option '%s'", name)
	}
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}
	*value, *dup = true, true
	return nil
}

func UnmarshalCaddyfileOptionDuration(d *caddyfile.Dispenser, name string, value *caddy.Duration, dup *bool) error {
	if *dup {
		return d.Errf("duplicate option '%s'", name)
	}
	if d.CountRemainingArgs() > 1 || !d.NextArg() {
		return d.ArgErr()
	}
	dur, err := caddy.ParseDuration(d.Val())
	if err != nil {
		return d.Errf("parsing option '%s' duration: %v", name, err)
	}
	*value, *dup = caddy.Duration(dur), true
	return nil
}

func UnmarshalCaddyfileOptionModule(d *caddyfile.Dispenser, name string, value *json.RawMessage, dup *bool,
	namespace string, inlineKey string, interfaceCheck func(string, caddyfile.Unmarshaler) error,
) error {
	if *dup {
		return d.Errf("duplicate option '%s'", name)
	}
	if !d.NextArg() {
		return d.ArgErr()
	}
	modName := d.Val()
	mod, err := caddy.GetModule(namespace + "." + modName)
	if err != nil {
		return d.Errf("getting module '%s': %v", modName, err)
	}
	unm, ok := mod.New().(caddyfile.Unmarshaler)
	if !ok {
		return d.Errf("module '%s' is not a Caddyfile unmarshaler", modName)
	}
	err = unm.UnmarshalCaddyfile(d.NewFromNextSegment())
	if err != nil {
		return err
	}
	err = interfaceCheck(modName, unm)
	if err != nil {
		return err
	}
	if len(inlineKey) > 0 {
		*value, err = layer4.SetModuleNameInline(inlineKey, modName, caddyconfig.JSON(unm, nil))
		if err != nil {
			return err
		}
		*dup = true
	} else {
		*value, *dup = caddyconfig.JSON(unm, nil), true
	}
	return nil
}

func UnmarshalCaddyfileOptionString(d *caddyfile.Dispenser, name string, value *string, dup *bool) error {
	if *dup {
		return d.Errf("duplicate option '%s'", name)
	}
	if d.CountRemainingArgs() > 1 || !d.NextArg() {
		return d.ArgErr()
	}
	*value, *dup = d.Val(), true
	return nil
}

func UnmarshalCaddyfileOptionUint16(d *caddyfile.Dispenser, name string, value *uint16, dup *bool) error {
	if *dup {
		return d.Errf("duplicate option '%s'", name)
	}
	if d.CountRemainingArgs() > 1 || !d.NextArg() {
		return d.ArgErr()
	}
	val, err := strconv.ParseUint(d.Val(), 10, 16)
	if err != nil {
		return d.Errf("parsing option '%s' value: %v", name, err)
	}
	*value, *dup = uint16(val), true
	return nil
}
