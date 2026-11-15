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
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/miekg/dns"
)

func init() {
	caddy.RegisterModule(&ProviderText{})
}

// Provider is a Resources provider for authoritative zones.
type Provider interface {
	// GetResources returns Resources, i.e. a slice of dns.RR pointers, or nil and error if there is nothing to return.
	// A request message may be optionally taken into account to return a few relevant records only instead of all.
	// It may be useful when Provider connects to an external data source where a lot of resource records are stored.
	GetResources(*dns.Msg) (Resources, error)
}

// ProviderText is a Resources provider for authoritative zones.
// It loads static RFC 1035 style zone file lines and parses them via dns.ZoneParser.
type ProviderText struct {
	// AllowInclude permits usage of $INCLUDE directives in the zone file. If unset, it equals the handler-wide value.
	AllowInclude bool `json:"allow_include,omitempty"`
	// FallbackOrigin is a fallback origin value used before/unless $ORIGIN directive is defined in Records.
	// If unset, an authoritative zone pattern is used.
	FallbackOrigin string `json:"fallback_origin,omitempty"`
	// FallbackPath is a fallback filepath used to resolve relative $INCLUDE directives. By default, it is empty.
	// If AllowInclude is unset, FallbackPath is ignored.
	FallbackPath string `json:"fallback_path,omitempty"`
	// FallbackTTL is a fallback TTL value used before/unless $TTL directive is defined in Records.
	// If unset, it equals 3600 seconds.
	FallbackTTL caddy.Duration `json:"fallback_ttl,omitempty"`
	// Records contain RFC 1035 style zone file lines. Syntax:
	//	$ORIGIN abc.com.                       ; sets the pattern for resolving a relative domain name
	//  $TTL 86400                             ; sets the TTL for all records below with no TTL value
	// 	abc.com. 3600 IN MX 10 mail
	//	www 3600 IN A 10.9.8.7
	//	mail IN A 10.11.12.13
	//	$GENERATE 10-12 host-$ IN A 10.11.12.$ ; generates multiple records using a specified pattern
	//	$INCLUDE /etc/caddy/db.abc.com         ; includes another file, valid if AllowInclude is true
	// Note: $ORIGIN defaults to the zone pattern. $TTL defaults to refer to the zone-wide FallbackTTL.
	// Refer to the dns.ZoneParser docs for more information on scanning resource records.
	Records []string `json:"records,omitempty"`

	records []dns.RR
}

// CaddyModule returns the Caddy module information.
func (p *ProviderText) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  NamespaceProviders + ".text",
		New: func() caddy.Module { return new(ProviderText) },
	}
}

// GetResources implements Provider.GetResources.
func (p *ProviderText) GetResources(_ *dns.Msg) (Resources, error) {
	return p.GetRecords(), nil
}

// GetRecords returns the inner records.
func (p *ProviderText) GetRecords() []dns.RR {
	return p.records
}

// ParseRecords converts the zone file lines into a list of pointers to dns.RR.
func (p *ProviderText) ParseRecords(lines []string) ([]dns.RR, error) {
	zp := dns.NewZoneParser(strings.NewReader(strings.Join(lines, "\n")), p.FallbackOrigin, p.FallbackPath)
	zp.SetDefaultTTL(DurationToSeconds(p.FallbackTTL))
	zp.SetIncludeAllowed(p.AllowInclude)

	rrs := make([]dns.RR, 0, len(p.Records))
	for {
		rr, ok := zp.Next()
		if !ok {
			break
		}
		rrs = append(rrs, rr)
	}
	return rrs, zp.Err()
}

// Provision prepares z's internal structures.
func (p *ProviderText) Provision(ctx caddy.Context) error {
	vars, err := CaddyContextGetVars(ctx)
	if err != nil {
		return err
	}

	if len(p.FallbackOrigin) == 0 {
		p.FallbackOrigin = vars[FallbackOriginVarCtxKey].(string)
	}
	if p.FallbackTTL <= 0 {
		p.FallbackTTL = caddy.Duration(DefProviderTextFallbackTTL)
	}

	repl := caddy.NewReplacer()
	lines := make([]string, 0, len(p.Records))
	for _, line := range p.Records {
		line = repl.ReplaceAll(line, "")
		lines = append(lines, line)
	}
	p.records, err = p.ParseRecords(lines)

	return err
}

// UnmarshalCaddyfile sets up the ProviderText from Caddyfile tokens. Syntax:
//
//	text {
//		allow_include
//		fallback_origin <string>
//		fallback_path <string>
//		fallback_ttl <duration>
//		records {
//			[<zone_file_lines...>]
//		}
//	}
func (p *ProviderText) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line arguments are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	var hasAllowInclude, hasDefaultOrigin, hasDefaultPath, hasDefaultTTL, hasRecords bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "allow_include":
			if err := UnmarshalCaddyfileOptionBool(d, optionName, &p.AllowInclude, &hasAllowInclude); err != nil {
				return err
			}
		case "fallback_origin":
			if err := UnmarshalCaddyfileOptionString(d, optionName, &p.FallbackOrigin, &hasDefaultOrigin); err != nil {
				return err
			}
		case "fallback_path":
			if err := UnmarshalCaddyfileOptionString(d, optionName, &p.FallbackPath, &hasDefaultPath); err != nil {
				return err
			}
		case "fallback_ttl":
			if err := UnmarshalCaddyfileOptionDuration(d, optionName, &p.FallbackTTL, &hasDefaultTTL); err != nil {
				return err
			}
		case "records":
			if hasRecords {
				return d.Errf("duplicate option '%s'", optionName)
			}
			if d.CountRemainingArgs() > 0 {
				return d.ArgErr()
			}
			for d.NextBlock(nesting + 1) {
				p.Records = append(p.Records, d.Val()+" "+strings.Join(d.RemainingArgs(), " "))
			}
			hasRecords = true
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed DNS provider '%s': nested blocks are not supported", wrapper)
		}
	}

	return nil
}

// Interface guards
var (
	_ Provider              = (*ProviderText)(nil)
	_ caddy.Provisioner     = (*ProviderText)(nil)
	_ caddyfile.Unmarshaler = (*ProviderText)(nil)
)

const (
	DefProviderTextFallbackTTL = 3600 * time.Second

	FallbackOriginVarCtxKey = "fallback_origin"
)
