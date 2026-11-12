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
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/miekg/dns"
)

func init() {
	caddy.RegisterModule(&ZoneAuth{})
	caddy.RegisterModule(&ZoneRec{})
	caddy.RegisterModule(&ZoneRef{})
}

// Zone is a shared interface each DNS zone module must implement.
type Zone interface {
	// GetPattern returns a fully qualified domain name pattern this zone serves.
	GetPattern() string
	// GetSecret returns a transaction signature secret this zone validates. Only base64 format is supported.
	GetSecret() string

	Dispatch(*Inbox, *Outbox) error
}

// ZoneAuth is an uthoritative DNS zone. It uses providers to obtain DNS records it serves.
type ZoneAuth struct {
	// ExpandCname enables canonical names expansion. By default, it is disabled. It only takes into account
	// the resource records available to this zone from Provider, i.e. no other zones are requested.
	ExpandCname bool `json:"expand_cname,omitempty"`
	// Pattern is a fully qualified domain name pattern this zone serves. It is also used as the default origin.
	// It may contain a single dot representing the root zone, or any valid domain name ending with a dot.
	// Besides, it may contain placeholders which are evaluated at provision.
	Pattern string `json:"pattern,omitempty"`
	// Secret is a transaction signature secret this zone validates. It may contain placeholders evaluated at provision.
	Secret string `json:"secret,omitempty"`
	// SupportWildcard enables wildcard matching support. By default, it is disabled.
	SupportWildcard bool `json:"support_wildcard,omitempty"`
	// Provider contains a zone-wide resource records provider.
	Provider json.RawMessage `json:"provider,omitempty" caddy:"namespace=layer4.handlers.dns.providers inline_key=name"`

	pattern string
	secret  string

	provider Provider
}

// CaddyModule returns the Caddy module information.
func (z *ZoneAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  NamespaceZones + ".auth",
		New: func() caddy.Module { return new(ZoneAuth) },
	}
}

// Dispatch handles authoritative zone requests.
func (z *ZoneAuth) Dispatch(in *Inbox, out *Outbox) error {
	// Populate the outgoing message internal structures
	inMsg, outMsg := in.GetMsg(), new(dns.Msg)
	outMsg.SetReply(inMsg)

	// Validate a transaction signature if provided in the incoming message
	inSig, inSigErr := in.Validate(z.secret, nil)
	if inSigErr != nil && !errors.Is(inSigErr, ErrInboxValidateSkipped) &&
		!errors.Is(inSigErr, ErrInboxValidateUnsigned) && !errors.Is(inSigErr, ErrInboxValidateNoSecret) {
		// TODO(vnxme): implement more response codes for TSIG
		// See https://www.rfc-editor.org/rfc/rfc2845
		outMsg.Rcode = dns.RcodeNotAuth
		return out.Push(outMsg)
	}

	// Obtain Resources, i.e. a slice of pointers to relevant or all available items of dns.RR
	res, err := z.provider.GetResources(inMsg)
	if err != nil || res == nil {
		outMsg.Rcode = dns.RcodeServerFailure
		return out.Push(outMsg)
	}

	// This is an authoritative zone
	outMsg.Authoritative = true

	err = res.Consume(inMsg, outMsg, z.SupportWildcard, z.ExpandCname, true)
	if err != nil {
		outMsg.Rcode = dns.RcodeRefused
		return out.Push(outMsg)
	}

	// If the incoming message is signed and its signature is valid, sign the outgoing message
	if outMsg.Rcode == dns.RcodeSuccess && inSig != nil && inSigErr == nil {
		return out.PushSign(outMsg, z.secret, inSig)
	}

	return out.Push(outMsg)
}

// GetPattern returns z's pattern after provisioning.
func (z *ZoneAuth) GetPattern() string {
	return z.pattern
}

// GetSecret return z's secret after provisioning.
func (z *ZoneAuth) GetSecret() string {
	return z.secret
}

// Provision prepares z's internal structures.
func (z *ZoneAuth) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	z.pattern = repl.ReplaceAll(z.Pattern, "")
	z.secret = repl.ReplaceAll(z.Secret, "")

	vars, err := CaddyContextGetVars(ctx)
	if err != nil {
		return err
	}
	vars[FallbackOriginVarCtxKey] = z.pattern

	if len(z.Provider) > 0 {
		mod, err := ctx.LoadModule(z, "Provider")
		if err != nil {
			return fmt.Errorf("loading DNS provider: %v", err)
		}
		p, ok := mod.(Provider)
		if !ok {
			return fmt.Errorf("loading DNS provider module: expected Provider, got %T", mod)
		}
		z.provider = p
	}

	return nil
}

// UnmarshalCaddyfile sets up the ZoneAuth from Caddyfile tokens. Syntax:
//
//	auth <pattern> [<secret>] {
//		expand_cname
//		provider <name> [<args...>] {
//			[<options...>]
//		}
//		support_wildcard
//	}
func (z *ZoneAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Only one or two same-line arguments are supported
	if d.CountRemainingArgs() > 2 || !d.NextArg() {
		return d.ArgErr()
	}

	z.Pattern = d.Val()
	if d.NextArg() {
		z.Secret = d.Val()
	}

	var hasExpandCname, hasProvider, hasSupportWildcard bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "expand_cname":
			if err := UnmarshalCaddyfileOptionBool(d, optionName, &z.ExpandCname, &hasExpandCname); err != nil {
				return err
			}
		case "provider":
			if err := UnmarshalCaddyfileOptionModule(d, optionName, &z.Provider, &hasProvider,
				NamespaceProviders,
				"name",
				func(name string, unm caddyfile.Unmarshaler) error {
					if _, ok := unm.(Provider); !ok {
						return fmt.Errorf("module '%s' is not a Provider; is %T", name, unm)
					}
					return nil
				},
			); err != nil {
				return err
			}
		case "support_wildcard":
			if err := UnmarshalCaddyfileOptionBool(d, optionName, &z.SupportWildcard, &hasSupportWildcard); err != nil {
				return err
			}
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed DNS zone '%s': nested blocks are not supported", wrapper)
		}
	}

	return nil
}

// ZoneRec is a recursive DNS zone. It uses upstreams to obtain DNS records it serves.
type ZoneRec struct {
	// Pattern is a fully qualified domain name to serve this zone for.
	// It may contain a single dot representing the root zone, or any valid domain name ending with a dot.
	// Besides, it may contain placeholders which are evaluated at provision.
	Pattern string `json:"pattern,omitempty"`

	// Cache contains a zone-wide raw DNS cache configuration.
	Cache json.RawMessage `json:"cache,omitempty" caddy:"namespace=layer4.handlers.dns.caches inline_key=name"`

	// Upstreams contains raw DNS upstream configurations.
	Upstreams []json.RawMessage `json:"upstreams,omitempty" caddy:"namespace=layer4.handlers.dns.upstreams inline_key=name"`
	// UpstreamsRandom enables upstream shuffling. By default, it is disabled.
	UpstreamsRandom bool `json:"upstreams_random,omitempty"`
	// UpstreamsSequential disables concurrent upstream dialing. By default, it is disabled.
	UpstreamsSequential bool `json:"upstreams_sequential,omitempty"`
	// UpstreamsTimeout is a zone-wide timeout for handling all upstreams. If unset, it equals the handler-wide value.
	UpstreamsTimeout caddy.Duration `json:"upstreams_timeout,omitempty"`

	pattern string

	cache     Cache
	upstreams []Upstream
}

// CaddyModule returns the Caddy module information.
func (z *ZoneRec) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  NamespaceZones + ".rec",
		New: func() caddy.Module { return new(ZoneRec) },
	}
}

// Dispatch handles recursive zone requests.
func (z *ZoneRec) Dispatch(in *Inbox, out *Outbox) error {
	inMsg := in.GetMsg()
	var outMsg *dns.Msg

	l := len(z.upstreams)
	if l > 0 {
		var err error
		if z.cache != nil {
			outMsg, err = z.cache.Get(inMsg)
		} else {
			err = ErrZoneHasNoCache
		}

		if err != nil {
			t := time.NewTimer(time.Duration(z.UpstreamsTimeout))
			ch := make(chan *dns.Msg, l)

			f := func(u Upstream, r *dns.Msg, ch chan *dns.Msg) bool {
				msg, err := u.Exchange(r)
				if err == nil && msg != nil {
					ch <- msg
					return true
				}
				return false
			}

			if l > 1 { // Multiple upstreams
				if z.UpstreamsSequential { // Sequential exchanging
					if z.UpstreamsRandom { // Random iteration order
						for _, i := range rand.Perm(l) {
							if f(z.upstreams[i], inMsg, ch) {
								break
							}
						}
					} else { // Fixed (default) iteration order
						for _, u := range z.upstreams {
							if f(u, inMsg, ch) {
								break
							}
						}
					}
				} else { // Concurrent (default) exchanging
					if z.UpstreamsRandom { // Random iteration order
						for _, i := range rand.Perm(l) {
							go f(z.upstreams[i], inMsg, ch)
						}
					} else { // Fixed (default) iteration order
						for _, u := range z.upstreams {
							go f(u, inMsg, ch)
						}
					}
				}
			} else { // Single upstream: UpstreamsRandom and UpstreamsSequential flags make no sense
				f(z.upstreams[0], inMsg, ch)
			}

			select {
			case <-t.C:
				break
			case outMsg = <-ch:
				if !t.Stop() {
					<-t.C
				}
				if z.cache != nil {
					_ = z.cache.Set(inMsg, outMsg)
				}
				break
			}
		}
	}

	if outMsg == nil {
		outMsg = new(dns.Msg)
		outMsg.SetRcode(inMsg, dns.RcodeServerFailure)
	}

	return out.Push(outMsg)
}

// GetPattern returns z's pattern after provisioning.
func (z *ZoneRec) GetPattern() string {
	return z.pattern
}

// GetSecret return z's secret after provisioning.
func (z *ZoneRec) GetSecret() string {
	return ""
}

// Provision prepares z's internal structures.
func (z *ZoneRec) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	z.pattern = repl.ReplaceAll(z.Pattern, "")

	if z.UpstreamsTimeout <= 0 {
		z.UpstreamsTimeout = caddy.Duration(DefZoneRecUpstreamsTimeout)
	}

	if len(z.Cache) > 0 {
		mod, err := ctx.LoadModule(z, "Cache")
		if err != nil {
			return fmt.Errorf("loading DNS cache: %v", err)
		}
		c, ok := mod.(Cache)
		if !ok {
			return fmt.Errorf("loading DNS cache module: expected Cache, got %T", mod)
		}
		z.cache = c
	}

	mods, err := ctx.LoadModule(z, "Upstreams")
	if err != nil {
		return fmt.Errorf("loading DNS upstreams: %v", err)
	}
	for _, mod := range mods.([]interface{}) {
		u, ok := mod.(Upstream)
		if !ok {
			return fmt.Errorf("loading DNS upstream module: expected Upstream, got %T", mod)
		}
		z.upstreams = append(z.upstreams, u)
	}

	return nil
}

// UnmarshalCaddyfile sets up the ZoneRec from Caddyfile tokens. Syntax:
//
//	rec <pattern> {
//		cache <name> [<args...>] {
//			[<options...>]
//		}
//
//		upstream <name> [<args...>] {
//			[<options...>]
//		}
//		upstreams_random
//		upstreams_sequential
//		upstreams_timeout <duration>
//	}
func (z *ZoneRec) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Only one same-line argument is supported
	if d.CountRemainingArgs() > 1 || !d.NextArg() {
		return d.ArgErr()
	}

	z.Pattern = d.Val()

	var hasCache, hasUpstreamsRandom, hasUpstreamsSequential, hasUpstreamsTimeout bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "cache":
			if err := UnmarshalCaddyfileOptionModule(d, optionName, &z.Cache, &hasCache,
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
		case "upstream":
			var (
				dup bool
				raw json.RawMessage
			)
			if err := UnmarshalCaddyfileOptionModule(d, optionName, &raw, &dup,
				NamespaceUpstreams,
				"name",
				func(name string, unm caddyfile.Unmarshaler) error {
					if _, ok := unm.(Upstream); !ok {
						return fmt.Errorf("module '%s' is not an Upstream; is %T", name, unm)
					}
					return nil
				},
			); err != nil {
				return err
			}
			z.Upstreams = append(z.Upstreams, raw)
		case "upstreams_random":
			if err := UnmarshalCaddyfileOptionBool(d, optionName, &z.UpstreamsRandom, &hasUpstreamsRandom); err != nil {
				return err
			}
		case "upstreams_sequential":
			if err := UnmarshalCaddyfileOptionBool(d, optionName, &z.UpstreamsSequential, &hasUpstreamsSequential); err != nil {
				return err
			}
		case "upstreams_timeout":
			if err := UnmarshalCaddyfileOptionDuration(d, optionName, &z.UpstreamsTimeout, &hasUpstreamsTimeout); err != nil {
				return err
			}
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed DNS zone '%s': nested blocks are not supported", wrapper)
		}
	}

	return nil
}

// ZoneRef is a reflective DNS zone. It sends back the client's IP address.
type ZoneRef struct {
	// Pattern is a fully qualified domain name to serve this zone for.
	// It may contain a single dot representing the root zone, or any valid domain name ending with a dot.
	// Besides, it may contain placeholders which are evaluated at provision.
	Pattern string `json:"pattern,omitempty"`
	// Secret is a TSIG secret. It may contain placeholders which are evaluated at provision.
	Secret string `json:"secret,omitempty"`

	// TTL is a zone-wide default TTL value. If unset, it equals 0 seconds.
	TTL caddy.Duration `json:"ttl,omitempty"`

	pattern string
	secret  string

	ttl uint32
}

func (z *ZoneRef) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  NamespaceZones + ".ref",
		New: func() caddy.Module { return new(ZoneRef) },
	}
}

func (z *ZoneRef) ComposeAddrRR(in *Inbox) dns.RR {
	var rIP net.IP
	rAddr := in.GetConn().RemoteAddr()
	if addr, ok := rAddr.(*net.TCPAddr); ok {
		rIP = addr.IP
	}
	if addr, ok := rAddr.(*net.UDPAddr); ok {
		rIP = addr.IP
	}
	if rIP == nil {
		return nil
	}

	rIPv4 := rIP.To4()
	if rIPv4 != nil {
		return &dns.A{
			Hdr: dns.RR_Header{Name: in.GetMsg().Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: z.ttl},
			A:   rIPv4,
		}
	} else {
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: in.GetMsg().Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: z.ttl},
			AAAA: rIP,
		}
	}
}

func (z *ZoneRef) ComposeAuthRR(in *Inbox) dns.RR {
	q := in.GetMsg().Question[0]

	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: z.ttl},
		Ns:      fmt.Sprintf("ns.%s", q.Name),
		Mbox:    fmt.Sprintf("mail.%s", q.Name),
		Refresh: 24 * 3600,
		Retry:   2 * 3600,
		Expire:  7 * 24 * 3600,
		Minttl:  2 * 24 * 3600,
		Serial:  uint32(min(time.Now().Unix()-time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), 2^32-1)), // #nosec G115
	}
}

func (z *ZoneRef) ComposeTextRR(in *Inbox) dns.RR {
	conn := in.GetConn()
	lAddr, rAddr := conn.LocalAddr(), conn.RemoteAddr()
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: in.GetMsg().Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: z.ttl},
		Txt: []string{
			fmt.Sprintf("protocol=%s; local=%s; remote=%s", rAddr.Network(), lAddr.String(), rAddr.String()),
		},
	}
}

// Dispatch handles reflective zone requests.
// Note: adapted from https://github.com/miekg/exdns/blob/master/reflect/reflect.go in August 2024.
func (z *ZoneRef) Dispatch(in *Inbox, out *Outbox) error {
	// Populate the outgoing message internal structures
	inMsg, outMsg := in.GetMsg(), new(dns.Msg)
	outMsg.SetReply(inMsg)

	// Validate a transaction signature if provided in the incoming message
	inSig, inSigErr := in.Validate(z.secret, nil)
	if inSigErr != nil && !errors.Is(inSigErr, ErrInboxValidateSkipped) &&
		!errors.Is(inSigErr, ErrInboxValidateUnsigned) && !errors.Is(inSigErr, ErrInboxValidateNoSecret) {
		// TODO(vnxme): implement more response codes for TSIG
		// See https://www.rfc-editor.org/rfc/rfc2845
		outMsg.Rcode = dns.RcodeNotAuth
		return out.Push(outMsg)
	}

	// This is an authoritative zone
	outMsg.Authoritative = true

	// We are sure that r.Question has at least one element because of the dns.DefaultMsgAcceptFunc checks
	q := inMsg.Question[0]

	// Compose address and text resource records for the response message
	a, t := z.ComposeAddrRR(in), z.ComposeTextRR(in)

	// Populate the answer and extra sections of the response message
	switch q.Qtype {
	case dns.TypeTXT:
		outMsg.Answer = append(outMsg.Answer, t)
		if a != nil {
			outMsg.Extra = append(outMsg.Extra, a)
		}
	default:
		fallthrough
	case dns.TypeAAAA, dns.TypeA:
		if a != nil {
			outMsg.Answer = append(outMsg.Answer, a)
		}
		outMsg.Extra = append(outMsg.Extra, t)
	case dns.TypeAXFR, dns.TypeIXFR:
		soa := z.ComposeAuthRR(in)
		outMsg.Answer = append(outMsg.Answer, soa, t)
		if a != nil {
			outMsg.Answer = append(outMsg.Answer, a)
		}
		outMsg.Answer = append(outMsg.Answer, soa)
	}

	// If the incoming message is signed and its signature is valid, sign the outgoing message
	if inSig != nil && inSigErr == nil {
		return out.PushSign(outMsg, z.secret, inSig)
	}

	return out.Push(outMsg)
}

// GetPattern returns z's pattern after provisioning.
func (z *ZoneRef) GetPattern() string {
	return z.pattern
}

// GetSecret returns z's secret after provisioning.
func (z *ZoneRef) GetSecret() string {
	return z.secret
}

// Provision prepares z's internal structures.
func (z *ZoneRef) Provision(_ caddy.Context) error {
	repl := caddy.NewReplacer()
	z.pattern = repl.ReplaceAll(z.Pattern, "")
	z.secret = repl.ReplaceAll(z.Secret, "")

	if z.TTL < 0 {
		z.TTL = -z.TTL
	}
	z.ttl = DurationToSeconds(z.TTL)

	return nil
}

// UnmarshalCaddyfile sets up the ZoneRef from Caddyfile tokens. Syntax:
//
//	ref <pattern> [<secret>] {
//		ttl <duration>
//	}
func (z *ZoneRef) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Only one or two same-line arguments are supported
	if d.CountRemainingArgs() > 2 || !d.NextArg() {
		return d.ArgErr()
	}

	z.Pattern = d.Val()
	if d.NextArg() {
		z.Secret = d.Val()
	}

	var hasTTL bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "ttl":
			if err := UnmarshalCaddyfileOptionDuration(d, optionName, &z.TTL, &hasTTL); err != nil {
				return err
			}
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed DNS zone '%s': nested blocks are not supported", wrapper)
		}
	}

	return nil
}

// Interface guards
var (
	_ Zone = (*ZoneAuth)(nil)
	_ Zone = (*ZoneRec)(nil)
	_ Zone = (*ZoneRef)(nil)

	_ caddy.Provisioner = (*ZoneAuth)(nil)
	_ caddy.Provisioner = (*ZoneRec)(nil)
	_ caddy.Provisioner = (*ZoneRef)(nil)

	_ caddyfile.Unmarshaler = (*ZoneAuth)(nil)
	_ caddyfile.Unmarshaler = (*ZoneRec)(nil)
	_ caddyfile.Unmarshaler = (*ZoneRef)(nil)
)

var ErrZoneHasNoCache = errors.New("no cache")

const (
	DefZoneRecUpstreamsTimeout = 10 * time.Second
)
