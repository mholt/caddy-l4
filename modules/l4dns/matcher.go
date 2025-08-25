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
	"context"
	"encoding/binary"
	"io"
	"net"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/miekg/dns"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchDNS{})
}

// MatchDNS is able to match connections that look like DNS protocol.
// Note: DNS messages sent via TCP are 2 bytes longer then those sent via UDP. Consequently, if Caddy listens on TCP,
// it has to proxy DNS messages to TCP upstreams only. The same is true for UDP. No TCP/UDP mixing is allowed.
// However, it's technically possible: an intermediary handler is required to add/strip 2 bytes before/after proxy.
// Please open a feature request and describe your use case if you need TCP/UDP mixing.
type MatchDNS struct {
	// Allow contains an optional list of rules to match the question section of the DNS request message against.
	// The matcher returns false if not matched by any of them (in the absence of any deny rules).
	Allow MatchDNSRules `json:"allow,omitempty"`
	// Deny contains an optional list of rules to match the question section of the DNS request message against.
	// The matcher returns false if matched by any of them  (in the absence of any allow rules).
	Deny MatchDNSRules `json:"deny,omitempty"`

	// If DefaultDeny is true, DNS request messages that haven't been matched by any allow and deny rules are denied.
	// The default action is allow. Use it to make the filter more restrictive when the rules aren't exhaustive.
	DefaultDeny bool `json:"default_deny,omitempty"`
	// If PreferAllow is true, DNS request messages that have been matched by both allow and deny rules are allowed.
	// The default action is deny. Use it to make the filter less restrictive when the rules are mutually exclusive.
	PreferAllow bool `json:"prefer_allow,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (m *MatchDNS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.dns",
		New: func() caddy.Module { return new(MatchDNS) },
	}
}

// Match returns true if the connection bytes represent a valid DNS request message.
func (m *MatchDNS) Match(cx *layer4.Connection) (bool, error) {
	var (
		msgBuf   []byte
		msgBytes uint16
	)

	// Detect the connection protocol: TCP or UDP.
	// Note: all non-TCP connections are treated as UDP, so no TCP packets could be matched while testing
	// with net.Pipe() unless a valid cx.LocalAddr() response is provided using a fakeTCPConn wrapper.
	if _, ok := cx.LocalAddr().(*net.TCPAddr); ok {
		// Read the first 2 bytes, validate them and adjust the DNS message length
		// Note: these 2 bytes represent the length of the remaining part of the packet
		// as a big endian uint16 number.
		err := binary.Read(cx, binary.BigEndian, &msgBytes)
		if err != nil || msgBytes < dnsHeaderBytes || msgBytes > dns.MaxMsgSize {
			return false, err
		}

		// Read the remaining bytes
		msgBuf = make([]byte, msgBytes)
		_, err = io.ReadFull(cx, msgBuf)
		if err != nil {
			return false, err
		}

		// Validate the remaining connection buffer
		// Note: if at least 1 byte remains, we can technically be sure, the protocol isn't DNS.
		// This behaviour may be changed in the future if there are many false negative matches.
		extraBuf := make([]byte, 1)
		_, err = io.ReadFull(cx, extraBuf)
		if err == nil {
			return false, nil
		}
	} else {
		// Read a minimum number of bytes
		msgBuf = make([]byte, dnsHeaderBytes)
		n, err := io.ReadAtLeast(cx, msgBuf, int(dnsHeaderBytes))
		if err != nil {
			return false, err
		}

		// Read the remaining bytes and validate their length
		var nn int
		tmpBuf := make([]byte, dns.MinMsgSize)
		for err == nil {
			nn, err = io.ReadAtLeast(cx, tmpBuf, 1)
			msgBuf = append(msgBuf, tmpBuf[:nn]...)
			n += nn
		}
		if n > dns.MaxMsgSize {
			return false, nil
		}
		msgBytes = uint16(n) //nolint:gosec // disable G115
	}

	// Unpack the DNS message with a third-party library
	// Note: it doesn't return an error if there are any bytes remaining in the buffer after parsing has completed.
	msg := new(dns.Msg)
	if err := msg.Unpack(msgBuf); err != nil {
		return false, nil
	}

	// Ensure there are no extra bytes in the packet
	if msg.Len() != int(msgBytes) {
		return false, nil
	}

	// Filter out invalid DNS request messages
	if len(msg.Question) == 0 || msg.Response || msg.Rcode != dns.RcodeSuccess || msg.Zero {
		return false, nil
	}

	// Apply the allow and deny rules to the question section of the DNS request message
	hasNoAllow, hasNoDeny := len(m.Allow) == 0, len(m.Deny) == 0
	if !hasNoAllow || !hasNoDeny {
		for _, q := range msg.Question {
			// Filter out DNS request messages with invalid question classes
			classValue, classFound := dns.ClassToString[q.Qclass]
			if !classFound {
				return false, nil
			}

			// Filter out DNS request messages with invalid question types
			typeValue, typeFound := dns.TypeToString[q.Qtype]
			if !typeFound {
				return false, nil
			}

			denied := m.Deny.Match(cx.Context, classValue, typeValue, q.Name)
			// If only deny rules are provided, filter out DNS request messages with denied question sections.
			// In other words, allow all unless explicitly denied.
			if hasNoAllow && !hasNoDeny && denied {
				return false, nil
			}

			allowed := m.Allow.Match(cx.Context, classValue, typeValue, q.Name)
			// If only allow rules are provided, filter out DNS request messages with not allowed question sections.
			// In other words, deny all unless explicitly allowed.
			if hasNoDeny && !hasNoAllow && !allowed {
				return false, nil
			}

			// If both rules are provided and the question section is both allowed and denied, deny rules prevail
			// unless the PreferAllow is set to true. If both rules are provided and the question section is
			// neither allowed nor denied, it is allowed unless the DefaultDeny flag is set to true.
			if denied {
				if !allowed || !m.PreferAllow {
					return false, nil
				}
			} else {
				if !allowed && m.DefaultDeny {
					return false, nil
				}
			}
		}
	}

	// Append the current DNS message to the messages list (it might be useful for other matchers or handlers)
	appendMessage(cx, msg)

	return true, nil
}

// Provision prepares m's allow and deny rules.
func (m *MatchDNS) Provision(cx caddy.Context) error {
	err := m.Allow.Provision(cx)
	if err != nil {
		return err
	}
	err = m.Deny.Provision(cx)
	if err != nil {
		return err
	}
	return nil
}

// UnmarshalCaddyfile sets up the MatchDNS from Caddyfile tokens. Syntax:
//
//	dns {
//		<allow|deny> <*|name> [<*|type> [<*|class>]]
//		<allow_regexp|deny_regexp> <*|name_pattern> [<*|type_pattern> [<*|class_pattern>]]
//		default_deny
//		prefer_allow
//	}
//	dns
//
// Note: multiple allow and deny options are allowed. If default_deny is set, DNS request messages that haven't been
// matched by any allow and deny rules are denied (the default action is allow). If prefer_allow is set, DNS request
// messages that have been matched by both allow and deny rules are allowed (the default action is deny). An asterisk
// should be used to skip filtering the corresponding question section field, i.e. it will match any value provided.
func (m *MatchDNS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line arguments are supported
	if d.CountRemainingArgs() != 0 {
		return d.ArgErr()
	}

	var hasDefaultDeny, hasPreferAllow bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "allow", "allow_regexp", "deny", "deny_regexp":
			if d.CountRemainingArgs() == 0 || d.CountRemainingArgs() > 3 {
				return d.ArgErr()
			}
			isRegexp := strings.HasSuffix(optionName, "regexp")
			r := new(MatchDNSRule)
			_, val := d.NextArg(), d.Val()
			if val != dnsSpecialAny {
				if isRegexp {
					r.NameRegexp = val
				} else {
					r.Name = val
				}
			}
			if d.NextArg() {
				val = d.Val()
				if val != dnsSpecialAny {
					if isRegexp {
						r.TypeRegexp = val
					} else {
						r.Type = val
					}
				}
			}
			if d.NextArg() {
				val = d.Val()
				if val != dnsSpecialAny {
					if isRegexp {
						r.ClassRegexp = val
					} else {
						r.Class = val
					}
				}
			}
			if strings.HasPrefix(optionName, "deny") {
				m.Deny = append(m.Deny, r)
			} else {
				m.Allow = append(m.Allow, r)
			}
		case "default_deny":
			if hasDefaultDeny {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() > 0 {
				return d.ArgErr()
			}
			m.DefaultDeny, hasDefaultDeny = true, true
		case "prefer_allow":
			if hasPreferAllow {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() > 0 {
				return d.ArgErr()
			}
			m.PreferAllow, hasPreferAllow = true, true
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option %s: nested blocks are not supported", wrapper, optionName)
		}
	}

	return nil
}

// MatchDNSRules may contain a number of MatchDNSRule instances. An empty MatchDNSRules instance won't match anything.
type MatchDNSRules []*MatchDNSRule

func (rs *MatchDNSRules) Match(cx context.Context, qClass string, qType string, qName string) bool {
	for _, r := range *rs {
		if r.Match(cx, qClass, qType, qName) {
			return true
		}
	}
	return false
}

func (rs *MatchDNSRules) Provision(cx caddy.Context) error {
	for _, r := range *rs {
		if err := r.Provision(cx); err != nil {
			return err
		}
	}
	return nil
}

// MatchDNSRule represents a set of filters to match against the question section of a DNS request message.
// Full and regular expression matching filters are supported. If both filters are provided for a single field,
// the full matcher is evaluated first. An empty MatchDNSRule will match anything.
type MatchDNSRule struct {
	// Class may contain a value to match the question class. Use upper case letters, e.g. "IN", "CH", "ANY".
	// See the full list of valid class values in dns.StringToClass.
	Class string `json:"class,omitempty"`
	// ClassRegexp may contain a regular expression to match the question class. E.g. "^(IN|CH)$".
	// See the full list of valid class values in dns.StringToClass.
	ClassRegexp string `json:"class_regexp,omitempty"`
	// Name may contain a value to match the question domain name. E.g. "example.com.".
	// The domain name is provided in lower case ending with a dot.
	Name string `json:"name,omitempty"`
	// NameRegexp may contain a regular expression to match the question domain name.
	// E.g. "^(|[-0-9a-z]+\.)example\.com\.$". The domain name is provided in lower case ending with a dot.
	NameRegexp string `json:"name_regexp,omitempty"`
	// Type may contain a value to match the question type. Use upper case letters, e.g. "A", "MX", "NS".
	// See the full list of valid type values in dns.StringToType.
	Type string `json:"type,omitempty"`
	// TypeRegexp may contain a regular expression to match the question type. E.g. "^(MX|NS)$".
	// See the full list of valid type values in dns.StringToType.
	TypeRegexp string `json:"type_regexp,omitempty"`

	classRegexp *regexp.Regexp
	nameRegexp  *regexp.Regexp
	typeRegexp  *regexp.Regexp
}

func (r *MatchDNSRule) Match(cx context.Context, qClass string, qType string, qName string) bool {
	repl := cx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// Validate the question class
	classFilter := repl.ReplaceAll(r.Class, "")
	if (len(classFilter) > 0 && qClass != classFilter) ||
		len(r.ClassRegexp) > 0 && !r.classRegexp.MatchString(qClass) {
		return false
	}

	// Validate the question type
	typeFilter := repl.ReplaceAll(r.Type, "")
	if (len(typeFilter) > 0 && qType != typeFilter) ||
		len(r.TypeRegexp) > 0 && !r.typeRegexp.MatchString(qType) {
		return false
	}

	// Validate the question domain name
	nameFilter := repl.ReplaceAll(r.Name, "")
	if (len(nameFilter) > 0 && qName != nameFilter) ||
		(len(r.NameRegexp) > 0 && !r.nameRegexp.MatchString(qName)) {
		return false
	}

	return true
}

func (r *MatchDNSRule) Provision(_ caddy.Context) (err error) {
	repl := caddy.NewReplacer()
	r.classRegexp, err = regexp.Compile(repl.ReplaceAll(r.ClassRegexp, ""))
	if err != nil {
		return err
	}
	r.typeRegexp, err = regexp.Compile(repl.ReplaceAll(r.TypeRegexp, ""))
	if err != nil {
		return err
	}
	r.nameRegexp, err = regexp.Compile(repl.ReplaceAll(r.NameRegexp, ""))
	if err != nil {
		return err
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchDNS)(nil)
	_ caddyfile.Unmarshaler = (*MatchDNS)(nil)
	_ layer4.ConnMatcher    = (*MatchDNS)(nil)

	_ caddy.Provisioner = (*MatchDNSRules)(nil)
	_ caddy.Provisioner = (*MatchDNSRule)(nil)
)

const (
	dnsHeaderBytes uint16 = 12 // read this many bytes to parse a DNS message header (equals dns.headerSize)
	dnsMessagesKey        = "dns_messages"
	dnsSpecialAny         = "*"
)

func appendMessage(cx *layer4.Connection, msg *dns.Msg) {
	var messages []*dns.Msg
	if val := cx.GetVar(dnsMessagesKey); val != nil {
		messages = val.([]*dns.Msg)
	}
	messages = append(messages, msg)
	cx.SetVar(dnsMessagesKey, messages)
}
