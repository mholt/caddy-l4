package l4socks

import (
	"io"
	"slices"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&Socks5Matcher{})
}

// Socks5Matcher matches SOCKSv5 connections according to RFC 1928 (https://www.rfc-editor.org/rfc/rfc1928.html).
// Since the SOCKSv5 header is very short it could produce a lot of false positives,
// use AuthMethods to exactly specify which METHODS you expect your clients to send.
// By default, only the most common methods are matched NO AUTH, GSSAPI & USERNAME/PASSWORD.
type Socks5Matcher struct {
	AuthMethods []uint16 `json:"auth_methods,omitempty"`
}

func (*Socks5Matcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.socks5",
		New: func() caddy.Module { return new(Socks5Matcher) },
	}
}

func (m *Socks5Matcher) Provision(_ caddy.Context) error {
	if len(m.AuthMethods) == 0 {
		m.AuthMethods = []uint16{0, 1, 2} // NO AUTH, GSSAPI, USERNAME/PASSWORD
	}
	return nil
}

// Match returns true if the connection looks like it is using the SOCKSv5 protocol.
func (m *Socks5Matcher) Match(cx *layer4.Connection) (bool, error) {
	// read the version byte
	buf := []byte{0}
	if _, err := io.ReadFull(cx, buf); err != nil {
		return false, err
	}
	if buf[0] != 5 {
		return false, nil
	}

	// read number of auth methods
	if _, err := io.ReadFull(cx, buf); err != nil {
		return false, err
	}

	// read auth methods
	methods := make([]byte, buf[0])
	_, err := io.ReadFull(cx, methods)
	if err != nil {
		return false, err
	}

	// match auth methods
	for _, requestedMethod := range methods {
		if !slices.Contains(m.AuthMethods, uint16(requestedMethod)) {
			return false, nil
		}
	}

	return true, nil
}

// UnmarshalCaddyfile sets up the Socks5Matcher from Caddyfile tokens. Syntax:
//
//	socks5 {
//		auth_methods <auth_methods...>
//	}
//
// socks5
func (m *Socks5Matcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "auth_methods":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			for d.NextArg() {
				authMethod, err := strconv.ParseUint(d.Val(), 10, 8)
				if err != nil {
					return d.WrapErr(err)
				}
				m.AuthMethods = append(m.AuthMethods, uint16(authMethod))
			}
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	return nil
}

var (
	_ layer4.ConnMatcher    = (*Socks5Matcher)(nil)
	_ caddy.Provisioner     = (*Socks5Matcher)(nil)
	_ caddyfile.Unmarshaler = (*Socks5Matcher)(nil)
)
