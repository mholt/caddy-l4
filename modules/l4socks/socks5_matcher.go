package l4socks

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"io"
)

func init() {
	caddy.RegisterModule(Socks5Matcher{})
}

// Socks5Matcher matches SOCKSv5 connections according to RFC 1928 (https://www.rfc-editor.org/rfc/rfc1928.html).
// Since the SOCKSv5 header is very short it could produce a lot of false positives,
// use AuthMethods to exactly specify which METHODS you expect your clients to send.
// By default only the most common methods are matched NO AUTH, GSSAPI & USERNAME/PASSWORD.
type Socks5Matcher struct {
	AuthMethods []uint8 `json:"auth_methods,omitempty"`
}

func (Socks5Matcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.socks5",
		New: func() caddy.Module { return new(Socks5Matcher) },
	}
}

func (m *Socks5Matcher) Provision(_ caddy.Context) error {
	if len(m.AuthMethods) == 0 {
		m.AuthMethods = []uint8{0, 1, 2} // NO AUTH, GSSAPI, USERNAME/PASSWORD
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
		if !contains(m.AuthMethods, requestedMethod) {
			return false, nil
		}
	}

	return true, nil
}

var (
	_ layer4.ConnMatcher = (*Socks5Matcher)(nil)
	_ caddy.Provisioner  = (*Socks5Matcher)(nil)
)

func contains(values []uint8, search uint8) bool {
	for _, value := range values {
		if value == search {
			return true
		}
	}
	return false
}
