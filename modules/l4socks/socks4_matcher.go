package l4socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&Socks4Matcher{})
}

// Socks4Matcher matches SOCKSv4 connections according to https://www.openssh.com/txt/socks4.protocol.
// Since the SOCKSv4 header is very short it could produce a lot of false positives.
// To improve the matching use Commands, Ports and Networks to specify to which destinations you expect clients to connect to.
// By default, CONNECT & BIND commands are matched with any destination ip and port.
type Socks4Matcher struct {
	// Only match on these commands. Default: ["CONNECT", "BIND"]
	Commands []string `json:"commands,omitempty"`
	// Only match on requests to one of these destination networks (IP or CIDR). Default: all networks.
	Networks []string `json:"networks,omitempty"`
	// Only match on requests to one of these destination ports. Default: all ports.
	Ports []uint16 `json:"ports,omitempty"`

	commands []uint8
	cidrs    []netip.Prefix
}

func (*Socks4Matcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.socks4",
		New: func() caddy.Module { return new(Socks4Matcher) },
	}
}

func (m *Socks4Matcher) Provision(_ caddy.Context) error {
	if len(m.Commands) == 0 {
		m.commands = []uint8{1, 2} // CONNECT & BIND
	} else {
		repl := caddy.NewReplacer()
		for _, c := range m.Commands {
			switch strings.ToUpper(repl.ReplaceAll(c, "")) {
			case "CONNECT":
				m.commands = append(m.commands, 1)
			case "BIND":
				m.commands = append(m.commands, 2)
			default:
				return fmt.Errorf("unknown command \"%s\" has to be one of [\"CONNECT\", \"BIND\"]", c)
			}
		}
	}
	repl := caddy.NewReplacer()
	for _, networkAddrOrCIDR := range m.Networks {
		networkAddrOrCIDR = repl.ReplaceAll(networkAddrOrCIDR, "")
		prefix, err := caddyhttp.CIDRExpressionToPrefix(networkAddrOrCIDR)
		if err != nil {
			return err
		}
		m.cidrs = append(m.cidrs, prefix)
	}
	return nil
}

// Match returns true if the connection looks like it is using the SOCKSv4 protocol.
func (m *Socks4Matcher) Match(cx *layer4.Connection) (bool, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(cx, buf); err != nil {
		return false, err
	}

	// match version (VN)
	if buf[0] != 4 {
		return false, nil
	}

	// match commands (CD)
	if !slices.Contains(m.commands, buf[1]) {
		return false, nil
	}

	// match destination port (DSTPORT)
	if len(m.Ports) > 0 {
		port := binary.BigEndian.Uint16(buf[2:4])
		if !slices.Contains(m.Ports, port) {
			return false, nil
		}
	}

	// match destination ipv4 (DSTIP)
	if len(m.cidrs) > 0 {
		ip := netip.AddrFrom4([4]byte(buf[4:8]))
		ipMatched := false
		for _, ipRange := range m.cidrs {
			if ipRange.Contains(ip) {
				ipMatched = true
				break
			}
		}
		if !ipMatched {
			return false, nil
		}
	}

	return true, nil
}

// UnmarshalCaddyfile sets up the Socks4Matcher from Caddyfile tokens. Syntax:
//
//	socks4 {
//		commands <commands...>
//		networks <ranges...>
//		ports <ports...>
//	}
//
// socks4
func (m *Socks4Matcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "commands":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			m.Commands = append(m.Commands, d.RemainingArgs()...)
		case "networks":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			for d.NextArg() {
				val := d.Val()
				if val == "private_ranges" {
					m.Networks = append(m.Networks, caddyhttp.PrivateRangesCIDR()...)
					continue
				}
				m.Networks = append(m.Networks, val)
			}
		case "ports":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			for d.NextArg() {
				port, err := strconv.ParseUint(d.Val(), 10, 16)
				if err != nil {
					return d.WrapErr(err)
				}
				m.Ports = append(m.Ports, uint16(port))
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
	_ layer4.ConnMatcher    = (*Socks4Matcher)(nil)
	_ caddy.Provisioner     = (*Socks4Matcher)(nil)
	_ caddyfile.Unmarshaler = (*Socks4Matcher)(nil)
)
