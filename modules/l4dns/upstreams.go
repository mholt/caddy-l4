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
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/miekg/dns"
)

func init() {
	caddy.RegisterModule(&UpstreamPlain{})
	caddy.RegisterModule(&UpstreamTCP{})
	caddy.RegisterModule(&UpstreamUDP{})
}

// Upstream is a DNS response message provider for recursive zones.
type Upstream interface {
	// Exchange gets a DNS request message and returns a DNS response message, or nil and error if it failed.
	// Multiple dial addresses may be called inside if available.
	Exchange(*dns.Msg) (*dns.Msg, error)
}

// UpstreamPool may be used as a base structure for all upstreams. It implements Upstream and caddy.Provisioner
// interfaces for multiple dial addresses. Any derivative upstream must also implement caddy.Module and
// caddyfile.Unmarshaler interfaces, as well as provide its own specific ExchangeOne function.
type UpstreamPool struct {
	// Dial is an address:port style dialing pool. Items may also contain placeholders evaluated at provision.
	Dial []string `json:"dial,omitempty"`

	// PoolRandom enables dial address shuffling. By default, it is disabled.
	PoolRandom bool `json:"pool_random,omitempty"`
	// PoolSequential disables concurrent dialing. By default, it is disabled.
	PoolSequential bool `json:"pool_sequential,omitempty"`
	// PoolTimeout is a timeout for dialing, writing and reading all addresses in total. By default, it equals 10s.
	PoolTimeout caddy.Duration `json:"pool_timeout,omitempty"`

	dial []string
}

// Exchange implements Upstream.Exchange.
func (u *UpstreamPool) Exchange(r *dns.Msg) (*dns.Msg, error) {
	return u.ExchangeAll(r, u.ExchangeOne)
}

// ExchangeAll implements Upstream.Exchange for all dial addresses.
func (u *UpstreamPool) ExchangeAll(r *dns.Msg, one func(*dns.Msg, string) (*dns.Msg, error)) (*dns.Msg, error) {
	l := len(u.dial)
	if l == 0 {
		return nil, ErrUpstreamHasNoDialAddresses
	}

	t := time.NewTimer(time.Duration(u.PoolTimeout))
	ch := make(chan *dns.Msg, l)

	f := func(r *dns.Msg, addr string, ch chan *dns.Msg) bool {
		msg, err := one(r, addr)
		if err == nil && msg != nil {
			ch <- msg
			return true
		}
		return false
	}

	if l > 1 { // Multiple dial addresses
		if u.PoolSequential { // Sequential dialing
			if u.PoolRandom { // Random iteration order
				for _, i := range rand.Perm(l) {
					if f(r, u.dial[i], ch) {
						break
					}
				}
			} else { // Fixed (default) iteration order
				for _, addr := range u.dial {
					if f(r, addr, ch) {
						break
					}
				}
			}
		} else { // Concurrent (default) dialing
			if u.PoolRandom { // Random iteration order
				for _, i := range rand.Perm(l) {
					go f(r, u.dial[i], ch)
				}
			} else { // Fixed (default) iteration order
				for _, addr := range u.dial {
					go f(r, addr, ch)
				}
			}
		}
	} else { // Single dial address: PoolRandom and PoolSequential flags make no sense
		f(r, u.dial[0], ch)
	}

	select {
	case <-t.C:
		return nil, ErrUpstreamPoolTimeoutExpired
	case m := <-ch:
		if !t.Stop() {
			<-t.C
		}
		return m, nil
	}
}

// ExchangeOne implements Upstream.Exchange for a given dial address.
func (u *UpstreamPool) ExchangeOne(_ *dns.Msg, _ string) (*dns.Msg, error) {
	return nil, ErrUpstreamFuncNotImplemented
}

// Provision prepares u's internal structures.
func (u *UpstreamPool) Provision(_ caddy.Context) error {
	repl := caddy.NewReplacer()
	for _, dial := range u.Dial {
		u.dial = append(u.dial, repl.ReplaceAll(dial, ""))
	}

	if u.PoolTimeout <= 0 {
		u.PoolTimeout = caddy.Duration(DefUpstreamPoolTimeout)
	}
	return nil
}

// UpstreamPlain exchanges DNS messages over UDP, unless TCP is preferred or a truncated response is received.
type UpstreamPlain struct {
	UpstreamPool

	// PreferTCP enables TCP transport preference. By default, it is disabled, i.e. UDP is always used first.
	PreferTCP bool `json:"prefer_tcp,omitempty"`

	// ClientTimeout sets a cumulative timeout for dial, write and read in a dns.Client, i.e. per each dial address.
	// By default, it equals 0 (disabled) and overrides ClientDialTimeout, ClientReadTimeout, ClientWriteTimeout
	// when a non-zero value is provided.
	ClientTimeout caddy.Duration `json:"client_timeout,omitempty"`
	// ClientDialTimeout sets net.DialTimeout value in a dns.Client. By default, it equals 2 seconds and is
	// overridden by ClientTimeout when that value is non-zero.
	ClientDialTimeout caddy.Duration `json:"client_dial_timeout,omitempty"`
	// ClientReadTimeout sets net.Conn.SetReadTimeout value in a dns.Client. By default, it equals 2 seconds and is
	// overridden by ClientTimeout when that value is non-zero.
	ClientReadTimeout caddy.Duration `json:"client_read_timeout,omitempty"`
	// ClientWriteTimeout sets net.Conn.SetWriteTimeout value in a dns.Client. By default, it equals 2 seconds and is
	// overridden by ClientTimeout when that value is non-zero.
	ClientWriteTimeout caddy.Duration `json:"client_write_timeout,omitempty"`
	// ClientUDPSize sets a minimum receive buffer for UDP messages in a dns.Client. By default, it is ignored if
	// a value less than dns.MinMsgSize (512 bytes) is provided and EDNS0 is not used.
	ClientUDPSize uint16 `json:"client_udp_size,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*UpstreamPlain) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  NamespaceUpstreams + ".plain",
		New: func() caddy.Module { return new(UpstreamPlain) },
	}
}

// Exchange implements Upstream.Exchange.
func (u *UpstreamPlain) Exchange(r *dns.Msg) (*dns.Msg, error) {
	return u.ExchangeAll(r, u.ExchangeOne)
}

// ExchangeOne implements Upstream.Exchange for a given dial address.
func (u *UpstreamPlain) ExchangeOne(r *dns.Msg, address string) (m *dns.Msg, err error) {
	var c *dns.Client

	if !u.PreferTCP {
		c = &dns.Client{
			Net:          "udp",
			Timeout:      time.Duration(u.ClientTimeout),
			DialTimeout:  time.Duration(u.ClientDialTimeout),
			ReadTimeout:  time.Duration(u.ClientReadTimeout),
			WriteTimeout: time.Duration(u.ClientWriteTimeout),
			UDPSize:      u.ClientUDPSize,
		}
		m, _, err = c.Exchange(r, address)
		if err == nil && m != nil && !m.Truncated {
			return
		}
	}

	c = &dns.Client{
		Net:          "tcp",
		Timeout:      time.Duration(u.ClientTimeout),
		DialTimeout:  time.Duration(u.ClientDialTimeout),
		ReadTimeout:  time.Duration(u.ClientReadTimeout),
		WriteTimeout: time.Duration(u.ClientWriteTimeout),
	}
	m, _, err = c.Exchange(r, address)
	return
}

// Provision prepares u's internal structures.
func (u *UpstreamPlain) Provision(ctx caddy.Context) error {
	err := u.UpstreamPool.Provision(ctx)
	if err != nil {
		return err
	}

	if u.ClientTimeout <= 0 {
		u.ClientTimeout = caddy.Duration(DefUpstreamClientTimeout)
	}
	if u.ClientDialTimeout <= 0 {
		u.ClientDialTimeout = caddy.Duration(DefUpstreamClientDialTimeout)
	}
	if u.ClientReadTimeout <= 0 {
		u.ClientReadTimeout = caddy.Duration(DefUpstreamClientReadTimeout)
	}
	if u.ClientWriteTimeout <= 0 {
		u.ClientWriteTimeout = caddy.Duration(DefUpstreamClientWriteTimeout)
	}

	return nil
}

// UnmarshalCaddyfile sets up the UpstreamPlain from Caddyfile tokens. Syntax:
//
//	plain [<address:port...>] {
//		dial <address:port> [<address:port...>]
//
//		pool_random
//		pool_sequential
//		pool_timeout <duration>
//
//		prefer_tcp
//
//		client_timeout <duration>
//		client_dial_timeout <duration>
//		client_read_timeout <duration>
//		client_write_timeout <duration>
//		client_udp_size <number>
//	}
func (u *UpstreamPlain) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Treat all same-line options as dial arguments
	shortcutArgs := d.RemainingArgs()

	var hasClientTimeout, hasClientDialTimeout, hasClientReadTimeout, hasClientWriteTimeout, hasClientUDPSize,
		hasPoolRandom, hasPoolSequential, hasPoolTimeout,
		hasPreferTCP bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "client_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.ClientTimeout, &hasClientTimeout)
			if err != nil {
				return err
			}
		case "client_dial_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.ClientDialTimeout, &hasClientDialTimeout)
			if err != nil {
				return err
			}
		case "client_read_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.ClientReadTimeout, &hasClientReadTimeout)
			if err != nil {
				return err
			}
		case "client_write_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.ClientWriteTimeout, &hasClientWriteTimeout)
			if err != nil {
				return err
			}
		case "client_udp_size":
			err := UnmarshalCaddyfileOptionUint16(d, optionName, &u.ClientUDPSize, &hasClientUDPSize)
			if err != nil {
				return err
			}
		case "dial":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			shortcutArgs = append(shortcutArgs, d.RemainingArgs()...)
		case "pool_random":
			err := UnmarshalCaddyfileOptionBool(d, optionName, &u.PoolRandom, &hasPoolRandom)
			if err != nil {
				return err
			}
		case "pool_sequential":
			err := UnmarshalCaddyfileOptionBool(d, optionName, &u.PoolSequential, &hasPoolSequential)
			if err != nil {
				return err
			}
		case "pool_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.PoolTimeout, &hasPoolTimeout)
			if err != nil {
				return err
			}
		case "prefer_tcp":
			err := UnmarshalCaddyfileOptionBool(d, optionName, &u.PreferTCP, &hasPreferTCP)
			if err != nil {
				return err
			}
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed DNS upstream '%s': nested blocks are not supported", wrapper)
		}
	}

	shortcutOptionName := "dial"
	if len(shortcutArgs) == 0 {
		return d.Errf("malformed DNS upstream '%s': at least one %s address must be provided", wrapper, shortcutOptionName)
	}
	u.Dial = append(u.Dial, shortcutArgs...)

	return nil
}

// UpstreamTCP exchanges DNS messages over TCP.
type UpstreamTCP struct {
	UpstreamPool

	// ClientTimeout sets a cumulative timeout for dial, write and read in a dns.Client, i.e. per each dial address.
	// By default, it equals 0 (disabled) and overrides ClientDialTimeout, ClientReadTimeout, ClientWriteTimeout
	// when a non-zero value is provided.
	ClientTimeout caddy.Duration `json:"client_timeout,omitempty"`
	// ClientDialTimeout sets net.DialTimeout value in a dns.Client. By default, it equals 2 seconds and is
	// overridden by ClientTimeout when that value is non-zero.
	ClientDialTimeout caddy.Duration `json:"client_dial_timeout,omitempty"`
	// ClientReadTimeout sets net.Conn.SetReadTimeout value in a dns.Client. By default, it equals 2 seconds and is
	// overridden by ClientTimeout when that value is non-zero.
	ClientReadTimeout caddy.Duration `json:"client_read_timeout,omitempty"`
	// ClientWriteTimeout sets net.Conn.SetWriteTimeout value in a dns.Client. By default, it equals 2 seconds and is
	// overridden by ClientTimeout when that value is non-zero.
	ClientWriteTimeout caddy.Duration `json:"client_write_timeout,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*UpstreamTCP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  NamespaceUpstreams + ".tcp",
		New: func() caddy.Module { return new(UpstreamTCP) },
	}
}

// Exchange implements Upstream.Exchange.
func (u *UpstreamTCP) Exchange(r *dns.Msg) (*dns.Msg, error) {
	return u.ExchangeAll(r, u.ExchangeOne)
}

// ExchangeOne implements Upstream.Exchange for a given dial address.
func (u *UpstreamTCP) ExchangeOne(r *dns.Msg, address string) (m *dns.Msg, err error) {
	c := &dns.Client{
		Net:          "tcp",
		Timeout:      time.Duration(u.ClientTimeout),
		DialTimeout:  time.Duration(u.ClientDialTimeout),
		ReadTimeout:  time.Duration(u.ClientReadTimeout),
		WriteTimeout: time.Duration(u.ClientWriteTimeout),
	}
	m, _, err = c.Exchange(r, address)
	return
}

// Provision prepares u's internal structures.
func (u *UpstreamTCP) Provision(ctx caddy.Context) error {
	err := u.UpstreamPool.Provision(ctx)
	if err != nil {
		return err
	}

	if u.ClientTimeout <= 0 {
		u.ClientTimeout = caddy.Duration(DefUpstreamClientTimeout)
	}
	if u.ClientDialTimeout <= 0 {
		u.ClientDialTimeout = caddy.Duration(DefUpstreamClientDialTimeout)
	}
	if u.ClientReadTimeout <= 0 {
		u.ClientReadTimeout = caddy.Duration(DefUpstreamClientReadTimeout)
	}
	if u.ClientWriteTimeout <= 0 {
		u.ClientWriteTimeout = caddy.Duration(DefUpstreamClientWriteTimeout)
	}

	return nil
}

// UnmarshalCaddyfile sets up the UpstreamTCP from Caddyfile tokens. Syntax:
//
//	tcp [<address:port...>] {
//		dial <address:port> [<address:port...>]
//
//		pool_random
//		pool_sequential
//		pool_timeout <duration>
//
//		client_timeout <duration>
//		client_dial_timeout <duration>
//		client_read_timeout <duration>
//		client_write_timeout <duration>
//	}
func (u *UpstreamTCP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Treat all same-line options as dial arguments
	shortcutArgs := d.RemainingArgs()

	var hasClientTimeout, hasClientDialTimeout, hasClientReadTimeout, hasClientWriteTimeout,
		hasPoolRandom, hasPoolSequential, hasPoolTimeout bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "client_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.ClientTimeout, &hasClientTimeout)
			if err != nil {
				return err
			}
		case "client_dial_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.ClientDialTimeout, &hasClientDialTimeout)
			if err != nil {
				return err
			}
		case "client_read_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.ClientReadTimeout, &hasClientReadTimeout)
			if err != nil {
				return err
			}
		case "client_write_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.ClientWriteTimeout, &hasClientWriteTimeout)
			if err != nil {
				return err
			}
		case "dial":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			shortcutArgs = append(shortcutArgs, d.RemainingArgs()...)
		case "pool_random":
			err := UnmarshalCaddyfileOptionBool(d, optionName, &u.PoolRandom, &hasPoolRandom)
			if err != nil {
				return err
			}
		case "pool_sequential":
			err := UnmarshalCaddyfileOptionBool(d, optionName, &u.PoolSequential, &hasPoolSequential)
			if err != nil {
				return err
			}
		case "pool_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.PoolTimeout, &hasPoolTimeout)
			if err != nil {
				return err
			}
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed DNS upstream '%s': nested blocks are not supported", wrapper)
		}
	}

	shortcutOptionName := "dial"
	if len(shortcutArgs) == 0 {
		return d.Errf("malformed DNS upstream '%s': at least one %s address must be provided", wrapper, shortcutOptionName)
	}
	u.Dial = append(u.Dial, shortcutArgs...)

	return nil
}

// UpstreamUDP exchanges DNS messages over UDP.
type UpstreamUDP struct {
	UpstreamPool

	// ClientTimeout sets a cumulative timeout for dial, write and read in a dns.Client, i.e. per each dial address.
	// By default, it equals 0 (disabled) and overrides ClientDialTimeout, ClientReadTimeout, ClientWriteTimeout
	// when a non-zero value is provided.
	ClientTimeout caddy.Duration `json:"client_timeout,omitempty"`
	// ClientDialTimeout sets net.DialTimeout value in a dns.Client. By default, it equals 2 seconds and is
	// overridden by ClientTimeout when that value is non-zero.
	ClientDialTimeout caddy.Duration `json:"client_dial_timeout,omitempty"`
	// ClientReadTimeout sets net.Conn.SetReadTimeout value in a dns.Client. By default, it equals 2 seconds and is
	// overridden by ClientTimeout when that value is non-zero.
	ClientReadTimeout caddy.Duration `json:"client_read_timeout,omitempty"`
	// ClientWriteTimeout sets net.Conn.SetWriteTimeout value in a dns.Client. By default, it equals 2 seconds and is
	// overridden by ClientTimeout when that value is non-zero.
	ClientWriteTimeout caddy.Duration `json:"client_write_timeout,omitempty"`
	// ClientUDPSize sets a minimum receive buffer for UDP messages in a dns.Client. By default, it is ignored if
	// a value less than dns.MinMsgSize (512 bytes) is provided and EDNS0 is not used.
	ClientUDPSize uint16 `json:"client_udp_size,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*UpstreamUDP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  NamespaceUpstreams + ".udp",
		New: func() caddy.Module { return new(UpstreamUDP) },
	}
}

// Exchange implements Upstream.Exchange.
func (u *UpstreamUDP) Exchange(r *dns.Msg) (*dns.Msg, error) {
	return u.ExchangeAll(r, u.ExchangeOne)
}

// ExchangeOne implements Upstream.Exchange for a given dial address.
func (u *UpstreamUDP) ExchangeOne(r *dns.Msg, address string) (m *dns.Msg, err error) {
	c := &dns.Client{
		Net:          "udp",
		Timeout:      time.Duration(u.ClientTimeout),
		DialTimeout:  time.Duration(u.ClientDialTimeout),
		ReadTimeout:  time.Duration(u.ClientReadTimeout),
		WriteTimeout: time.Duration(u.ClientWriteTimeout),
		UDPSize:      u.ClientUDPSize,
	}
	m, _, err = c.Exchange(r, address)
	return
}

// Provision prepares u's internal structures.
func (u *UpstreamUDP) Provision(ctx caddy.Context) error {
	err := u.UpstreamPool.Provision(ctx)
	if err != nil {
		return err
	}

	if u.ClientTimeout <= 0 {
		u.ClientTimeout = caddy.Duration(DefUpstreamClientTimeout)
	}
	if u.ClientDialTimeout <= 0 {
		u.ClientDialTimeout = caddy.Duration(DefUpstreamClientDialTimeout)
	}
	if u.ClientReadTimeout <= 0 {
		u.ClientReadTimeout = caddy.Duration(DefUpstreamClientReadTimeout)
	}
	if u.ClientWriteTimeout <= 0 {
		u.ClientWriteTimeout = caddy.Duration(DefUpstreamClientWriteTimeout)
	}

	return nil
}

// UnmarshalCaddyfile sets up the UpstreamUDP from Caddyfile tokens. Syntax:
//
//	udp [<address:port...>] {
//		dial <address:port> [<address:port...>]
//
//		pool_random
//		pool_sequential
//		pool_timeout <duration>
//
//		client_timeout <duration>
//		client_dial_timeout <duration>
//		client_read_timeout <duration>
//		client_write_timeout <duration>
//		client_udp_size <number>
//	}
func (u *UpstreamUDP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Treat all same-line options as dial arguments
	shortcutArgs := d.RemainingArgs()

	var hasClientTimeout, hasClientDialTimeout, hasClientReadTimeout, hasClientWriteTimeout, hasClientUDPSize,
		hasPoolRandom, hasPoolSequential, hasPoolTimeout bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "client_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.ClientTimeout, &hasClientTimeout)
			if err != nil {
				return err
			}
		case "client_dial_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.ClientDialTimeout, &hasClientDialTimeout)
			if err != nil {
				return err
			}
		case "client_read_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.ClientReadTimeout, &hasClientReadTimeout)
			if err != nil {
				return err
			}
		case "client_write_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.ClientWriteTimeout, &hasClientWriteTimeout)
			if err != nil {
				return err
			}
		case "client_udp_size":
			err := UnmarshalCaddyfileOptionUint16(d, optionName, &u.ClientUDPSize, &hasClientUDPSize)
			if err != nil {
				return err
			}
		case "dial":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			shortcutArgs = append(shortcutArgs, d.RemainingArgs()...)
		case "pool_random":
			err := UnmarshalCaddyfileOptionBool(d, optionName, &u.PoolRandom, &hasPoolRandom)
			if err != nil {
				return err
			}
		case "pool_sequential":
			err := UnmarshalCaddyfileOptionBool(d, optionName, &u.PoolSequential, &hasPoolSequential)
			if err != nil {
				return err
			}
		case "pool_timeout":
			err := UnmarshalCaddyfileOptionDuration(d, optionName, &u.PoolTimeout, &hasPoolTimeout)
			if err != nil {
				return err
			}
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed DNS upstream '%s': nested blocks are not supported", wrapper)
		}
	}

	shortcutOptionName := "dial"
	if len(shortcutArgs) == 0 {
		return d.Errf("malformed DNS upstream '%s': at least one %s address must be provided", wrapper, shortcutOptionName)
	}
	u.Dial = append(u.Dial, shortcutArgs...)

	return nil
}

// Interface guards
var (
	_ Upstream = (*UpstreamPlain)(nil)
	_ Upstream = (*UpstreamTCP)(nil)
	_ Upstream = (*UpstreamUDP)(nil)

	_ caddy.Provisioner = (*UpstreamPlain)(nil)
	_ caddy.Provisioner = (*UpstreamTCP)(nil)
	_ caddy.Provisioner = (*UpstreamUDP)(nil)

	_ caddyfile.Unmarshaler = (*UpstreamPlain)(nil)
	_ caddyfile.Unmarshaler = (*UpstreamTCP)(nil)
	_ caddyfile.Unmarshaler = (*UpstreamUDP)(nil)
)

// Errors
var (
	ErrUpstreamFuncNotImplemented = fmt.Errorf("func not implemented")
	ErrUpstreamHasNoDialAddresses = fmt.Errorf("no dial addresses")
	ErrUpstreamPoolTimeoutExpired = fmt.Errorf("pool timeout expired")
)

const (
	DefUpstreamClientTimeout      = 0 * time.Second
	DefUpstreamClientDialTimeout  = 2 * time.Second
	DefUpstreamClientReadTimeout  = 2 * time.Second
	DefUpstreamClientWriteTimeout = 2 * time.Second

	DefUpstreamPoolTimeout = 10 * time.Second
)
