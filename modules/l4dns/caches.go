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
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/miekg/dns"
)

func init() {
	caddy.RegisterModule(&CacheShared{})
	caddy.RegisterModule(&CacheSimple{})
}

// Cache is a storage engine capable of retrieving DNS messages.
type Cache interface {
	// Get takes a valid DNS request message (unchanged, i.e. as received from the client) and returns
	// a valid DNS response message (ready to be sent to the client, no expired resource records inside)
	// and nil if available, otherwise it returns nil and error.
	Get(*dns.Msg) (*dns.Msg, error)
	// Set takes valid DNS request and response messages (both unchanged, i.e. the former as received
	// from the client and the latter as obtained from the upstream) and stores it for future requests.
	Set(*dns.Msg, *dns.Msg) error
}

// CacheShared is a storage engine capable of retrieving DNS messages. It uses a shared underlying Cache under the hood.
type CacheShared struct {
	underlying Cache
}

// CaddyModule returns the Caddy module information.
func (*CacheShared) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  NamespaceCaches + ".shared",
		New: func() caddy.Module { return new(CacheShared) },
	}
}

// Get implements Cache.Get.
func (c *CacheShared) Get(r *dns.Msg) (*dns.Msg, error) {
	return c.underlying.Get(r)
}

// Provision prepares c's internal structures.
func (c *CacheShared) Provision(ctx caddy.Context) error {
	vars, err := CaddyContextGetVars(ctx)
	if err != nil {
		return err
	}

	c.underlying = vars[CacheCtxKey].(Cache)
	if c.underlying == nil {
		return ErrCacheSharedHasNoUnderlying
	}

	return nil
}

// Set implements Cache.Set.
func (c *CacheShared) Set(r *dns.Msg, m *dns.Msg) error {
	return c.underlying.Set(r, m)
}

// UnmarshalCaddyfile sets up the CacheShared from Caddyfile tokens. Syntax:
//
//	shared
func (c *CacheShared) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line arguments are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed DNS cache '%s': blocks are not supported", wrapper)
	}

	return nil
}

// CacheSimple is a storage engine capable of retrieving DNS messages. It uses a sync.Map under the hood.
type CacheSimple struct {
	ClearInterval caddy.Duration `json:"clear_interval,omitempty"`

	store sync.Map
}

// CaddyModule returns the Caddy module information.
func (*CacheSimple) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  NamespaceCaches + ".simple",
		New: func() caddy.Module { return new(CacheSimple) },
	}
}

// ComposeStoreKey generates a comparable store key from a DNS request message.
func (c *CacheSimple) ComposeStoreKey(r *dns.Msg) (any, error) {
	b, err := r.Pack()
	if err != nil {
		return nil, err
	}

	// Ensure the DNS message ID (uint16) equals zero
	b[0], b[1] = 0x00, 0x00

	// Calculate sha256 digest of the DNS message bytes
	d := sha256.Sum256(b)

	return d, nil
}

// ComposeStoreValue generates a store value from a DNS response message.
func (c *CacheSimple) ComposeStoreValue(m *dns.Msg) (any, error) {
	return (&CacheSimpleStoreValue{}).Wrap(m), nil
}

// ComposeReturnValue generates a valid DNS response message from a DNS request message and a store value.
func (c *CacheSimple) ComposeReturnValue(r *dns.Msg, v any) *dns.Msg {
	m := new(dns.Msg)
	v.(*CacheSimpleStoreValue).Unwrap().CopyTo(m)
	m.Id = r.Id
	return m
}

// Get implements Cache.Get.
func (c *CacheSimple) Get(r *dns.Msg) (*dns.Msg, error) {
	k, err := c.ComposeStoreKey(r)
	if err != nil {
		return nil, err
	}

	v, ok := c.store.Load(k)
	if !ok {
		return nil, ErrCacheSimpleKeyNotFound
	}

	err = c.ValidateStoreValue(v)
	if err != nil {
		c.store.Delete(k)
	}

	return c.ComposeReturnValue(r, v), err
}

// Provision spawns a goroutine to clear c's internal store.
func (c *CacheSimple) Provision(ctx caddy.Context) error {
	go func() {
		t := time.NewTicker(DefCacheSimpleClearInterval)
		for {
			select {
			case <-t.C:
				t.Stop()
				c.store.Range(func(k, v any) bool {
					if !v.(*CacheSimpleStoreValue).IsValid() {
						c.store.Delete(k)
					}
					return true
				})
				t.Reset(DefCacheSimpleClearInterval)
			}
		}
	}()
	return nil
}

// Set implements Cache.Set.
func (c *CacheSimple) Set(r *dns.Msg, m *dns.Msg) error {
	k, err := c.ComposeStoreKey(r)
	if err != nil {
		return err
	}

	v, err := c.ComposeStoreValue(m)
	if err != nil {
		return err
	}

	c.store.Store(k, v)
	return nil
}

// ValidateStoreValue checks whether a store value is valid.
func (c *CacheSimple) ValidateStoreValue(v any) error {
	if !v.(*CacheSimpleStoreValue).IsValid() {
		return ErrCacheSimpleValueExpired
	}

	return nil
}

// UnmarshalCaddyfile sets up the CacheSimple from Caddyfile tokens. Syntax:
//
//	simple {
//		clear_interval <duration>
//	}
func (c *CacheSimple) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line arguments are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed DNS cache '%s': blocks are not supported", wrapper)
	}

	return nil
}

// CacheSimpleStoreValue contains a DNS response message and the time which this message will be valid before.
type CacheSimpleStoreValue struct {
	// Payload contains a DNS response message without any modifications, i.e. as obtained from an upstream.
	Payload *dns.Msg
	// ValidBefore contains a UTC time which Payload will be valid before.
	ValidBefore time.Time
}

// IsValid returns true unless Payload is nil or the current time is after its ValidBefore time.
func (v *CacheSimpleStoreValue) IsValid() bool {
	return v.Payload != nil && !time.Now().UTC().After(v.ValidBefore)
}

// Wrap saves a DNS response message as Payload and calculates its ValidBefore time.
func (v *CacheSimpleStoreValue) Wrap(m *dns.Msg) *CacheSimpleStoreValue {
	var hasAtLeastOneTTL bool
	var minTTL, tmpTTL uint32

	minTTL = ^uint32(0)
outerLoop:
	for _, rrs := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range rrs {
			tmpTTL, hasAtLeastOneTTL = rr.Header().Ttl, true
			if minTTL > tmpTTL {
				minTTL = tmpTTL
			}
			// It makes no sense to continue since 0 is the minimum uint32 value.
			if minTTL == 0 {
				break outerLoop
			}
		}
	}

	// If no resource records have been found, don't cache this message.
	if !hasAtLeastOneTTL {
		minTTL = 0
	}

	v.Payload = m
	v.ValidBefore = time.Now().UTC().Add(time.Duration(minTTL) * time.Second)
	return v
}

// Unwrap returns the DNS response message stored in Payload.
func (v *CacheSimpleStoreValue) Unwrap() *dns.Msg {
	return v.Payload
}

// Interface guards
var (
	_ Cache = (*CacheSimple)(nil)
	_ Cache = (*CacheShared)(nil)

	_ caddy.Provisioner = (*CacheSimple)(nil)
	_ caddy.Provisioner = (*CacheShared)(nil)

	_ caddyfile.Unmarshaler = (*CacheSimple)(nil)
	_ caddyfile.Unmarshaler = (*CacheShared)(nil)
)

// Local errors
var (
	ErrCacheSharedHasNoUnderlying = errors.New("no underlying cache")
	ErrCacheSimpleKeyNotFound     = errors.New("key not found")
	ErrCacheSimpleValueExpired    = errors.New("value expired")
)

var DefCache Cache = &CacheSimple{}

const (
	CacheCtxKey = "cache"

	DefCacheSimpleClearInterval = 5 * time.Minute
)
