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
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/mholt/caddy-l4/layer4"
)

// HandleSmart handles the DNS connection. It unpacks incoming data, processes requests, composes responses, and
// packs outgoing data on its own. It uses Dispatcher, Inbox and Outbox under the hood.
func (h *HandleDNS) HandleSmart(cx *layer4.Connection, _ layer4.Handler) error {
	in := NewInboxWithConn(cx)
	in.SetValidate(h.Validate)

	out := NewOutboxFromInbox(in)
	out.SetCompress(h.Compress)

	inMsg, inErr := in.Pull()
	if inErr != nil {
		if errors.Is(inErr, ErrDispatcherCantUnpack) {
			return out.Push(new(dns.Msg).SetRcode(inMsg, dns.RcodeFormatError))
		}
		return inErr
	}

	if inMsg.Opcode != dns.OpcodeQuery {
		return out.Push(new(dns.Msg).SetRcode(inMsg, dns.RcodeNotImplemented))
	}

	outErr := h.dis.Dispatch(in, out)
	if outErr != nil {
		if errors.Is(outErr, ErrDispatcherEmptyRequest) {
			return out.Push(new(dns.Msg).SetRcode(inMsg, dns.RcodeFormatError))
		}
		if errors.Is(outErr, ErrDispatcherEmptyStore) || errors.Is(outErr, ErrDispatcherZoneNotFound) {
			return out.Push(new(dns.Msg).SetRcode(inMsg, dns.RcodeRefused))
		}
		return outErr
	}

	return nil
}

// Dispatcher is a mechanism to store a pattern to Zone mapping (at provision)
// and find the most appropriate Zone to dispatch Inbox and Outbox (at handle).
type Dispatcher struct {
	store map[string]Zone
}

// Dispatch finds the most appropriate Zone and dispatches Inbox and Outbox.
// Adapted from dns.ServeMux.match() in September 2024.
func (d *Dispatcher) Dispatch(in *Inbox, out *Outbox) error {
	if d.store == nil {
		return ErrDispatcherEmptyStore
	}

	questions := in.GetMsg().Question
	if len(questions) == 0 {
		return ErrDispatcherEmptyRequest
	}

	q := questions[0]
	qName, qType := dns.CanonicalName(q.Name), q.Qtype

	var matchedZone Zone
	for off, end := 0, false; !end; off, end = dns.NextLabel(qName, off) {
		if z, ok := d.store[qName[off:]]; ok {
			if qType != dns.TypeDS {
				return z.Dispatch(in, out)
			}
			// Continue for DS to see if we have a parent too, if so delegate to the parent
			matchedZone = z
		}
	}

	// Wildcard match, if we have found nothing try the root zone as a last resort.
	if z, ok := d.store["."]; ok {
		return z.Dispatch(in, out)
	}

	if matchedZone != nil {
		return matchedZone.Dispatch(in, out)
	}

	return ErrDispatcherZoneNotFound
}

// RegisterZone adds a Zone to the inner store. No mutexes are used inside. It is designed to be called at provision.
func (d *Dispatcher) RegisterZone(z Zone) error {
	pattern := z.GetPattern()
	if len(pattern) == 0 {
		return ErrDispatcherEmptyPattern
	}

	if d.store == nil {
		d.store = make(map[string]Zone)
	}

	pattern = dns.CanonicalName(pattern)
	if _, exists := d.store[pattern]; exists {
		return ErrDispatcherDuplicatePattern
	}

	d.store[pattern] = z
	return nil
}

// Box is a container that simultaneously stores a pointer to layer4.Connection, a slice of bytes representing
// the DNS message and a pointer to dns.Msg. It is used as a base struct for Inbox and Outbox.
type Box struct {
	conn  *layer4.Connection
	bytes []byte
	msg   *dns.Msg
}

// GetConn returns a pointer to layer4.Connection.
func (b *Box) GetConn() *layer4.Connection {
	return b.conn
}

// GetBytes returns a slice of bytes representing the DNS message.
func (b *Box) GetBytes() []byte {
	return b.bytes
}

// GetMsg returns a pointer to dns.Msg.
func (b *Box) GetMsg() *dns.Msg {
	return b.msg
}

// SetConn assigns the inner conn to a pointer to layer4.Connection.
func (b *Box) SetConn(cx *layer4.Connection) {
	b.conn = cx
}

// SetBytes assigns the inner bytes to a slice of bytes representing the DNS message.
func (b *Box) SetBytes(bytes []byte) {
	b.bytes = bytes
}

// SetMsg assigns the inner msg to a pointer to dns.Msg.
func (b *Box) SetMsg(msg *dns.Msg) {
	b.msg = msg
}

// Inbox is a Box to handle incoming DNS messages.
type Inbox struct {
	Box

	validate bool
}

// ReadBytes reads the inner bytes from the inner conn.
func (i *Inbox) ReadBytes() (err error) {
	i.bytes, err = ReadBytes(i.conn)
	return
}

// UnpackMsg assigns the inner msg from the inner bytes.
func (i *Inbox) UnpackMsg() (err error) {
	i.msg = new(dns.Msg)
	err = i.msg.Unpack(i.bytes)
	return
}

// ReadMsg does ReadBytes and UnpackMsg.
func (i *Inbox) ReadMsg() (err error) {
	err = i.ReadBytes()
	if err != nil {
		return err
	}
	err = i.UnpackMsg()
	if err != nil {
		return fmt.Errorf("%v: %v", ErrDispatcherCantUnpack, err)
	}
	return
}

// Pull does ReadMsg and returns a pointer to dns.Msg.
func (i *Inbox) Pull() (*dns.Msg, error) {
	err := i.ReadMsg()
	return i.msg, err
}

// GetValidate returns true if a transaction signature (TSIG) should be validated.
func (i *Inbox) GetValidate() bool {
	return i.validate
}

// SetValidate assigns the inner validate to true if a transaction signature (TSIG) should be validated.
func (i *Inbox) SetValidate(v bool) {
	i.validate = v
}

// Validate checks if a transaction signature (TSIG) is valid using dns.TsigVerify.
func (i *Inbox) Validate(secret string, prev *dns.TSIG) (*dns.TSIG, error) {
	if !i.validate {
		return nil, ErrInboxValidateSkipped
	}
	sig := i.msg.IsTsig()
	if sig == nil {
		return nil, ErrInboxValidateUnsigned
	}
	if len(secret) == 0 {
		return nil, ErrInboxValidateNoSecret
	}
	if prev != nil {
		return sig, dns.TsigVerify(i.bytes, secret, prev.MAC, len(prev.MAC) != 0)
	}
	return sig, dns.TsigVerify(i.bytes, secret, "", false)
}

// Outbox is a Box to handle outgoing DNS messages.
type Outbox struct {
	Box

	compress bool
}

// WriteBytes writes the inner bytes to the inner conn.
func (o *Outbox) WriteBytes() (err error) {
	_, err = WriteBytes(o.conn, o.bytes)
	return
}

// PackMsg assigns the inner bytes from the inner msg.
func (o *Outbox) PackMsg() (err error) {
	o.msg.Compress = o.compress
	o.bytes, err = o.msg.Pack()
	return err
}

// WriteMsg does PackMsg and WriteBytes.
func (o *Outbox) WriteMsg() (err error) {
	err = o.PackMsg()
	if err != nil {
		return err
	}
	err = o.WriteBytes()
	return
}

// Push assigns the inner msg to a pointer to dns.Msg and does WriteMsg.
func (o *Outbox) Push(msg *dns.Msg) (err error) {
	o.msg = msg
	return o.WriteMsg()
}

// GetCompress returns true if a DNS message should be compressed while packing into bytes.
func (o *Outbox) GetCompress() bool {
	return o.compress
}

// SetCompress assigns the inner compress to true if a DNS message should be compressed while packing into bytes.
func (o *Outbox) SetCompress(v bool) {
	o.compress = v
}

// PushSign assigns the inner msg to a pointer to dns.Msg, adds an empty transaction signature (TSIG) record to it,
// assigns the inner bytes using dns.TsigGenerate and does WriteMsg.
func (o *Outbox) PushSign(msg *dns.Msg, secret string, prev *dns.TSIG) (err error) {
	o.msg = msg
	o.msg.Compress = o.compress
	o.msg.SetTsig(prev.Hdr.Name, prev.Algorithm, prev.Fudge, time.Now().Unix())
	o.bytes, _, err = dns.TsigGenerate(o.msg, secret, prev.MAC, len(prev.MAC) != 0)
	if err != nil {
		return err
	}
	err = o.WriteBytes()
	return
}

var (
	ErrDispatcherCantUnpack       = errors.New("can't unpack")
	ErrDispatcherEmptyPattern     = errors.New("empty pattern")
	ErrDispatcherEmptyRequest     = errors.New("empty request")
	ErrDispatcherEmptyStore       = errors.New("empty store")
	ErrDispatcherDuplicatePattern = errors.New("duplicate pattern")
	ErrDispatcherZoneNotFound     = errors.New("zone not found")

	ErrInboxValidateNoSecret = errors.New("no secret")
	ErrInboxValidateSkipped  = errors.New("skipped")
	ErrInboxValidateUnsigned = errors.New("unsigned")
)

const (
	DefInboxValidate  = false
	DefOutboxCompress = false
)

// NewInboxWithConn returns a pointer to Inbox with the inner conn set to a pointer to layer4.Connection.
func NewInboxWithConn(cx *layer4.Connection) *Inbox {
	return &Inbox{Box: Box{conn: cx}, validate: DefInboxValidate}
}

// NewOutboxWithConn returns a pointer to Outbox with the inner conn set to a pointer to layer4.Connection.
func NewOutboxWithConn(cx *layer4.Connection) *Outbox {
	return &Outbox{Box: Box{conn: cx}, compress: DefOutboxCompress}
}

// NewOutboxFromInbox returns a pointer to Outbox with its inner conn set to the inner conn of an Inbox.
func NewOutboxFromInbox(in *Inbox) *Outbox {
	return NewOutboxWithConn(in.conn)
}
