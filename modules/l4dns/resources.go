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
	"strings"

	"github.com/miekg/dns"
)

// Resources are items of dns.RR type to be consumed by authoritative zones.
type Resources []dns.RR

// Consume fills selected Resources into the inner structures of an outgoing message
// based on the contents of the incoming message and a number of extra flags.
func (r Resources) Consume(inMsg *dns.Msg, outMsg *dns.Msg, supportWildcard, expandCNAME, expandDNAME bool) error {
	// There is at least one element because of the validateHeaderCounters and Dispatcher.Dispatch checks
	q := &dns.Question{
		Name:   dns.CanonicalName(inMsg.Question[0].Name),
		Qtype:  inMsg.Question[0].Qtype,
		Qclass: inMsg.Question[0].Qclass,
	}

	// Add matching resource records to the answer section of the outgoing message
	switch q.Qtype {
	case dns.TypeIXFR, dns.TypeAXFR:
		rrs := r.FindFollowNextLabel(
			&dns.Question{Name: q.Name, Qtype: dns.TypeSOA, Qclass: q.Qclass},
			r.FindExact,
		)
		if len(rrs) == 0 {
			return ErrResourcesNoSOA
		}

		outMsg.Answer = rrs[0:1]
		soa := rrs[0].(*dns.SOA)
		origin := soa.Hdr.Name
		for _, rr := range r {
			if strings.HasSuffix(rr.Header().Name, origin) {
				outMsg.Answer = append(outMsg.Answer, rr)
			}
		}
		outMsg.Answer = append(outMsg.Answer, soa)
	case dns.TypeANY, dns.TypeCNAME, dns.TypeDNAME:
		var f func(*dns.Question) Resources
		if supportWildcard {
			f = r.FindWildOrCanonicalName
		} else {
			f = r.FindExactOrCanonicalName
		}
		outMsg.Answer = f(q)
	default:
		var f, ff, fff func(*dns.Question) Resources
		if supportWildcard {
			f = r.FindWildOrCanonicalName
		} else {
			f = r.FindExactOrCanonicalName
		}
		if expandCNAME {
			ff = func(q *dns.Question) Resources {
				return r.FindCanonicalNameTree(q, f, 0)
			}
		} else {
			ff = f
		}
		if expandDNAME {
			fff = func(q *dns.Question) Resources {
				return r.FindDelegationNameTree(q, ff)
			}
		} else {
			fff = ff
		}
		outMsg.Answer = fff(q)
	}

	// If there are no matching resource records, add a SOA record to the authority section of the outgoing message
	if len(outMsg.Answer) == 0 {
		rrs := r.FindFollowNextLabel(
			&dns.Question{Name: q.Name, Qtype: dns.TypeSOA, Qclass: q.Qclass},
			r.FindExact,
		)
		if len(rrs) == 0 {
			return ErrResourcesNoSOA
		}
		outMsg.Ns = rrs[0:1]
		outMsg.Rcode = dns.RcodeNameError
	}

	return nil
}

// FindCanonicalNameTree recursively follows a local canonical name tree (no more than 10 iterations)
// to return Resources matching a dns.Question (as rendered by a given function). The resulting slice contains
// records of dns.TypeCNAME found on each iteration as well as matching records for the final canonical name.
func (r Resources) FindCanonicalNameTree(q *dns.Question, f func(*dns.Question) Resources, c uint) Resources {
	rrs := f(q)
	if c < 10 && len(rrs) > 0 && rrs[0].Header().Rrtype == dns.TypeCNAME {
		tree := r.FindCanonicalNameTree(
			&dns.Question{Name: rrs[0].(*dns.CNAME).Target, Qtype: q.Qtype, Qclass: q.Qclass}, f, c+1,
		)
		tree = append(tree, rrs[0])
		return tree
	}
	return rrs
}

func (r Resources) FindDelegationNameTree(q *dns.Question, f func(*dns.Question) Resources) Resources {
	rrs := f(q)
	if len(rrs) > 0 {
		return rrs
	}

	off, end := dns.NextLabel(q.Name, 0)
	if end {
		return rrs
	}

	rrs = r.FindFollowNextLabel(&dns.Question{Name: q.Name[off:], Qtype: dns.TypeDNAME, Qclass: q.Qclass}, r.FindExact)
	if len(rrs) == 0 {
		return rrs
	}

	_, ok := rrs[0].(*dns.DNAME)
	if !ok {
		return rrs
	}

	var replacer func(string, []dns.RR, int) string
	replacer = func(name string, rrs []dns.RR, off int) string {
		if off < len(rrs)-1 {
			name = replacer(name, rrs, off+1)
		}

		switch rrs[off].(type) {
		case *dns.CNAME:
			cname := rrs[off].(*dns.CNAME)
			s, _ := strings.CutSuffix(name, cname.Hdr.Name)
			return s + cname.Target
		case *dns.DNAME:
			dname := rrs[off].(*dns.DNAME)
			s, _ := strings.CutSuffix(name, dname.Hdr.Name)
			return s + dname.Target
		default:
			return name
		}
	}

	tree := r.FindDelegationNameTree(&dns.Question{Name: replacer(q.Name, rrs, 0), Qtype: q.Qtype, Qclass: q.Qclass}, f)
	tree = append(tree, rrs...)
	return tree
}

// FindFollowNextLabel recursively trims labels from the left of a given domain name
// to return Resources matching a dns.Question (as rendered by a given function).
func (r Resources) FindFollowNextLabel(q *dns.Question, f func(*dns.Question) Resources) Resources {
	for off, end := 0, false; !end; off, end = dns.NextLabel(q.Name, off) {
		rrs := f(&dns.Question{Name: q.Name[off:], Qtype: q.Qtype, Qclass: q.Qclass})
		if len(rrs) > 0 {
			return rrs
		}
	}
	return make([]dns.RR, 0)
}

// FindExact returns Resources exactly matching a dns.Question, i.e. having a matching domain name,
// class (skipped if dns.ClassANY is requested) and type (skipped if dns.TypeANY is requested).
func (r Resources) FindExact(q *dns.Question) Resources {
	return r.FindExactParam(q, false)
}

// FindExactOrCanonicalName returns Resources exactly matching a dns.Question, i.e. having a matching domain name,
// class (skipped if dns.ClassANY is requested) and type (skipped if dns.TypeANY is requested). If there is a matching
// record of dns.TypeCNAME for a given domain name, a single-item slice with this dns.RR is returned instead.
func (r Resources) FindExactOrCanonicalName(q *dns.Question) Resources {
	return r.FindExactParam(q, true)
}

// FindExactParam implements FindExact and FindExactOrCanonicalName.
func (r Resources) FindExactParam(q *dns.Question, prioritizeCNAME bool) Resources {
	return r.FindParam(q, false, prioritizeCNAME)
}

// FindWild returns Resources matching a dns.Question, i.e. having a matching domain name,
// class (skipped if dns.ClassANY is requested) and type (skipped if dns.TypeANY is requested).
func (r Resources) FindWild(q *dns.Question) Resources {
	return r.FindWildParam(q, false)
}

// FindWildOrCanonicalName returns Resources matching a dns.Question, i.e. having a matching domain name,
// class (skipped if dns.ClassANY is requested) and type (skipped if dns.TypeANY is requested). If there is a matching
// record of dns.TypeCNAME for a given domain name, a single-item slice with this dns.RR is returned instead.
func (r Resources) FindWildOrCanonicalName(q *dns.Question) Resources {
	return r.FindWildParam(q, true)
}

// FindWildParam implements FindWild and FindWildOrCanonicalName.
func (r Resources) FindWildParam(q *dns.Question, prioritizeCNAME bool) Resources {
	return r.FindParam(q, true, prioritizeCNAME)
}

// FindParam implements FindExactParam and FindWildParam.
func (r Resources) FindParam(q *dns.Question, searchWildcard, prioritizeCNAME bool) Resources {
	qNames := []string{q.Name}
	if searchWildcard && len(q.Name) > 1 && q.Name[0] != '*' {
		off, _ := dns.NextLabel(q.Name, 0)
		qNames = append(qNames, "*."+q.Name[off:])
	}

	rrs := make([]dns.RR, 0)
	var a *dns.RR_Header
	for _, qName := range qNames {
		for _, rr := range r {
			a = rr.Header()
			if (qName == a.Name) && (q.Qclass == dns.ClassANY || q.Qclass == a.Class) {
				if q.Qtype == dns.TypeANY || q.Qtype == a.Rrtype {
					rrs = append(rrs, rr)
					continue
				}
				// If there is a canonical name, ignore everything else
				if prioritizeCNAME && a.Rrtype == dns.TypeCNAME {
					rrs = append(rrs[0:0], rr)
					break
				}
			}
		}
		// If there is at least one matching resource record, ignore everything else
		if len(rrs) > 0 {
			break
		}
	}
	return rrs
}

var ErrResourcesNoSOA = errors.New("no SOA records found")
