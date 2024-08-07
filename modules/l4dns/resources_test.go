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
	"testing"

	"github.com/miekg/dns"
)

func Test_FindDelegationNameTree_RFC6672_S2_2(t *testing.T) {
	rrs, err := (&ProviderText{}).ParseRecords(rfc6672)
	if err != nil {
		t.Fatalf("Unexpected error: %s\n", err)
	}

	type test struct {
		q *dns.Question
		a []string
	}

	tests := []test{
		{
			&dns.Question{Name: "com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			[]string{},
		},
		{
			&dns.Question{Name: "one.com.", Qtype: dns.TypeDNAME, Qclass: dns.ClassINET},
			[]string{
				"one.com.\t0\tIN\tDNAME\tone.net.",
			},
		},
		{
			&dns.Question{Name: "one.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			[]string{},
		},
		{
			&dns.Question{Name: "a.one.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			[]string{
				"a.one.net.\t0\tIN\tA\t127.0.0.2",
				"one.com.\t0\tIN\tDNAME\tone.net.",
			},
		},
		{
			&dns.Question{Name: "a.bb.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			[]string{
				"a.bb.example.net.\t0\tIN\tA\t127.0.0.3",
				"example.com.\t0\tIN\tDNAME\texample.net.",
			},
		},
		{
			&dns.Question{Name: "rexample.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			[]string{},
		},
		{
			&dns.Question{Name: "foo.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			[]string{
				"foo.example.net.\t0\tIN\tA\t127.0.0.4",
				"example.com.\t0\tIN\tDNAME\texample.net.",
			},
		},
		{
			&dns.Question{Name: "a.x.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			[]string{
				"a.example.net.\t0\tIN\tA\t127.0.0.2",
				"x.example.com.\t0\tIN\tDNAME\texample.net.",
			},
		},
	}

	funcs := []func(*dns.Question) Resources{
		Resources(rrs).FindExact,
		Resources(rrs).FindWild,
		Resources(rrs).FindExactOrCanonicalName,
		Resources(rrs).FindWildOrCanonicalName,
		func(q *dns.Question) Resources {
			return Resources(rrs).FindCanonicalNameTree(q, Resources(rrs).FindExactOrCanonicalName, 0)
		},
		func(q *dns.Question) Resources {
			return Resources(rrs).FindCanonicalNameTree(q, Resources(rrs).FindWildOrCanonicalName, 0)
		},
	}

	var result Resources
	for i, tc := range tests {
		for j, f := range funcs {
			result = Resources(rrs).FindDelegationNameTree(tc.q, f)
			if len(result) != len(tc.a) {
				t.Fatalf("Test %d, func %d: wrong result length; expected %d\n", i, j, len(result))
			}
			for k, line := range result {
				s := line.String()
				if s != tc.a[k] {
					t.Fatalf("Test %d, func %d: wrong result %d; expected '%s'\n", i, j, k, s)
				}
			}
		}
	}
}

var (
	rfc6672 = []string{
		"$ORIGIN .",
		"$TTL 0",
		"one.com. IN DNAME one.net.",
		"b.two.com. IN DNAME two.net.",
		"x.three.com. IN DNAME three.net.",
		"four.com. IN DNAME y.four.net.",
		"five.com. IN DNAME five.com.",
		"six. IN DNAME .",
		"one.net. IN A 127.0.0.1",
		"a.one.net. IN A 127.0.0.2",
		"a.b.one.net. IN A 127.0.0.3",
		"foo.example.net. IN A 127.0.0.4",
	}
)
