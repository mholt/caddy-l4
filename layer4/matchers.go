// Copyright 2020 Matthew Holt
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

package layer4

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
)

// ConnMatcher is a type that can match a connection.
type ConnMatcher interface {
	// Match returns true if the given connection matches.
	// It should read from the connection as little as possible:
	// only as much as necessary to determine a match.
	Match(*Connection) (bool, error)
}

// MatcherSet is a set of matchers which
// must all match in order for the request
// to be matched successfully.
type MatcherSet []ConnMatcher

// Match returns true if the connection matches all matchers in mset
// or if there are no matchers. Any error terminates matching.
func (mset MatcherSet) Match(cx *Connection) (matched bool, err error) {
	for _, m := range mset {
		cx.record()
		matched, err = m.Match(cx)
		cx.rewind()
		if !matched || err != nil {
			return
		}
	}
	matched = true
	return
}

// RawMatcherSets is a group of matcher sets in their
// raw JSON form.
type RawMatcherSets []caddy.ModuleMap

// MatcherSets is a group of matcher sets capable of checking
// whether a connection matches any of the sets.
type MatcherSets []MatcherSet

// AnyMatch returns true if the connection matches any of the matcher sets
// in mss or if there are no matchers, in which case the request always
// matches. Any error terminates matching.
func (mss MatcherSets) AnyMatch(cx *Connection) (matched bool, err error) {
	for _, m := range mss {
		matched, err = m.Match(cx)
		if matched || err != nil {
			return
		}
	}
	matched = len(mss) == 0
	return
}

// FromInterface fills ms from an interface{} value obtained from LoadModule.
func (mss *MatcherSets) FromInterface(matcherSets interface{}) error {
	for _, matcherSetIfaces := range matcherSets.([]map[string]interface{}) {
		var matcherSet MatcherSet
		for _, matcher := range matcherSetIfaces {
			connMatcher, ok := matcher.(ConnMatcher)
			if !ok {
				return fmt.Errorf("decoded module is not a ConnMatcher: %#v", matcher)
			}
			matcherSet = append(matcherSet, connMatcher)
		}
		*mss = append(*mss, matcherSet)
	}
	return nil
}
