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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// Route represents a collection of handlers that are gated by
// matching logic. A route is invoked if its matchers match
// the byte stream. In an equivalent "if...then" statement,
// matchers are like the "if" clause and handlers are the "then"
// clause: if the matchers match, then the handlers will be
// executed.
type Route struct {
	// Matchers define the conditions upon which to execute the handlers.
	// All matchers within the same set must match, and at least one set
	// must match; in other words, matchers are AND'ed together within a
	// set, but multiple sets are OR'ed together. No matchers match all.
	MatcherSetsRaw []caddy.ModuleMap `json:"match,omitempty" caddy:"namespace=layer4.matchers"`

	// Handlers define the behavior for handling the stream. They are
	// executed in sequential order if the route's matchers match.
	HandlersRaw []json.RawMessage `json:"handle,omitempty" caddy:"namespace=layer4.handlers inline_key=handler"`

	matcherSets MatcherSets
	middleware  []Middleware
}

var ErrMatchingTimeout = errors.New("aborted matching according to timeout")

// Provision sets up a route.
func (r *Route) Provision(ctx caddy.Context) error {
	// matchers
	matchersIface, err := ctx.LoadModule(r, "MatcherSetsRaw")
	if err != nil {
		return fmt.Errorf("loading matcher modules: %v", err)
	}
	err = r.matcherSets.FromInterface(matchersIface)
	if err != nil {
		return err
	}

	// handlers
	mods, err := ctx.LoadModule(r, "HandlersRaw")
	if err != nil {
		return err
	}
	var handlers Handlers
	for _, mod := range mods.([]any) {
		handler := mod.(NextHandler)
		handlers = append(handlers, handler)
	}
	for _, midhandler := range handlers {
		r.middleware = append(r.middleware, wrapHandler(midhandler))
	}
	return nil
}

// RouteList is a list of connection routes that can create
// a middleware chain. Routes are evaluated in sequential
// order: for the first route, the matchers will be evaluated,
// and if matched, the handlers invoked; and so on for the
// second route, etc.
type RouteList []*Route

// Provision sets up all the routes.
func (routes RouteList) Provision(ctx caddy.Context) error {
	for i, r := range routes {
		err := r.Provision(ctx)
		if err != nil {
			return fmt.Errorf("route %d: %v", i, err)
		}
	}
	return nil
}

const (
	// routes that need more data to determine the match
	routeNeedsMore = iota
	// routes definitely not matched
	routeNotMatched
	routeMatched
)

// Compile prepares a middleware chain from the route list.
// This should only be done once: after all the routes have
// been provisioned, and before the server loop begins.
func (routes RouteList) Compile(logger *zap.Logger, matchingTimeout time.Duration, next Handler) Handler {
	return HandlerFunc(func(cx *Connection) error {
		deadline := time.Now().Add(matchingTimeout)

		var (
			lastMatchedRouteIdx = -1
			lastNeedsMoreIdx    = -1
			routesStatus        = make(map[int]int)
			matcherNeedMore     bool
		)
		// this loop should only be done if there are matchers that can't determine the match,
		// i.e. some of the matchers returned false, ErrConsumedAllPrefetchedBytes. The index which
		// the loop begins depends upon if there is a matched route.
	loop:
		// timeout matching to protect against malicious or very slow clients
		err := cx.SetReadDeadline(deadline)
		if err != nil {
			return err
		}
		for {
			// only read more because matchers require more (no matcher in the simplest case).
			// can happen if this routes list is embedded in another
			if matcherNeedMore {
				err = cx.prefetch()
				if err != nil {
					logFunc := logger.Error
					if errors.Is(err, os.ErrDeadlineExceeded) {
						err = ErrMatchingTimeout
						logFunc = logger.Warn
					}
					logFunc("matching connection", zap.String("remote", cx.RemoteAddr().String()), zap.Error(err))
					return nil // return nil so the error does not get logged again
				}
			}

			for i, route := range routes {
				if i <= lastMatchedRouteIdx {
					continue
				}

				// If the route is definitely not matched, skip it
				if s, ok := routesStatus[i]; ok && s == routeNotMatched && i <= lastNeedsMoreIdx {
					continue
				}
				// now the matcher is after a matched route and current route needs more data to determine if more data is needed.
				// note a matcher is skipped if the one after it can determine it is matched

				// A route must match at least one of the matcher sets
				matched, err := route.matcherSets.AnyMatch(cx)
				if errors.Is(err, ErrConsumedAllPrefetchedBytes) {
					lastNeedsMoreIdx = i
					routesStatus[i] = routeNeedsMore
					// the first time a matcher requires more data, exit the loop to force a prefetch
					if !matcherNeedMore {
						break
					}
					continue // ignore and try next route
				}
				if err != nil {
					logger.Error("matching connection", zap.String("remote", cx.RemoteAddr().String()), zap.Error(err))
					return nil
				}
				if matched {
					routesStatus[i] = routeMatched
					lastMatchedRouteIdx = i
					lastNeedsMoreIdx = i
					// remove deadline after we matched
					err = cx.SetReadDeadline(time.Time{})
					if err != nil {
						return err
					}

					isTerminal := true
					lastHandler := HandlerFunc(func(conn *Connection) error {
						// Catch potentially wrapped connection to use it as input for the next round of route matching.
						// This is for example required for matchers after a tls handler.
						cx = conn
						// If this handler is called all handlers before where not terminal
						isTerminal = false
						return nil
					})
					// compile the route handler stack with lastHandler being called last
					handler := wrapHandler(forwardNextHandler{})(lastHandler)
					for i := len(route.middleware) - 1; i >= 0; i-- {
						handler = route.middleware[i](handler)
					}
					err = handler.Handle(cx)
					if err != nil {
						return err
					}

					// If handler is terminal we stop routing,
					// otherwise we try the next handler.
					if isTerminal {
						return nil
					}
				} else {
					routesStatus[i] = routeNotMatched
				}
			}
			// end of match
			if lastMatchedRouteIdx == len(routes)-1 {
				// next is called because if the last handler is terminal, it's already returned
				return next.Handle(cx)
			}
			var indetermined int
			for i, s := range routesStatus {
				if i > lastMatchedRouteIdx && s == routeNeedsMore {
					indetermined++
				}
			}
			// some of the matchers can't reach a conclusion
			if indetermined > 0 {
				matcherNeedMore = true
				goto loop
			}
			// fallback route, removing deadline
			// see: https://github.com/mholt/caddy-l4/issues/274
			err = cx.SetReadDeadline(time.Time{})
			if err != nil {
				return err
			}
			return next.Handle(cx)
		}
	})
}
