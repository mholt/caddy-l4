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
	// set, but multiple sets are OR'ed together. No matchers matches all.
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
	for _, mod := range mods.([]interface{}) {
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

// Compile prepares a middleware chain from the route list.
// This should only be done once: after all the routes have
// been provisioned, and before the server loop begins.
func (routes RouteList) Compile(logger *zap.Logger, matchingTimeout time.Duration, next NextHandler) Handler {
	return HandlerFunc(func(cx *Connection) error {
		deadline := time.Now().Add(matchingTimeout)
	router:
		// timeout matching to protect against malicious or very slow clients
		err := cx.Conn.SetReadDeadline(deadline)
		if err != nil {
			return err
		}
		isFirstPrefetch := true
		for { // retry prefetching and matching routes until timeout

			// Do not call prefetch if this is the first loop iteration and there already is some data available,
			// since this means we are at the start of a subroute handler and previous prefetch calls likely already fetched all bytes available from the client.
			// Which means it would block the subroute handler. In the second iteration (if no subroute routes match) blocking is the correct behaviour.
			if !isFirstPrefetch || cx.buf == nil || len(cx.buf[cx.offset:]) == 0 {
				err = cx.prefetch()
				isFirstPrefetch = false
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

			for _, route := range routes {
				// A route must match at least one of the matcher sets
				matched, err := route.matcherSets.AnyMatch(cx)
				if errors.Is(err, ErrConsumedAllPrefetchedBytes) {
					continue // ignore and try next route
				}
				if err != nil {
					logger.Error("matching connection", zap.String("remote", cx.RemoteAddr().String()), zap.Error(err))
					return nil
				}
				if matched {
					// remove deadline after we matched
					err = cx.Conn.SetReadDeadline(time.Time{})
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
					handler := wrapHandler(next)(lastHandler)
					for i := len(route.middleware) - 1; i >= 0; i-- {
						handler = route.middleware[i](handler)
					}
					err = handler.Handle(cx)
					if err != nil {
						return err
					}

					// If handler is terminal we stop routing,
					// otherwise we jump back to the start of the routing loop to peel of more protocol layers.
					if isTerminal {
						return nil
					} else {
						goto router
					}
				}
			}
		}
	})
}
