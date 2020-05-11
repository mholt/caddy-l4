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
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// Route represents a collection of handlers that are gated
// by matching and other kinds of logic.
type Route struct {
	MatcherSetsRaw []caddy.ModuleMap `json:"match,omitempty" caddy:"namespace=layer4.matchers"`
	HandlersRaw    []json.RawMessage `json:"handle,omitempty" caddy:"namespace=layer4.handlers inline_key=handler"`

	matcherSets MatcherSets
	middleware  []Middleware
}

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
		handlers = append(handlers, mod.(NextHandler))
	}
	for _, midhandler := range handlers {
		r.middleware = append(r.middleware, wrapHandler(midhandler))
	}

	return nil
}

// RouteList is a list of connection routes that can create
// a middleware chain.
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
func (routes RouteList) Compile(next Handler, logger *zap.Logger) Handler {
	mid := make([]Middleware, 0, len(routes))
	for _, route := range routes {
		mid = append(mid, wrapRoute(route, logger))
	}
	stack := next
	for i := len(mid) - 1; i >= 0; i-- {
		stack = mid[i](stack)
	}
	return stack
}

// wrapRoute wraps route with a middleware and handler so that it can
// be chained in and defer evaluation of its matchers to request-time.
// Like wrapMiddleware, it is vital that this wrapping takes place in
// its own stack frame so as to not overwrite the reference to the
// intended route by looping and changing the reference each time.
func wrapRoute(route *Route, logger *zap.Logger) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(cx *Connection) error {
			// TODO: Update this comment, it seems we've moved the copy into the handler?
			// copy the next handler (it's an interface, so it's just
			// a very lightweight copy of a pointer); this is important
			// because this is a closure to the func below, which
			// re-assigns the value as it compiles the middleware stack;
			// if we don't make this copy, we'd affect the underlying
			// pointer for all future request (yikes); we could
			// alternatively solve this by moving the func below out of
			// this closure and into a standalone package-level func,
			// but I just thought this made more sense
			nextCopy := next

			// route must match at least one of the matcher sets
			matched, err := route.matcherSets.AnyMatch(cx)
			if err != nil {
				logger.Error("matching connection", zap.Error(err))
			}
			if !matched {
				return nextCopy.Handle(cx)
			}

			// TODO: other routing features?

			// // if route is part of a group, ensure only the
			// // first matching route in the group is applied
			// if route.Group != "" {
			// 	groups := req.Context().Value(routeGroupCtxKey).(map[string]struct{})

			// 	if _, ok := groups[route.Group]; ok {
			// 		// this group has already been
			// 		// satisfied by a matching route
			// 		return nextCopy.ServeHTTP(rw, req)
			// 	}

			// 	// this matching route satisfies the group
			// 	groups[route.Group] = struct{}{}
			// }

			// // make terminal routes terminate
			// if route.Terminal {
			// 	nextCopy = emptyHandler
			// }

			// compile this route's handler stack
			for i := len(route.middleware) - 1; i >= 0; i-- {
				nextCopy = route.middleware[i](nextCopy)
			}
			return nextCopy.Handle(cx)
		})
	}
}
