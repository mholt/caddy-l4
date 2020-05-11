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

// Handlers is a list of connection handlers.
type Handlers []NextHandler

// Compile assembles the list of handlers into a
// single handler chain.
func (h Handlers) Compile() Handler {
	var midware []Middleware
	for _, midhandler := range h {
		midware = append(midware, wrapHandler(midhandler))
	}
	var next Handler = nopHandler{}
	for i := len(midware) - 1; i >= 0; i-- {
		next = midware[i](next)
	}
	return next
}

// NextHandler is a type that can handle connections
// as part of a middleware chain.
type NextHandler interface {
	Handle(*Connection, Handler) error
}

// Handler is a type that can handle connections.
type Handler interface {
	Handle(*Connection) error
}

// Middleware is a function that wraps a handler.
type Middleware func(Handler) Handler

func wrapHandler(h NextHandler) Middleware {
	return func(next Handler) Handler {
		// TODO: copy next?
		return HandlerFunc(func(cx *Connection) error {
			return h.Handle(cx, next) // TODO: refer to copy here?
		})
	}
}

// HandlerFunc can turn a function into a Handler type.
type HandlerFunc func(*Connection) error

// Handle handles a connection; it implements the Handler interface.
func (h HandlerFunc) Handle(cx *Connection) error { return h(cx) }

// nopHandler is a connection handler that does nothing with the
// connection, not even reading from it; it simply returns. It is
// the default end of all handler chains.
//
// A nopHandler is distinct from a "discard" handler that reads
// the connection and drains it into a black hole: while such a
// handler would ensure that any concurrent branches handling the
// connection don't get blocked, it could also burn through data
// transfer unnecessarily. So as a slight security feature, we
// don't drain a client's unused connection, and instead opt to
// return and close the connection.
type nopHandler struct{}

func (nopHandler) Handle(_ *Connection) error { return nil }
