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

package l4tee

import (
	"encoding/json"
	"io"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a layer4 handler that replicates a connection so
// that a branch of handlers can concurrently handle it. Reads
// happen in lock-step with all concurrent branches so as to
// avoid buffering: if one of the branches (including the main
// handler chain) stops reading from the connection, it will
// block all branches.
type Handler struct {
	// Handlers is the list of handlers that constitute this
	// concurrent branch. Any handlers that do connection
	// matching (which involves recording and rewinding the
	// stream) are unsafe to tee, so do all connection
	// matching before teeing.
	HandlersRaw []json.RawMessage `json:"branch,omitempty" caddy:"namespace=layer4.handlers inline_key=handler"`

	compiledChain layer4.Handler
	logger        *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.tee",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (t *Handler) Provision(ctx caddy.Context) error {
	t.logger = ctx.Logger(t)

	// set up the handler chain
	mods, err := ctx.LoadModule(t, "HandlersRaw")
	if err != nil {
		return err
	}
	var handlers layer4.Handlers
	for _, mod := range mods.([]interface{}) {
		handlers = append(handlers, mod.(layer4.NextHandler))
	}
	t.compiledChain = handlers.Compile()

	return nil
}

// Handle handles the connection.
func (t Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	// what is read by the next handler will also be
	// read by the branch handlers; this is done by
	// writing conn's reads into a pipe, and having
	// the branch read from the pipe
	pr, pw := io.Pipe()

	// this is the conn we pass to the next handler;
	// anything read by it will be teed into the pipe
	// (it also needs a pointer to the pipe so it can
	// close the pipe when the connection closes,
	// otherwise we'll leak the goroutine, yikes!)
	nextc := *cx
	nextc.Conn = nextConn{
		Conn:   cx,
		Reader: io.TeeReader(cx, pw),
		pipe:   pw,
	}

	// this is the conn we pass to the branch
	branchc := *cx
	branchc.Conn = teeConn{
		Conn:   cx,
		Reader: pr,
	}

	// run the branch concurrently
	go func() {
		err := t.compiledChain.Handle(&branchc)
		if err != nil {
			t.logger.Error("handling connection in branch", zap.Error(err))
		}
	}()

	return next.Handle(&nextc)
}

// teeConn is a connection wrapper that reads
// from a different reader.
type teeConn struct {
	net.Conn
	io.Reader
}

func (tc teeConn) Read(p []byte) (int, error) {
	return tc.Reader.Read(p)
}

// nextConn is a connection wrapper that reads from
// a different reader, and when the reader returns
// EOF, the associated pipe is closed.
type nextConn struct {
	net.Conn
	io.Reader
	pipe *io.PipeWriter
}

func (nc nextConn) Read(p []byte) (n int, err error) {
	n, err = nc.Reader.Read(p)
	if err == io.EOF {
		nc.pipe.Close()
	}
	return
}

// Interface guard
var _ layer4.NextHandler = (*Handler)(nil)
