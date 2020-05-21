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
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// Server represents a Caddy layer4 server.
type Server struct {
	Listen []string  `json:"listen,omitempty"`
	Routes RouteList `json:"routes,omitempty"`

	logger        *zap.Logger
	listenAddrs   []caddy.NetworkAddress
	compiledRoute Handler
}

// Provision sets up the server.
func (s *Server) Provision(ctx caddy.Context, logger *zap.Logger) error {
	s.logger = logger

	for i, address := range s.Listen {
		addr, err := caddy.ParseNetworkAddress(address)
		if err != nil {
			return fmt.Errorf("parsing listener address '%s' in position %d: %v", address, i, err)
		}
		s.listenAddrs = append(s.listenAddrs, addr)
	}

	err := s.Routes.Provision(ctx)
	if err != nil {
		return err
	}
	s.compiledRoute = s.Routes.Compile(nopHandler{}, s.logger)

	return nil
}

func (s Server) serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err // TODO: lol, this isn't good (I think)
		}
		go s.handle(conn)
	}
}

func (s Server) handle(conn net.Conn) {
	defer conn.Close()

	repl := caddy.NewReplacer()
	repl.Set("l4.conn.remote_addr", conn.RemoteAddr())
	repl.Set("l4.conn.local_addr", conn.LocalAddr())

	ctx := context.Background()
	ctx = context.WithValue(ctx, VarsCtxKey, make(map[string]interface{}))
	ctx = context.WithValue(ctx, ReplacerCtxKey, repl)

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	cx := &Connection{
		Context: ctx,
		buf:     buf,
	}
	cx.Conn = &recordableConn{
		Conn: conn,
		cx:   cx,
	}

	err := s.compiledRoute.Handle(cx)
	if err != nil {
		s.logger.Error("handling connection", zap.Error(err))
	}
}
