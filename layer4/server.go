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
	"fmt"
	"net"
	"sync"
	"time"

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
		if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
			s.logger.Error("accepting connection: temporary error", zap.Error(err))
			continue
		}
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s Server) servePacket(pc net.PacketConn) error {
	for {
		buf := udpBufPool.Get().([]byte)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		go func(buf []byte, n int, addr net.Addr) {
			defer udpBufPool.Put(buf)
			s.handle(packetConn{
				PacketConn: pc,
				buf:        bytes.NewBuffer(buf[:n]),
				addr:       addr,
			})
		}(buf, n, addr)
	}
}

func (s Server) handle(conn net.Conn) {
	defer conn.Close()

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	cx := WrapConnection(conn, buf)

	start := time.Now()
	err := s.compiledRoute.Handle(cx)
	duration := time.Since(start)
	if err != nil {
		s.logger.Error("handling connection", zap.Error(err))
	}

	s.logger.Debug("connection stats",
		zap.String("remote", cx.RemoteAddr().String()),
		zap.Uint64("read", cx.bytesRead),
		zap.Uint64("written", cx.bytesWritten),
		zap.Duration("duration", duration),
	)
}

type packetConn struct {
	net.PacketConn
	buf  *bytes.Buffer
	addr net.Addr
}

func (pc packetConn) Read(b []byte) (n int, err error) {
	return pc.buf.Read(b)
}

func (pc packetConn) Write(b []byte) (n int, err error) {
	return pc.PacketConn.WriteTo(b, pc.addr)
}

func (pc packetConn) RemoteAddr() net.Addr { return pc.addr }

var udpBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1024)
	},
}
