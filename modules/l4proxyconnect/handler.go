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

package l4proxyconnect

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
	"net"
	"net/http"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a connection handler that terminates an HTTP CONNECT.
type Handler struct {
	ctx     caddy.Context
	logger  *zap.Logger
	baseCfg *http.Server
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.http-connect",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the module.
func (t *Handler) Provision(ctx caddy.Context) error {
	t.ctx = ctx
	t.logger = ctx.Logger(t)

	return nil
}

// Handle handles the connections.
func (t *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	ch := &ConnectHandler{next: next, cx: cx, t: t}
	s1 := &http.Server{
		Addr:              "",
		Handler:           ch,
		ReadTimeout:       0,
		ReadHeaderTimeout: 0,
		WriteTimeout:      0,
		IdleTimeout:       0,
		MaxHeaderBytes:    0,
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ConnState:    nil,
		ErrorLog:     nil,
		BaseContext: func(listener net.Listener) context.Context {
			return t.ctx
		},
		ConnContext: nil,
	}

	l := NewSingleConnListener(cx)
	err := s1.Serve(l)
	if err != nil {
		return err
	}
	if ch.err != nil {
		t.logger.Error("CONNECT serve error",
			zap.Error(ch.err))
	}
	return ch.err
}

type ConnectHandler struct {
	next layer4.Handler
	cx   *layer4.Connection
	t    *Handler
	err  error
}

func (chf *ConnectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		chf.err = fmt.Errorf("Only CONNECT requests supported")
		http.Error(w, chf.err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		chf.err = fmt.Errorf("Hijacking not supported")
		http.Error(w, chf.err.Error(), http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		chf.err = err
		http.Error(w, chf.err.Error(), http.StatusServiceUnavailable)
		return
	}

	chf.t.logger.Debug("CONNECT",
		zap.String("remote", client_conn.RemoteAddr().String()),
		zap.String("local", client_conn.LocalAddr().String()),
		zap.String("target", r.Host),
	)

	if err = chf.next.Handle(chf.cx.Wrap(client_conn)); err != nil {
		chf.err = err
		http.Error(w, "Failed to handle "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// Interface guards
var (
	_ caddy.Provisioner  = (*Handler)(nil)
	_ layer4.NextHandler = (*Handler)(nil)
)
