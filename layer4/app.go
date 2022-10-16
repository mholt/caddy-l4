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
	"net"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
}

// App is a Caddy app that operates closest to layer 4 of the OSI model.
type App struct {
	// Servers are the servers to create. The key of each server must be
	// a unique name identifying the server for your own convenience;
	// the order of servers does not matter.
	Servers map[string]*Server `json:"servers,omitempty"`

	listeners   []net.Listener
	packetConns []net.PacketConn
	logger      *zap.Logger
	ctx         caddy.Context
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the app.
func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger()

	for srvName, srv := range a.Servers {
		err := srv.Provision(ctx, a.logger)
		if err != nil {
			return fmt.Errorf("server '%s': %v", srvName, err)
		}
	}

	return nil
}

// Start starts the app.
func (a *App) Start() error {
	for _, s := range a.Servers {
		for _, addr := range s.listenAddrs {
			listeners, err := addr.ListenAll(a.ctx, net.ListenConfig{})
			if err != nil {
				return err
			}
			for _, lnAny := range listeners {
				var lnAddr string
				switch ln := lnAny.(type) {
				case net.Listener:
					a.listeners = append(a.listeners, ln)
					lnAddr = caddy.JoinNetworkAddress(ln.Addr().Network(), ln.Addr().String(), "")
					go s.serve(ln)
				case net.PacketConn:
					a.packetConns = append(a.packetConns, ln)
					lnAddr = caddy.JoinNetworkAddress(ln.LocalAddr().Network(), ln.LocalAddr().String(), "")
					go s.servePacket(ln)
				}
				s.logger.Debug("listening", zap.String("address", lnAddr))
			}
		}
	}
	return nil
}

// Stop stops the servers and closes all listeners.
func (a App) Stop() error {
	for _, pc := range a.packetConns {
		err := pc.Close()
		if err != nil {
			a.logger.Error("closing packet listener",
				zap.String("network", pc.LocalAddr().Network()),
				zap.String("address", pc.LocalAddr().String()),
				zap.Error(err))
		}
	}
	for _, ln := range a.listeners {
		err := ln.Close()
		if err != nil {
			a.logger.Error("closing listener",
				zap.String("network", ln.Addr().Network()),
				zap.String("address", ln.Addr().String()),
				zap.Error(err))
		}
	}
	return nil
}

// Interface guard
var _ caddy.App = (*App)(nil)
