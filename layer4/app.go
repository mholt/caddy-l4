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
	"strings"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
}

// App is a Caddy app that operates closest to layer 4 of the OSI model.
type App struct {
	Servers map[string]*Server `json:"servers,omitempty"`

	listeners   []net.Listener
	packetConns []net.PacketConn
	logger      *zap.Logger
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
	a.logger = ctx.Logger(a)

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
			for i := uint(0); i < addr.PortRangeSize(); i++ {
				var lnAddr string
				if strings.Contains(addr.Network, "udp") {
					pc, err := caddy.ListenPacket(addr.Network, addr.JoinHostPort(i))
					if err != nil {
						return err
					}
					a.packetConns = append(a.packetConns, pc)
					lnAddr = pc.LocalAddr().Network() + "/" + pc.LocalAddr().String()
					go s.servePacket(pc)
				} else {
					ln, err := caddy.Listen(addr.Network, addr.JoinHostPort(i))
					if err != nil {
						return err
					}
					a.listeners = append(a.listeners, ln)
					lnAddr = ln.Addr().Network() + "/" + ln.Addr().String()
					go s.serve(ln)
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
