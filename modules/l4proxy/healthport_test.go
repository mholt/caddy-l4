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

package l4proxy

import (
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func TestActiveHealthCheckPortPreservesPeerAddress(t *testing.T) {
	const testTimeout = 2 * time.Second

	listenTCP := func(name string) *net.TCPListener {
		t.Helper()
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 0,
		})
		if err != nil {
			t.Fatalf("listen on %s: %v", name, err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		return listener
	}

	dataListener := listenTCP("data port")
	healthListener := listenTCP("health-check port")
	dataPort := dataListener.Addr().(*net.TCPAddr).Port
	healthPort := healthListener.Addr().(*net.TCPAddr).Port
	if dataPort == healthPort {
		t.Fatalf("data and health listeners unexpectedly share port %d", dataPort)
	}

	dataAddress := dataListener.Addr().String()
	peerAddr, err := caddy.ParseNetworkAddress(dataAddress)
	if err != nil {
		t.Fatalf("parse peer address: %v", err)
	}
	p := &peer{address: &peerAddr, dialAddr: dataAddress}
	originalPeerAddr := *p.address
	upstream := &Upstream{
		Dial:  []string{dataAddress},
		peers: []*peer{p},
	}
	logger := zap.NewNop()
	h := &Handler{
		logger: logger,
		HealthChecks: &HealthChecks{Active: &ActiveHealthChecks{
			Port:    healthPort,
			Timeout: caddy.Duration(testTimeout),
			logger:  logger,
		}},
	}

	if err := h.doActiveHealthCheck(upstream, p); err != nil {
		t.Fatalf("active health check: %v", err)
	}
	if err := healthListener.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("set health listener deadline: %v", err)
	}
	healthConn, err := healthListener.AcceptTCP()
	if err != nil {
		t.Fatalf("accept health-check connection on port %d: %v", healthPort, err)
	}
	t.Cleanup(func() { _ = healthConn.Close() })
	_ = healthConn.Close()

	downClient, downServer := net.Pipe()
	t.Cleanup(func() {
		_ = downClient.Close()
		_ = downServer.Close()
	})
	down := layer4.WrapConnection(downServer, nil, logger)

	upConns, dialErr := h.dialPeers(upstream, down.Replacer(), down)
	t.Cleanup(func() {
		for _, conn := range upConns {
			_ = conn.Close()
		}
	})
	if dialErr != nil {
		t.Errorf("dial data upstream: %v", dialErr)
	}
	if len(upConns) != 1 {
		t.Errorf("data upstream connection count = %d, want 1", len(upConns))
	}

	dataReachedConfiguredPort := false
	if len(upConns) == 1 {
		remoteAddr, ok := upConns[0].RemoteAddr().(*net.TCPAddr)
		if !ok {
			t.Errorf("data connection remote address type = %T, want *net.TCPAddr", upConns[0].RemoteAddr())
		} else if remoteAddr.Port != dataPort {
			t.Errorf("data connection reached port %d, want configured upstream port %d; health port is %d",
				remoteAddr.Port, dataPort, healthPort)
		} else {
			dataReachedConfiguredPort = true
		}
	}

	// Only accept on the data listener after RemoteAddr confirms that the
	// connection reached it; otherwise AcceptTCP would wait until its deadline.
	if dataReachedConfiguredPort {
		if err := dataListener.SetDeadline(time.Now().Add(testTimeout)); err != nil {
			t.Errorf("set data listener deadline: %v", err)
		} else {
			dataConn, err := dataListener.AcceptTCP()
			if err != nil {
				t.Errorf("accept data connection on port %d: %v", dataPort, err)
			} else {
				t.Cleanup(func() { _ = dataConn.Close() })
				_ = dataConn.Close()
			}
		}
	}

	if p.address == nil {
		t.Error("peer address became nil")
	} else if got := *p.address; got != originalPeerAddr {
		t.Errorf("peer address changed: got %+v, want %+v", got, originalPeerAddr)
	}
}
