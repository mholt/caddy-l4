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

package l4throttle

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler throttles connections using leaky bucket rate limiting.
type Handler struct {
	// The number of bytes to read per second, per connection.
	ReadBytesPerSecond float64 `json:"read_bytes_per_second,omitempty"`

	// The maximum number of bytes to read at once (rate permitting) per connection.
	// If a rate is specified, burst must be greater than zero; default is same as
	// the rate (truncated to integer).
	ReadBurstSize int `json:"read_burst_size,omitempty"`

	// The number of bytes to read per second, across all connections ("per handler").
	TotalReadBytesPerSecond float64 `json:"total_read_bytes_per_second,omitempty"`

	// The maximum number of bytes to read at once (rate permitting) across all
	// connections ("per handler"). If a rate is specified, burst must be greater
	// than zero; default is same as the rate (truncated to integer).
	TotalReadBurstSize int `json:"total_read_burst_size,omitempty"`

	// Delay before initial read on each connection.
	Latency caddy.Duration `json:"latency,omitempty"`

	logger       *zap.Logger
	totalLimiter *rate.Limiter
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.throttle",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	if h.ReadBytesPerSecond < 0 {
		return fmt.Errorf("bytes per second must be at least 0: %f", h.ReadBytesPerSecond)
	}
	if h.ReadBytesPerSecond > 0 && h.ReadBurstSize == 0 {
		h.ReadBurstSize = int(h.ReadBytesPerSecond) + 1
	}
	if h.TotalReadBytesPerSecond < 0 {
		return fmt.Errorf("total bytes per second must be at least 0: %f", h.TotalReadBytesPerSecond)
	}
	if h.TotalReadBytesPerSecond > 0 && h.TotalReadBurstSize == 0 {
		h.TotalReadBurstSize = int(h.TotalReadBytesPerSecond) + 1
	}
	if h.ReadBurstSize < 0 {
		return fmt.Errorf("burst size must be greater than 0: %d", h.ReadBurstSize)
	}
	if h.TotalReadBurstSize < 0 {
		return fmt.Errorf("total burst size must be greater than 0: %d", h.TotalReadBurstSize)
	}
	if h.TotalReadBytesPerSecond > 0 || h.TotalReadBurstSize > 0 {
		h.totalLimiter = rate.NewLimiter(rate.Limit(h.TotalReadBytesPerSecond), h.TotalReadBurstSize)
	}
	return nil
}

// Handle handles the connection.
func (h Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	var localLimiter *rate.Limiter
	if h.ReadBytesPerSecond > 0 || h.ReadBurstSize > 0 {
		localLimiter = rate.NewLimiter(rate.Limit(h.ReadBytesPerSecond), h.ReadBurstSize)
	}
	cx.Conn = throttledConn{
		Conn:         cx.Conn,
		ctx:          cx.Context,
		logger:       h.logger.Named("conn"),
		totalLimiter: h.totalLimiter,
		localLimiter: localLimiter,
	}
	if h.Latency > 0 {
		timer := time.NewTimer(time.Duration(h.Latency))
		select {
		case <-timer.C:
		case <-cx.Context.Done():
			return context.Canceled
		}
	}
	return next.Handle(cx)
}

type throttledConn struct {
	net.Conn
	ctx                        context.Context
	logger                     *zap.Logger
	totalLimiter, localLimiter *rate.Limiter
}

func (tc throttledConn) Read(p []byte) (int, error) {
	// The rate limiters will not let us wait for more than their burst
	// size, so the max we can read in each iteration is the minimum of
	// len(p) and both limiters' burst sizes.
	batchSize := len(p)
	if tc.totalLimiter != nil {
		if burstSize := tc.totalLimiter.Burst(); batchSize > burstSize {
			batchSize = burstSize
		}
	}
	if tc.localLimiter != nil {
		if burstSize := tc.localLimiter.Burst(); batchSize > burstSize {
			batchSize = burstSize
		}
	}

	if tc.totalLimiter != nil {
		err := tc.totalLimiter.WaitN(tc.ctx, batchSize)
		if err != nil {
			return 0, fmt.Errorf("waiting for total limiter: %v", err)
		}
	}
	if tc.localLimiter != nil {
		err := tc.localLimiter.WaitN(tc.ctx, batchSize)
		if err != nil {
			return 0, fmt.Errorf("waiting for local limiter: %v", err)
		}
	}

	n, err := tc.Conn.Read(p[:batchSize])

	tc.logger.Debug("read",
		zap.String("remote", tc.RemoteAddr().String()),
		zap.Int("batch_size", batchSize),
		zap.Int("bytes_read", n),
		zap.Error(err))

	return n, err
}

// Interface guards
var (
	_ caddy.Provisioner  = (*Handler)(nil)
	_ layer4.NextHandler = (*Handler)(nil)
)
