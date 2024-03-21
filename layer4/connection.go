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
	"context"
	"errors"
	"net"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// WrapConnection wraps an underlying connection into a layer4 connection that
// supports recording and rewinding, as well as adding context with a replacer
// and variable table. This function is intended for use at the start of a
// connection handler chain where the underlying connection is not yet a layer4
// Connection value.
func WrapConnection(underlying net.Conn, buf []byte, logger *zap.Logger) *Connection {
	repl := caddy.NewReplacer()
	repl.Set("l4.conn.remote_addr", underlying.RemoteAddr())
	repl.Set("l4.conn.local_addr", underlying.LocalAddr())

	ctx := context.Background()
	ctx = context.WithValue(ctx, VarsCtxKey, make(map[string]interface{}))
	ctx = context.WithValue(ctx, ReplacerCtxKey, repl)

	return &Connection{
		Conn:    underlying,
		Context: ctx,
		Logger:  logger,
		buf:     buf,
	}
}

// Connection contains information about the connection as it
// passes through various handlers. It also has the capability
// of recording and rewinding when necessary.
//
// A Connection can be used as a net.Conn because it embeds a
// net.Conn; but when wrapping underlying connections, usually
// you want to be careful to replace the embedded Conn, not
// this entire Connection value.
//
// Connection structs are NOT safe for concurrent use.
type Connection struct {
	// The underlying connection.
	net.Conn

	// The context for the connection.
	Context context.Context

	Logger *zap.Logger

	buf       []byte // stores recorded data
	offset    int
	recording bool

	bytesRead, bytesWritten uint64
}

var ErrConsumedAllPrefetchedBytes = errors.New("consumed all prefetched bytes")
var ErrMatchingBufferFull = errors.New("matching buffer is full")

// Read implements io.Reader in such a way that reads first
// deplete any associated buffer from the prior recording,
// and once depleted (or if there isn't one), it continues
// reading from the underlying connection.
func (cx *Connection) Read(p []byte) (n int, err error) {
	if cx.recording {
		if len(cx.buf) == 0 {
			err = cx.prefetch()
			if err != nil {
				return 0, err
			}
		}
		if len(cx.buf[cx.offset:])-len(p) < 0 {
			return 0, ErrConsumedAllPrefetchedBytes
		}
	}

	// if there is a buffer we should read from, start
	// with that; we only read from the underlying conn
	// after the buffer has been "depleted"
	if cx.offset < len(cx.buf) {
		n := copy(p, cx.buf[cx.offset:])
		cx.offset += n
		return n, nil
	}

	// buffer has been "depleted" so read from
	// underlying connection
	n, err = cx.Conn.Read(p)
	cx.bytesRead += uint64(n)

	if cx.recording {
		cx.buf = append(cx.buf, p[:n]...)
		cx.offset += n
		if len(cx.buf) >= MaxMatchingBytes {
			return n, ErrMatchingBufferFull
		}
	}

	return
}

func (cx *Connection) Write(p []byte) (n int, err error) {
	n, err = cx.Conn.Write(p)
	cx.bytesWritten += uint64(n)

	// reset buf so the next Read during matching calls prefetch again
	if len(cx.buf) > 0 {
		cx.buf = cx.buf[:0]
		cx.offset = 0
	}

	return
}

// Wrap wraps conn in a new Connection based on cx (reusing
// cx's existing buffer and context). This is useful after
// a connection is wrapped by a package that does not support
// our Connection type (for example, `tls.Server()`).
func (cx *Connection) Wrap(conn net.Conn) *Connection {
	return &Connection{
		Conn:         conn,
		Context:      cx.Context,
		Logger:       cx.Logger,
		buf:          cx.buf,
		offset:       cx.offset,
		recording:    cx.recording,
		bytesRead:    cx.bytesRead,
		bytesWritten: cx.bytesWritten,
	}
}

// prefetch tries to read all bytes that a client initially sent us without blocking.
func (cx *Connection) prefetch() (err error) {
	var n int
	var tmp []byte

	for len(cx.buf) < MaxMatchingBytes {
		if len(cx.buf) == 0 && cap(cx.buf) >= PrefetchChunkSize {
			n, err = cx.Conn.Read(cx.buf[:PrefetchChunkSize])
			cx.buf = cx.buf[:n]
		} else {
			if tmp == nil {
				tmp = bufPool.Get().([]byte)
				tmp = tmp[:PrefetchChunkSize]
				defer bufPool.Put(tmp)
			}
			n, err = cx.Conn.Read(tmp)
			cx.buf = append(cx.buf, tmp[:n]...)
		}

		cx.bytesRead += uint64(n)

		if err != nil {
			return err
		}

		if n < PrefetchChunkSize {
			break
		}
	}

	if cx.Logger.Core().Enabled(zap.DebugLevel) {
		cx.Logger.Debug("prefetched",
			zap.String("remote", cx.RemoteAddr().String()),
			zap.Int("bytes", len(cx.buf)),
		)
	}

	return nil
}

// record starts recording the stream into cx.buf.
func (cx *Connection) record() {
	cx.recording = true
}

// rewind stops recording and resets the buffer offset
// so that the next reads come from the buffer first.
func (cx *Connection) rewind() {
	cx.recording = false
	cx.offset = 0
}

// SetVar sets a value in the context's variable table with
// the given key. It overwrites any previous value with the
// same key.
func (cx *Connection) SetVar(key string, value interface{}) {
	varMap, ok := cx.Context.Value(VarsCtxKey).(map[string]interface{})
	if !ok {
		return
	}
	varMap[key] = value
}

// GetVar gets a value from the context's variable table with
// the given key. It returns the value if found, and true if
// it found a value with that key; false otherwise.
func (cx *Connection) GetVar(key string) interface{} {
	varMap, ok := cx.Context.Value(VarsCtxKey).(map[string]interface{})
	if !ok {
		return nil
	}
	return varMap[key]
}

// MatchingBytes returns all bytes currently available for matching. This is only intended for reading.
// Do not write into the slice it's a view of the internal buffer and you will likely mess up the connection.
func (cx *Connection) MatchingBytes() ([]byte, error) {
	// ensure prefetch was executed, for example when this was called before the first Read
	if cx.recording && len(cx.buf) == 0 {
		err := cx.prefetch()
		if err != nil {
			return nil, err
		}
	}
	return cx.buf[cx.offset:], nil
}

var (
	// VarsCtxKey is the key used to store the variables table
	// in a Connection's context.
	VarsCtxKey caddy.CtxKey = "vars"

	// ReplacerCtxKey is the key used to store the replacer.
	ReplacerCtxKey caddy.CtxKey = "replacer"

	// listenerCtxKey is the key used to get the listener from a handler
	listenerCtxKey caddy.CtxKey = "listener"
)

const PrefetchChunkSize = 1024

// MaxMatchingBytes is the amount of bytes that are at most prefetched during matching.
// This is probably most relevant for the http matcher since http requests do not have a size limit.
// 8 KiB should cover most use-cases and is similar to popular webservers.
const MaxMatchingBytes = 8 * 1024

var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, PrefetchChunkSize)
	},
}
