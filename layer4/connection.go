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
	"io"
	"net"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

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

	buf       *bytes.Buffer // stores recordings
	bufReader io.Reader     // used to read buf so it doesn't discard bytes
	recording bool

	bytesRead, bytesWritten uint64
}

// Read implements io.Reader in such a way that reads first
// deplete any associated buffer from the prior recording,
// and once depleted (or if there isn't one), it continues
// reading from the underlying connection.
func (cx *Connection) Read(p []byte) (n int, err error) {
	// if there is a buffer we should read from, start
	// with that; we only read from the underlying conn
	// after the buffer has been "depleted"
	if cx.bufReader != nil {
		n, err = cx.bufReader.Read(p)
		if err == io.EOF {
			cx.bufReader = nil
			err = nil
		}
		return
	}

	// buffer has been "depleted" so read from
	// underlying connection
	n, err = cx.Conn.Read(p)
	cx.bytesRead += uint64(n)

	if !cx.recording {
		return
	}

	// since we're recording at this point, anything that
	// was read needs to be written to the buffer, even
	// if there was an error
	if n > 0 {
		if nw, errw := cx.buf.Write(p[:n]); errw != nil {
			return nw, errw
		}
	}

	return
}

func (cx *Connection) Write(p []byte) (n int, err error) {
	n, err = cx.Conn.Write(p)
	cx.bytesWritten += uint64(n)
	return
}

// record starts recording the stream into cx.buf.
func (cx *Connection) record() {
	cx.recording = true
}

// rewind stops recording and creates a reader for the
// buffer so that the next reads from an associated
// recordableConn come from the buffer first, then
// continue with the underlying conn.
func (cx *Connection) rewind() {
	cx.recording = false
	cx.bufReader = bytes.NewReader(cx.buf.Bytes())
}

// SetVar sets a value in the context's variable table with
// the given key. It overwrites any previous value with the
// same key.
func (cx Connection) SetVar(key string, value interface{}) {
	varMap, ok := cx.Context.Value(VarsCtxKey).(map[string]interface{})
	if !ok {
		return
	}
	varMap[key] = value
}

// GetVar gets a value from the context's variable table with
// the given key. It returns the value if found, and true if
// it found a value with that key; false otherwise.
func (cx Connection) GetVar(key string) interface{} {
	varMap, ok := cx.Context.Value(VarsCtxKey).(map[string]interface{})
	if !ok {
		return nil
	}
	return varMap[key]
}

var (
	// VarsCtxKey is the key used to store the variables table
	// in a Connection's context.
	VarsCtxKey caddy.CtxKey = "vars"

	// ReplacerCtxKey is the key used to store the replacer.
	ReplacerCtxKey caddy.CtxKey = "replacer"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}
