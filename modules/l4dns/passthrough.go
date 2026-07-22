// Copyright 2024 VNXME
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

package l4dns

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/mholt/caddy-l4/layer4"
)

// HandlePassthrough handles the DNS connection. It launches a dns.Server listening to a FakeListener.
// It also uses HookReader and HookWriter to manage handling process states and shutdown the server.
func (h *HandleDNS) HandlePassthrough(cx *layer4.Connection, _ layer4.Handler) (err error) {
	// Determine whether the connection is TCP or not
	// Note: all non-TCP connections are treated as UDP,
	// i.e. having no length bytes prepending message bytes.
	_, isTCP := cx.LocalAddr().(*net.TCPAddr)

	// Read DNS request message bytes
	var inBuf, outBuf []byte
	if isTCP {
		if inBuf, err = ReadBytesFromTCP(cx); err != nil {
			return err
		}
	} else {
		if inBuf, err = ReadBytesFromUDP(cx); err != nil {
			return err
		}
	}

	// Set up a state tracker that ensures correct reader and writer performance
	state := stateDefault

	// Set up waiting groups to sync this handler with the DNS server
	wgRead := &sync.WaitGroup{}
	wgRead.Add(1) // done after a request message is read
	wgWrite := &sync.WaitGroup{}
	wgWrite.Add(1) // done after a response message is written
	wgStart := &sync.WaitGroup{}
	wgStart.Add(1) // done after the DNS server is started
	wgStop := &sync.WaitGroup{}
	wgStop.Add(2) // done after the DNS server is stopped

	// Set up a fake TCP listener for the DNS server to serve on
	fl := new(FakeListener).Init()

	mux := new(dns.ServeMux)
	sig := make(map[string]string)

	// Configure the DNS server
	srv := new(dns.Server)
	srv.DecorateReader = func(r dns.Reader) dns.Reader {
		return &HookReader{
			// Only FakeReadTCP is required since the DNS server is run in TCP mode for any layer4.Connection
			FakeReadTCP: func(_ *HookReader, _ net.Conn, _ time.Duration) ([]byte, error) {
				if atomic.CompareAndSwapUint32(&state, stateDefault, stateRead) {
					defer wgRead.Done()
					return inBuf, nil
				}
				return nil, io.EOF
			},
		}
	}
	srv.DecorateWriter = func(w dns.Writer) dns.Writer {
		return &HookWriter{
			FakeWrite: func(_ *HookWriter, data []byte) (int, error) {
				if atomic.CompareAndSwapUint32(&state, stateRead, stateWritten) {
					defer wgWrite.Done()
					outBuf = data
					return len(data), nil
				}
				return 0, io.EOF
			},
		}
	}
	srv.Handler = mux
	srv.Listener = fl
	srv.NotifyStartedFunc = func() { wgStart.Done() }
	srv.TsigSecret = sig

	// Start the DNS server
	go func() {
		_ = srv.ActivateAndServe() // blocking until srv.Shutdown is called
		wgStop.Done()
	}()

	wgStart.Wait()

	// Unblock fl.Accept to make the DNS server proceed to reading and writing
	var clt net.Conn
	if clt, err = fl.Pipe(cx.LocalAddr(), cx.RemoteAddr()); err != nil {
		return
	}
	defer func() { _ = clt.Close() }()

	wgRead.Wait()
	wgWrite.Wait()

	// Stop the DNS server
	go func() {
		_ = srv.Shutdown() // non-blocking, but it may take some time to execute
		wgStop.Done()
	}()

	wgStop.Wait()

	// Write DNS response message bytes
	if isTCP {
		_, err = WriteBytesToTCP(cx, outBuf)
	} else {
		_, err = WriteBytesToUDP(cx, outBuf)
	}

	return
}

type FakeListener struct {
	conns chan net.Conn
	close chan int
	state uint32
}

func (l *FakeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.close:
		return nil, l.ErrClosed()
	}
}

func (l *FakeListener) Addr() net.Addr {
	return new(net.TCPAddr)
}

func (l *FakeListener) Close() error {
	if atomic.CompareAndSwapUint32(&l.state, 0, 1) {
		close(l.close)
	}
	return nil
}

func (l *FakeListener) ErrClosed() error {
	return fmt.Errorf("%T closed", *l)
}

func (l *FakeListener) Init() *FakeListener {
	l.conns = make(chan net.Conn)
	l.close = make(chan int)
	return l
}

func (l *FakeListener) Pipe(local, remote net.Addr) (net.Conn, error) {
	select {
	case <-l.close:
		return nil, l.ErrClosed()
	default:
	}

	server, client := net.Pipe()
	l.Push(&ConnWithFakeAddr{Conn: server, Local: local, Remote: remote})
	return &ConnWithFakeAddr{Conn: client, Local: remote, Remote: local}, nil
}

func (l *FakeListener) Push(conn net.Conn) *FakeListener {
	l.conns <- conn
	return l
}

type ConnWithFakeAddr struct {
	net.Conn
	Local  net.Addr
	Remote net.Addr
}

func (c *ConnWithFakeAddr) LocalAddr() net.Addr {
	if c.Local != nil {
		return c.Local
	}
	return c.Conn.LocalAddr()
}

func (c *ConnWithFakeAddr) RemoteAddr() net.Addr {
	if c.Remote != nil {
		return c.Remote
	}
	return c.Conn.RemoteAddr()
}

type HookReader struct {
	dns.PacketConnReader

	FakeReadPacketConn func(r *HookReader, conn net.PacketConn, timeout time.Duration) ([]byte, net.Addr, error)
	FakeReadTCP        func(r *HookReader, conn net.Conn, timeout time.Duration) ([]byte, error)
	FakeReadUDP        func(r *HookReader, conn net.Conn, timeout time.Duration) ([]byte, *dns.SessionUDP, error)

	PreReadPacketConn func(r *HookReader, conn net.PacketConn, timeout time.Duration)
	PreReadTCP        func(r *HookReader, conn net.Conn, timeout time.Duration)
	PreReadUDP        func(r *HookReader, conn *net.UDPConn, timeout time.Duration)

	PostReadPacketConn func(r *HookReader, conn net.PacketConn, timeout time.Duration)
	PostReadTCP        func(r *HookReader, conn net.Conn, timeout time.Duration)
	PostReadUDP        func(r *HookReader, conn *net.UDPConn, timeout time.Duration)
}

func (r *HookReader) ReadPacketConn(conn net.PacketConn, timeout time.Duration) ([]byte, net.Addr, error) {
	if r.PreReadPacketConn != nil {
		r.PreReadPacketConn(r, conn, timeout)
	}
	if r.PostReadPacketConn != nil {
		defer r.PostReadPacketConn(r, conn, timeout)
	}
	if r.FakeReadPacketConn != nil {
		return r.FakeReadPacketConn(r, conn, timeout)
	}
	return r.PacketConnReader.ReadPacketConn(conn, timeout)
}

func (r *HookReader) ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if r.PreReadTCP != nil {
		r.PreReadTCP(r, conn, timeout)
	}
	if r.PostReadTCP != nil {
		defer r.PostReadTCP(r, conn, timeout)
	}
	if r.FakeReadTCP != nil {
		return r.FakeReadTCP(r, conn, timeout)
	}
	return r.PacketConnReader.ReadTCP(conn, timeout)
}

func (r *HookReader) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *dns.SessionUDP, error) {
	if r.PreReadUDP != nil {
		r.PreReadUDP(r, conn, timeout)
	}
	if r.PostReadUDP != nil {
		defer r.PostReadUDP(r, conn, timeout)
	}
	if r.FakeReadUDP != nil {
		return r.FakeReadUDP(r, conn, timeout)
	}
	return r.PacketConnReader.ReadUDP(conn, timeout)
}

type HookWriter struct {
	dns.Writer

	FakeWrite func(w *HookWriter, data []byte) (int, error)
	PreWrite  func(w *HookWriter, data []byte)
	PostWrite func(w *HookWriter, data []byte)
}

func (w *HookWriter) Write(data []byte) (int, error) {
	if w.PreWrite != nil {
		w.PreWrite(w, data)
	}
	if w.PostWrite != nil {
		defer w.PostWrite(w, data)
	}
	if w.FakeWrite != nil {
		return w.FakeWrite(w, data)
	}
	return w.Writer.Write(data)
}

// Interface guards
var (
	_ net.Listener = (*FakeListener)(nil)

	_ dns.PacketConnReader = (*HookReader)(nil)
	_ dns.Writer           = (*HookWriter)(nil)
)

const (
	stateDefault uint32 = 0
	stateRead    uint32 = 1
	stateWritten uint32 = 2
)
