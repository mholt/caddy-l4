// Copyright 2024 Matthew Holt
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

package l4postgres

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func sslRequest() []byte {
	b := make([]byte, minMessageLen)
	binary.BigEndian.PutUint32(b[:lenFieldSize], minMessageLen)
	binary.BigEndian.PutUint32(b[lenFieldSize:], sslRequestCode)
	return b
}

func TestStartTLSRepliesSAndContinues(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	cx := layer4.WrapConnection(server, []byte{}, zap.NewNop())

	nextCalled := make(chan struct{}, 1)
	errc := make(chan error, 1)
	go func() {
		h := &Handler{}
		errc <- h.Handle(cx, layer4.HandlerFunc(func(*layer4.Connection) error {
			nextCalled <- struct{}{}
			return nil
		}))
	}()

	// client sends SSLRequest, then must receive a single 'S'
	if _, err := client.Write(sslRequest()); err != nil {
		t.Fatalf("writing SSLRequest: %v", err)
	}
	reply := make([]byte, 1)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("reading reply: %v", err)
	}
	if reply[0] != 'S' {
		t.Fatalf("reply = %q, want 'S'", reply[0])
	}

	select {
	case <-nextCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("next handler was not called")
	}
	if err := <-errc; err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
}

func TestStartTLSRejectsNonSSLRequest(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	cx := layer4.WrapConnection(server, []byte{}, zap.NewNop())

	// a plaintext v3 startup message code (196608), not an SSLRequest
	msg := make([]byte, minMessageLen)
	binary.BigEndian.PutUint32(msg[:lenFieldSize], minMessageLen)
	binary.BigEndian.PutUint32(msg[lenFieldSize:], 196608)
	go func() { _, _ = client.Write(msg) }()

	h := &Handler{}
	err := h.Handle(cx, layer4.HandlerFunc(func(*layer4.Connection) error {
		t.Error("next handler must not be called for a non-SSLRequest")
		return nil
	}))
	if err == nil {
		t.Fatal("expected an error for a non-SSLRequest message")
	}
}
