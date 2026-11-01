package layer4

import (
	"bytes"
	"io"
	"net"
	"testing"

	"go.uber.org/zap"
)

func TestConnection_FreezeAndUnfreeze(t *testing.T) {
	in, out := net.Pipe()
	defer func() { _ = in.Close() }()
	defer func() { _ = out.Close() }()

	cx := WrapConnection(out, []byte{}, zap.NewNop())
	defer func() { _ = cx.Close() }()

	matcherData := []byte("foo")
	consumeData := []byte("bar")

	buf := make([]byte, len(matcherData))

	go func() {
		_, _ = in.Write(matcherData)
		_, _ = in.Write(consumeData)
	}()

	// prefetch like server handler would
	err := cx.prefetch()
	if err != nil {
		t.Fatal(err)
	}

	// 1st matcher
	cx.freeze()

	n, err := cx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(matcherData) {
		t.Fatalf("expected to read %d bytes but got %d", len(matcherData), n)
	}
	if !bytes.Equal(matcherData, buf) {
		t.Fatalf("expected %s but received %s", matcherData, buf)
	}

	cx.unfreeze()

	// 2nd matcher (reads same data)

	cx.freeze()

	n, err = cx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(matcherData) {
		t.Fatalf("expected to read %d bytes but got %d", len(matcherData), n)
	}
	if !bytes.Equal(matcherData, buf) {
		t.Fatalf("expected %s but received %s", matcherData, buf)
	}

	cx.unfreeze()

	// 1st consumer (no freeze call)

	n, err = cx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(matcherData) {
		t.Fatalf("expected to read %d bytes but got %d", len(matcherData), n)
	}
	if !bytes.Equal(matcherData, buf) {
		t.Fatalf("expected %s but received %s", matcherData, buf)
	}

	// 2nd consumer (reads other data)

	n, err = cx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(consumeData) {
		t.Fatalf("expected to read %d bytes but got %d", len(consumeData), n)
	}
	if !bytes.Equal(consumeData, buf) {
		t.Fatalf("expected %s but received %s", consumeData, buf)
	}
}

func TestConnectionBytesReadWritten(t *testing.T) {
	in, out := net.Pipe()
	defer func() { _ = in.Close() }()
	defer func() { _ = out.Close() }()

	cx := WrapConnection(out, []byte{}, zap.NewNop())

	go func() {
		_, _ = in.Write([]byte("hello")) // 5 bytes for cx to read
		reply := make([]byte, 3)
		_, _ = io.ReadFull(in, reply) // consume the 3 bytes cx writes
	}()

	buf := make([]byte, 5)
	if _, err := io.ReadFull(cx, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := cx.Write([]byte("bye")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := cx.BytesRead(); got != 5 {
		t.Errorf("BytesRead() = %d, want 5", got)
	}
	if got := cx.BytesWritten(); got != 3 {
		t.Errorf("BytesWritten() = %d, want 3", got)
	}
}
