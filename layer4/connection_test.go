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

	if read, written := cx.TrafficSnapshot(); read != 5 || written != 3 {
		t.Errorf("TrafficSnapshot() = (%d, %d), want (5, 3)", read, written)
	}
}

// TestConnectionTrafficSnapshotPrefetch checks that bytes prefetched for
// matching but not yet replayed are not counted as read.
func TestConnectionTrafficSnapshotPrefetch(t *testing.T) {
	in, out := net.Pipe()
	defer func() { _ = in.Close() }()
	defer func() { _ = out.Close() }()

	cx := WrapConnection(out, []byte{}, zap.NewNop())

	go func() { _, _ = in.Write([]byte("foobarz")) }() // 7 bytes

	if err := cx.prefetch(); err != nil {
		t.Fatal(err)
	}
	if cx.bytesRead != 7 {
		t.Fatalf("raw bytesRead = %d, want 7 (prefetch reads from the socket)", cx.bytesRead)
	}
	if read, _ := cx.TrafficSnapshot(); read != 0 {
		t.Errorf("read after prefetch = %d, want 0 (all 7 still buffered)", read)
	}

	// matching reads must not move the snapshot either: the buffer is rewound
	cx.freeze()
	if _, err := io.ReadFull(cx, make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	cx.unfreeze()
	if read, _ := cx.TrafficSnapshot(); read != 0 {
		t.Errorf("read after matching = %d, want 0", read)
	}

	// replaying 3 bytes to the handler chain counts them
	if _, err := io.ReadFull(cx, make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	if read, _ := cx.TrafficSnapshot(); read != 3 {
		t.Errorf("read after replaying 3 = %d, want 3", read)
	}

	// replaying the rest empties the buffer
	if _, err := io.ReadFull(cx, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	if read, _ := cx.TrafficSnapshot(); read != 7 {
		t.Errorf("read after replaying all = %d, want 7", read)
	}
}
