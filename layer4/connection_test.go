package layer4

import (
	"bytes"
	"net"
	"testing"

	"go.uber.org/zap"
)

func TestConnection_RecordAndRewind(t *testing.T) {
	in, out := net.Pipe()
	defer in.Close()
	defer out.Close()

	cx := WrapConnection(out, &bytes.Buffer{}, zap.NewNop())
	defer cx.Close()

	matcherData := []byte("foo")
	consumeData := []byte("bar")

	buf := make([]byte, len(matcherData))

	go func() {
		in.Write(matcherData)
		in.Write(consumeData)
	}()

	// 1st matcher

	cx.record()

	n, err := cx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(matcherData) {
		t.Fatalf("expected to read %d bytes but got %d", len(matcherData), n)
	}
	if bytes.Compare(matcherData, buf) != 0 {
		t.Fatalf("expected %s but received %s", matcherData, buf)
	}

	cx.rewind()

	// 2nd matcher (reads same data)

	cx.record()

	n, err = cx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(matcherData) {
		t.Fatalf("expected to read %d bytes but got %d", len(matcherData), n)
	}
	if bytes.Compare(matcherData, buf) != 0 {
		t.Fatalf("expected %s but received %s", matcherData, buf)
	}

	cx.rewind()

	// 1st consumer (no record call)

	n, err = cx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(matcherData) {
		t.Fatalf("expected to read %d bytes but got %d", len(matcherData), n)
	}
	if bytes.Compare(matcherData, buf) != 0 {
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
	if bytes.Compare(consumeData, buf) != 0 {
		t.Fatalf("expected %s but received %s", consumeData, buf)
	}
}
