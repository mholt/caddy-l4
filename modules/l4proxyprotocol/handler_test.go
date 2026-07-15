package l4proxyprotocol

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func assertString(t *testing.T, expected string, value string) {
	t.Helper()
	if value != expected {
		t.Fatalf("Expected '%s' but got '%s'\n", expected, value)
	}
}

func TestProxyProtocolHandleV1(t *testing.T) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	cx := layer4.WrapConnection(in, []byte{}, zap.NewNop())
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = out.Close() }()
		_, err := out.Write(ProxyV1Example)
		assertNoError(t, err)
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := Handler{}
	err := handler.Provision(ctx)
	assertNoError(t, err)

	var nextCx *layer4.Connection
	err = handler.Handle(cx, layer4.HandlerFunc(func(c *layer4.Connection) error {
		nextCx = c
		return nil
	}))
	assertNoError(t, err)

	if nextCx == nil {
		t.Fatalf("handler did not call next")
	}

	assertString(t, "192.168.0.1:56324", nextCx.RemoteAddr().String())
	assertString(t, "192.168.0.11:443", nextCx.LocalAddr().String())

	_, _ = io.Copy(io.Discard, in)
}

func TestProxyProtocolHandleV2(t *testing.T) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	cx := layer4.WrapConnection(in, []byte{}, zap.NewNop())
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = out.Close() }()
		_, err := out.Write(ProxyV2Example)
		assertNoError(t, err)
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := Handler{}
	err := handler.Provision(ctx)
	assertNoError(t, err)

	var nextCx *layer4.Connection
	err = handler.Handle(cx, layer4.HandlerFunc(func(c *layer4.Connection) error {
		nextCx = c
		return nil
	}))
	assertNoError(t, err)

	if nextCx == nil {
		t.Fatalf("handler did not call next")
	}

	assertString(t, "127.0.0.1:47111", nextCx.RemoteAddr().String())
	assertString(t, "127.0.0.1:443", nextCx.LocalAddr().String())

	_, _ = io.Copy(io.Discard, in)
}

func TestProxyProtocolHandleGarbage(t *testing.T) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	cx := layer4.WrapConnection(in, []byte{}, zap.NewNop())
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = out.Close() }()
		_, err := out.Write([]byte("some garbage"))
		assertNoError(t, err)
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := Handler{}
	err := handler.Provision(ctx)
	assertNoError(t, err)

	var nextCx *layer4.Connection
	err = handler.Handle(cx, layer4.HandlerFunc(func(c *layer4.Connection) error {
		nextCx = c
		return nil
	}))
	if err == nil || err.Error() != "PROXY header required but not received" {
		t.Fatalf("handler did not return an error or the wrong error -> %s", err)
	}

	if nextCx != nil {
		t.Fatalf("handler did call next")
	}

	_, _ = io.Copy(io.Discard, in)
}

// TestProxyProtocolHandleDoesNotLeaveStaleBufferForNextMatcher is a
// regression test for a buffer-alignment bug between caddy-l4's
// prefetched matching buffer and pires/go-proxyproto's internal
// bufio.Reader.
//
// In production, when the matching loop has already prefetched a large
// chunk (e.g. PROXY v2 header + a 1.8 KB TLS ClientHello) into cx.buf
// and the proxy_protocol matcher then matches, the handler invokes
// proxyproto.NewConn(cx). go-proxyproto's default bufio.Reader is
// hard-coded to 256 bytes (see go-proxyproto protocol.go: const
// readBufferSize = 256). Its first fill issues one cx.Read for 256
// bytes, advancing cx.offset to 256 but leaving cx.buf at its
// prefetched length — because the cx.Read reset branch only fires
// when offset == len(buf). After that:
//   - cx.buf[0:256] has been consumed by bufio (28 bytes go to
//     parseHeader; ~228 remain inside bufio's private buffer);
//   - cx.buf[256:] is unread by anyone but still present in the slice.
//
// cx.Wrap then carries the now-misaligned cx.buf into the wrapped
// connection, and subsequent matchers either read mid-stream junk out
// of cx.buf[256:] (when matching=false reads bypass bufio) or run out
// of bytes waiting for ones that won't arrive (when reads go through
// bufio and the underlying conn is already drained). In production
// the latter manifests as a 3-second ErrMatchingTimeout; in this test
// the underlying net.Pipe is closed so the same condition surfaces as
// io.ErrUnexpectedEOF.
//
// The fix is to size go-proxyproto's bufio.Reader to layer4.MaxBufLen
// (= MaxMatchingBytes + prefetchChunkSize) via the WithBufferSize
// option. That sizing strictly exceeds the upper bound on cx.buf, so
// the first fill drains all of cx.buf in one cx.Read, triggering the
// reset branch and leaving cx.buf empty while bufio holds the entire
// post-PROXY-header byte stream. Subsequent reads through
// proxyproto.Conn return TLS bytes in stream order.
//
// The test reads two regions: the 5-byte TLS record header (catches
// the misalignment variant — hdr[0] would be 0xAA filler if reads
// bypass bufio) and the full record body (catches the byte-loss
// variant — ReadFull would EOF mid-body if cx.buf bytes were dropped
// or made unreachable).
func TestProxyProtocolHandleDoesNotLeaveStaleBufferForNextMatcher(t *testing.T) {
	payload := buildPROXYv2PlusFakeTLSPayload(1832)
	assertProxyV2WithFakeTLSReadsCleanlyAfterHandler(t, payload)
}

// TestProxyProtocolHandleDoesNotLeaveStaleBufferForNextMatcher_LargePrefetch
// guards the failure mode the smaller test cannot reach: cx.buf can
// grow past MaxMatchingBytes by up to one prefetchChunkSize, because
// prefetch() gates with `len(cx.buf) < MaxMatchingBytes` before the
// read rather than after. A bufio sized only to MaxMatchingBytes leaves
// the same alignment bug active at the high end of cx.buf's range.
// Sizing to MaxBufLen (= MaxMatchingBytes + prefetchChunkSize) is what
// makes the fix's invariant hold strictly. Without the fix, hdr[0]
// here would be mid-stream filler from cx.buf[MaxMatchingBytes:].
func TestProxyProtocolHandleDoesNotLeaveStaleBufferForNextMatcher_LargePrefetch(t *testing.T) {
	// 17 KiB total = PROXY v2 (28 bytes) + a TLS-shaped record whose
	// length pushes cx.buf past 16 KiB (= MaxMatchingBytes) into the
	// prefetchChunkSize-wide hole the old sizing left open. The record
	// body must be ≤ 2^14-1 (TLS spec), so we fragment via two
	// back-to-back TLS records.
	const totalBytes = 17 * 1024
	payload := buildPROXYv2PlusTwoFakeTLSRecordsPayload(t, totalBytes)
	if len(payload) != totalBytes {
		t.Fatalf("payload builder produced %d bytes, want %d", len(payload), totalBytes)
	}
	assertProxyV2WithFakeTLSReadsCleanlyAfterHandler(t, payload)
}

// assertProxyV2WithFakeTLSReadsCleanlyAfterHandler runs payload (PROXY
// v2 header + one or more TLS-shaped records) through the handler with
// cx.buf pre-populated, then verifies the wrapped Connection serves the
// post-header bytes in stream order — first 5 bytes are the TLS record
// header, full record body is readable and starts with the ClientHello
// handshake type 0x01. Used by both the small-payload and
// large-payload regression tests above.
func assertProxyV2WithFakeTLSReadsCleanlyAfterHandler(t *testing.T, payload []byte) {
	t.Helper()

	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Close immediately — the payload is delivered via cx.buf,
		// not via Pipe reads. Any read on cx.Conn after bufio drains
		// its leftover should EOF cleanly.
		_ = out.Close()
	}()

	cx := layer4.WrapConnection(in, payload, zap.NewNop())

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := Handler{}
	err := handler.Provision(ctx)
	assertNoError(t, err)

	var wrappedCx *layer4.Connection
	err = handler.Handle(cx, layer4.HandlerFunc(func(c *layer4.Connection) error {
		wrappedCx = c
		return nil
	}))
	assertNoError(t, err)
	if wrappedCx == nil {
		t.Fatalf("handler did not call next")
	}
	assertString(t, "1.2.3.4:12345", wrappedCx.RemoteAddr().String())

	// Read the 5-byte TLS record header — catches the misalignment
	// variant (reads bypassing bufio land in cx.buf[256:]).
	hdr := make([]byte, 5)
	n, readErr := io.ReadFull(wrappedCx, hdr)
	if readErr != nil {
		t.Fatalf("ReadFull(5): n=%d err=%v", n, readErr)
	}
	if hdr[0] != 0x16 {
		t.Fatalf("subsequent matcher would read non-TLS bytes after proxy_protocol "+
			"handler: hdr=% x (want first byte 0x16). The handler is leaving a stale "+
			"prefetched buffer behind; ensure proxyproto.NewConn is given "+
			"WithBufferSize(layer4.MaxBufLen) so its bufio drains cx.buf in one read.",
			hdr)
	}
	if hdr[1] != 0x03 || hdr[2] != 0x01 {
		t.Errorf("TLS record version bytes look wrong: hdr=% x (want 16 03 01 ..)", hdr)
	}

	// Read the full record body — catches the byte-loss variant. Under
	// the original 256-byte bufio (or any sizing < cx.buf length), this
	// EOFs mid-body because cx.buf's unread tail was dropped on the
	// floor or rendered unreachable to the wrapped conn.
	bodyLen := int(uint16(hdr[3])<<8 | uint16(hdr[4]))
	body := make([]byte, bodyLen)
	n2, readErr2 := io.ReadFull(wrappedCx, body)
	if readErr2 != nil {
		t.Fatalf("ReadFull(record body, len=%d): n=%d err=%v — the proxy_protocol "+
			"handler is dropping bytes that cx.buf had but proxyproto's bufio "+
			"hadn't yet consumed; ensure proxyproto.NewConn is given "+
			"WithBufferSize(layer4.MaxBufLen).", bodyLen, n2, readErr2)
	}
	// First handshake byte should be the ClientHello type (0x01) we
	// stamped at the start of the record body.
	if body[0] != 0x01 {
		t.Errorf("handshake header at body[0]=0x%02x, want 0x01 (ClientHello). "+
			"Stream alignment is broken even though hdr[0]==0x16.", body[0])
	}
}

// buildPROXYv2PlusFakeTLSPayload returns a PROXY v2 TCPv4 header (28
// bytes) followed by a TLS handshake record whose body is the given
// length. Body bytes after the 4-byte handshake header are filled
// with 0xAA so any byte read past the record header is clearly
// identifiable as mid-handshake-body filler.
func buildPROXYv2PlusFakeTLSPayload(recordBodyLen int) []byte {
	var p []byte

	// PROXY v2 TCPv4 header (28 bytes total).
	p = append(p,
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A,
		0x51, 0x55, 0x49, 0x54, 0x0A, // 12-byte signature
	)
	p = append(p, 0x21)                   // v2 + PROXY command
	p = append(p, 0x11)                   // TCPv4
	p = append(p, 0x00, 0x0C)             // 12 address bytes follow
	p = append(p, 0x01, 0x02, 0x03, 0x04) // src 1.2.3.4
	p = append(p, 0x05, 0x06, 0x07, 0x08) // dst 5.6.7.8
	p = append(p, 0x30, 0x39)             // src port 12345
	p = append(p, 0x01, 0xBB)             // dst port 443

	// TLS handshake record: 5-byte header + recordBodyLen-byte body.
	p = append(p, 0x16, 0x03, 0x01,
		byte(recordBodyLen>>8), byte(recordBodyLen&0xFF))

	body := make([]byte, recordBodyLen)
	body[0] = 0x01 // handshake type: ClientHello
	body[1] = byte((recordBodyLen - 4) >> 16)
	body[2] = byte((recordBodyLen - 4) >> 8)
	body[3] = byte((recordBodyLen - 4) & 0xFF)
	for i := 4; i < len(body); i++ {
		body[i] = 0xAA
	}
	p = append(p, body...)

	return p
}

// buildPROXYv2PlusTwoFakeTLSRecordsPayload returns totalBytes of payload
// shaped as: 28-byte PROXY v2 TCPv4 header + two back-to-back TLS
// handshake records sized so the combined payload pushes cx.buf past
// MaxMatchingBytes into the prefetchChunkSize-wide hole. The first
// record is a ClientHello whose body is filled with 0xAA; the second
// is a continuation record of the same shape. Used to exercise the
// over-MaxMatchingBytes regime that the original (small-payload)
// regression test cannot reach.
//
// Two records are necessary because TLSPlaintext.length is uint16 with
// a hard ceiling at 2^14 (= 16 384) per RFC 8446 §5.1 — a single
// 17 KiB record body is invalid. The handler doesn't care about record
// validity (caddy-l4's TLS matcher does, but this test reads bytes
// directly from the wrapped Connection), so any fragmentation works
// as long as the first record header has the canonical TLS handshake
// shape.
func buildPROXYv2PlusTwoFakeTLSRecordsPayload(t *testing.T, totalBytes int) []byte {
	const (
		proxyHdrLen = 28
		tlsHdrLen   = 5
	)

	// Sized so record1 body + record2 (header + body) + proxy header == totalBytes.
	// Split roughly in half, keeping each body within the 2^14-1 ceiling.
	availForRecords := totalBytes - proxyHdrLen
	record1BodyLen := (availForRecords - tlsHdrLen) / 2
	record2BodyLen := availForRecords - record1BodyLen - 2*tlsHdrLen
	if record1BodyLen > (1<<14)-1 || record2BodyLen > (1<<14)-1 {
		t.Fatal("buildPROXYv2PlusTwoFakeTLSRecordsPayload: bodyLen exceeds TLS record ceiling")
	}

	var p []byte
	p = append(p,
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A,
		0x51, 0x55, 0x49, 0x54, 0x0A,
	)
	p = append(p, 0x21, 0x11)
	p = append(p, 0x00, 0x0C)
	p = append(p, 0x01, 0x02, 0x03, 0x04)
	p = append(p, 0x05, 0x06, 0x07, 0x08)
	p = append(p, 0x30, 0x39)
	p = append(p, 0x01, 0xBB)

	// Record 1: TLS handshake (ClientHello shape).
	p = append(p, 0x16, 0x03, 0x01,
		byte(record1BodyLen>>8), byte(record1BodyLen&0xFF))
	body1 := make([]byte, record1BodyLen)
	body1[0] = 0x01 // ClientHello
	body1[1] = byte((record1BodyLen - 4) >> 16)
	body1[2] = byte((record1BodyLen - 4) >> 8)
	body1[3] = byte((record1BodyLen - 4) & 0xFF)
	for i := 4; i < len(body1); i++ {
		body1[i] = 0xAA
	}
	p = append(p, body1...)

	// Record 2: more handshake bytes; treated as opaque continuation.
	p = append(p, 0x16, 0x03, 0x01,
		byte(record2BodyLen>>8), byte(record2BodyLen&0xFF))
	body2 := make([]byte, record2BodyLen)
	for i := range body2 {
		body2[i] = 0xBB
	}
	p = append(p, body2...)

	return p
}
