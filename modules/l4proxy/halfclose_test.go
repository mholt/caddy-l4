package l4proxy

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// waitHandle reports whether Handle returned within d.
func waitHandle(done <-chan error, d time.Duration) bool {
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// TestHandleWaitsForHalfClosedDownstreamByDefault documents the default: once
// the upstream has finished, the proxy waits for the downstream to finish too,
// however long it takes. A client that never closes (or a layer 4 load balancer
// that never forwards a close) keeps the connection, its goroutines and its file
// descriptors around for as long as it stays open.
func TestHandleWaitsForHalfClosedDownstreamByDefault(t *testing.T) {
	up := listenTCP(t)
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("hello"))
		_ = c.Close()
	}()

	h := newTestProxy(t, up.Addr().String())
	client, down := tcpDownstream(t, h)
	done := make(chan error, 1)
	go func() { done <- h.Handle(down, nil) }()

	if got, err := io.ReadAll(client); err != nil || string(got) != "hello" {
		t.Fatalf("reading from downstream = %q, %v; want %q", got, err, "hello")
	}
	if waitHandle(done, 500*time.Millisecond) {
		t.Fatal("Handle returned while the downstream was still open, without a half_close_timeout")
	}
	_ = client.Close()
	if !waitHandle(done, 5*time.Second) {
		t.Fatal("Handle did not return after the downstream connection was closed")
	}
}

// TestHandleHalfCloseTimeoutAfterUpstreamFinishes: with half_close_timeout the
// proxy stops waiting for a downstream that stays silent after the upstream has
// finished.
func TestHandleHalfCloseTimeoutAfterUpstreamFinishes(t *testing.T) {
	up := listenTCP(t)
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("hello"))
		_ = c.Close()
	}()

	h := newTestProxy(t, up.Addr().String())
	h.HalfCloseTimeout = caddy.Duration(200 * time.Millisecond)
	client, down := tcpDownstream(t, h)
	done := make(chan error, 1)
	go func() { done <- h.Handle(down, nil) }()

	if got, err := io.ReadAll(client); err != nil || string(got) != "hello" {
		t.Fatalf("reading from downstream = %q, %v; want %q", got, err, "hello")
	}
	// The client neither sends nor closes.
	if !waitHandle(done, 2*time.Second) {
		t.Fatal("Handle kept waiting for a silent downstream past half_close_timeout")
	}
}

// TestHandleHalfCloseTimeoutAfterDownstreamFinishes: the same applies the other
// way around, to an upstream that neither answers nor closes once the downstream
// has finished.
func TestHandleHalfCloseTimeoutAfterDownstreamFinishes(t *testing.T) {
	up := listenTCP(t)
	held := make(chan struct{})
	t.Cleanup(func() { close(held) })
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		_, _ = io.ReadAll(c)
		<-held // never answers, never closes
		_ = c.Close()
	}()

	h := newTestProxy(t, up.Addr().String())
	h.HalfCloseTimeout = caddy.Duration(200 * time.Millisecond)
	client, down := tcpDownstream(t, h)
	done := make(chan error, 1)
	go func() { done <- h.Handle(down, nil) }()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("writing to downstream: %v", err)
	}
	_ = client.CloseWrite()
	if !waitHandle(done, 2*time.Second) {
		t.Fatal("Handle kept waiting for a silent upstream past half_close_timeout")
	}
}

// TestHandleHalfCloseTimeoutIsAnIdleTimeout: half_close_timeout only cuts a
// side that stays silent. A side that keeps sending is waited for, even for
// much longer than the timeout.
func TestHandleHalfCloseTimeoutIsAnIdleTimeout(t *testing.T) {
	const chunks = 8
	up := listenTCP(t)
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		_, _ = io.ReadAll(c)
		for range chunks {
			time.Sleep(100 * time.Millisecond)
			_, _ = c.Write([]byte("x"))
		}
		_ = c.Close()
	}()

	h := newTestProxy(t, up.Addr().String())
	h.HalfCloseTimeout = caddy.Duration(300 * time.Millisecond)
	client, down := tcpDownstream(t, h)
	done := make(chan error, 1)
	go func() { done <- h.Handle(down, nil) }()

	_ = client.CloseWrite()
	got, err := io.ReadAll(client)
	if err != nil || string(got) != strings.Repeat("x", chunks) {
		t.Fatalf("reading from downstream = %q, %v; want %d bytes sent over %s, longer than the timeout",
			got, err, chunks, chunks*100*time.Millisecond)
	}
	if !waitHandle(done, 2*time.Second) {
		t.Fatal("Handle did not return after both sides finished")
	}
}

func TestProvisionRejectsNegativeHalfCloseTimeout(t *testing.T) {
	h := &Handler{HalfCloseTimeout: caddy.Duration(-time.Second)}
	err := h.Provision(caddy.Context{})
	if err == nil || !strings.Contains(err.Error(), "half_close_timeout") {
		t.Fatalf("expected a half_close_timeout error, got %v", err)
	}
}
