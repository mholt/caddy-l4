package l4proxy

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// TestProxyUDPFlows runs a layer4 app proxying a UDP socket to a UDP upstream, and asserts that
// each client is proxied over an upstream flow of its own, and gets the replies to its packets only.
func TestProxyUDPFlows(t *testing.T) {
	// The upstream echoes each packet, followed by the address it came from
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for upstream: %v", err)
	}
	defer upstream.Close()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := upstream.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = upstream.WriteTo(fmt.Appendf(nil, "%s|%s", buf[:n], addr), addr)
		}
	}()

	reserved, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	listen := reserved.LocalAddr().String()
	_ = reserved.Close()

	config := fmt.Sprintf(`{
		"admin": {"disabled": true, "config": {"persist": false}},
		"apps": {"layer4": {"servers": {"udp": {
			"listen": ["udp/%s"],
			"routes": [{"handle": [{"handler": "proxy", "upstreams": [{"dial": ["udp/%s"]}]}]}]
		}}}}
	}`, listen, upstream.LocalAddr())
	if err = caddy.Load([]byte(config), true); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	defer func() { _ = caddy.Stop() }()

	const clients, packets = 5, 5
	var (
		mu    sync.Mutex
		flows = make(map[string]int) // Upstream flows by the client proxied over them
		wg    sync.WaitGroup
	)
	for i := range clients {
		c, err := net.Dial("udp", listen)
		if err != nil {
			t.Fatalf("dialing: %v", err)
		}
		defer c.Close()

		wg.Go(func() {
			buf := make([]byte, 64<<10)
			for j := range packets {
				want := fmt.Sprintf("client-%d/packet-%d", i, j)
				if _, err := c.Write([]byte(want)); err != nil {
					t.Errorf("client %d: writing: %v", i, err)
					return
				}
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, err := c.Read(buf)
				if err != nil {
					t.Errorf("client %d: reading: %v", i, err)
					return
				}
				got, flow, _ := strings.Cut(string(buf[:n]), "|")
				if got != want {
					t.Errorf("client %d: got reply %q, want %q", i, got, want)
				}
				mu.Lock()
				if prev, ok := flows[flow]; ok && prev != i {
					t.Errorf("client %d: proxied over the upstream flow %s of client %d", i, flow, prev)
				}
				flows[flow] = i
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	if len(flows) != clients {
		t.Errorf("got %d upstream flows, want one per client, i.e. %d: %v", len(flows), clients, flows)
	}
}
