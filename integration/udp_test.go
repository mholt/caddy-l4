package integration

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	_ "github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4echo"
	_ "github.com/mholt/caddy-l4/modules/l4regexp"
)

const (
	testUDPCaddyfile = `
{
	debug
	layer4 {
		udp/:2000 {
			@e regexp ^ECHO\d\d\d\d$ 8
			route {
				echo
			}
		}
	}
}
	` // Caddy configuration to test

	testUDPHostname = "localhost"          // Hostname that clients connect to
	testUDPPortEcho = 2000                 // Port serving echo only
	testUDPDelay    = 0 * time.Millisecond // How much time to wait between sending messages
)

func TestUDP(t *testing.T) {
	// Load Caddy
	loadCaddyWithCaddyfile(t, testUDPCaddyfile[1:][:len(testUDPCaddyfile)-2]) // Workaround to avoid caddyfile warnings

	// Use a wait group to sync goroutines
	var wg sync.WaitGroup

	address := fmt.Sprintf("%s:%d", testUDPHostname, testUDPPortEcho)

	messages := make([][]byte, 1)
	for i := range messages {
		messages[i] = []byte(fmt.Sprintf("ECHO%04d", i))
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		t.Logf("[UDP-%d] connecting to %s, sending %s, expecting %s", testUDPPortEcho, address, messages[0], messages[0])

		config := udpExchangeConfig{
			ExchangeId: fmt.Sprintf("UDP-%d", testUDPPortEcho),
			Timeout:    waitForUDPExchange,
			Delay:      testUDPDelay,

			Address:  address,
			Messages: messages,
		}
		config.Check = func(t *testing.T, m []byte, r []byte) {
			if !bytes.Equal(m, r) {
				t.Errorf("[%s] expected %s, got %s", config.ExchangeId, string(m), string(r))
			}
		}

		exchangeUDP(t, &config)
	}()

	// Delay for all goroutines to finish
	wg.Wait()

	// Stop Caddy
	stopCaddy(t)
}
