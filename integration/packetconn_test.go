package integration

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	_ "github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4dns"
	_ "github.com/mholt/caddy-l4/modules/l4echo"
	_ "github.com/mholt/caddy-l4/modules/l4proxy"
	_ "github.com/mholt/caddy-l4/modules/l4regexp"
)

const (
	testPCWCaddyfile = `
{
	debug
	layer4 {
		udp/:2000 {
			@e regexp ^ECHO\d\d\d\d$ 8
			route {
				echo
			}
		}
		udp/:5300 {
			@d dns
			route @d {
				proxy udp/one.one.one.one:53
			}
		}
	}
	servers :443 {
		packet_conn_wrappers {
			layer4 {
				@d dns
				route @d {
					proxy udp/one.one.one.one:53
				}
				@e regexp ^ECHO\d\d\d\d$ 8
				route @e {
					echo
				}
			}
		}
		protocols h3
	}
	servers :8443 {
		protocols h3
	}
}
https://localhost, https://localhost:8443 {
	tls {
		issuer internal
	}
	respond "{http.request.uri.query}" 200
}
	` // Caddy configuration to test

	testPCWHostname = "localhost" // Hostname that clients connect to

	testPCWPortMultiplex = 443  // Port serving multiple services
	testPCWPortEchoOnly  = 2000 // Port serving echo only
	testPCWPortDNSOnly   = 5300 // Port serving DNS only
	testPCWPortHTTP3Only = 8443 // Port serving HTTP/3 only

	testPCWMultiplier = 10 // How many times each domain is requested by DNS client

	testPCWWait = 100 * time.Millisecond // How much time to wait between spawning clients
)

var (
	testPCWDomains = []string{
		"baidu.com.",
		"bing.com.",
		"chatgpt.com.",
		"facebook.com.",
		"google.com.",
		"instagram.com.",
		"reddit.com.",
		"tiktok.com.",
		"x.com.",
		"wikipedia.org.",
	} // List of domains requested by DNS client. Its length determines the number of tests (adjusted by the multiplier).
)

func testPCWWithDNSQueries(t *testing.T, wg *sync.WaitGroup, port int) {
	t.Helper()

	defer wg.Done()

	address := fmt.Sprintf("%s:%d", testPCWHostname, port)

	multiplier, qType := testPCWMultiplier, dns.TypeA
	if port == testPCWPortDNSOnly {
		multiplier, qType = 1, dns.TypeNS // Disregard the multiplier for DNS only tests, query NS instead of A
	}

	var c int
	l := len(testPCWDomains)
	for j := range multiplier {
		for i, domain := range testPCWDomains {
			c = i + j*l

			wg.Add(1)
			go func() {
				defer wg.Done()

				t.Logf("[DNS-%d.%d] connecting to %s, querying %s IN %s, expecting at least one", port, c, address, domain, dns.TypeToString[qType])

				config := dnsQueryConfig{
					QueryId:   fmt.Sprintf("DNS-%d.%d", port, c),
					Timeout:   waitForDNSRequest,
					TLSConfig: nil,

					Net:        "udp",
					Address:    address,
					QueryType:  qType,
					DomainName: domain,
				}
				config.Check = provideDNSMessageCheck(config.QueryId, true, qType)

				queryDNS(t, &config)
			}()

			time.Sleep(testPCWWait)
		}
	}
}

func testPCWWithHTTP3Requests(t *testing.T, wg *sync.WaitGroup, port int) {
	t.Helper()

	defer wg.Done()

	address := fmt.Sprintf("%s:%d", testPCWHostname, port)

	var payload, url string
	for i := range testPCWMultiplier * len(testPCWDomains) {
		payload = strconv.Itoa(i)
		url = "https://" + address + "/?" + payload

		wg.Add(1)
		go func() {
			defer wg.Done()

			t.Logf("[HTTP/3-%d.%d] connecting to %s, requesting %s, expecting %s", port, i, address, url, payload)

			config := httpRequestConfig{
				RequestId: fmt.Sprintf("HTTP/3-%d.%d", port, i),
				Timeout:   waitForHTTP3Request,
				TLSConfig: provideTLSConfig(true, testPCWHostname),

				Method: "GET",
				Url:    url,
				Body:   nil,
			}
			config.Check = provideHTTPResponseCheck(config.RequestId, 200, payload)

			requestHTTP3(t, &config)
		}()

		time.Sleep(testPCWWait)
	}
}

func testPCWWithUDPExchanges(t *testing.T, wg *sync.WaitGroup, port int) {
	t.Helper()

	defer wg.Done()

	address := fmt.Sprintf("%s:%d", testPCWHostname, port)

	messages := make([][]byte, testPCWMultiplier*len(testPCWDomains))
	for i, _ := range messages {
		messages[i] = []byte(fmt.Sprintf("ECHO%04d", i))
	}

	for i := range 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			t.Logf("[UDP-%d.%d] connecting to %s, sending %s, expecting %s", port, i, address, messages[0], messages[0])

			config := udpExchangeConfig{
				ExchangeId: fmt.Sprintf("UDP-%d.%d", port, i),
				Timeout:    waitForUDPExchange,
				Wait:       testPCWWait,

				Address:  address,
				Messages: messages,
			}

			exchangeUDP(t, &config)
		}()

		time.Sleep(testPCWWait)
	}
}

// TestPCW tests the packet conn wrapper implementation.
func TestPCW(t *testing.T) {
	// Load Caddy
	loadCaddyWithCaddyfile(t, testPCWCaddyfile[1:]) // skip a line break to avoid a caddyfile format warning on line 1

	// Use a wait group to sync goroutines
	var wg sync.WaitGroup

	// Spawn goroutines that make HTTP/3 requests
	for _, port := range []int{testPCWPortHTTP3Only, testPCWPortMultiplex} {
		wg.Add(1)
		go testPCWWithHTTP3Requests(t, &wg, port)
	}

	// Spawn goroutines that make DNS queries
	for _, port := range []int{testPCWPortDNSOnly, testPCWPortMultiplex} {
		wg.Add(1)
		go testPCWWithDNSQueries(t, &wg, port)
	}

	// TODO: resolve close of closed channel panic
	//// Spawn goroutines that exchange UDP messages
	//for _, port := range []int{testPCWPortEchoOnly, testPCWPortMultiplex} {
	//	wg.Add(1)
	//	go testPCWWithUDPExchanges(t, &wg, port)
	//}

	// Wait for all goroutines to finish
	wg.Wait()

	// Stop Caddy
	stopCaddy(t)
}
