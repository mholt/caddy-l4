package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/vnxme/hybrid"

	_ "github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4dns"
	_ "github.com/mholt/caddy-l4/modules/l4echo"
	_ "github.com/mholt/caddy-l4/modules/l4proxy"
	_ "github.com/mholt/caddy-l4/modules/l4regexp"
)

const (
	testPCWHostname = "localhost"           // Hostname that clients connect to
	testPCWAddress  = "localhost:443"       // Address served by HTTP/3 and the packet conn wrapper
	testPCWUpdated  = "updated:"            // Response body prefix of an updated config
	testPCWNoReply  = 1 * time.Second       // How long to wait for a reply that shouldn't come
	testPCWTrunk    = "trunk"               // Network of the trunks Caddy listens on in place of UDP sockets
	testPCWDelay    = 20 * time.Millisecond // How much time to wait between spawning clients

	testPCWPortMultiplex = 443  // Port serving multiple services
	testPCWPortEchoOnly  = 2000 // Port serving echo only
	testPCWPortDNSOnly   = 5300 // Port serving DNS only
	testPCWPortHTTP3Only = 8443 // Port serving HTTP/3 only

	testPCWMultiplier = 2 // How many times each domain is requested by DNS client
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

// testPCWCaddyfile returns a config serving HTTP/3, DNS and echo on port 443, HTTP/3 only on port 8443, DNS only
// on port 5300, and echo only on port 2000, with DNS proxied to the upstream given.
func testPCWCaddyfile(dnsUpstream string) string {
	return fmt.Sprintf(`{
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
				proxy udp/%[1]s
			}
		}
	}
	servers :443 {
		packet_conn_wrappers {
			layer4 {
				@d dns
				route @d {
					proxy udp/%[1]s
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
}`, dnsUpstream)
}

// testPCWEchoCaddyfile returns a config serving HTTP/3 on port 443, wrapped with a packet conn wrapper echoing
// the flows matching echoRegexp, and proxying those matching ^PROXY\d{4}$ to a layer 4 echo server on port 2000.
// HTTP/3 responses are prefixed with body. HTTP to HTTPS redirects are disabled, so as not to listen on port 80,
// which Caddy may not have released yet once the config of the previous test has been stopped.
func testPCWEchoCaddyfile(echoRegexp string, echoLength int, body string) string {
	return fmt.Sprintf(`{
	debug
	auto_https disable_redirects
	layer4 {
		udp/:2000 {
			route {
				echo
			}
		}
	}
	servers :443 {
		packet_conn_wrappers {
			layer4 {
				@e regexp %s %d
				route @e {
					echo
				}
				@p regexp ^PROXY\d\d\d\d$ 9
				route @p {
					proxy udp/127.0.0.1:2000
				}
			}
		}
		protocols h3
	}
}
https://localhost {
	tls {
		issuer internal
	}
	respond "%s{http.request.uri.query}" 200
}`, echoRegexp, echoLength, body)
}

// stopPCWCaddy stops Caddy, and waits until UDP ports 443 and 2000, and the other UDP addresses given, are released,
// as Caddy shuts its HTTP/3 servers down in the background, so that the next test can listen on them.
func stopPCWCaddy(t *testing.T, addrs ...string) {
	t.Helper()

	stopCaddy(t)
	deadline := time.Now().Add(10 * time.Second)
	for _, addr := range append([]string{":443", ":2000"}, addrs...) {
		for {
			pc, err := net.ListenPacket("udp", addr)
			if err == nil {
				_ = pc.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("UDP %s isn't released once Caddy has stopped: %v", addr, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// startDNSServer serves DNS over UDP on a local address until the test ends, answering every question
// of type A or NS with a record of its type, and returns the address.
func startDNSServer(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen DNS: %v", err)
	}
	started := make(chan struct{})
	server := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			for _, q := range r.Question {
				hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}
				switch q.Qtype {
				case dns.TypeA:
					m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IPv4(192, 0, 2, 53)})
				case dns.TypeNS:
					m.Answer = append(m.Answer, &dns.NS{Hdr: hdr, Ns: "ns." + q.Name})
				}
			}
			_ = w.WriteMsg(m)
		}),
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String()
}

// checkPCWHTTP3 requests the given payload over HTTP/3, expecting it back prefixed with body.
func checkPCWHTTP3(t *testing.T, address, payload, body string) {
	t.Helper()

	config := httpRequestConfig{
		RequestId: fmt.Sprintf("HTTP/3-%s-%s", address, payload),
		Timeout:   waitForHTTP3Request,
		TLSConfig: provideTLSConfig(true, testPCWHostname),

		Method: "GET",
		Url:    "https://" + address + "/?" + payload,
	}
	config.Check = provideHTTPResponseCheck(config.RequestId, 200, body+payload)
	requestHTTP3(t, &config)
}

// checkPCWDNS queries the given domain over DNS, expecting at least one record of the type queried.
func checkPCWDNS(t *testing.T, address, domain string, qType uint16) {
	t.Helper()

	config := dnsQueryConfig{
		QueryId: fmt.Sprintf("DNS-%s-%s", address, domain),
		Timeout: waitForDNSRequest,

		Net:        "udp",
		Address:    address,
		QueryType:  qType,
		DomainName: domain,
	}
	config.Check = provideDNSMessageCheck(config.QueryId, true, qType)
	queryDNS(t, &config)
}

// checkPCWEcho exchanges the messages over a flow, expecting each of them echoed.
func checkPCWEcho(t *testing.T, address string, delay time.Duration, messages ...string) {
	t.Helper()

	config := udpExchangeConfig{
		ExchangeId: fmt.Sprintf("UDP-%s-%s", address, messages[0]),
		Timeout:    waitForUDPExchange + time.Duration(len(messages))*delay,
		Delay:      delay,
		Address:    address,
	}
	for _, m := range messages {
		config.Messages = append(config.Messages, []byte(m))
	}
	config.Check = func(t *testing.T, m []byte, r []byte) {
		if !bytes.Equal(m, r) {
			t.Errorf("[%s] expected %s, got %s", config.ExchangeId, m, r)
		}
	}
	exchangeUDP(t, &config)
}

// checkPCWNoEcho sends a message to the wrapper, expecting no echo, as no route matches it.
func checkPCWNoEcho(t *testing.T, m string) {
	t.Helper()

	c, err := net.Dial("udp", testPCWAddress)
	if err != nil {
		t.Fatalf("dial UDP: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, err = c.Write([]byte(m)); err != nil {
		t.Fatalf("write UDP message: %v", err)
	}
	buf := make([]byte, 9000)
	_ = c.SetReadDeadline(time.Now().Add(testPCWNoReply))
	if n, err := c.Read(buf); err == nil && string(buf[:n]) == m {
		t.Errorf("got %q echoed, want no echo", m)
	}
}

// TestPCW tests the packet conn wrapper multiplexing HTTP/3, DNS and echo on one port,
// along with ports serving each of them alone.
func TestPCW(t *testing.T) {
	loadCaddyWithCaddyfile(t, testPCWCaddyfile(startDNSServer(t)))

	// Run clients of each service concurrently, as the helpers report failures without stopping the test
	var wg sync.WaitGroup
	for _, port := range []int{testPCWPortHTTP3Only, testPCWPortMultiplex} {
		address := fmt.Sprintf("%s:%d", testPCWHostname, port)
		for i := range testPCWMultiplier * len(testPCWDomains) {
			wg.Go(func() { checkPCWHTTP3(t, address, strconv.Itoa(i), "") })
			time.Sleep(testPCWDelay)
		}
	}
	for _, port := range []int{testPCWPortDNSOnly, testPCWPortMultiplex} {
		address := fmt.Sprintf("%s:%d", testPCWHostname, port)
		multiplier, qType := testPCWMultiplier, dns.TypeA
		if port == testPCWPortDNSOnly {
			multiplier, qType = 1, dns.TypeNS // Disregard the multiplier for DNS only tests, query NS instead of A
		}
		for range multiplier {
			for _, domain := range testPCWDomains {
				wg.Go(func() { checkPCWDNS(t, address, domain, qType) })
				time.Sleep(testPCWDelay)
			}
		}
	}
	for _, port := range []int{testPCWPortEchoOnly, testPCWPortMultiplex} {
		messages := make([]string, testPCWMultiplier*len(testPCWDomains))
		for i := range messages {
			messages[i] = fmt.Sprintf("ECHO%04d", i)
		}
		wg.Go(func() { checkPCWEcho(t, fmt.Sprintf("%s:%d", testPCWHostname, port), testPCWDelay, messages...) })
	}
	wg.Wait()

	stopPCWCaddy(t, fmt.Sprintf(":%d", testPCWPortDNSOnly), fmt.Sprintf(":%d", testPCWPortHTTP3Only))
}

// TestPCWProxy tests proxying UDP flows through the packet conn wrapper, along with HTTP/3 on the same port.
func TestPCWProxy(t *testing.T) {
	loadCaddyWithCaddyfile(t, testPCWEchoCaddyfile(`^ECHO\d\d\d\d$`, 8, ""))
	defer stopPCWCaddy(t)

	for i := range 5 {
		checkPCWEcho(t, testPCWAddress, 0, fmt.Sprintf("PROXY%04d", i))
		checkPCWEcho(t, testPCWAddress, 0, fmt.Sprintf("ECHO%04d", i))
		checkPCWHTTP3(t, testPCWAddress, strconv.Itoa(i), "")
	}
}

// TestPCWJunk tests that the packet conn wrapper keeps serving HTTP/3 and its routes while flows of junk
// matching no route, of any size from empty to the largest packet read, go to the HTTP/3 server.
func TestPCWJunk(t *testing.T) {
	loadCaddyWithCaddyfile(t, testPCWEchoCaddyfile(`^ECHO\d\d\d\d$`, 8, ""))
	defer stopPCWCaddy(t)

	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			c, err := net.Dial("udp", testPCWAddress)
			if err != nil {
				t.Errorf("junk client %d: dial UDP: %v", i, err)
				return
			}
			defer func() { _ = c.Close() }()
			for {
				junk := make([]byte, rand.IntN(9001))
				for j := range junk {
					junk[j] = byte(rand.Uint())
				}
				if _, err = c.Write(junk); err != nil && !errors.Is(err, net.ErrClosed) {
					// A write may fail, e.g. if an ICMP error has been received, which isn't the point here
					t.Logf("junk client %d: write UDP message: %v", i, err)
				}
				select {
				case <-done:
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		})
	}

	for i := range 10 {
		checkPCWHTTP3(t, testPCWAddress, strconv.Itoa(i), "")
		checkPCWEcho(t, testPCWAddress, 0, fmt.Sprintf("ECHO%04d", i))
		checkPCWEcho(t, testPCWAddress, 0, fmt.Sprintf("PROXY%04d", i))
	}
	close(done)
	wg.Wait()
}

// TestPCWReload tests that HTTP/3 keeps working through the packet conn wrapper once the config is reloaded,
// and that, as Caddy wraps a socket once, the routes of the wrapper stay those of the config it was started with.
func TestPCWReload(t *testing.T) {
	loadCaddyWithCaddyfile(t, testPCWEchoCaddyfile(`^ECHO\d\d\d\d$`, 8, ""))
	defer stopPCWCaddy(t)
	checkPCWHTTP3(t, testPCWAddress, "before", "")
	checkPCWEcho(t, testPCWAddress, 0, "ECHO0000")
	checkPCWEcho(t, testPCWAddress, 0, "PROXY0000")

	loadCaddyWithCaddyfile(t, testPCWEchoCaddyfile(`^PING\d\d\d\d$`, 8, testPCWUpdated))
	checkPCWHTTP3(t, testPCWAddress, "after", testPCWUpdated)
	checkPCWEcho(t, testPCWAddress, 0, "ECHO0001") // The routes of the first config are still in place
	checkPCWEcho(t, testPCWAddress, 0, "PROXY0001")
	checkPCWNoEcho(t, "PING0001")
}

// TestPCWRestart tests that once Caddy stops, the socket of the packet conn wrapper is released,
// so that Caddy can be started again on the same port.
func TestPCWRestart(t *testing.T) {
	for i := range 3 {
		loadCaddyWithCaddyfile(t, testPCWEchoCaddyfile(`^ECHO\d\d\d\d$`, 8, ""))
		checkPCWHTTP3(t, testPCWAddress, strconv.Itoa(i), "")
		checkPCWEcho(t, testPCWAddress, 0, fmt.Sprintf("ECHO%04d", i))
		checkPCWEcho(t, testPCWAddress, 0, fmt.Sprintf("PROXY%04d", i))
		stopPCWCaddy(t)
	}
}

func init() {
	caddy.RegisterNetwork(testPCWTrunk, listenTestTrunk)
	caddyhttp.RegisterNetworkHTTP3(testPCWTrunk, testPCWTrunk)
}

// testTrunks holds the client ends of the trunks Caddy listens on, by the address of their server ends.
var testTrunks = struct {
	sync.Mutex
	m map[string]hybrid.FromToPacketConn
}{m: make(map[string]hybrid.FromToPacketConn)}

// listenTestTrunk listens on the trunk network in place of Caddy listening on a UDP socket: it returns the server
// end of a trunk with the address given, keeping its client end for testTrunk.
func listenTestTrunk(_ context.Context, _, host, portRange string, portOffset uint, _ net.ListenConfig) (any, error) {
	port, err := strconv.Atoi(portRange)
	if err != nil {
		return nil, err
	}
	server := &net.UDPAddr{IP: net.ParseIP(host), Port: port + int(portOffset)}
	client, serverEnd := hybrid.BufferedTrunk(1024, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 1000}, server)

	testTrunks.Lock()
	defer testTrunks.Unlock()
	testTrunks.m[server.String()] = client
	return serverEnd, nil
}

// testTrunk returns the client end of the trunk Caddy listens on with the address given.
func testTrunk(t *testing.T, server string) hybrid.FromToPacketConn {
	t.Helper()

	testTrunks.Lock()
	defer testTrunks.Unlock()
	client, ok := testTrunks.m[server]
	if !ok {
		t.Fatalf("Caddy doesn't listen on %s/%s", testPCWTrunk, server)
	}
	delete(testTrunks.m, server)
	return client
}

// TestPCWTrunk tests the packet conn wrapper multiplexing HTTP/3 and echo with Caddy listening on a trunk rather
// than on a UDP socket, which makes the test independent of the network stack, e.g. of ports being released.
// A QUIC transport serves the HTTP/3 client over the client end of the trunk, and an echo client writes over it
// from an address of its own, so as to make a flow of its own, while its packets, which aren't QUIC packets as
// their first byte is '#', are read with the QUIC transport.
func TestPCWTrunk(t *testing.T) {
	const server = "127.0.0.1:443"
	loadCaddyWithJSON(t, []byte(`{
		"logging": {"logs": {"default": {"level": "DEBUG"}}},
		"apps": {
			"http": {
				"servers": {
					"srv0": {
						"listen": ["`+testPCWTrunk+`/`+server+`"],
						"protocols": ["h3"],
						"automatic_https": {"disable_redirects": true},
						"packet_conn_wrappers": [{
							"wrapper": "layer4",
							"routes": [{
								"match": [{"regexp": {"pattern": "^#ECHO\\d\\d\\d\\d$", "count": 9}}],
								"handle": [{"handler": "echo"}]
							}]
						}],
						"routes": [{
							"match": [{"host": ["localhost"]}],
							"handle": [{
								"handler": "static_response",
								"body": "{http.request.uri.query}",
								"status_code": 200
							}],
							"terminal": true
						}]
					}
				}
			},
			"tls": {
				"automation": {
					"policies": [{"subjects": ["localhost"], "issuers": [{"module": "internal"}]}]
				}
			}
		}
	}`))
	defer stopCaddy(t)

	client := testTrunk(t, server)
	serverAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		t.Fatalf("resolve %s: %v", server, err)
	}
	tr := &quic.Transport{Conn: client}
	defer func() { _ = tr.Close() }()

	// HTTP/3 over the trunk
	for i := range 5 {
		payload := strconv.Itoa(i)
		config := httpRequestConfig{
			RequestId: "HTTP/3-" + testPCWTrunk + "-" + payload,
			Timeout:   waitForHTTP3Request,
			TLSConfig: provideTLSConfig(true, testPCWHostname),

			Method: "GET",
			Url:    "https://" + testPCWAddress + "/?" + payload,
			Transport: func() http.RoundTripper {
				return &http3.Transport{
					TLSClientConfig: provideTLSConfig(true, testPCWHostname),
					Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
						return tr.DialEarly(ctx, serverAddr, tlsCfg, cfg)
					},
				}
			},
		}
		config.Check = provideHTTPResponseCheck(config.RequestId, 200, payload)
		requestHTTP(t, &config)
	}

	// Echo over the trunk, from an address of its own, and a flow matching no route, which goes to HTTP/3
	echoAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 2000}
	buf := make([]byte, 1500)
	// The QUIC transport drops the packets that aren't QUIC packets until it's asked to read them for the first time
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	_, _, _ = tr.ReadNonQUICPacket(done, buf)
	for i := range 5 {
		want := fmt.Sprintf("#ECHO%04d", i)
		if _, err = client.WriteToFrom([]byte(want), serverAddr, echoAddr, 0); err != nil {
			t.Fatalf("write %q: %v", want, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), waitForUDPExchange)
		n, _, err := tr.ReadNonQUICPacket(ctx, buf)
		cancel()
		if err != nil {
			t.Fatalf("read the echo of %q: %v", want, err)
		}
		if string(buf[:n]) != want {
			t.Errorf("got %q echoed, want %q", buf[:n], want)
		}
	}
	junkAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 3), Port: 3000}
	if _, err = client.WriteToFrom([]byte("#PING0000"), serverAddr, junkAddr, 0); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testPCWNoReply)
	defer cancel()
	if n, _, err := tr.ReadNonQUICPacket(ctx, buf); err == nil {
		t.Errorf("got %q for a flow matching no route, want nothing", buf[:n])
	}
}
