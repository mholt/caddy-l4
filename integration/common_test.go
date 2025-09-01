package integration

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

// dnsQueryConfig contains DNS query parameters and a function for response message validation.
type dnsQueryConfig struct {
	// QueryId is an identifier used for logging.
	QueryId string
	// Timeout is a DNS request timeout (set via context.WithTimeout).
	Timeout time.Duration
	// TLSConfig in a TLS configuration.
	TLSConfig *tls.Config

	// Net can be "tcp-tls", "tcp" or "udp", "" is a synonym for "udp".
	Net string
	// Address must be given in "{address}:{port}" or another format supported by net.Dial.
	Address string
	// QueryType must be one of dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS, etc.
	QueryType uint16
	// DomainName must be a FQDN ending with a dot.
	DomainName string

	// Check validates a DNS response message.
	Check func(*testing.T, *dns.Msg)
}

// httpRequestConfig contains HTTP request parameters and a function for response validation.
type httpRequestConfig struct {
	// RequestId is an identifier used for logging.
	RequestId string
	// Timeout is an HTTP request timeout (set via context.WithTimeout).
	Timeout time.Duration
	// TLSConfig in a TLS configuration.
	TLSConfig *tls.Config

	// Method is an HTTP method, e.g. "GET", "PUT", etc.
	Method string
	// Url is a resource locator in "{scheme}://{hostname}:{port}/{path}?{query}" format.
	Url string
	// Body is an optional request body.
	Body io.Reader

	// Check validates an HTTP response.
	Check func(*testing.T, *http.Response)
	// Transport returns an http.RoundTripper implementation.
	Transport func() http.RoundTripper
}

// udpExchangeConfig contains UDP exchange parameters and a function for response message validation.
type udpExchangeConfig struct {
	// ExchangeId is an identifier used for logging.
	ExchangeId string
	// Timeout is a UDP connection timeout (set via conn.SetDeadline).
	Timeout time.Duration
	// Delay is a period of time UDP exchange sleeps between message exchanges.
	Delay time.Duration

	// Address must be given in "{address}:{port}" or another format supported by net.Dial.
	Address string

	// Messages contains a list of byte sequences to send.
	Messages [][]byte
	// Check validates a UDP response message.
	Check func(*testing.T, []byte, []byte)
}

func exchangeUDP(t *testing.T, config *udpExchangeConfig) {
	t.Helper()

	var logPrefix string
	if len(config.ExchangeId) > 0 {
		logPrefix = "[" + config.ExchangeId + "] "
	}

	// Resolve address
	udpAddr, err := net.ResolveUDPAddr("udp", config.Address)
	if err != nil {
		t.Fatalf("%sresolve UDP address: %v", logPrefix, err)
	}

	// Dial UDP (connectionless, but gives us a socket)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("%sdial UDP: %v", logPrefix, err)
	}
	defer func() { _ = conn.Close() }()

	// Set a deadline so we don't block forever
	_ = conn.SetDeadline(time.Now().Add(config.Timeout))

	// Send messages and read responses
	buf := make([][]byte, len(config.Messages))
	for i, m := range config.Messages {
		// Send message
		_, err = conn.Write(m)
		if err != nil {
			t.Fatalf("%swrite UDP message: %v", logPrefix, err)
		}

		if config.Check != nil {
			// Receive response
			buf[i] = make([]byte, 9000)
			n, _, err := conn.ReadFromUDP(buf[i])
			if err != nil {
				t.Fatalf("%sread UDP response: %v", logPrefix, err)
			}

			r := buf[i][:n]
			t.Logf("%swrote UDP message %v, read UDP response %v", logPrefix, string(m), string(r))

			config.Check(t, m, r)
		}

		time.Sleep(config.Delay)
	}
}

// loadCaddyWithJSON launches Caddy instance with a given JSON config.
func loadCaddyWithJSON(t *testing.T, config []byte) {
	t.Helper()

	// Start Caddy with the given config
	err := caddy.Load(config, true)
	if err != nil {
		t.Fatalf("load Caddy: %v", err)
	}

	// Give Caddy a moment to come up
	time.Sleep(waitForCaddyLaunch)
}

// loadCaddyWithCaddyfile launches Caddy instance with a given caddyfile config.
func loadCaddyWithCaddyfile(t *testing.T, caddyfileConfig string) {
	t.Helper()

	// Create a caddyfile adapter
	adapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}

	// Parse the given config, process warnings and errors
	config, warnings, err := adapter.Adapt([]byte(caddyfileConfig), nil)
	if len(warnings) > 0 {
		t.Logf("caddyfile warnings: %v", warnings)
	}
	if err != nil {
		t.Fatalf("adapt caddyfile: %v", err)
	}

	loadCaddyWithJSON(t, config)
}

// provideDNSMessageCheck returns a function that conducts DNS response code and resource record checks.
func provideDNSMessageCheck(queryId string, checkRecords bool, expectedRecordType uint16) func(*testing.T, *dns.Msg) {
	return func(t *testing.T, r *dns.Msg) {
		var logPrefix string
		if len(queryId) > 0 {
			logPrefix = "[" + queryId + "] "
		}

		// Do a status code check
		if r.Rcode != dns.RcodeSuccess {
			t.Fatalf("%sexpected DNS response code NOERROR, got %s", logPrefix, dns.RcodeToString[r.Rcode])
		}

		if checkRecords {
			// Process resource records
			found := false
			for _, ans := range r.Answer {
				t.Logf("%sreceived DNS resource record: %s", logPrefix, ans.String())
				if ans.Header().Rrtype == expectedRecordType {
					found = true
				}
			}
			if !found {
				t.Errorf("%sexpected at least one DNS record of type %s, got none", logPrefix, dns.TypeToString[expectedRecordType])
			}
		}
	}
}

// provideHTTPResponseCheck returns a function that conducts HTTP status code and response body checks.
func provideHTTPResponseCheck(requestId string, expectedCode int, expectedBody string) func(*testing.T, *http.Response) {
	return func(t *testing.T, resp *http.Response) {
		var logPrefix string
		if len(requestId) > 0 {
			logPrefix = "[" + requestId + "] "
		}

		if expectedCode > 0 && resp.StatusCode != expectedCode {
			t.Errorf("%sexpected HTTP status code %d, got %d", logPrefix, expectedCode, resp.StatusCode)
		}

		if len(expectedBody) > 0 && resp.Body != nil {
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("%sread HTTP response: %v", logPrefix, err)
			}

			if string(respBody) != expectedBody {
				t.Errorf("%sexpected HTTP response body %s, got %s", logPrefix, expectedBody, string(respBody))
			}

			t.Logf("%sreceived HTTP response body: %s", logPrefix, string(respBody))
		}
	}
}

// provideTLSConfig return a basic TLS config.
func provideTLSConfig(insecureSkipVerify bool, serverName string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		ServerName:         serverName,
	}
}

// queryDNS makes a DNS query.
func queryDNS(t *testing.T, config *dnsQueryConfig) {
	t.Helper()

	var logPrefix string
	if len(config.QueryId) > 0 {
		logPrefix = "[" + config.QueryId + "] "
	}

	// Compose a DNS query
	m := new(dns.Msg)
	m.SetQuestion(config.DomainName, config.QueryType)

	// Create a DNS client
	c := &dns.Client{
		Net:       config.Net,
		TLSConfig: config.TLSConfig,
	}

	// Create an empty context with the given timeout
	ctx, cancel := context.WithTimeout(t.Context(), config.Timeout)
	defer cancel()

	// Make the client conduct the query
	r, _, err := c.ExchangeContext(ctx, m, config.Address)
	if err != nil {
		t.Fatalf("%smake DNS query: %v", logPrefix, err)
	}

	// Do status code and resource record checks
	check := config.Check
	if check == nil {
		check = provideDNSMessageCheck(config.QueryId, true, config.QueryType)
	}
	check(t, r)
}

// requestHTTP3 makes an HTTP/3 request.
func requestHTTP3(t *testing.T, config *httpRequestConfig) {
	t.Helper()

	// Create an HTTP/3 transport
	config.Transport = func() http.RoundTripper {
		return &http3.Transport{
			TLSClientConfig: config.TLSConfig,
		}
	}

	requestHTTP(t, config)
}

// requestHTTP makes an HTTP request.
func requestHTTP(t *testing.T, config *httpRequestConfig) {
	t.Helper()

	var logPrefix string
	if len(config.RequestId) > 0 {
		logPrefix = "[" + config.RequestId + "] "
	}

	// Create an HTTP transport unless there is a custom http.RoundTripper implementation
	var transport http.RoundTripper
	if config.Transport != nil {
		transport = config.Transport()
	}
	if transport == nil {
		transport = &http.Transport{
			TLSClientConfig: config.TLSConfig,
		}
	}
	if closable, ok := transport.(io.Closer); ok {
		defer func() {
			_ = closable.Close()
		}()
	}

	// Create an HTTP client with a custom transport
	client := http.Client{
		Transport: transport,
	}

	// Create an empty context with the given timeout
	ctx, cancel := context.WithTimeout(t.Context(), config.Timeout)
	defer cancel()

	// Compose an HTTP request with the context and given parameters
	req, err := http.NewRequestWithContext(ctx, config.Method, config.Url, config.Body)
	if err != nil {
		t.Fatalf("%scompose HTTP request: %v", logPrefix, err)
	}

	// Make the client conduct the request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%smake HTTP request: %v", logPrefix, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Do status code, response or custom checks
	check := config.Check
	if check == nil {
		check = provideHTTPResponseCheck(config.RequestId, 200, "")
	}
	check(t, resp)
}

// stopCaddy stops Caddy instance.
func stopCaddy(t *testing.T) {
	t.Helper()

	err := caddy.Stop()
	if err != nil {
		t.Fatalf("stop Caddy: %v", err)
	}
}

const (
	waitForCaddyLaunch  = 500 * time.Millisecond
	waitForDNSRequest   = 5 * time.Second
	waitForHTTP3Request = 5 * time.Second
	waitForUDPExchange  = 5 * time.Second
)
