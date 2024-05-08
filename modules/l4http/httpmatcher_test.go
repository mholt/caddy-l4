package l4http

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Unexpected error: %s\n", err)
	}
}

func httpMatchTester(t *testing.T, matchers json.RawMessage, data []byte) (bool, error) {
	in, out := net.Pipe()
	defer in.Close()
	defer out.Close()

	cx := layer4.WrapConnection(in, make([]byte, 0, layer4.PrefetchChunkSize), zap.NewNop())
	go func() {
		_, err := out.Write(data)
		assertNoError(t, err)
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	routes := layer4.RouteList{&layer4.Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"http": matchers},
		},
	}}
	err := routes.Provision(ctx)
	assertNoError(t, err)

	matched := false
	compiledRoute := routes.Compile(layer4.NextHandlerFunc(func(con *layer4.Connection, _ layer4.Handler) error {
		matched = true
		return nil
	}), zap.NewNop(), 10*time.Millisecond)

	err = compiledRoute.Handle(cx)
	assertNoError(t, err)

	return matched, err
}

func TestHttp1Matching(t *testing.T) {
	http1RequestExample := []byte("GET /foo/bar?aaa=bbb HTTP/1.1\nHost: localhost:10443\nUser-Agent: curl/7.82.0\nAccept: */*\n\n")

	for _, tc := range []struct {
		name     string
		matchers json.RawMessage
		data     []byte
	}{
		{
			name:     "match-by-host",
			matchers: json.RawMessage("[{\"host\":[\"localhost\"]}]"),
			data:     http1RequestExample,
		},
		{
			name:     "match-by-method",
			matchers: json.RawMessage("[{\"method\":[\"GET\"]}]"),
			data:     http1RequestExample,
		},
		{
			name:     "match-by-path",
			matchers: json.RawMessage("[{\"path\":[\"/foo/bar\"]}]"),
			data:     http1RequestExample,
		},
		{
			name:     "match-by-query",
			matchers: json.RawMessage("[{\"query\":{\"aaa\":[\"bbb\"]}}]"),
			data:     http1RequestExample,
		},
		{
			name:     "match-by-header",
			matchers: json.RawMessage("[{\"header\":{\"user-agent\":[\"curl*\"]}}]"),
			data:     http1RequestExample,
		},
		{
			name:     "match-by-protocol",
			matchers: json.RawMessage("[{\"protocol\":\"http\"}]"),
			data:     http1RequestExample,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := httpMatchTester(t, tc.matchers, tc.data)
			assertNoError(t, err)
			if !matched {
				t.Errorf("matcher did not match")
			}
		})
	}
}

func TestHttp2Matching(t *testing.T) {
	http2PriorKnowledgeRequestExample, err := base64.StdEncoding.DecodeString("UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAASBAAAAAAAAAMAAABkAAQCAAAAAAIAAAAAAAAECAAAAAAAAf8AAQAALAEFAAAAAYIEjGJTnYjHZ/gxjgjjj4dBi6DkHROdCbgQNNM/eogltlDDq7wlwVMDKi8q")
	assertNoError(t, err)

	http2UpgradeRequestExample, err := base64.StdEncoding.DecodeString("R0VUIC9mb28vYmFyP2FhYT1iYmIgSFRUUC8xLjENCkhvc3Q6IGxvY2FsaG9zdDoxMDQ0Mw0KVXNlci1BZ2VudDogY3VybC83LjgyLjANCkFjY2VwdDogKi8qDQpDb25uZWN0aW9uOiBVcGdyYWRlLCBIVFRQMi1TZXR0aW5ncw0KVXBncmFkZTogaDJjDQpIVFRQMi1TZXR0aW5nczogQUFNQUFBQmtBQVFDQUFBQUFBSUFBQUFBDQoNCg==")
	assertNoError(t, err)

	for _, tc := range []struct {
		name     string
		matchers json.RawMessage
		data     []byte
	}{
		{
			name:     "match-by-host",
			matchers: json.RawMessage("[{\"host\":[\"localhost\"]}]"),
			data:     http2PriorKnowledgeRequestExample,
		},
		{
			name:     "match-by-method",
			matchers: json.RawMessage("[{\"method\":[\"GET\"]}]"),
			data:     http2PriorKnowledgeRequestExample,
		},
		{
			name:     "match-by-path",
			matchers: json.RawMessage("[{\"path\":[\"/foo/bar\"]}]"),
			data:     http2PriorKnowledgeRequestExample,
		},
		{
			name:     "match-by-query",
			matchers: json.RawMessage("[{\"query\":{\"aaa\":[\"bbb\"]}}]"),
			data:     http2PriorKnowledgeRequestExample,
		},
		{
			name:     "match-by-header",
			matchers: json.RawMessage("[{\"header\":{\"user-agent\":[\"curl*\"]}}]"),
			data:     http2PriorKnowledgeRequestExample,
		},
		{
			name:     "match-by-protocol",
			matchers: json.RawMessage("[{\"protocol\":\"http\"}]"),
			data:     http2PriorKnowledgeRequestExample,
		},

		{
			name:     "upgrade-match-by-host",
			matchers: json.RawMessage("[{\"host\":[\"localhost\"]}]"),
			data:     http2UpgradeRequestExample,
		},
		{
			name:     "upgrade-match-by-method",
			matchers: json.RawMessage("[{\"method\":[\"GET\"]}]"),
			data:     http2UpgradeRequestExample,
		},
		{
			name:     "upgrade-match-by-path",
			matchers: json.RawMessage("[{\"path\":[\"/foo/bar\"]}]"),
			data:     http2UpgradeRequestExample,
		},
		{
			name:     "upgrade-match-by-query",
			matchers: json.RawMessage("[{\"query\":{\"aaa\":[\"bbb\"]}}]"),
			data:     http2UpgradeRequestExample,
		},
		{
			name:     "upgrade-match-by-header",
			matchers: json.RawMessage("[{\"header\":{\"user-agent\":[\"curl*\"]}}]"),
			data:     http2UpgradeRequestExample,
		},
		{
			name:     "upgrade-match-by-protocol",
			matchers: json.RawMessage("[{\"protocol\":\"http\"}]"),
			data:     http2UpgradeRequestExample,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := httpMatchTester(t, tc.matchers, tc.data)
			assertNoError(t, err)
			if !matched {
				t.Errorf("matcher did not match")
			}
		})
	}
}

func TestHttpMatchingByProtocolWithHttps(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	routes := layer4.RouteList{&layer4.Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"http": json.RawMessage("[{\"protocol\":\"https\"}]")},
		},
	}}

	err := routes.Provision(ctx)
	assertNoError(t, err)

	handlerCalled := false
	compiledRoute := routes.Compile(layer4.NextHandlerFunc(func(con *layer4.Connection, _ layer4.Handler) error {
		handlerCalled = true
		return nil
	}), zap.NewNop(), 100*time.Millisecond)

	in, out := net.Pipe()
	defer in.Close()
	defer out.Close()

	cx := layer4.WrapConnection(in, []byte{}, zap.NewNop())
	go func() {
		_, err := out.Write([]byte("GET /foo/bar?aaa=bbb HTTP/1.1\nHost: localhost:10443\n\n"))
		assertNoError(t, err)
	}()

	// pretend the tls handler was executed before, not an ideal test setup but better then nothing
	cx.SetVar("tls_connection_states", []*tls.ConnectionState{{ServerName: "localhost"}})

	err = compiledRoute.Handle(cx)
	assertNoError(t, err)
	if !handlerCalled {
		t.Fatalf("matcher did not match")
	}
}

func TestHttpMatchingGarbage(t *testing.T) {
	matchers := json.RawMessage("[{\"host\":[\"localhost\"]}]")

	matched, err := httpMatchTester(t, matchers, []byte("not a valid http request"))
	assertNoError(t, err)
	if matched {
		t.Fatalf("matcher did match")
	}

	validHttp2MagicWithoutHeadersFrame, err := base64.StdEncoding.DecodeString("UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAASBAAAAAAAAAMAAABkAAQCAAAAAAIAAAAATm8gbG9uZ2VyIHZhbGlkIGh0dHAyIHJlcXVlc3QgZnJhbWVz")
	assertNoError(t, err)
	matched, err = httpMatchTester(t, matchers, validHttp2MagicWithoutHeadersFrame)
	if matched {
		t.Fatalf("matcher did match")
	}
}

func TestMatchHTTP_isHttp(t *testing.T) {
	for _, tc := range []struct {
		name        string
		data        []byte
		shouldMatch bool
	}{
		{
			name:        "http/1.1-only-lf",
			data:        []byte("GET /foo/bar?aaa=bbb HTTP/1.1\nHost: localhost:10443\n\n"),
			shouldMatch: true,
		},
		{
			name:        "http/1.1-cr-lf",
			data:        []byte("GET /foo/bar?aaa=bbb HTTP/1.1\r\nHost: localhost:10443\r\n\r\n"),
			shouldMatch: true,
		},
		{
			name:        "http/1.0-cr-lf",
			data:        []byte("GET /foo/bar?aaa=bbb HTTP/1.0\r\nHost: localhost:10443\r\n\r\n"),
			shouldMatch: true,
		},
		{
			name:        "http/2.0-cr-lf",
			data:        []byte("PRI * HTTP/2.0\r\n\r\n"),
			shouldMatch: true,
		},
		{
			name:        "dummy-short",
			data:        []byte("dum\n"),
			shouldMatch: false,
		},
		{
			name:        "dummy-long",
			data:        []byte("dummydummydummy\n"),
			shouldMatch: false,
		},
		{
			name:        "http/1.1-without-space-in-front",
			data:        []byte("HTTP/1.1\n"),
			shouldMatch: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matched := MatchHTTP{}.isHttp(tc.data)
			if matched != tc.shouldMatch {
				t.Fatalf("test %v | matched: %v != shouldMatch: %v", tc.name, matched, tc.shouldMatch)
			}
		})
	}
}
