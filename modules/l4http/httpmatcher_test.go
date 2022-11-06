package l4http

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

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

func httpMatchTester(t *testing.T, matcherSets caddyhttp.RawMatcherSets, data []byte) (bool, error) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer func() {
		wg.Wait()
		_ = in.Close()
		_ = out.Close()
	}()

	cx := layer4.WrapConnection(in, make([]byte, 0, layer4.PrefetchChunkSize), zap.NewNop())
	go func() {
		wg.Add(1)
		defer func() {
			wg.Done()
			_ = out.Close()
		}()
		_, err := out.Write(data)
		assertNoError(t, err)
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	matcher := MatchHTTP{MatcherSetsRaw: matcherSets}
	err := matcher.Provision(ctx)
	assertNoError(t, err)

	mset := layer4.MatcherSet{matcher} // use MatcherSet to correctly call freeze() before matching
	matched, err := mset.Match(cx)

	_, _ = io.Copy(io.Discard, in)

	return matched, err
}

func TestHttp1Matching(t *testing.T) {
	http1RequestExample := []byte("GET /foo/bar?aaa=bbb HTTP/1.1\nHost: localhost:10443\nUser-Agent: curl/7.82.0\nAccept: */*\n\n")

	for _, tc := range []struct {
		name        string
		matcherSets caddyhttp.RawMatcherSets
		data        []byte
	}{
		{
			name:        "match-by-host",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"host": json.RawMessage("[\"localhost\"]")}},
			data:        http1RequestExample,
		},
		{
			name:        "match-by-method",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"method": json.RawMessage("[\"GET\"]")}},
			data:        http1RequestExample,
		},
		{
			name:        "match-by-path",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"path": json.RawMessage("[\"/foo/bar\"]")}},
			data:        http1RequestExample,
		},
		{
			name:        "match-by-query",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"query": json.RawMessage("{\"aaa\":[\"bbb\"]}")}},
			data:        http1RequestExample,
		},
		{
			name:        "match-by-header",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"header": json.RawMessage("{\"user-agent\":[\"curl*\"]}")}},
			data:        http1RequestExample,
		},
		{
			name:        "match-by-protocol",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"protocol": json.RawMessage("\"http\"")}},
			data:        http1RequestExample,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := httpMatchTester(t, tc.matcherSets, tc.data)
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
		name        string
		matcherSets caddyhttp.RawMatcherSets
		data        []byte
	}{
		{
			name:        "match-by-host",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"host": json.RawMessage("[\"localhost\"]")}},
			data:        http2PriorKnowledgeRequestExample,
		},
		{
			name:        "match-by-method",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"method": json.RawMessage("[\"GET\"]")}},
			data:        http2PriorKnowledgeRequestExample,
		},
		{
			name:        "match-by-path",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"path": json.RawMessage("[\"/foo/bar\"]")}},
			data:        http2PriorKnowledgeRequestExample,
		},
		{
			name:        "match-by-query",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"query": json.RawMessage("{\"aaa\":[\"bbb\"]}")}},
			data:        http2PriorKnowledgeRequestExample,
		},
		{
			name:        "match-by-header",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"header": json.RawMessage("{\"user-agent\":[\"curl*\"]}")}},
			data:        http2PriorKnowledgeRequestExample,
		},
		{
			name:        "match-by-protocol",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"protocol": json.RawMessage("\"http\"")}},
			data:        http2PriorKnowledgeRequestExample,
		},

		{
			name:        "upgrade-match-by-host",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"host": json.RawMessage("[\"localhost\"]")}},
			data:        http2UpgradeRequestExample,
		},
		{
			name:        "upgrade-match-by-method",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"method": json.RawMessage("[\"GET\"]")}},
			data:        http2UpgradeRequestExample,
		},
		{
			name:        "upgrade-match-by-path",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"path": json.RawMessage("[\"/foo/bar\"]")}},
			data:        http2UpgradeRequestExample,
		},
		{
			name:        "upgrade-match-by-query",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"query": json.RawMessage("{\"aaa\":[\"bbb\"]}")}},
			data:        http2UpgradeRequestExample,
		},
		{
			name:        "upgrade-match-by-header",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"header": json.RawMessage("{\"user-agent\":[\"curl*\"]}")}},
			data:        http2UpgradeRequestExample,
		},
		{
			name:        "upgrade-match-by-protocol",
			matcherSets: caddyhttp.RawMatcherSets{caddy.ModuleMap{"protocol": json.RawMessage("\"http\"")}},
			data:        http2UpgradeRequestExample,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := httpMatchTester(t, tc.matcherSets, tc.data)
			assertNoError(t, err)
			if !matched {
				t.Errorf("matcher did not match")
			}
		})
	}
}

func TestHttpMatchingByProtocolWithHttps(t *testing.T) {
	matcherSets := caddyhttp.RawMatcherSets{caddy.ModuleMap{"protocol": json.RawMessage("\"https\"")}}

	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer func() {
		wg.Wait()
		_ = in.Close()
		_ = out.Close()
	}()

	cx := layer4.WrapConnection(in, []byte{}, zap.NewNop())
	go func() {
		wg.Add(1)
		defer func() {
			wg.Done()
			_ = out.Close()
		}()
		_, err := out.Write([]byte("GET /foo/bar?aaa=bbb HTTP/1.1\nHost: localhost:10443\n\n"))
		assertNoError(t, err)
	}()

	// pretend the tls handler was executed before, not an ideal test setup but better then nothing
	cx.SetVar("tls_connection_states", []*tls.ConnectionState{{ServerName: "localhost"}})

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	matcher := MatchHTTP{MatcherSetsRaw: matcherSets}
	err := matcher.Provision(ctx)
	assertNoError(t, err)

	mset := layer4.MatcherSet{matcher} // use MatcherSet to correctly call freeze() before matching
	matched, err := mset.Match(cx)
	assertNoError(t, err)
	if !matched {
		t.Fatalf("matcher did not match")
	}

	_, _ = io.Copy(io.Discard, in)
}

func TestHttpMatchingGarbage(t *testing.T) {
	matcherSets := caddyhttp.RawMatcherSets{caddy.ModuleMap{"host": json.RawMessage("[\"localhost\"]")}}

	matched, err := httpMatchTester(t, matcherSets, []byte("not a valid http request"))
	assertNoError(t, err)
	if matched {
		t.Fatalf("matcher did match")
	}

	validHttp2MagicWithoutHeadersFrame, err := base64.StdEncoding.DecodeString("UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAASBAAAAAAAAAMAAABkAAQCAAAAAAIAAAAATm8gbG9uZ2VyIHZhbGlkIGh0dHAyIHJlcXVlc3QgZnJhbWVz")
	assertNoError(t, err)
	matched, err = httpMatchTester(t, matcherSets, validHttp2MagicWithoutHeadersFrame)
	if matched {
		t.Fatalf("matcher did match")
	}
	if !errors.Is(err, layer4.ErrConsumedAllPrefetchedBytes) {
		t.Fatalf("handler did not return an error or the wrong error -> %v", err)
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
