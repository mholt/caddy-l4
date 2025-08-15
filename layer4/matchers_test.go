package layer4

import (
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

var (
	_ net.Conn = &dummyConn{}
	_ net.Addr = dummyAddr{}
)

type dummyAddr struct {
	ip      string
	network string
}

// Network implements net.Addr.
func (da dummyAddr) Network() string {
	return da.network
}

// String implements net.Addr.
func (da dummyAddr) String() string {
	return da.ip
}

type dummyConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

// LocalAddr implements net.Conn.
func (dc *dummyConn) LocalAddr() net.Addr {
	return dc.localAddr
}

// RemoteAddr implements net.Conn.
func (dc *dummyConn) RemoteAddr() net.Addr {
	return dc.remoteAddr
}

type provisionableMatcher interface {
	caddy.Provisioner
	ConnMatcher
}

func provision(in provisionableMatcher) ConnMatcher {
	_ = in.Provision(caddy.Context{})
	return in
}

func TestNotMatcher(t *testing.T) {
	for i, tc := range []struct {
		cx        *Connection
		matcher   MatchNot
		match     bool
		expectErr bool
	}{
		{
			matcher:   MatchNot{},
			match:     true,
			expectErr: false,
		},
		{
			cx: &Connection{
				Conn: &dummyConn{
					localAddr:  dummyAddr{ip: "127.0.0.1", network: "tcp"},
					remoteAddr: dummyAddr{ip: "127.0.0.1", network: "tcp"},
				},
				Logger: zap.NewNop(),
			},
			matcher: MatchNot{
				MatcherSets: []MatcherSet{
					{
						provision(&MatchRemoteIP{Ranges: []string{"127.0.0.1"}}),
					},
				},
			},
			match:     false,
			expectErr: false,
		},
		{
			cx: &Connection{
				Conn: &dummyConn{
					localAddr:  dummyAddr{ip: "127.0.0.1", network: "tcp"},
					remoteAddr: dummyAddr{ip: "192.168.0.1", network: "tcp"},
				},
				Logger: zap.NewNop(),
			},
			matcher: MatchNot{
				MatcherSets: []MatcherSet{
					{
						provision(&MatchRemoteIP{Ranges: []string{"127.0.0.1"}}),
					},
				},
			},
			match:     true,
			expectErr: false,
		},
		{
			cx: &Connection{
				Conn: &dummyConn{
					localAddr:  dummyAddr{ip: "127.0.0.1", network: "tcp"},
					remoteAddr: dummyAddr{ip: "192.168.0.1", network: "tcp"},
				},
				Logger: zap.NewNop(),
			},
			matcher: MatchNot{
				MatcherSets: []MatcherSet{
					{
						provision(&MatchRemoteIP{Ranges: []string{"172.16.0.1"}}),
					},
					{
						provision(&MatchLocalIP{Ranges: []string{"127.0.0.1"}}),
					},
				},
			},
			match:     false,
			expectErr: false,
		},
		{
			cx: &Connection{
				Conn: &dummyConn{
					localAddr:  dummyAddr{ip: "127.0.0.1", network: "tcp"},
					remoteAddr: dummyAddr{ip: "172.16.0.1", network: "tcp"},
				},
				Logger: zap.NewNop(),
			},
			matcher: MatchNot{
				MatcherSets: []MatcherSet{
					{
						provision(&MatchRemoteIP{Ranges: []string{"172.16.0.1"}}),
					},
					{
						provision(&MatchLocalIP{Ranges: []string{"127.0.0.1"}}),
					},
				},
			},
			match:     false,
			expectErr: false,
		},
		{
			cx: &Connection{
				Conn: &dummyConn{
					localAddr:  dummyAddr{ip: "192.168.0.1", network: "tcp"},
					remoteAddr: dummyAddr{ip: "192.168.0.1", network: "tcp"},
				},
				Logger: zap.NewNop(),
			},
			matcher: MatchNot{
				MatcherSets: []MatcherSet{
					{
						provision(&MatchRemoteIP{Ranges: []string{"172.16.0.1"}}),
					},
					{
						provision(&MatchLocalIP{Ranges: []string{"127.0.0.1"}}),
					},
				},
			},
			match:     true,
			expectErr: false,
		},
		{
			cx: &Connection{
				Conn: &dummyConn{
					localAddr:  dummyAddr{ip: "127.0.0.1", network: "tcp"},
					remoteAddr: dummyAddr{ip: "172.16.0.1", network: "tcp"},
				},
				Logger: zap.NewNop(),
			},
			matcher: MatchNot{
				MatcherSets: []MatcherSet{
					{
						provision(&MatchRemoteIP{Ranges: []string{"172.16.0.1"}}),
						provision(&MatchLocalIP{Ranges: []string{"127.0.0.1"}}),
					},
				},
			},
			match:     false,
			expectErr: false,
		},
		{
			cx: &Connection{
				Conn: &dummyConn{
					localAddr:  dummyAddr{ip: "127.0.0.1", network: "tcp"},
					remoteAddr: dummyAddr{ip: "192.168.0.1", network: "tcp"},
				},
				Logger: zap.NewNop(),
			},
			matcher: MatchNot{
				MatcherSets: []MatcherSet{
					{
						provision(&MatchRemoteIP{Ranges: []string{"172.16.0.1"}}),
						provision(&MatchLocalIP{Ranges: []string{"127.0.0.1"}}),
					},
				},
			},
			match:     true,
			expectErr: false,
		},
	} {
		actual, err := tc.matcher.Match(tc.cx)
		if err != nil && !tc.expectErr {
			t.Errorf("Test %d %+v: Expected no error, got: %v", i, tc.matcher, err)
			continue
		}
		if actual != tc.match {
			t.Errorf("Test %d %+v: Expected %t, got %t for: Connection=%+v,", i, tc.matcher, tc.match, actual, tc.cx)
			continue
		}
	}
}
