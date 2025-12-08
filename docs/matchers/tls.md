---
title: TLS Matcher
---

# TLS Matcher

## Summary

The TLS matcher allows to match connections that start with TLS handshakes.
It does independent raw packet parsing under the hood.

## Syntax

The matcher may contain one or many [inner modules](https://caddyserver.com/docs/modules/)
in the `tls.handshake_match` namespace which jointly constitute a matcher set.
Matchers within a matcher set are AND'ed together.

[Placeholder](https://caddyserver.com/docs/conventions#placeholders) support of the matcher's inner modules
in the `tls.handshake_match` namespace generally depends on their implementations:
- some modules resolve placeholders at match, e.g. `alpn`, `sni`;
- some modules resolve placeholders at provision, e.g. `local_ip`, `remote_ip`, `sni_regexp`;
- other modules may not resolve placeholders at all.

When TLS traffic is detected, the matcher registers the following placeholders:
- `l4.tls.server_name` with the relevant TLS server name, e.g. `example.com`;
- `l4.tls.version` with the relevant TLS version, e.g. `772` for TLS 1.3.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `tls` matches any TLS traffic
tls

# match TLS traffic if the given TLS matcher module,
# i.e. a module in the tls.handshake_match namespace, returns true
tls <matcher> [<args...>]

# otherwise specify multiple conditions to match TLS traffic
tls {
    <matcher> [<args...>]
    <matcher> [<args...>]
}
```

An example config of the Layer 4 app that uses `l4.tls.server_name` placeholder in combination with `sni` matcher
and `alpn` matcher to proxy TLS traffic:
```caddyfile
{
    layer4 {
        :8843 {
            # proxy TLS requests on TCP port 8843
            # for `one.com` and `two.com`
            # to tcp/one.com:443 and tcp/two.com:443 respectively
            @q1 tls sni one.com two.com
            route @q1 {
                proxy tcp/{l4.tls.server_name}:443
            }
            
            # proxy TLS requests on TCP port 8843 for `example.com`
            # with `custom` ALPN to tcp/localhost:6543
            @q2 tls {
                alpn custom
                sni example.com
            }
            route @q2 {
                proxy tcp/localhost:6543
            }
        }
    }
}
```

### JSON

JSON equivalent to the caddyfile config provided above:
```json
{
    "apps": {
        "layer4": {
            "servers": {
                "srv0": {
                    "listen": [
                        ":8843"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "tls": {
                                        "sni": [
                                            "one.com",
                                            "two.com"
                                        ]
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "tcp/{l4.tls.server_name}:443"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "tls": {
                                        "alpn": [
                                            "custom"
                                        ],
                                        "sni": [
                                            "example.com"
                                        ]
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "tcp/localhost:6543"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            }
        }
    }
}
```

## Contributing

Any inner module of the matcher should be placed into a separate Go file within a package starting with *l4* and have
at least the following code. The key part of the code is **Match** function. Try to save resources and keep it as tiny
as possible, since Caddy may process thousands of incoming packets per second, and this function is called
every time a new connection is established.

It is generally recommended to include comments that would be reasonably sufficient to understand how to use
the matcher and what is going on under the hood.

```go
package l4dummy

import (
    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
    "github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
    caddy.RegisterModule(&MatchDummy{})
}

// MatchDummy is able to match TLS ClientHelloInfo.
type MatchDummy struct{
    /*
       put here any relevant options to modify matcher behaviour
    */
}

// CaddyModule returns the Caddy module information.
func (*MatchDummy) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "tls.handshake_match.dummy",
        New: func() caddy.Module { return new(MatchDummy) },
    }
}

// Match returns true if the TLS ClientHelloInfo satisfies the applicable criteria.
func (m *MatchDummy) Match(hello *tls.ClientHelloInfo) bool {
    /*
       put here any matching logic
    */

    return true
}

// UnmarshalCaddyfile sets up the MatchDummy from Caddyfile tokens. Syntax:
//
//    dummy
func (m *MatchDummy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
    /*
       put here wrapper name, same-line options and blocks parsing code
    */

    return nil
}

// Interface guards
var (
    _ caddytls.ConnectionMatcher = (*MatchDummy)(nil)
    _ caddyfile.Unmarshaler      = (*MatchDummy)(nil)
)
```
