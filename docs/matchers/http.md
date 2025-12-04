---
title: HTTP Matcher
---

# HTTP Matcher

## Summary

The HTTP matcher allows to match connections that starting with HTTP requests.
It does independent raw packet parsing under the hood.

## Syntax

The matcher has optional `matchers` field which contains one or many matcher sets, where a matcher set is a set of
[inner modules](https://caddyserver.com/docs/json/apps/http/servers/routes/match/) in the `http.matchers` namespace.
Matchers within a matcher set are AND'ed together, while multiple matcher sets are ORed.

Note: Caddyfile syntax provides for a single matcher set only, i.e. no OR logic is supported in terms of
the matcher's inner modules. However, you may use multiple `http` matchers instead. JSON syntax supports
multiple matcher sets, i.e. OR logic may be realised with either many `http` matchers, or many matcher sets
inside a single `http` matcher.

[Placeholder](https://caddyserver.com/docs/conventions#placeholders) support of the matcher's inner modules
in the `http.matchers` namespace generally depends on their implementations:
- some modules resolve placeholders at match,
  e.g. `header`, `header_regexp`, `host`, `path`, `path_regexp`, `query`, `vars`, `vars_regexp`;
- some modules resolve placeholders at provision,
  e.g. `client_ip`, `remote_ip`;
- other modules don't resolve placeholders at all,
  e.g. `method`, `protocol`.

When HTTP traffic is detected, the matcher registers `l4.http.host` placeholder with the relevant HTTP host value.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `http` matches any HTTP traffic
http

# match HTTP traffic if the given HTTP matcher module,
# i.e. a module in the http.matchers namespace, returns true
http <matcher> [<args...>]

# match HTTP traffic if the given HTTP matcher module,
# i.e. a module in the http.matchers namespace, returns false
http not <matcher> [<args...>]

# otherwise specify multiple conditions to match HTTP traffic
http {
    <matcher> [<args...>]
    not <matcher> [<args...>]
    not {
        <matcher> [<args...>]
    }
}
```

An example config of the Layer 4 app that proxies HTTP traffic to several upstreams
depending on HTTP host, path and remote IP criteria:
```caddyfile
{
    layer4 {
        :80 {
            # proxy HTTP traffic on TCP port 80 to localhost:8081
            # if HTTP host equals `localhost`
            @a http host localhost
            route @a {
                proxy localhost:8081
            }
            
            # proxy HTTP traffic on TCP port 80 to localhost:8082
            # if HTTP host equals `example.com`
            # and remote IP belongs to 192.168.0.0/16 range
            @b http {
                host example.com
                remote_ip 192.168.0.0/16
            }
            route @b {
                proxy localhost:8082
            }
            
            # proxy HTTP traffic on TCP port 80 to localhost:8083
            # if HTTP path doesn't equal `/index.html`
            @c http not path /index.html
            route @c {
                proxy localhost:8083
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
                        ":80"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "http": [
                                        {
                                            "not": [
                                                {
                                                    "path": [
                                                        "/index.html"
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "localhost:8083"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "http": [
                                        {
                                            "host": [
                                                "localhost"
                                            ]
                                        }
                                    ]
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "localhost:8081"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "http": [
                                        {
                                            "host": [
                                                "example.com"
                                            ],
                                            "remote_ip": {
                                                "ranges": [
                                                    "192.168.0.0/16"
                                                ]
                                            }
                                        }
                                    ]
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "localhost:8082"
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
    "github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
    caddy.RegisterModule(&MatchDummy{})
}

// MatchDummy is able to match HTTP request.
type MatchDummy struct{
    /*
       put here any relevant options to modify matcher behaviour
    */
}

// CaddyModule returns the Caddy module information.
func (*MatchDummy) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "http.matchers.dummy",
        New: func() caddy.Module { return new(MatchDummy) },
    }
}

// Match returns true if the HTTP request satisfies the applicable criteria.
func (m *MatchDummy) Match(r *http.Request) bool {
    match, _ := m.MatchWithError(r)
    return match
}

// MatchWithError returns true if the HTTP request satisfies the applicable criteria.
func (m *MatchDummy) MatchWithError(r *http.Request) (bool, error) {
    /*
       put here any matching logic
    */

    return true, nil
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
    _ caddyhttp.RequestMatcher          = (*MatchDummy)(nil)
    _ caddyhttp.RequestMatcherWithError = (*MatchDummy)(nil)
    _ caddyfile.Unmarshaler             = (*MatchDummy)(nil)
)
```
