---
title: Routes
---

# Routes

Routes define how incoming network traffic (TCP/UDP) should be processed based on matching conditions
and corresponding actions. 

## Purpose

Routes allow Caddy-L4 to selectively process traffic and apply different behaviors depending on the connection
properties. They form an integral part of [servers](/docs/servers.md), [listener wrappers](/docs/listener_wrappers.md) and [subroutes](/docs/handlers/subroute.md).
A route consists of:
- [**Matchers**](/docs/matchers.md) – Criteria to filter connections (e.g., by IP, TLS SNI).
- [**Handlers**](/docs/handlers.md) – Actions to take on matched traffic (e.g., echo, proxy).

## Syntax

A route technically includes a list of unnamed matcher sets and a list of handlers. If a route has *no* matcher sets,
it handles *all* traffic, and *no* routes following it are taken into account. A route with *no* handlers can't handle
any traffic, and it makes sense only within a listener wrapper block to pass traffic handling back to the next listener
wrapper (outside Caddy-L4), though it works the same way even without an empty route.

**AND vs. OR logic for traffic matching.** A matcher set may include no, one or several matchers.
It accepts connections if ALL its matchers return true, i.e. AND logic applies. If a route contains
more than one matcher set, a connection is accepted if ANY matcher set returns true, i.e. OR logic applies.
All matchers within one matcher set must be *unique*.

**Matchers, matcher sets and handlers ordering.** The order is irrelevant for both matchers within a matcher set
and for matcher sets within a route. However, the sequence is important for the list of handlers, as they execute
sequentially in a chain.

### Caddyfile

A route block is introduced with `route` directive. No, one or several named matcher sets may follow this directive
before curly braces, but they *must be defined above* the route block. Handlers are placed inside curly braces:
```caddyfile
# put matcher sets here
route [@named_mset [...]] {
    # put handlers here
}
```

A named matcher set is introduced with `@<name>` directive (a matcher set name with no spaces prepended with
the at symbol). A matcher set name must be unique within a server block, a listener wrapper block or a subroute block,
and no matcher set cross-reference among servers, listener wrappers and/or subroutes is allowed. Matcher set naming is
only supported in a caddyfile and contributes to config legibility, but makes no impact on traffic routing. 

A named matcher set with *no* matchers is invalid in a caddyfile. If only one matcher is required,
a matcher directive can be placed in the same line. Otherwise, matchers are placed inside curly braces:
```caddyfile
@single_matcher_mset_1 <matcher> [<option> [...]]

@single_matcher_mset_2 <matcher> {
    # put options here
}

@single_matcher_mset_3 {
    <matcher> [<option> [...]]
}

@multi_matcher_mset {
    <matcher_1> [<option> [...]]
    <matcher_2> {
        # put options here
    }
    # put more matchers here
}
```

An example config combining `route` directives and named matcher sets:
```caddyfile
# `@tls` matches any connections starting with TLS handshakes.
@tls tls

# `@gd` matches any connections starting with TLS handshakes
# with SNI equal to gamma.example.com or delta.example.com
# from any IP within 192.168.1.0/24 and 172.28.0.0/16 ranges.
@gd {
    remote_ip 192.168.1.0/24 172.28.0.0/16
    tls sni gamma.example.com delta.example.com
}

# Any traffic matched with `@gd` is processed here.
# Note that `@gd` route is placed above `@tls` route,
# otherwise this route would be completely ignored.
route @gd {
    # Everything is proxied to three.machine.local:443.
    proxy three.machine.local:443
}

# Any traffic matched with `@tls` is processed here.
route @tls {
    # `tls` handler terminates TLS (encrypts/decrypts inner traffic).
    tls
    # `subroute` handler routes traffic with another set of routes (recursion).
    subroute {
        # `@alpha` and `@beta` match HTTP traffic
        # to alpha.example.com or beta.example.com.
        @alpha http host alpha.example.com
        @beta http host beta.example.com

        # Any traffic matched with `@alpha` or `@beta`
        # is proxied to one.machine.local:80.
        route @alpha @beta {
            proxy one.machine.local:80
        }

        # Other traffic including non-HTTP is proxied to two.machine.local:80.
        # Note that `@alpha` and `@beta` traffic is routed above,
        # othwerwise it would be proxied here as well.
        route {
            proxy two.machine.local:80
        }
    }
}
```

### JSON

A JSON equivalent to the caddyfile config explained above:
```json
{
  "routes": [
    {
      "handle": [
        {
          "handler": "proxy",
          "upstreams": [
            {
              "dial": [
                "three.machine.local:443"
              ]
            }
          ]
        }
      ],
      "match": [
        {
          "remote_ip": {
            "ranges": [
              "192.168.1.0/24",
              "172.28.0.0/16"
            ]
          },
          "tls": {
            "sni": [
              "gamma.example.com",
              "delta.example.com"
            ]
          }
        }
      ]
    },
    {
      "handle": [
        {
          "handler": "tls"
        },
        {
          "handler": "subroute",
          "routes": [
            {
              "handle": [
                {
                  "handler": "proxy",
                  "upstreams": [
                    {
                      "dial": [
                        "one.machine.local:80"
                      ]
                    }
                  ]
                }
              ],
              "match": [
                {
                  "http": [
                    {
                      "host": [
                        "alpha.example.com"
                      ]
                    }
                  ]
                },
                {
                  "http": [
                    {
                      "host": [
                        "beta.example.com"
                      ]
                    }
                  ]
                }
              ]
            },
            {
              "handle": [
                {
                  "handler": "proxy",
                  "upstreams": [
                    {
                      "dial": [
                        "two.machine.local:80"
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
      ],
      "match": [
        {
          "tls": {}
        }
      ]
    }
  ]
}
```