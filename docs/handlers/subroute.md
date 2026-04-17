---
title: Subroute Handler
---

# Subroute Handler

## Summary

The Subroute handler implements recursion logic, i.e. allows to match and handle already matched connections.

The handler launches another set of traffic matching attempts which may be useful for a batch of routes that
all inherit the same matchers, or for multiple routes that should be treated as a single route.

## Syntax

The handler has the following fields:
- `matching_timeout` is the maximum time connections have to complete the matching phase
  (the first terminal handler is matched). By default, it equals 3s.
- `routes` contains [routes](/docs/routes.md) the same way they are defined in [servers](/docs/servers.md).

No [placeholders](https://caddyserver.com/docs/conventions#placeholders) are supported.

### Caddyfile

The handler supports the following syntax:
```caddyfile
subroute {
    # optionally adjust the matching timeout
    matching_timeout <duration>
    
    # put routes here
}
```

An example config of the Layer 4 app that subroutes TLS traffic matching:
```caddyfile
{
    layer4 {
        :443 {
            @tls tls
            route @tls {
                subroute {
                    @abc tls sni abc.example.com
                    route @abc {
                        proxy abc.machine.local:443
                    }
                    @def tls sni def.example.com
                    @ghi tls sni ghi.example.com
                    route @def @ghi {
                        proxy defghi.machine.local:443
                    }
                }
            }
            route {
                echo
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
                        ":443"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "tls": {}
                                }
                            ],
                            "handle": [
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
                                                                "abc.machine.local:443"
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ],
                                            "match": [
                                                {
                                                    "tls": {
                                                        "sni": [
                                                            "abc.example.com"
                                                        ]
                                                    }
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
                                                                "defghi.machine.local:443"
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ],
                                            "match": [
                                                {
                                                    "tls": {
                                                        "sni": [
                                                            "def.example.com"
                                                        ]
                                                    }
                                                },
                                                {
                                                    "tls": {
                                                        "sni": [
                                                            "ghi.example.com"
                                                        ]
                                                    }
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "handle": [
                                {
                                    "handler": "echo"
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
