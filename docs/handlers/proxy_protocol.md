---
title: Proxy Protocol Handler
---

# Proxy Protocol Handler

## Summary

The Proxy Protocol handler enables Caddy
to receive [HAProxy Proxy Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt).
It uses [mastercactapus/proxyprotocol](github.com/mastercactapus/proxyprotocol) under the hood.

## Syntax

The handler has the following optional fields:
- `allow` may contain one or many CIDR expressions to allow/require PROXY headers from. E.g. `192.168.1.0/24`.
- `timeout` may contain a duration value to indicate how much time to wait for PROXY headers. By default, it is zero.

Only `allow` field supports [placeholders](https://caddyserver.com/docs/conventions#placeholders) which are resolved at provision.

### Caddyfile

The handler supports the following syntax:
```caddyfile
# bare `proxy_protocol` allows any remote IPs and
# waits no time for PROXY header to be received
proxy_protocol

# otherwise specify handler options
proxy_protocol {
    allow <ranges...>
    timeout <duration>
}
```

An example config of the Layer 4 app that proxies connections on TCP4 ports 8080 and 8081 with specific PROXY headers:
```caddyfile
{
    layer4 {
        0.0.0.0:8080 {
            route {
                proxy_protocol {
                    allow 10.0.0.0/8
                    timeout 5s
                }
                proxy 10.0.0.1:8080
            }
        }
        0.0.0.0:8081 {
            route {
                proxy_protocol {
                    allow 10.0.0.0/8 192.168.0.0/16
                    timeout 3s
                }
                proxy 192.168.0.1:8080
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
                        "0.0.0.0:8080"
                    ],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "allow": [
                                        "10.0.0.0/8"
                                    ],
                                    "handler": "proxy_protocol",
                                    "timeout": 5000000000
                                },
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "10.0.0.1:8080"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                },
                "srv1": {
                    "listen": [
                        "0.0.0.0:8081"
                    ],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "allow": [
                                        "10.0.0.0/8",
                                        "192.168.0.0/16"
                                    ],
                                    "handler": "proxy_protocol",
                                    "timeout": 3000000000
                                },
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "192.168.0.1:8080"
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
