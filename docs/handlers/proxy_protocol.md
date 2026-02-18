---
title: Proxy Protocol Handler
---

# Proxy Protocol Handler

## Summary

The Proxy Protocol handler enables Caddy
to receive [HAProxy Proxy Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt).
It uses [pires/go-proxyproto](https://github.com/pires/go-proxyproto) under the hood.

## Syntax

The handler has the following optional fields:
- `allow` may contain one or many CIDR expressions to allow/require PROXY headers from, e.g. `192.168.1.0/24`. The special value `private_ranges` can be used to allow all private IP ranges.
- `deny` may contain one or many CIDR expressions to deny PROXY headers from, e.g. `10.0.0.0/8`. The special value `private_ranges` can be used to deny all private IP ranges.
- `fallback_policy` specifies the policy to use when the downstream IP address is not in the Allow list nor in the Deny list. Accepted values are: `IGNORE` (default), `USE`, `REJECT`, `REQUIRE`, `SKIP`.
- `timeout` may contain a duration value to indicate how much time to wait for PROXY headers. By default, it is zero.

The `allow` and `deny` fields support [placeholders](https://caddyserver.com/docs/conventions#placeholders) which are resolved at provision.

### Policy Values

- `IGNORE`: Ignore address from PROXY header, but accept connection
- `USE`: Use address from PROXY header
- `REJECT`: Reject connection when PROXY header is sent
- `REQUIRE`: Require connection to send PROXY header, reject if not present
- `SKIP`: Accept connection without requiring the PROXY header

### Caddyfile

The handler supports the following syntax:
```caddyfile
# bare `proxy_protocol` allows any remote IPs and
# waits no time for PROXY header to be received
proxy_protocol

# otherwise specify handler options
proxy_protocol {
    allow <ranges...>
    deny <ranges...>
    fallback_policy <policy>
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
                    deny 10.0.1.0/24
                    fallback_policy REJECT
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
                                    "deny": [
                                        "10.0.1.0/24"
                                    ],
                                    "fallback_policy": "REJECT",
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
