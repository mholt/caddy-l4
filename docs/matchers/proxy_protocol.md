---
title: Proxy Protocol Matcher
---

# Proxy Protocol Matcher

## Summary

The Proxy Protocol matcher allows to match connections that start
with [HAProxy Proxy Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt).
It does independent raw packet parsing under the hood.

## Syntax

The matcher provides no configurable fields.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `proxy_protocol` matches any traffic
# of Proxy Protocol Versions 1 & 2 
proxy_protocol
```

An example config of the Layer 4 app that ...:
```caddyfile
{
    layer4 {
        :443 {
            # proxy to haproxy.machine.local:443
            # any Proxy Protocol traffic on TCP port 443
            @a proxy_protocol
            route @a {
                proxy haproxy.machine.local:443
            }
            
            # otherwise proxy to fallback.machine.local:443
            route {
                proxy fallback.machine.local:443
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
                                    "proxy_protocol": {}
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "haproxy.machine.local:443"
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
                                                "fallback.machine.local:443"
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
