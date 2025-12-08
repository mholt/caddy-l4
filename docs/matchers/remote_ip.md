---
title: Remote IP Matcher
---

# Remote IP Matcher

## Summary

The Remote IP matcher allows to match connections based on *remote* IP (or CIDR range).

## Syntax

The matcher has `ranges` field that contains one or many IP or CIDR expressions and
supports [placeholders](https://caddyserver.com/docs/conventions#placeholders) which are resolved at provision.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
remote_ip <ranges...>
```

An example config of the Layer 4 app that proxies non-loopback connections on TCP port 8080 to another machine:
```caddyfile
{
    layer4 {
        :8080 {
            @allowed not remote_ip 127.0.0.0/8 ::1
            route @allowed {
                proxy another.machine.local:80
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
                      ":8080"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "not": [
                                        {
                                            "remote_ip": {
                                                "ranges": [
                                                    "127.0.0.0/8",
                                                    "::1"
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
                                                "another.machine.local:80"
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
