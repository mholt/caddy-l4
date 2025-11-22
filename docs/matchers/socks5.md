---
title: SOCKS5 Matcher
---

# SOCKS5 Matcher

## Summary

The SOCKS5 matcher allows to match connections that look like [SOCKSv5](https://www.rfc-editor.org/rfc/rfc1928).
It does independent raw packet parsing under the hood.

Since the SOCKSv5 header is very short, it could produce a lot of false positives. To improve matching you may use
the supported matcher fields (defined below) to specify which data you expect your clients to send.

## Syntax

The matcher has `auth_methods` field which may contain one or many unsigned integers in 0-255 range to match
the authentication methods. By default, this list includes `NO AUTH` (0x00), `GSSAPI` (0x01) and `Username/Password`
(0x02).

No [placeholders](https://caddyserver.com/docs/conventions#placeholders) are supported by the matcher.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `socks5` matches any SOCKSv5 traffic
socks5

# otherwise specify matcher options
socks5 {
    auth_methods <auth_methods...>
}
```

An example config of the Layer 4 app that multiplexes SOCKSv5 on TCP port 443:
```caddyfile
{
    layer4 {
        :443 {
            # proxy to socks5.machine.local:1080
            # any SOCKSv5 traffic if its auth method is
            # 0x01 (GSSAPI) or 0x02 (Username/Password)
            @s5 socks5 {
                auth_methods 1 2
            }
            route @s5 {
                proxy socks5.machine.local:1080
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
                                    "socks5": {
                                        "auth_methods": [
                                            1,
                                            2
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
                                                "socks5.machine.local:1080"
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
