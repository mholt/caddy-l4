---
title: WireGuard Matcher
---

# WireGuard Matcher

## Summary

The WireGuard matcher allows to match connections that like [WireGuard](https://www.wireguard.com/protocol/).
It does independent raw packet parsing under the hood.

## Syntax

The only field this matcher has is `zero` which may be used to match reserved zero bytes of the message type field
when they have non-zero values (e.g. for obfuscation purposes). E.g. it may be set to `4,285,988,864` (0xFF770000)
in order to match custom handshake initiation messages starting with 0x010077FF byte sequence. Note: any non-zero
value is a violation of the WireGuard protocol.

The matcher supports no [placeholders](https://caddyserver.com/docs/conventions#placeholders).

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `wireguard` matches any WireGuard traffic
# while a custom zero value allows to match non-standard messages
wireguard [<zero>]
```

An example config of the Layer 4 app that multiplexes WireGuard connections on UDP port 51820:
```caddyfile
{
    layer4 {
        udp/:51820 {
            # proxy to udp/wg.machine.local:51820
            # any WireGuard traffic received on UDP port 51820
            # with zeroes in the message type reserved bytes
            @wg0 wireguard
            route @wg0 {
                proxy udp/wg.machine.local:51820
            }
            
            # proxy to udp/wg.machine.local:51821
            # any WireGuard traffic received on UDP port 51820
            # with 0xFF 0x77 0x00 in the message type reserved bytes
            @wgX wireguard 4285988864
            route @wgX {
                proxy udp/wg.machine.local:51821
            }
            
            # otherwise echo
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
                        "udp/:51820"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "wireguard": {}
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "udp/wg.machine.local:51820"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "wireguard": {
                                        "zero": 4285988864
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "udp/wg.machine.local:51821"
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
