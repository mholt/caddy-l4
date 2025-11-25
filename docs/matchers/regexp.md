---
title: Regexp Matcher
---

# Regexp Matcher

## Summary

The Regexp matcher allows to match connections when the first packet received by Caddy satisfies a regular expression.

## Syntax

The matcher provides `pattern` field that contains a regular expression to match bytes against and
supports [placeholders](https://caddyserver.com/docs/conventions#placeholders) which are resolved at provision.

The matcher also has `count` field that sets the number of bytes read from the beginning of the first packet
to match against. By default, it equals `4`. It shouldn't exceed `16 KiB` (`MaxMatchingBytes` constant value) which is
the amount of bytes that are at most prefetched during matching.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
regexp <pattern> [<count>]
```

An example config of the Layer 4 app that proxies connections based on regular expressions applied
to their first packets:
```caddyfile
{
    layer4 {
        :12345 {
            # proxy to r1.machine.local:10001
            # any traffic on TCP port 12345
            # if the first packet Caddy receives
            # has at least one digit in its first 4 bytes
            @r1 regexp \d+
            route @r1 {
                proxy r1.machine.local:10001
            }
            
            # proxy to r2.machine.local:10001
            # any traffic on TCP port 12345
            # if the first packet Caddy receives
            # has `FF EE DD CC BB AA` as its first 6 bytes
            @r2 regexp \xFF\xEE\xDD\xCC\xBB\xAA 6
            route @r2 {
                proxy r2.machine.local:10001
            }
            
            # proxy to r3.machine.local:10001
            # any traffic on TCP port 12345
            # if the first packet Caddy receives
            # has its first 10 bytes beginning with `bat`, `cat` or `rat`,
            # ending with 2 zero bytes and containing
            # any character except line terminators in the middle
            @r3 regexp ^(b|c|r)at(.*)\x00\x00$ 10
            route @r3 {
                proxy r3.machine.local:10001
            }
            
            # otherwise echo anything received on TCP port 12345
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
                        ":12345"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "regexp": {
                                        "pattern": "\\d+"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "r1.machine.local:10001"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "regexp": {
                                        "count": 6,
                                        "pattern": "\\xFF\\xEE\\xDD\\xCC\\xBB\\xAA"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "r2.machine.local:10001"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "regexp": {
                                        "count": 10,
                                        "pattern": "^(b|c|r)at(.*)\\x00\\x00$"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "r3.machine.local:10001"
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
