---
title: SOCKS4 Matcher
---

# SOCKS4 Matcher

## Summary

The SOCKS4 matcher allows to match connections that look like [SOCKSv4](https://www.openssh.com/txt/socks4.protocol).
It does independent raw packet parsing under the hood.

Since the SOCKSv4 header is very short, it could produce a lot of false positives. To improve matching you may use
the supported matcher fields (defined below) to specify which destinations you expect your clients to connect to.

## Syntax

The matcher supports the following optional fields:
- `commands` may contain one or many string values to match SOCKSv4 commands. E.g. `CONNECT`. By default, 
  this list includes `CONNECT` (0x01) and `BIND` (0x02) commands. Note: `commands` are case-insensitive.
- `networks` may contain one or many IP or CIDR expressions to match SOCKSv4 destination IP. E.g. `192.168.0.0/24`.
  Note: IPv6 isn't supported by the protocol.
- `ports` may contain one or many unsigned integers in 0-65535 range to match SOCKSv4 destination port. E.g. `443`.

All the matcher fields except `ports` support [placeholders](https://caddyserver.com/docs/conventions#placeholders)
which are resolved at provision.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `socks4` matches any SOCKSv4 traffic
socks4

# otherwise specify matcher options
socks4 {
    commands <commands...>
    networks <ranges...>
    ports <ports...>
}
```

An example config of the Layer 4 app that multiplexes SOCKSv4 on TCP port 443:
```caddyfile
{
    layer4 {
        :443 {
            # proxy to socks4.machine.local:1080
            # any SOCKSv4 traffic if it has
            # BIND or CONNECT commands,
            # destination IPs in 10.0.0.0/8 and
            # 443 or 1080 as destination ports
            @s4 socks4 {
                commands BIND CONNECT
                networks 10.0.0.0/8
                ports 443 1080
            }
            route @s4 {
                proxy socks4.machine.local:1080
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
                                    "socks4": {
                                        "commands": [
                                            "BIND",
                                            "CONNECT"
                                        ],
                                        "networks": [
                                            "10.0.0.0/8"
                                        ],
                                        "ports": [
                                            443,
                                            1080
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
                                                "socks4.machine.local:1080"
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
