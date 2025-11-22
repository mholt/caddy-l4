---
title: WinBox Matcher
---

# WinBox Matcher

## Summary

The WinBox matcher allows to match connections initiated
by [MikroTik WinBox](https://help.mikrotik.com/docs/display/ROS/WinBox) which is a graphical tool for MikroTik
hardware and software routers management. As of v3.41 and v4.0 the tool used an undocumented proprietary protocol.
This matcher does independent raw packet parsing under the hood and is based on a number of recent studies describing
RouterOS architecture and vulnerabilities, especially the ones published
by [Margin Research](https://github.com/MarginResearch).

## Syntax

The matcher has the following optional fields:
- `modes` may contain a list of supported WinBox modes to match against incoming auth messages.
  The field is case-insensitive. Each of the following values shall only be present once in the list:
  - `standard` mode is a default one (it used to be called `secure` mode in previous versions of WinBox);
  - `romon` mode makes the destination router act as an agent so that its neighbour routers in isolated L2 segments
    could be reachable by the clients behind the agent.


- `username` may contain a plaintext username value to search for in the incoming connections. In WinBox it is
  what the user types into the login field. According to the docs, it must start and end with an alphanumeric
  character, but it can also include `_`, `.`, `#`, `-`, and `@` symbols. No maximum username length is
  specified in the docs, so this matcher applies a reasonable limit of no more than 255 characters.
- `username_regexp` may contain a username pattern to match the incoming connections against. This matcher verifies
  that any username matches `^[0-9A-Za-z](?:[-#.0-9@A-Z_a-z]+[0-9A-Za-z])?$`, so `username_regexp` must not provide
  a wider pattern. Note: it's only tested when `username` is unset or empty, so that full match takes precedence over
  regular expressions.

All the matcher fields except `modes` support [placeholders](https://caddyserver.com/docs/conventions#placeholders)
which are resolved at provision for `username_regexp` and at match for `username`.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `winbox` matches any WinBox traffic
winbox

# otherwise specify matcher options
winbox {
    modes <standard|romon> [<...>]
    
    username <value>
    # or
    username_regexp <pattern>
}
```

An example config of the Layer 4 app that multiplexes WinBox on TCP port 443:
```caddyfile
{
    layer4 {
        :443 {
            # proxy to 192.168.0.1:8291
            # any WinBox traffic if it has
            # `standard` or `romon` mode
            # and `toms` username
            @w1 winbox {
                modes standard romon
                username toms
            }
            route @w1 {
                proxy 192.168.0.1:8291
            }
            
            # proxy to 192.168.0.2:8291
            # any WinBox traffic if it has
            # `standard` mode and
            # `andris`, `edgars` or `juris` username
            @w2 winbox {
                modes standard
                username_regexp ^andris|edgars|juris$
            }
            route @w2 {
                proxy 192.168.0.2:8291
            }
            
            # otherwise proxy to 192.168.0.3:443
            route {
                proxy 192.168.0.3:443
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
                                    "winbox": {
                                        "modes": [
                                            "standard",
                                            "romon"
                                        ],
                                        "username": "toms"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "192.168.0.1:8291"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "winbox": {
                                        "modes": [
                                            "standard"
                                        ],
                                        "username_regexp": "^andris|edgars|juris$"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "192.168.0.2:8291"
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
                                                "192.168.0.3:443"
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
