---
title: RDP Matcher
---

# RDP Matcher

## Summary

The RDP matcher allows to match connections that look
like [RDP](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-RDPBCGR/%5BMS-RDPBCGR%5D.pdf).
It does independent raw packet parsing under the hood.

## Syntax

The matcher has the following optional fields:
- `cookie_hash` may contain a string value to match the cookie hash (`mstshash`). E.g. `user`, `domain\us`. Note:
  for any domain and username value, `domain\username` expression is truncated to 9 characters with domain value
  being optional and backslash (`\`) used as a separator.
- `cookie_hash_regexp` may contain a regular expression to match the cookie hash. E.g. `^user[1-9]$`. Note:
  it's only tested when `cookie_hash` is unset or empty, so that full match takes precedence over regular expressions.


- `cookie_ip` may contain one or many IP or CIDR expressions to match the cookie IP (`msts`). E.g. `192.168.0.0/24`.
  Note: if no `cookie_port` is provided in addition to `cookie_ip`, the cookie IP is matched with any port value.
- `cookie_port` may contain one or many unsigned integers in 0-65535 range to match the cookie port (`msts`). E.g. `89`.
  Note: if no `cookie_ip` is provided in addition to `cookie_port`, the cookie port is matched with any IP value.


- `custom_info` may contain a string value to match the custom info (used primarily for load balancing purposes).
  E.g. `arbitrary_text`. Note: it corresponds to `load balance info/cookie` field in Apache Guacamole.
- `custom_info_regexp` may contain a regular expression to match the custom info. E.g. `^[A-Za-z0-9]$`. Note:
  it's only tested when `custom_info` is unset or empty, so that full match takes precedence over regular expressions.

Regular expression fields including `cookie_hash_regexp` and `custom_info_regexp`, as well as `cookie_ip`, support
[placeholders](https://caddyserver.com/docs/conventions#placeholders) which are resolved at provision.
Other fields including `cookie_hash` and `custom_info` support placeholders which are resolved at match.

When RDP traffic is detected, the matcher registers the following placeholders:
- `l4.rdp.cookie_hash` with the relevant RDP cookie hash, e.g. `domain\us`, if `mstshash` cookie is included;
- `l4.rdp.cookie_ip` with the relevant RDP cookie IP, e.g. `192.168.0.1`, if `msts` cookie is included;
- `l4.rdp.cookie_port` with the relevant RDP cookie port, e.g. `89`, if `msts` cookie is included;
- `l4.rdp.custom_info` with the relevant RDP custom info, e.g. `arbitrary_text`, if an RDP connection request packet
  includes anything else *instead of* `mstshash` and `msts` cookies.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `rdp` matches any RDP traffic
rdp

# match RDP connections having
# the given cookie hash value
rdp {
    cookie_hash <value>
    # or
    cookie_hash_regexp <pattern>
}

# match RDP connections having
# the given cookie IP and port
rdp {
    cookie_ip <ranges...>
    cookie_port <ports...>
}

# match RDP connections having
# the given custom info value
rdp {
    custom_info <value>
    # or
    custom_info_regexp <pattern>
}
```

An example config of the Layer 4 app that multiplexes RDP connections on TCP port 443:
```caddyfile
{
    layer4 {
        :443 {
            # proxy to jacob.machine.local:3389
            # any RDP traffic received on TCP port 443
            # if it has `jacob` as the username (cookie hash)
            # of anything ending with `jacob` as the custom info
            @ch_jacob rdp {
                cookie_hash jacob
            }
            @ci_jacob rdp {
                custom_info_regexp ^(.*)jacob$
            }
            route @ch_jacob @ci_jacob {
                proxy jacob.machine.local:3389
            }

            # proxy to sarah.machine.local:3389
            # any RDP traffic received on TCP port 443
            # if it has `sarah` as the username (cookie hash)
            # of anything ending with `sarah` as the custom info
            @ch_sarah rdp {
                cookie_hash sarah
            }
            @ci_sarah rdp {
                custom_info_regexp ^(.*)sarah$
            }
            route @ch_sarah @ci_sarah {
                proxy sarah.machine.local:3389
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
                                    "rdp": {
                                        "cookie_hash": "jacob"
                                    }
                                },
                                {
                                    "rdp": {
                                        "custom_info_regexp": "^(.*)jacob$"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "jacob.machine.local:3389"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "rdp": {
                                        "cookie_hash": "sarah"
                                    }
                                },
                                {
                                    "rdp": {
                                        "custom_info_regexp": "^(.*)sarah$"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "sarah.machine.local:3389"
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

## Caveats

According to the protocol documentation, RDP cookies are *optional*, i.e. it depends on the RDP client whether
they are included in the first packet (RDP connection request) or not. No connections could be matched by the matcher
unless RDP connection request packets include the cookies this matcher tests.

No valid RDP connection request packet must contain `mstshash` and `msts` at the same time, i.e. the matcher will
never match connections if both `cookie_hash` and any of `cookie_ip` and `cookie_port` are set simultaneously.

There are some RDP clients (e.g. Apache Guacamole) that support any text to be included into an RDP connection request
packet *instead of* `mstshash` and `msts` cookies for load balancing and/or routing purposes, parsed as `custom_info`.
If `custom_info` is combined with `cookie_hash`, `cookie_ip` or `cookie_port`, no connections could be matched.

### Client Notes

- **Microsoft Remote Desktop Client for Windows** (`mstsc.exe`) and `cookie_hash`.
  This client seems to have a bug related to `mstshash` cookie update. When you open it, only fill the computer field
  (in host:port format) and leave username and password empty, it sends an RDP connection request without any cookie -
  it's correct. Next, if you fill both the computer field and username fields, it takes the first 9 characters of the
  username you provided as `mstshash` cookie value to include into an RDP connection request - it's correct again.
  However, if you cancel connection and change the username, it won't update `mstshash` cookie value, i.e. an RDP 
  connection request will include 9 characters of the username you provided before the change - that's where the bug
  occurs which leads to *Caddy misrouting RDP connections*. Reopening the client resolves the problem.


- **Microsoft Remote Desktop Clients for macOS and iOS** and `cookie_hash`.
  These clients don't send cookie hashes at all, so no RDP connection matching based on `cookie_hash` is possible.


- **Apache Guacamole** and `cookie_hash`.
  This client ignores any domain name, so it's only username value that's included into an RDP connection request
  packet as `mstshash`. What's great about this client is that it has a custom load balance info/cookie field, which
  takes precedence over the standard cookie payload. Thus, you can effectively use `custom_info` or `custom_info_regexp`
  for RDP connections routing.


- **Other RDP clients**.
  It's unclear why some clients include usernames as cookie hashes while others don't. It seems this part of RDP is not
  fully standardised, so each group of developers decide what to do. If this matcher doesn't work for you as expected,
  the best way to debug is to capture the first packet with Wireshark.
