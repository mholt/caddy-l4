---
title: QUIC Matcher
---

# QUIC Matcher

## Summary

The QUIC matcher allows to match connections that look like [QUIC](https://quic.xargs.org/).
The matcher uses [quic-go](https://github.com/quic-go/quic-go) package to parse QUIC traffic under the hood.

## Syntax

The matcher may contain one or many [inner modules](https://caddyserver.com/docs/modules/)
in the `tls.handshake_match` namespace which jointly constitute a matcher set.
Matchers within a matcher set are AND'ed together.

[Placeholder](https://caddyserver.com/docs/conventions#placeholders) support of the matcher's inner modules
in the `tls.handshake_match` namespace generally depends on their implementations:
- some modules resolve placeholders at match, e.g. `alpn`, `sni`;
- some modules resolve placeholders at provision, e.g. `local_ip`, `remote_ip`, `sni_regexp`;
- other modules may not resolve placeholders at all.

When QUIC traffic is detected, the matcher registers the following placeholders:
- `l4.quic.tls.server_name` with the relevant TLS server name, e.g. `example.com`;
- `l4.quic.tls.version` with the relevant TLS version, e.g. `772` for TLS 1.3;
- `l4.quic.version` with the relevant QUIC version, e.g. `draft-29`, `v1`, `v2`. 

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `quic` matches any QUIC traffic
quic

# match QUIC traffic if the given QUIC matcher module,
# i.e. a module in the tls.handshake_match namespace, returns true
quic <matcher> [<args...>]

# otherwise specify multiple conditions to match QUIC traffic
quic {
    <matcher> [<args...>]
    <matcher> [<args...>]
}
```

An example config of the Layer 4 app that uses `l4.quic.tls.server_name` placeholder in combination with `sni` matcher
and `alpn` matcher to proxy QUIC traffic:
```caddyfile
{
    layer4 {
        udp/:8843 {
            # proxy QUIC requests on UDP port 8843
            # for `one.com` and `two.com`
            # to udp/one.com:443 and udp/two.com:443 respectively
            @q1 quic sni one.com two.com
            route @q1 {
                proxy udp/{l4.quic.tls.server_name}:443
            }
            
            # proxy QUIC requests on UDP port 8843 for `example.com`
            # with `custom` ALPN to udp/localhost:6543
            @q2 quic {
                alpn custom
                sni example.com
            }
            route @q2 {
                proxy udp/localhost:6543
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
                        "udp/:8843"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "quic": {
                                        "sni": [
                                            "one.com",
                                            "two.com"
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
                                                "udp/{l4.quic.tls.server_name}:443"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "quic": {
                                        "alpn": [
                                            "custom"
                                        ],
                                        "sni": [
                                            "example.com"
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
                                                "udp/localhost:6543"
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

## Contributing

See the contributing section for [`tls` matcher](/docs/matchers/tls.md).
