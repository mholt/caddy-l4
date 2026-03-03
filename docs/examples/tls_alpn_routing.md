---
title: TLS ALPN Routing Example
---

# TLS ALPN Routing Example

## Summary

This example shows how to route TLS traffic based on the application-layer protocols (ALPN) provided
by the client in its ClientHello message.

As per [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1), the ALPN value may include
any non-empty byte string. Certain ALPN values are standardized and listed on the [IANA assignments page](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids),
including `http/1.1`, `h2`, `dot`, `postgresql`, etc.

The application protocol negotiation is accomplished within the TLS handshake, without adding network
round-trips, and allows the server to associate a different certificate with each application protocol.

The client may specify multiple supported ALPN values in its ClientHello message, and the `alpn` submatcher
of the `tls` matcher returns `true` when it finds the desired ALPN value in the client's list of ALPNs. 

See also https://github.com/mholt/caddy-l4/issues/304.

## Configuration

### Caddyfile

```caddyfile
{
    layer4 {
        # route TLS traffic on TCP/4443 based on ALPN values:
        # "custom_protocol"    -> custom.backend.local:443
        # "dot" (DNS-over-TLS) -> dot.backend.local:853
        # "postgresql"         -> postgresql.backend.local:443
        # [any other value]    -> fallback.backend.local:443
        #
        # otherwise explicitly close connections
        tcp/:4443 {
            @tls-custom tls alpn custom_protocol
            route @tls-custom {
                proxy tcp/custom.backend.local:443
            }

            @tls-dot tls alpn dot
            route @tls-dot {
                proxy tcp/dot.backend.local:853
            }

            @tls-postgresql tls alpn postgresql
            route @tls-postgresql {
                proxy tcp/postgresql.backend.local:443
            }

            @tls-fallback tls
            route @tls-fallback {
                proxy tcp/fallback.backend.local:443
            }

            route {
                close
            }
        }
    }

    servers :443 {
        listener_wrappers {
            # route TLS traffic on TCP/443 based on ALPN values:
            # "custom_protocol"    -> custom.backend.local:443
            # "dot" (DNS-over-TLS) -> dot.backend.local:853
            # "postgresql"         -> postgresql.backend.local:443
            #
            # otherwise try to terminate TLS and handle HTTP request internally
            layer4 {
                @tls-custom tls alpn custom_protocol
                route @tls-custom {
                    proxy tcp/custom.backend.local:443
                }

                @tls-dot tls alpn dot
                route @tls-dot {
                    proxy tcp/dot.backend.local:853
                }

                @tls-postgresql tls alpn postgresql
                route @tls-postgresql {
                    proxy tcp/postgresql.backend.local:443
                }
            }
            tls
        }
    }
}

*.example.com {
    respond "OK" 200
}
```

### JSON

```json
{
    "apps": {
        "http": {
            "servers": {
                "srv0": {
                    "listen": [
                        ":443"
                    ],
                    "listener_wrappers": [
                        {
                            "routes": [
                                {
                                    "handle": [
                                        {
                                            "handler": "proxy",
                                            "upstreams": [
                                                {
                                                    "dial": [
                                                        "tcp/custom.backend.local:443"
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                    "match": [
                                        {
                                            "tls": {
                                                "alpn": [
                                                    "custom_protocol"
                                                ]
                                            }
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
                                                        "tcp/dot.backend.local:853"
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                    "match": [
                                        {
                                            "tls": {
                                                "alpn": [
                                                    "dot"
                                                ]
                                            }
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
                                                        "tcp/postgresql.backend.local:443"
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                    "match": [
                                        {
                                            "tls": {
                                                "alpn": [
                                                    "postgresql"
                                                ]
                                            }
                                        }
                                    ]
                                }
                            ],
                            "wrapper": "layer4"
                        },
                        {
                            "wrapper": "tls"
                        }
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "host": [
                                        "*.example.com"
                                    ]
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "subroute",
                                    "routes": [
                                        {
                                            "handle": [
                                                {
                                                    "body": "OK",
                                                    "handler": "static_response",
                                                    "status_code": 200
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                            "terminal": true
                        }
                    ]
                }
            }
        },
        "layer4": {
            "servers": {
                "srv0": {
                    "listen": [
                        "tcp/:4443"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "tls": {
                                        "alpn": [
                                            "custom_protocol"
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
                                                "tcp/custom.backend.local:443"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "tls": {
                                        "alpn": [
                                            "dot"
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
                                                "tcp/dot.backend.local:853"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "tls": {
                                        "alpn": [
                                            "postgresql"
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
                                                "tcp/postgresql.backend.local:443"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "tls": {}
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "tcp/fallback.backend.local:443"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "handle": [
                                {
                                    "handler": "close"
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
