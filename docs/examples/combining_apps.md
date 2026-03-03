---
title: Combining Apps Example
---

# Combining Apps Example

## Summary

This example shows hot to combine the HTTP and Layer 4 apps, i.e. use Caddy’s regular HTTP app for serving
a static website while also forwarding traffic to certain backends with or without encrypting it.

## Configuration

### Caddyfile

```caddyfile
{
    layer4 {
        # never try to bind to the ports the HTTP app is bound to,
        # use listener (TCP) and/or packet connection (UDP) wrappers instead;
        # see also: https://github.com/mholt/caddy-l4/blob/master/docs/servers.md

        # the following block will cause issues and won't work correctly,
        # if the HTTP app listens to port 443 which is the default HTTPS port
        # tcp/:443 {
        #     ...
        # }

        # the following block will cause issues and won't work correctly,
        # unless HTTP/3 is disabled for the HTTP app listening to port 443
        # udp/:443 {
        #     ...
        # }
        
        # this block works completely fine, but closes any incoming connections
        tcp/:1234 {
            route {
                close
            }
        }
    }

    # while `:443` after the `servers` directive below is optional, it makes sense
    # if the HTTP app listens to multiple ports and the configuration given below
    # should be applicable to one of them exclusively;
    # see also: https://caddyserver.com/docs/caddyfile/options#server-options
    servers :443 {
        # listener wrappers defined below can only handle TCP traffic, e.g. DNS, HTTP, TLS, etc.
        listener_wrappers {
            layer4 {
                # handle all TLS traffic in a single route block for efficiency
                @tls tls
                route @tls {
                    subroute {
                        @tls-1 tls sni subdomain-1.example.com
                        route @tls-1 {
                            # terminate TLS with previously obtained certificates
                            tls
                            # proxy decrypted traffic in clear text to the backend
                            proxy tcp/backend:80
                        }

                        @tls-2 tls sni subdomain-2.example.com
                        route @tls-2 {
                            # terminate TLS with previously obtained certificates
                            tls
                            # proxy decrypted traffic insecurely to the backend
                            proxy {
                                upstream tcp/backend:443 {
                                    # enable TLS and accept any certificates the backend provides
                                    tls_insecure_skip_verify
                                }
                            }
                        }

                        @tls-3 tls sni subdomain-3.example.com
                        route @tls-3 {
                            # terminate TLS with previously obtained certificates
                            tls
                            # proxy decrypted traffic securely to the backend
                            proxy {
                                upstream tcp/backend:443 {
                                    # enable TLS and verify the backend's certificates
                                    tls
                                }
                            }
                        }

                        @tls-4 tls sni subdomain-4.example.com
                        route @tls-4 {
                            # proxy encrypted traffic to the backend
                            proxy {
                                # forward client information to the backend
                                proxy_protocol v2
                                upstream tcp/backend:443 {
                                    # no need to enable TLS, because the traffic is encrypted
                                }
                            }
                        }
                    }           
                }

                # proxy DNS traffic from local subnets to Cloudflare
                @dns {
                    dns
                    remote_ip 10.0.0.0/8 fd00:1122:3344:5566::/64
                }
                route @dns {
                    proxy tcp/1.1.1.1:53
                }
            }
            tls
        }

        # packet connection wrappers defined below can only handle UDP traffic, e.g. DNS, QUIC, etc.
        packet_conn_wrappers {
            # WIP, to be updated once the Layer 4 app becomes capable of wrapping packet connections;
            # by default any UDP traffic received on port 443 is consumed and handled by the HTTP app
        }
    }
}

# this block makes Caddy obtain a wildcard TLS certificate
*.example.com {
    respond "OK" 200
}

:80 {
    respond "INSECURE" 200
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
                                            "handler": "subroute",
                                            "routes": [
                                                {
                                                    "handle": [
                                                        {
                                                            "handler": "tls"
                                                        },
                                                        {
                                                            "handler": "proxy",
                                                            "upstreams": [
                                                                {
                                                                    "dial": [
                                                                        "tcp/backend:80"
                                                                    ]
                                                                }
                                                            ]
                                                        }
                                                    ],
                                                    "match": [
                                                        {
                                                            "tls": {
                                                                "sni": [
                                                                    "subdomain-1.example.com"
                                                                ]
                                                            }
                                                        }
                                                    ]
                                                },
                                                {
                                                    "handle": [
                                                        {
                                                            "handler": "tls"
                                                        },
                                                        {
                                                            "handler": "proxy",
                                                            "upstreams": [
                                                                {
                                                                    "dial": [
                                                                        "tcp/backend:443"
                                                                    ],
                                                                    "tls": {
                                                                        "insecure_skip_verify": true
                                                                    }
                                                                }
                                                            ]
                                                        }
                                                    ],
                                                    "match": [
                                                        {
                                                            "tls": {
                                                                "sni": [
                                                                    "subdomain-2.example.com"
                                                                ]
                                                            }
                                                        }
                                                    ]
                                                },
                                                {
                                                    "handle": [
                                                        {
                                                            "handler": "tls"
                                                        },
                                                        {
                                                            "handler": "proxy",
                                                            "upstreams": [
                                                                {
                                                                    "dial": [
                                                                        "tcp/backend:443"
                                                                    ],
                                                                    "tls": {}
                                                                }
                                                            ]
                                                        }
                                                    ],
                                                    "match": [
                                                        {
                                                            "tls": {
                                                                "sni": [
                                                                    "subdomain-3.example.com"
                                                                ]
                                                            }
                                                        }
                                                    ]
                                                },
                                                {
                                                    "handle": [
                                                        {
                                                            "handler": "proxy",
                                                            "proxy_protocol": "v2",
                                                            "upstreams": [
                                                                {
                                                                    "dial": [
                                                                        "tcp/backend:443"
                                                                    ]
                                                                }
                                                            ]
                                                        }
                                                    ],
                                                    "match": [
                                                        {
                                                            "tls": {
                                                                "sni": [
                                                                    "subdomain-4.example.com"
                                                                ]
                                                            }
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                    "match": [
                                        {
                                            "tls": {}
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
                                                        "tcp/1.1.1.1:53"
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                    "match": [
                                        {
                                            "dns": {},
                                            "remote_ip": {
                                                "ranges": [
                                                    "10.0.0.0/8",
                                                    "fd00:1122:3344:5566::/64"
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
                },
                "srv1": {
                    "listen": [
                        ":80"
                    ],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "body": "INSECURE",
                                    "handler": "static_response",
                                    "status_code": 200
                                }
                            ]
                        }
                    ]
                }
            }
        },
        "layer4": {
            "servers": {
                "srv0": {
                    "listen": [
                        "tcp/:1234"
                    ],
                    "routes": [
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
