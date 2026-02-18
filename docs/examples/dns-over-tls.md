---
title: DNS-over-TLS Example
---

# DNS-over-TLS Example

## Summary

The DNS-over-TLS example shows how to proxy secure DNS connections using Caddy for TLS termination.

## Configuration

### Caddyfile

```caddyfile
{
    layer4 {
        :853 {
            @dot tls sni dns.example.com
            route @dot {
                tls {
                    # the connection policy below is optional
                    connection_policy {
                        alpn dot
                    }
                }
                # decrypted traffic is presumed to be DNS,
                # so no other checks are made before proxying it
                proxy tcp/1.1.1.1:53
            }
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
    "apps":{
        "http":{
            "servers":{
                "srv0":{
                    "listen":[
                        ":443"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "host":[
                                        "*.example.com"
                                    ]
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"subroute",
                                    "routes":[
                                        {
                                            "handle":[
                                                {
                                                    "body":"OK",
                                                    "handler":"static_response",
                                                    "status_code":200
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                            "terminal":true
                        }
                    ]
                }
            }
        },
        "layer4":{
            "servers":{
                "srv0":{
                    "listen":[
                        ":853"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "tls":{
                                        "sni":[
                                            "dns.example.com"
                                        ]
                                    }
                                }
                            ],
                            "handle":[
                                {
                                    "connection_policies":[
                                        {
                                            "alpn":[
                                                "dot"
                                            ]
                                        }
                                    ],
                                    "handler":"tls"
                                },
                                {
                                    "handler":"proxy",
                                    "upstreams":[
                                        {
                                            "dial":[
                                                "tcp/1.1.1.1:53"
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
