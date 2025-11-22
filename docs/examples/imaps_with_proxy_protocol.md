---
title: IMAPS with Proxy Protocol Example
---

# IMAPS with Proxy Protocol Example

## Summary

The IMAPS with Proxy Protocol example shows how to serve IMAPS on TCP port 993 and IMAP on TCP port 143 sending
the PROXY protocol headers to a single IMAP backend on TCP port 1143.

## Configuration

### Caddyfile

```caddyfile
{
    layer4 {
        :993 {
            @imaps tls sni imap.example.com
            route @imaps {
                tls
                proxy {
                    # send proxy protocol v1
                    proxy_protocol v1
                    upstream localhost:143
                }
            }
        }
        :143 {
            route {
                # receive proxy protocol v1 or v2
                proxy_protocol
                proxy {
                    # send proxy protocol v2
                    proxy_protocol v2
                    upstream localhost:1143
                }
            }
        }
    }
}

# automatically obtain SSL certificates
# used for TLS termination on port 993
imap.example.com {
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
                                        "imap.example.com"
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
                        ":993"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "tls":{
                                        "sni":[
                                            "imap.example.com"
                                        ]
                                    }
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"tls"
                                },
                                {
                                    "handler":"proxy",
                                    "proxy_protocol":"v1",
                                    "upstreams":[
                                        {
                                            "dial":[
                                                "localhost:143"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                },
                "srv1":{
                    "listen":[
                        ":143"
                    ],
                    "routes":[
                        {
                            "handle":[
                                {
                                    "handler":"proxy_protocol"
                                },
                                {
                                    "handler":"proxy",
                                    "proxy_protocol":"v2",
                                    "upstreams":[
                                        {
                                            "dial":[
                                                "localhost:1143"
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
