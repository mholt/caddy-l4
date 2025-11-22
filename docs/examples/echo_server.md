---
title: Echo Server Example
---

# Echo Server Example

## Summary

The Echo Server example shows how to use `echo` handler with and without TLS termination.

## Configuration

### Caddyfile

```caddyfile
{
    layer4 {
        # a simple echo server
        # listening on TCP port 5000
        # of the loopback interface
        # with dual stack support
        127.0.0.1:5000 [::1]:5000 {
            route {
                echo
            }
        }
        
        # a simple echo server with TLS termination
        # listening on TCP port 5001
        # of the loopback interface
        # with dual stack support
        127.0.0.1:5001 [::1]:5001 {
            route {
                tls
                echo
            }
        }
    }
}

# use the internal issuer
# to obtain SSL certificates
# for TLS termination on port 5001,
# also serve HTTPS on port 443
localhost {
    tls {
        issuer internal
    }
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
                                        "localhost"
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
                        "127.0.0.1:5000",
                        "[::1]:5000"
                    ],
                    "routes":[
                        {
                            "handle":[
                                {
                                    "handler":"echo"
                                }
                            ]
                        }
                    ]
                },
                "srv1":{
                    "listen":[
                        "127.0.0.1:5001",
                        "[::1]:5001"
                    ],
                    "routes":[
                        {
                            "handle":[
                                {
                                    "handler":"tls"
                                },
                                {
                                    "handler":"echo"
                                }
                            ]
                        }
                    ]
                }
            }
        },
        "tls":{
            "automation":{
                "policies":[
                    {
                        "subjects":[
                            "localhost"
                        ],
                        "issuers":[
                            {
                                "module":"internal"
                            }
                        ]
                    }
                ]
            }
        }
    }
}
```
