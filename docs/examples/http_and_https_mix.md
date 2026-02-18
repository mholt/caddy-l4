---
title: HTTP & HTTPS Mix Example
---

# HTTP & HTTPS Mix Example

## Summary

The HTTP & HTTPS Mix example shows how to multiplex HTTP and HTTPS on a single port without TLS termination.

## Configuration

### Caddyfile

```caddyfile
{
    layer4 {
        # serve on the loopback interface only
        127.0.0.1:5000 [::1]:5000 {
            @insecure http
            route @insecure {
                proxy localhost:80
            }
            @secure tls
            route @secure {
                proxy localhost:443
            }
        }
        
        # serve on any interface, but filter by HTTP Host and TLS SNI
        :6000 {
            @insecure http host example.com
            route @insecure {
                proxy localhost:80
            }
            @secure tls sni example.com
            route @secure {
                proxy localhost:443
            }
        }
    }
}

localhost:80 example.com:80 {
    respond "insecure" 200
}

localhost {
    tls {
        issuer internal
    }
    respond "secure, internal issuer" 200
}

example.com {
    respond "secure, external issuer" 200
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
                                        "example.com"
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
                                                    "body":"secure, external issuer",
                                                    "handler":"static_response",
                                                    "status_code":200
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                            "terminal":true
                        },
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
                                                    "body":"secure, internal issuer",
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
                },
                "srv1":{
                    "listen":[
                        ":80"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "host":[
                                        "localhost",
                                        "example.com"
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
                                                    "body":"insecure",
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
                            "match":[
                                {
                                    "http":[
                                        {
                                            
                                        }
                                    ]
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"proxy",
                                    "upstreams":[
                                        {
                                            "dial":[
                                                "localhost:80"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match":[
                                {
                                    "tls":{
                                        
                                    }
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"proxy",
                                    "upstreams":[
                                        {
                                            "dial":[
                                                "localhost:443"
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
                        ":6000"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "http":[
                                        {
                                            "host":[
                                                "example.com"
                                            ]
                                        }
                                    ]
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"proxy",
                                    "upstreams":[
                                        {
                                            "dial":[
                                                "localhost:80"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match":[
                                {
                                    "tls":{
                                        "sni":[
                                            "example.com"
                                        ]
                                    }
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"proxy",
                                    "upstreams":[
                                        {
                                            "dial":[
                                                "localhost:443"
                                            ]
                                        }
                                    ]
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
                            "example.com"
                        ]
                    },
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
