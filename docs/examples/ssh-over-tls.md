---
title: SSH-over-TLS Example
---

# SSH-over-TLS Example

## Summary

The SSH-over-TLS example shows how to multiplex HTTP/1.1 and SSH-in-TLS on a single port (443/tcp).

Note: SSH client support is required to connect to an SSH server over TLS.

See also: https://github.com/mholt/caddy-l4/issues/101.

## Configuration

### Caddyfile

```caddyfile
{
    layer4 {
        :443 {
            @tls-a tls sni a.example.com
            route @tls-a {
                tls {
                    # enable HTTP/1.1 only
                    connection_policy {
                        alpn http/1.1
                    }
                }
                subroute {
                    @ssh ssh
                    route @ssh {
                        proxy a.machine.local:22
                    }
                    
                    @http http host a.example.com
                    route @http {
                        proxy a.machine.local:80
                    }
                }
            }
            
            @tls-b tls sni b.example.com
            route @tls-b {
                tls {
                    # enable HTTP/1.1 only
                    connection_policy {
                        alpn http/1.1
                    }
                }
                subroute {
                    @ssh ssh
                    route @ssh {
                        proxy b.machine.local:22
                    }
                    
                    @http http host b.example.com
                    route @http {
                        proxy b.machine.local:80
                    }
                }
            }
            
            @tls-self tls sni self.example.com
            route @tls-self {
                tls {
                    # enable HTTP/1.1 only
                    connection_policy {
                        alpn http/1.1
                    }
                }
                subroute {
                    @ssh ssh
                    route @ssh {
                        proxy localhost:22
                    }
                    
                    @http http host self.example.com
                    route @http {
                        proxy localhost:80
                    }
                }
            }
        }
    }
}

# required to respond to requests for self.example.com
# unless another web server listens on TCP port 80
:80 {
    respond "OK" 200
}

# required to automatically obtain a wildcard certificate
# for a.example.com, b.example.com and self.example.com
# used by Caddy-L4 for terminating TLS on TCP port 443
https://*.example.com:1443 {
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
                        ":1443"
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
                },
                "srv1":{
                    "listen":[
                        ":80"
                    ],
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
            }
        },
        "layer4":{
            "servers":{
                "srv0":{
                    "listen":[
                        ":443"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "tls":{
                                        "sni":[
                                            "a.example.com"
                                        ]
                                    }
                                }
                            ],
                            "handle":[
                                {
                                    "connection_policies":[
                                        {
                                            "alpn":[
                                                "http/1.1"
                                            ]
                                        }
                                    ],
                                    "handler":"tls"
                                },
                                {
                                    "handler":"subroute",
                                    "routes":[
                                        {
                                            "handle":[
                                                {
                                                    "handler":"proxy",
                                                    "upstreams":[
                                                        {
                                                            "dial":[
                                                                "a.machine.local:22"
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ],
                                            "match":[
                                                {
                                                    "ssh":{
                                                        
                                                    }
                                                }
                                            ]
                                        },
                                        {
                                            "handle":[
                                                {
                                                    "handler":"proxy",
                                                    "upstreams":[
                                                        {
                                                            "dial":[
                                                                "a.machine.local:80"
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ],
                                            "match":[
                                                {
                                                    "http":[
                                                        {
                                                            "host":[
                                                                "a.example.com"
                                                            ]
                                                        }
                                                    ]
                                                }
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
                                            "b.example.com"
                                        ]
                                    }
                                }
                            ],
                            "handle":[
                                {
                                    "connection_policies":[
                                        {
                                            "alpn":[
                                                "http/1.1"
                                            ]
                                        }
                                    ],
                                    "handler":"tls"
                                },
                                {
                                    "handler":"subroute",
                                    "routes":[
                                        {
                                            "handle":[
                                                {
                                                    "handler":"proxy",
                                                    "upstreams":[
                                                        {
                                                            "dial":[
                                                                "b.machine.local:22"
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ],
                                            "match":[
                                                {
                                                    "ssh":{
                                                        
                                                    }
                                                }
                                            ]
                                        },
                                        {
                                            "handle":[
                                                {
                                                    "handler":"proxy",
                                                    "upstreams":[
                                                        {
                                                            "dial":[
                                                                "b.machine.local:80"
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ],
                                            "match":[
                                                {
                                                    "http":[
                                                        {
                                                            "host":[
                                                                "b.example.com"
                                                            ]
                                                        }
                                                    ]
                                                }
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
                                            "self.example.com"
                                        ]
                                    }
                                }
                            ],
                            "handle":[
                                {
                                    "connection_policies":[
                                        {
                                            "alpn":[
                                                "http/1.1"
                                            ]
                                        }
                                    ],
                                    "handler":"tls"
                                },
                                {
                                    "handler":"subroute",
                                    "routes":[
                                        {
                                            "handle":[
                                                {
                                                    "handler":"proxy",
                                                    "upstreams":[
                                                        {
                                                            "dial":[
                                                                "localhost:22"
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ],
                                            "match":[
                                                {
                                                    "ssh":{
                                                        
                                                    }
                                                }
                                            ]
                                        },
                                        {
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
                                            ],
                                            "match":[
                                                {
                                                    "http":[
                                                        {
                                                            "host":[
                                                                "self.example.com"
                                                            ]
                                                        }
                                                    ]
                                                }
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
