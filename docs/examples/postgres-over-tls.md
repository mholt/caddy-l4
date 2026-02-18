---
title: Postgres-over-TLS Example
---

# Postgres-over-TLS Example

## Summary

The Postgres-over-TLS example shows how to proxy PostgreSQL connections
while serving HTTPS on the same port (443/tcp).

## Configuration

### Caddyfile

```caddyfile
{
    servers {
        listener_wrappers {
            layer4 {
                @tls-pgsql tls {
                    # including the ALPN condition below
                    # lets Caddy serve HTTPS requests
                    # for the same server name
                    alpn postgresql
                    sni pgsql.example.com
                }
                route @tls-pgsql {
                    tls {
                        # the connection policy below is required
                        # if the matcher above has no ALPN condition,
                        # otherwise it may be securely omitted
                        connection_policy {
                            # supported by PostgreSQL 17 or later
                            alpn postgresql
                        }
                    }
                    # decrypted traffic is presumed to be PostgreSQL,
                    # so no other checks are made before proxying it
                    proxy localhost:5432
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
    "apps":{
        "http":{
            "servers":{
                "srv0":{
                    "listen":[
                        ":443"
                    ],
                    "listener_wrappers":[
                        {
                            "routes":[
                                {
                                    "handle":[
                                        {
                                            "connection_policies":[
                                                {
                                                    "alpn":[
                                                        "postgresql"
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
                                                        "localhost:5432"
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                    "match":[
                                        {
                                            "tls":{
                                                "alpn":[
                                                    "postgresql"
                                                ],
                                                "sni":[
                                                    "pgsql.example.com"
                                                ]
                                            }
                                        }
                                    ]
                                }
                            ],
                            "wrapper":"layer4"
                        },
                        {
                            "wrapper":"tls"
                        }
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
        }
    }
}
```
