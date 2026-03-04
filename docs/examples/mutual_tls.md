---
title: Mutual TLS Example
---

# Mutual TLS Example

## Summary

This example shows how to configure mutual TLS (mTLS), a type of mutual authentication in which
the two parties in a connection authenticate each other using the TLS protocol.

## Configuration

### Caddyfile

```caddyfile
{
    # disable automatic redirects from HTTP to HTTPS
    auto_https disable_redirects

    layer4 {
        tcp/:1443 {
            route {
                tls {
                    connection_policy {
                        # the ALPN below is required to allow proxying to port 80,
                        # if the client supports HTTP/2 in addition to HTTP/1.1
                        alpn http/1.1
                        client_auth {
                            # supported client authentication modes include:
                            # `request`, `require`, `verify_if_given`, and `require_and_verify`;
                            # see also: https://caddyserver.com/docs/caddyfile/directives/tls#mode
                            mode require_and_verify
                            # certificate authorities to verify client certificates
                            # are loaded with trust pools; available pools include:
                            # `inline`, `file`, `pki_root`, `pki_intermediate`, `storage`, and `http`;
                            # see also: https://caddyserver.com/docs/caddyfile/directives/tls#trust_pool
                            trust_pool file {
                                # multiple `pem_file` directives are supported to load more certificates
                                pem_file "path/to/ca.crt"
                            }
                        }
                    }
                }
                proxy tcp/localhost:80
            }
        }
    }
}

# use the internal TLS issuer
localhost {
    tls {
        issuer internal
    }

    respond "OK" 200
}

# load a custom TLS certificate
example.com {
    tls "path/to/example.com.crt" "path/to/example.com.key"
    
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
                    "routes": [
                        {
                            "match": [
                                {
                                    "host": [
                                        "example.com"
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
                        },
                        {
                            "match": [
                                {
                                    "host": [
                                        "localhost"
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
                    ],
                    "tls_connection_policies": [
                        {
                            "match": {
                                "sni": [
                                    "example.com"
                                ]
                            },
                            "certificate_selection": {
                                "any_tag": [
                                    "cert0"
                                ]
                            }
                        },
                        {}
                    ],
                    "automatic_https": {
                        "disable_redirects": true
                    }
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
                    ],
                    "automatic_https": {
                        "disable_redirects": true
                    }
                }
            }
        },
        "layer4": {
            "servers": {
                "srv0": {
                    "listen": [
                        "tcp/:1443"
                    ],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "connection_policies": [
                                        {
                                            "alpn": [
                                                "http/1.1"
                                            ],
                                            "client_authentication": {
                                                "ca": {
                                                    "pem_files": [
                                                        "path/to/ca.crt"
                                                    ],
                                                    "provider": "file"
                                                },
                                                "mode": "require_and_verify"
                                            }
                                        }
                                    ],
                                    "handler": "tls"
                                },
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "tcp/localhost:80"
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
        "tls": {
            "certificates": {
                "load_files": [
                    {
                        "certificate": "path/to/example.com.crt",
                        "key": "path/to/example.com.key",
                        "tags": [
                            "cert0"
                        ]
                    }
                ]
            },
            "automation": {
                "policies": [
                    {
                        "subjects": [
                            "example.com"
                        ]
                    },
                    {
                        "subjects": [
                            "localhost"
                        ],
                        "issuers": [
                            {
                                "module": "internal"
                            }
                        ]
                    }
                ]
            }
        }
    }
}
```
