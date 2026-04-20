---
title: TLS Handler
---

# TLS Handler

## Summary

The TLS handler terminates TLS, i.e. all reads and writes performed with any handlers following it will now be
decrypted and encrypted.

This handler is one of the most frequently used handlers this package includes, but it's also known for having caused
some misunderstanding. It's crucial to keep in mind that the handler does *no* SSL certificates management, i.e. it
can't obtain or generate them - *you have to do it by means of configuring Caddy*. The only thing the handler does
is TLS termination using a set of SSL certificates *Caddy already has* and applying a set of connection policies.

## Syntax

The handler has `connection_policies` field which is a list of `caddytls.ConnectionPolicy` structures. It is an ordered
group of connection policies that govern the establishment of TLS connections. The first matching policy will be used
to configure TLS connections at handshake-time. If no policies are provided, the defaults apply. Please refer to
the [relevant Caddy docs](https://caddyserver.com/docs/json/apps/http/servers/tls_connection_policies/) for more info.
Note: the handler's syntax provides for *one* `connection_policies` in JSON, but *one or many* `connection_policy`
in Caddyfile.

The handler itself supports no [placeholders](https://caddyserver.com/docs/conventions#placeholders), but they may be supported at Caddy level for some connection policy
fields.

When TLS is successfully terminated, the handler registers the following placeholders:
- `l4.tls.cipher_suite` with the relevant cipher suite name, e.g. `TLS_CHACHA20_POLY1305_SHA256`;
- `l4.tls.ech` having `true` if an encrypted ClientHello is offered and accepted, otherwise `false`;
- `l4.tls.proto` with the relevant application protocol negotiated with ALPN, e.g. `h2`;
- `l4.tls.proto_mutual` always having `true`;
- `l4.tls.resumed` having `true` if the connection is resumed from a previous session, otherwise `false`;
- `l4.tls.server_name` with the TLS server name requested by the client, e.g. `example.com`;
- `l4.tls.version` with the TLS version name, e.g. `tls1.3`.

### Mutual TLS

For a mutual TLS (mTLS) session, the handler also registers the following placeholders:
- `l4.tls.client.certificate_der_base64` with the base64-encoded value of the client's certificate;
- `l4.tls.client.certificate_pem` with the PEM-encoded value of the client's certificate;
- `l4.tls.client.fingerprint` with the SHA256 checksum of the client's certificate;
- `l4.tls.client.public_key` with the public key of the client's certificate;
- `l4.tls.client.public_key_sha256` with the SHA256 checksum of the client's public key;
- `l4.tls.client.issuer` with the issuer DN of the client's certificate;
- `l4.tls.client.serial` with the serial number of the client's certificate;
- `l4.tls.client.subject` with the subject DN of the client's certificate;


- `l4.tls.client.issuer.common_name` with the client's certificate issuer common name;
- `l4.tls.client.issuer.serial` with the client's certificate issuer serial number;
- `l4.tls.client.issuer.organization`* with the client's certificate issuer organization;
- `l4.tls.client.issuer.organizational_unit`* with the client's certificate issuer organizational unit;
- `l4.tls.client.issuer.country`* with the client's certificate issuer country;
- `l4.tls.client.issuer.locality`* with the client's certificate issuer locality;
- `l4.tls.client.issuer.province`* with the client's certificate issuer province;
- `l4.tls.client.issuer.street_address`* with the client's certificate issuer street address;
- `l4.tls.client.issuer.postal_code`* with the client's certificate issuer postal code;


- `l4.tls.client.san.dns_names`* with the client's certificate SAN domain names;
- `l4.tls.client.san.emails`* with the client's certificate SAN email addresses;
- `l4.tls.client.san.ips`* with the client's certificate SAN IP addresses;
- `l4.tls.client.san.uris`* with the client's certificate SAN URIs;


- `l4.tls.client.subject.common_name` with the client's certificate subject common name;
- `l4.tls.client.subject.serial` with the client's certificate subject serial number;
- `l4.tls.client.subject.organization`* with the client's certificate subject organization;
- `l4.tls.client.subject.organizational_unit`* with the client's certificate subject organizational unit;
- `l4.tls.client.subject.country`* with the client's certificate subject country;
- `l4.tls.client.subject.locality`* with the client's certificate subject locality;
- `l4.tls.client.subject.province`* with the client's certificate subject province;
- `l4.tls.client.subject.street_address`* with the client's certificate subject street address;
- `l4.tls.client.subject.postal_code`* with the client's certificate subject postal code;

Similar to how it works in the HTTP app for some TLS-related placeholders in the `http.request.tls` domain,
if a dot and a numeric index are supplied as a suffix to the placeholder marked above with an asterisk (`*`),
only one of the items listed in the relevant field is returned instead. E.g. `l4.tls.client.san.dns_names.0` is
replaced with the first domain name SAN. See also the [relevant Caddy docs](https://caddyserver.com/docs/modules/http#docs).

### Caddyfile

The handler supports the following syntax:
```caddyfile
# bare `tls` terminates TLS
# with the default connection policy
tls

# otherwise specify a custom set of connection policies
tls {
    connection_policy {
        # put connection policy options here
        # see Caddy documentation for more info
    }
    
    # two or more connection policies may be defined
    connection_policy {
        # put connection policy options here
    }
}
```

An example config of the Layer 4 app that terminates TLS and routes traffic based on ALPN and SNI:
```caddyfile
{
    layer4 {
        :4443 {
            # terminate TLS traffic on TCP port 4443
            # with ALPN http/1.0 or http/1.1,
            # apply the default connection policy,
            # then apply extra criteria to route HTTP traffic
            @h1 tls alpn http/1.0 http/1.1
            route @h1 {
                tls
                subroute {
                    @alpha http host alpha.example.com
                    route @alpha {
                        proxy alpha.machine.local:80
                    }
                    @beta http host beta.example.com
                    route @beta {
                        proxy beta.machine.local:80
                    }
                    route {
                        proxy gamma.machine.local:80
                    }
                }
            }
            
            # terminate TLS traffic on TCP port 4443
            # with ALPN h2 and SNI alpha.example.com,
            # apply a custom connection policy,
            # proxy decrypted HTTP/2 traffic to alpha.machine.local:80
            # (the upstream must support processing such traffic)
            @h2a tls {
                alpn h2
                sni alpha.example.com
            }
            route @h2a {
                tls {
                    connection_policy {
                        curves x25519
                        cert_selection {
                            serial_number 123456789012
                        }
                    }
                }
                proxy alpha.machine.local:80
            }
            
            # terminate TLS traffic on TCP port 4443
            # with ALPN h2 and SNI beta.example.com,
            # apply a custom connection policy,
            # proxy decrypted HTTP/2 traffic to beta.machine.local:80
            # (the upstream must support processing such traffic)
            @h2b tls {
                alpn h2
                sni beta.example.com
            }
            route @h2b {
                tls {
                    connection_policy {
                        curves secp256r1
                        cert_selection {
                            serial_number 123456789012
                        }
                    }
                }
                proxy beta.machine.local:80
            }
            
            # otherwise echo any bytes received on TCP port 4443
            route {
                echo
            }
        }
    }
}

# the example config above is incomplete unless
# alpha.example.com and beta.example.com (or *.example.com)
# SSL certificates are obtained or generated by Caddy;
# it may be done by defining *.example.com HTTPS server block
*.example.com {
    respond "OK" 200
}
```

### JSON

JSON equivalent to the caddyfile config provided above:
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
                        ":4443"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "tls": {
                                        "alpn": [
                                            "http/1.0",
                                            "http/1.1"
                                        ]
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "tls"
                                },
                                {
                                    "handler": "subroute",
                                    "routes": [
                                        {
                                            "handle": [
                                                {
                                                    "handler": "proxy",
                                                    "upstreams": [
                                                        {
                                                            "dial": [
                                                                "alpha.machine.local:80"
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ],
                                            "match": [
                                                {
                                                    "http": [
                                                        {
                                                            "host": [
                                                                "alpha.example.com"
                                                            ]
                                                        }
                                                    ]
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
                                                                "beta.machine.local:80"
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ],
                                            "match": [
                                                {
                                                    "http": [
                                                        {
                                                            "host": [
                                                                "beta.example.com"
                                                            ]
                                                        }
                                                    ]
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
                                                                "gamma.machine.local:80"
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
                            "match": [
                                {
                                    "tls": {
                                        "alpn": [
                                            "h2"
                                        ],
                                        "sni": [
                                            "alpha.example.com"
                                        ]
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "connection_policies": [
                                        {
                                            "certificate_selection": {
                                                "serial_number": [
                                                    "123456789012"
                                                ]
                                            },
                                            "curves": [
                                                "x25519"
                                            ]
                                        }
                                    ],
                                    "handler": "tls"
                                },
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "alpha.machine.local:80"
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
                                            "h2"
                                        ],
                                        "sni": [
                                            "beta.example.com"
                                        ]
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "connection_policies": [
                                        {
                                            "certificate_selection": {
                                                "serial_number": [
                                                    "123456789012"
                                                ]
                                            },
                                            "curves": [
                                                "secp256r1"
                                            ]
                                        }
                                    ],
                                    "handler": "tls"
                                },
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "beta.machine.local:80"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "handle": [
                                {
                                    "handler": "echo"
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
