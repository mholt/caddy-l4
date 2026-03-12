---
title: Vars Matcher
---

# Vars Matcher

## Summary

The Vars matcher allows to match connections based on variables in the context or placeholder values.
It's similar to the [eponymous matcher in the HTTP app](https://caddyserver.com/docs/caddyfile/matchers#vars).

## Syntax

Under the hood, the Vars matcher is implemented as a map of string to a slice of strings.
The key is the placeholder or name of the variable, and the values are possible values
the variable can be in order to match (logical OR'ed).

If the key is surrounded by `{ }`, it is assumed to be a placeholder. Otherwise, it will be considered a variable name.

[Placeholders](https://caddyserver.com/docs/conventions#placeholders) in the keys are not expanded,
but placeholders in both the values of variables and the possible values are resolved at match.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
vars <variable> <values...>
```

Unlike JSON, the Caddyfile syntax above doesn't support specifying more than one variable for a single matcher.
The OR logic can be implemented with a number of matcher sets instead.

An example config of the Layer 4 app that terminates TLS and proxies decrypted traffic to a dedicated TLS upstream
if the cipher suite name negotiated for the downstream connection is `TLS_CHACHA20_POLY1305_SHA256`:
```caddyfile
{
    layer4 {
        tcp/:4443 {
            route {
                tls
                subroute {
                    @chacha vars {l4.tls.cipher_suite} TLS_CHACHA20_POLY1305_SHA256
                    route @chacha {
                        proxy {
                            upstream tcp/chacha.backend.local:443 {
                                tls_insecure_skip_verify
                            }
                        }
                    }
                    
                    route {
                        proxy {
                            upstream tcp/fallback.backend.local:443 {
                                tls_insecure_skip_verify
                            }
                        }
                    }
                }
            }
        }
    }
}

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
                        "tcp/:4443"
                    ],
                    "routes": [
                        {
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
                                                                "tcp/chacha.backend.local:443"
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
                                                    "vars": {
                                                        "{l4.tls.cipher_suite}": [
                                                            "TLS_CHACHA20_POLY1305_SHA256"
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
                                                                "tcp/other.backend.local:443"
                                                            ],
                                                            "tls": {
                                                                "insecure_skip_verify": true
                                                            }
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
