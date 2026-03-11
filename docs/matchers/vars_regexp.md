---
title: Vars Regexp Matcher
---

# Vars Regexp Matcher

## Summary

The Vars Regexp matcher allows to match connections based on variables in the context or placeholder values.
It's similar to the [eponymous matcher in the HTTP app](https://caddyserver.com/docs/caddyfile/matchers#vars-regexp).

## Syntax

Under the hood, the Vars Regexp matcher is implemented as a map of string to a `MatchRegexp` structure.
The key is the placeholder or name of the variable, and the value represents the regular expression to test
which has the mandatory `pattern` field containing a regular expression and the optional `name` field.

If the key is surrounded by `{ }`, it is assumed to be a placeholder. Otherwise, it will be considered a variable name.

[Placeholders](https://caddyserver.com/docs/conventions#placeholders) in the keys are not expanded, but placeholders in the values of variables are resolved at match.
There is no secure way to resolve placeholders in the regular expressions either at provision, or at match.

Upon a match, it adds placeholders to the connection: `{l4.regexp.name.capture_group}` where `name` is
the regular expression's name, and `capture_group` is either the named or positional capture group from
the expression itself. If no name is given, then the placeholder omits the name: `{l4.regexp.capture_group}`
(potentially leading to collisions).

### Caddyfile

The matcher supports the following syntax:
```caddyfile
vars_regexp [<name>] <variable> <regexp>
```

Unlike JSON, the Caddyfile syntax above doesn't support specifying more than one variable for a single matcher.
The OR logic can be implemented with a number of matcher sets instead.

An example config of the Layer 4 app that terminates TLS and proxies decrypted traffic to a dedicated TLS upstream
if the cipher suite name negotiated for the downstream connection is any `AES` in `GCM` mode:
```caddyfile
{
    layer4 {
        tcp/:4443 {
            route {
                tls
                subroute {
                    @aes_gcm vars_regexp aes_gcm {l4.tls.cipher_suite} ^TLS_([_A-Z]?)AES_(?<key>\d+)_GCM_SHA(?<hash>\d+)$
                    route @aes_gcm {
                        proxy {
                            upstream tcp/aes{l4.regexp.aes_gcm.key}gcm{l4.regexp.aes_gcm.hash}.backend.local:443 {
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
                                                                "tcp/aes{l4.regexp.aes_gcm.key}gcm{l4.regexp.aes_gcm.hash}.backend.local:443"
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
                                                    "vars_regexp": {
                                                        "{l4.tls.cipher_suite}": {
                                                            "name": "aes_gcm",
                                                            "pattern": "^TLS_([_A-Z]?)AES_(?\u003ckey\u003e\\d+)_GCM_SHA(?\u003chash\u003e\\d+)$"
                                                        }
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
                                                                "tcp/fallback.backend.local:443"
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
