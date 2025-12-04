---
title: SSH Matcher
---

# SSH Matcher

## Summary

The SSH matcher allows to match connections that look like [SSH](https://www.rfc-editor.org/rfc/rfc4253).

## Syntax

The matcher provides no configurable fields.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `ssh` matches any SSH traffic
ssh
```

An example config of the Layer 4 app that multiplexes SSH connections with TLS traffic:
```caddyfile
{
    layer4 {
        :443 {
            # proxy to localhost:22
            # any SSH traffic on TCP port 443
            @a ssh
            route @a {
                proxy localhost:22
            }
            
            # otherwise terminate TLS
            # and proxy decrypted bytes to localhost:8080
            route {
                tls
                proxy localhost:8080
            }
        }
    }
}

# put here other relevant config blocks to let Caddy know
# where certificates should come from for TLS termination 
```

### JSON

JSON equivalent to the caddyfile config provided above:
```json
{
    "apps": {
        "layer4": {
            "servers": {
                "srv0": {
                    "listen": [
                        ":443"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "ssh": {}
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "localhost:22"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "handle": [
                                {
                                    "handler": "tls"
                                },
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "localhost:8080"
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
