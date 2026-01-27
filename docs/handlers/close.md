---
title: Close Handler
---

# Close Handler

## Summary

The Close handler close connections. Note that it's relevant to connection-oriented protocols (e.g. TCP)
and irrelevant to connectionless protocols (e.g. UDP).

## Syntax

The handler has no fields and supports no [placeholders](https://caddyserver.com/docs/conventions#placeholders).

### Caddyfile

The handler supports the following syntax:
```caddyfile
close
```

An example config of the Layer 4 app that closes any incoming connections on TCP4 port 8888:
```caddyfile
{
    layer4 {
        0.0.0.0:8888 {
            route {
                close
            }
        }
    }
}
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
                        "0.0.0.0:8888"
                    ],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "close"
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
