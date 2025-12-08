---
title: Echo Handler
---

# Echo Handler

## Summary

The Echo handler implements an echo server, i.e. sends back exactly what it receives.

## Syntax

The handler has no fields and supports no [placeholders](https://caddyserver.com/docs/conventions#placeholders).

### Caddyfile

The handler supports the following syntax:
```caddyfile
echo
```

An example config of the Layer 4 app that sends back anything it receives on TCP4 port 8888:
```caddyfile
{
    layer4 {
        0.0.0.0:8888 {
            route {
                echo
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
