---
title: Close Handler
---

# Close Handler

## Summary

The Close handler close connections.

Note that it's primarily relevant to *connection-oriented* protocols, i.e. `net.Conn` implementations (e.g. TCP).
When it comes to *connectionless* protocols, i.e. `net.PacketConn` implementations (e.g. UDP), the handler closes
a virtual connection which is created when the first packet is received on the socket from some address:port
combination. But the sender never knows that the receiver closes this connection. Once this virtual connection
is closed, and should the same sender (with equal address:port) continue sending traffic to Caddy, a new virtual
connection will be created, and matching/routing repeats. Thus, the handler may only be relevant to *connectionless*
protocols, if a user wants to filter particular packets.

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
