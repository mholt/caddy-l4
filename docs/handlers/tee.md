---
title: Tee Handler
---

# Tee Handler

## Summary

The Tee handler implements branching logic, i.e. allows to handle connections with concurrent handler chains.

The handler replicates a connection so that a branch of handlers can concurrently handle it. Reads happen in
lock-step with all concurrent branches to avoid buffering: if one of the branches (including the main handler chain)
stops reading from the connection, it will block all branches.

## Syntax

The handler has `branch` field which is a list of [handlers](/docs/handlers.md) that constitute a concurrent branch.
Any handlers that do connection matching (which involves recording and rewinding the stream) are *unsafe* to tee,
so do all connection matching before teeing

No [placeholders](https://caddyserver.com/docs/conventions#placeholders) are supported.

### Caddyfile

The handler supports the following syntax:
```caddyfile
tee {
    # list handlers to run concurrently
    <handler>
    <handler> [<args>]
}
```

An example config of the Layer 4 app that proxies external connections on TCP4 port 443 to two machines concurrently:
```caddyfile
{
    layer4 {
        0.0.0.0:443 {
            @external not remote_ip 192.168.0.0/16
            route @external {
                tee {
                    proxy primary.machine.local:443
                    proxy secondary.machine.local:443
                }
            }
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
                        "0.0.0.0:443"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "not": [
                                        {
                                            "remote_ip": {
                                                "ranges": [
                                                    "192.168.0.0/16"
                                                ]
                                            }
                                        }
                                    ]
                                }
                            ],
                            "handle": [
                                {
                                    "branch": [
                                        {
                                            "handler": "proxy",
                                            "upstreams": [
                                                {
                                                    "dial": [
                                                        "primary.machine.local:443"
                                                    ]
                                                }
                                            ]
                                        },
                                        {
                                            "handler": "proxy",
                                            "upstreams": [
                                                {
                                                    "dial": [
                                                        "secondary.machine.local:443"
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                    "handler": "tee"
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
