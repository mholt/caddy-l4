---
title: Postgres Matcher
---

# Postgres Matcher

## Summary

The Postgres (PostgreSQL) matcher allows to match connections that look
like [Postgres Wire Protocol](https://www.postgresql.org/docs/current/protocol.html).
It does independent raw packet parsing under the hood.

## Syntax

The matcher provides no configurable fields.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `postgres` matches any Postgres traffic
postgres
```

An example config of the Layer 4 app that multiplexes Postgres and anything else on TCP port 443:
```caddyfile
{
    layer4 {
        :443 {
            # proxy to postgres.machine.local:443
            # any Postgres traffic on TCP port 443
            @a postgres
            route @a {
                proxy postgres.machine.local:443
            }
            
            # otherwise proxy to fallback.machine.local:443
            route {
                proxy fallback.machine.local:443
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
                        ":443"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "postgres": {}
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "postgres.machine.local:443"
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
                                                "fallback.machine.local:443"
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
