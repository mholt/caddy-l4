---
title: Postgres Matcher
---

# Postgres Matcher

## Summary

The Postgres (PostgreSQL) matcher allows to match connections that look
like [Postgres Wire Protocol](https://www.postgresql.org/docs/current/protocol.html).
It does independent raw packet parsing under the hood.

This package also provides two companion matchers:
[`postgres_client`](postgres_client.md) (match on the `application_name`
parameter) and [`postgres_ssl`](postgres_ssl.md) (require or reject an
`SSLRequest`).

## Syntax

By default the matcher matches any Postgres connection. It can optionally filter
on the `user` and `database` parameters carried by the StartupMessage:

- `user` maps a Postgres user name to the list of databases it is allowed to use.
  The special key `*` applies to any user that is not listed explicitly. An empty
  database list allows any database for that user. The filter only applies to
  StartupMessages; an `SSLRequest` never matches when a `user` filter is set.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `postgres` matches any Postgres traffic
postgres

# filter on user/database pairs
postgres {
    # repeat `user` for each entry; `*` is the wildcard user
    user <name> [<database>...]
}
```

For example, allow `alice` only on `planets_db`/`stars_db`, and any other user
only on `public_db`:
```caddyfile
postgres {
    user alice planets_db stars_db
    user * public_db
}
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
