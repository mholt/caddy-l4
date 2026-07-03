---
title: Postgres Matcher
---

# Postgres Matcher

## Summary

The Postgres (PostgreSQL) matcher allows to match connections that look
like [Postgres Wire Protocol](https://www.postgresql.org/docs/current/protocol.html).
It does independent raw packet parsing under the hood.

## Syntax

By default the matcher matches any Postgres connection. It can optionally filter
on the contents of the first message the client sends. When more than one filter
is set, all must be satisfied.

- `user` maps a Postgres user name to the list of databases it is allowed to use.
  The special key `*` applies to any user that is not listed explicitly. An empty
  database list allows any database for that user.
- `client` is a list of accepted `application_name` values.
- `tls` constrains whether the connection must begin with an `SSLRequest`:
  `enabled` requires one, `disabled` requires its absence, and `*` (the default)
  is indifferent.

`user` and `client` are carried only by the StartupMessage, so an `SSLRequest`
never matches when either is set (and, conversely, `tls enabled` combined with a
`user`/`client` filter can never match, since those live on different messages).

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `postgres` matches any Postgres traffic
postgres

postgres {
    # repeat `user` for each entry; `*` is the wildcard user
    user <name> [<database>...]
    # match the application_name parameter
    client <name> [<name>...]
    # require (enabled) or reject (disabled) an SSLRequest; `*` is indifferent
    tls <enabled|disabled|*>
}
```

For example, allow `alice` only on `planets_db`/`stars_db`, and any other user
only on `public_db`, over plaintext connections:
```caddyfile
postgres {
    user alice planets_db stars_db
    user * public_db
    tls disabled
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
