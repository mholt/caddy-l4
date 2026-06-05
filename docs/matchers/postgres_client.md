---
title: Postgres Client Matcher
---

# Postgres Client Matcher

## Summary

The Postgres Client matcher matches Postgres connections whose StartupMessage
carries an `application_name` parameter equal to one of the configured client
names. This is useful to route or gate connections based on the client tool
(e.g. `psql`, `pgAdmin`, `TablePlus`) that advertises itself.

It belongs to the same package as the [`postgres`](postgres.md) matcher and
relies on the same raw StartupMessage parsing. Connections that begin with an
`SSLRequest` (which carries no parameters) never match.

## Syntax

- `client` is the list of accepted `application_name` values. A connection
  matches when its `application_name` is exactly one of them.

### Caddyfile

```caddyfile
# match connections whose application_name is psql or TablePlus
postgres_client <name> [<name>...]
```

An example that proxies known GUI clients to one backend and everything else
to a fallback:
```caddyfile
{
    layer4 {
        :443 {
            @a postgres_client psql TablePlus
            route @a {
                proxy postgres.machine.local:443
            }
            route {
                proxy fallback.machine.local:443
            }
        }
    }
}
```

### JSON

JSON equivalent to the matcher block above:
```json
{
    "postgres_client": {
        "client": [
            "psql",
            "TablePlus"
        ]
    }
}
```
