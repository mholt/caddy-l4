---
title: Postgres SSL Matcher
---

# Postgres SSL Matcher

## Summary

The Postgres SSL matcher matches a Postgres connection based on whether it
begins with an `SSLRequest`. By default it matches connections that request SSL;
with `disabled` it instead matches connections that do **not** request SSL.

It belongs to the same package as the [`postgres`](postgres.md) matcher. A
typical use is to split TLS-initiating connections from plaintext ones so each
can be routed differently (for example, terminating TLS on the SSL branch with
the [`postgres_starttls`](../handlers/postgres_starttls.md) handler).

## Syntax

- `disabled` (boolean, default `false`) inverts the match: when set, the matcher
  requires the absence of an `SSLRequest` instead of its presence.

### Caddyfile

```caddyfile
# match connections that request SSL
postgres_ssl

# match connections that do NOT request SSL
postgres_ssl disabled
```

An example that routes SSL and non-SSL Postgres connections to different
backends:
```caddyfile
{
    layer4 {
        :443 {
            @a postgres_ssl
            route @a {
                proxy secure.machine.local:443
            }
            @b postgres_ssl disabled
            route @b {
                proxy plaintext.machine.local:443
            }
        }
    }
}
```

### JSON

JSON equivalents:
```json
{
    "postgres_ssl": {}
}
```
```json
{
    "postgres_ssl": {
        "disabled": true
    }
}
```
