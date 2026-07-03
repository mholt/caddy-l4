---
title: Postgres Matching Example
---

# Postgres Matching Example

## Summary

This example shows how to route or gate PostgreSQL connections with the
[`postgres`](/docs/matchers/postgres.md) matcher, which can filter on the
`user`/`database` pair, the `application_name`, and whether the connection
requests SSL.

The key thing to understand is **where each parameter lives in the protocol**:

- A client that wants TLS first sends an 8-byte `SSLRequest` (the `postgres`
  matcher's `ssl` option matches on this). That message carries **no**
  `user`/`database`/`application_name`.
- Only the later **StartupMessage** carries those parameters. On a plaintext
  connection it is the first message; on an SSL connection it is sent **after**
  the TLS handshake, so it is encrypted on the wire.

So `ssl enabled` and a `user`/`client` filter never match the same message. To
filter by user/database on an SSL connection you must terminate TLS first and
then match the (now cleartext) StartupMessage — see the second config below.

## Plaintext connections

Match the StartupMessage directly. Here `alice` may only reach `planets_db` and
`stars_db`, any other user may only reach `public_db`, and only `psql` or
`TablePlus` clients are allowed:

```caddyfile
{
    layer4 {
        :5432 {
            @pg_allowed postgres {
                user alice planets_db stars_db
                user * public_db
                client psql TablePlus
            }
            route @pg_allowed {
                proxy upstream.local:5432
            }
        }
    }
}
```

## SSL connections (terminate TLS, then match)

When clients connect with `sslmode` other than `disable`, gate on the
`SSLRequest`, terminate TLS with the
[`postgres_starttls`](/docs/handlers/postgres_starttls.md) handler followed by
`tls`, then re-match the decrypted StartupMessage inside a `subroute`:

```caddyfile
{
    layer4 {
        :5432 {
            @pg_ssl postgres {
                ssl enabled
            }
            route @pg_ssl {
                postgres_starttls
                tls
                subroute {
                    @pg_allowed postgres {
                        user alice planets_db stars_db
                        user * public_db
                        client psql TablePlus
                    }
                    route @pg_allowed {
                        proxy upstream.local:5432
                    }
                }
            }
        }
    }
}
```

After `tls` terminates the connection, the `subroute` sees the cleartext
StartupMessage, so the inner `postgres` matcher can filter on `user`/`database`
and `application_name` exactly as in the plaintext case.

> Note: this classic `SSLRequest` negotiation is different from PostgreSQL 17+
> direct-TLS (ALPN `postgresql`), which the standard `tls` handler/matcher
> handles on its own — see the [Postgres-over-TLS](/docs/examples/postgres-over-tls.md)
> example.
