---
title: Metrics Handler
---

# Metrics Handler

## Summary

The Metrics handler is a passthrough handler that records per-connection traffic
metrics to Prometheus. It counts every connection that passes through it and,
once the rest of the handler chain has finished, adds the connection's bytes
received and sent to counters.

Place it early in a route so it wraps the whole chain. Because layer4's byte
accounting is kept on the underlying connection, the counts reflect the raw
on-the-wire traffic even when a later handler (such as `tls`) terminates the
connection.

## Exported metrics

All metrics are registered on Caddy's instance metrics registry (reset across
config reloads) under the `caddy_layer4` subsystem:

- `caddy_layer4_connections_total` — total number of connections handled through
  the handler;
- `caddy_layer4_received_bytes_total` — total number of bytes received from
  clients;
- `caddy_layer4_sent_bytes_total` — total number of bytes sent to clients.

## Syntax

The handler has no configurable fields.

### Caddyfile

The handler supports the following syntax:
```caddyfile
metrics
```

An example config that collects connection metrics for TCP port 5432 proxied to
a Postgres backend:
```caddyfile
{
    layer4 {
        :5432 {
            route {
                metrics
                proxy localhost:5433
            }
        }
    }
}
```

### JSON

JSON equivalent to the handler in the config above:
```json
{
    "handler": "metrics"
}
```
