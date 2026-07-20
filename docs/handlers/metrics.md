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

## Scraping the metrics

The `metrics` handler only *records* into Caddy's instance metrics registry — the
same registry Caddy uses for its own metrics. Exposing that registry for a
Prometheus scraper is done with Caddy's built-in metrics endpoints, so nothing
extra is needed in the `layer4` app itself.

There are two ways to expose it (see the [Caddy metrics docs](https://caddyserver.com/docs/metrics)):

### 1. The admin endpoint (default, zero-config)

Caddy permanently mounts a `/metrics` endpoint on its admin API (by default
`http://localhost:2019/metrics`, local-only). Once the `metrics` handler is in a
route, its counters appear there:

```console
$ curl -s localhost:2019/metrics | grep caddy_layer4
# HELP caddy_layer4_connections_total Total number of connections handled through the metrics handler.
# TYPE caddy_layer4_connections_total counter
caddy_layer4_connections_total 3
# HELP caddy_layer4_received_bytes_total Total number of bytes received from clients through the metrics handler.
# TYPE caddy_layer4_received_bytes_total counter
caddy_layer4_received_bytes_total 264
# HELP caddy_layer4_sent_bytes_total Total number of bytes sent to clients through the metrics handler.
# TYPE caddy_layer4_sent_bytes_total counter
caddy_layer4_sent_bytes_total 191
```

### 2. A dedicated scrape endpoint (HTTP app)

To expose the same metrics on a normal port (e.g. for a remote Prometheus),
serve them with the HTTP app's [`metrics`](https://caddyserver.com/docs/caddyfile/directives/metrics)
handler alongside the `layer4` app:

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

# a plain HTTP site that serves the shared registry for scraping
:9180 {
    metrics /metrics
}
```

Then point Prometheus at it:

```yaml
scrape_configs:
  - job_name: caddy-l4
    static_configs:
      - targets: ["localhost:9180"]
```

Because everything registers on the one shared registry, this endpoint also
carries Caddy's own metrics (and the [`proxy`](proxy.md) handler's
`caddy_layer4_proxy_*` metrics when that handler is used) next to the
`caddy_layer4_*` counters above.
