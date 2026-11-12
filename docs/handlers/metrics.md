---
title: Metrics Handler
---

# Metrics Handler

## Summary

The Metrics handler is a passthrough handler that records the traffic of the
rest of its handler chain to Prometheus under a required tag. It counts every
connection that passes through it and, once the rest of the chain has finished,
adds the bytes received and sent *since the handler started* to counters.

The handler measures a **delta**: it snapshots the connection's byte counters
when it starts and subtracts the snapshot from the final values. Bytes that were
prefetched for matching and are replayed to the handler chain count as received
by the first handler that reads them. This means that:

- a `metrics` handler placed *before* `tls` measures the raw on-the-wire
  traffic, handshake included;
- a `metrics` handler placed *after* `tls` measures only the decrypted traffic.

Place several tagged handlers in a config to compare stages. Using the same tag
in several places adds their numbers up.

## Long-lived connections

Values are recorded **when the connection ends**. A proxied tunnel that stays
open for hours reports nothing until it closes, and then appears as a single
spike. Keep this in mind when graphing or alerting on these counters.

## Known limitation

The totals are read when the handler's downstream returns. A `metrics` handler
placed in front of a handler that hijacks the connection (for example, some
`listener_wrappers` that take the connection over) may therefore under-count.
Place `metrics` after such handlers.

## Exported metrics

All metrics are registered on Caddy's instance metrics registry (reset across
config reloads), each with a `tag` label holding the handler's tag:

- `caddy_layer4_handler_connections_total` — total number of connections handled
  through the handler;
- `caddy_layer4_handler_received_bytes_total` — total number of bytes received
  from clients;
- `caddy_layer4_handler_sent_bytes_total` — total number of bytes sent to
  clients.

The set of tags is limited by the config, so cardinality stays bounded.

## Syntax

The tag is required; the handler fails to provision (and the Caddyfile fails to
parse) without one.

### Caddyfile

The handler supports the following syntax:
```caddyfile
metrics <tag>
```

An example config that collects connection metrics for TCP port 5432 proxied to
a Postgres backend:
```caddyfile
{
    layer4 {
        :5432 {
            route {
                metrics postgres
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
    "handler": "metrics",
    "tag": "postgres"
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
$ curl -s localhost:2019/metrics | grep caddy_layer4_handler
# HELP caddy_layer4_handler_connections_total Total number of connections handled through the metrics handler, labeled by tag.
# TYPE caddy_layer4_handler_connections_total counter
caddy_layer4_handler_connections_total{tag="postgres"} 3
# HELP caddy_layer4_handler_received_bytes_total Total number of bytes received from clients through the metrics handler, labeled by tag.
# TYPE caddy_layer4_handler_received_bytes_total counter
caddy_layer4_handler_received_bytes_total{tag="postgres"} 264
# HELP caddy_layer4_handler_sent_bytes_total Total number of bytes sent to clients through the metrics handler, labeled by tag.
# TYPE caddy_layer4_handler_sent_bytes_total counter
caddy_layer4_handler_sent_bytes_total{tag="postgres"} 191
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
                metrics postgres
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
`caddy_layer4_handler_*` counters above.
