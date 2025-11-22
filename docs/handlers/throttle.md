---
title: Throttle Handler
---

# Throttle Handler

## Summary

The Throttle handler implements connection throttling to simulate slowness and latency.
It uses leaky bucket rate limiting under the hood.

## Syntax

The handler has the following optional fields:
- `latency` sets a delay before initial read on each connection;
- `read_burst_size` sets the maximum number of bytes to read at once (rate permitting) per connection.
  If a rate is specified, burst must be greater than zero; default is same as the rate (truncated to integer);
- `read_bytes_per_second` sets the number of bytes to read per second, per connection;
- `total_read_burst_size` sets the maximum number of bytes to read at once (rate permitting) across all
  connections ("per handler"). If a rate is specified, burst must be greater than zero; default is same as the rate
  (truncated to integer);
- `total_read_bytes_per_second` sets the number of bytes to read per second, across all connections ("per handler").

No [placeholders](https://caddyserver.com/docs/conventions#placeholders) are supported.

### Caddyfile

The handler supports the following syntax:
```caddyfile
throttle {
    latency <duration>
    read_burst_size <int>
    read_bytes_per_second <float>
    total_read_burst_size <int>
    total_read_bytes_per_second <float>
}
```

An example config of the Layer 4 app that throttles connections on TCP port 80 proxied to localhost:8080:
```caddyfile
{
    layer4 {
        :80 {
            route {
                throttle {
                    read_bytes_per_second 100000
                    total_read_bytes_per_second 500000
                    read_burst_size 20000
                    total_read_burst_size 100000
                    latency 2s
                }
                proxy localhost:8080
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
                        ":80"
                    ],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "throttle",
                                    "latency": 2000000000,
                                    "read_burst_size": 20000,
                                    "read_bytes_per_second": 100000,
                                    "total_read_burst_size": 100000,
                                    "total_read_bytes_per_second": 500000
                                },
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "localhost:8080"
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
