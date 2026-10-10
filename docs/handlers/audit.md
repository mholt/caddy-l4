---
title: Audit Handler
---

# Audit Handler

## Summary

The Audit handler emits one structured audit log record for every connection it handles: *who*
connected (remote address), *what* they asked for (the TLS SNI, when a ClientHello is available
in the connection's prefetched bytes) and the *decision* (`verdict`, a free-form label assigned by
the config author).

In a layer 4 firewall every decision *is* a route, so placing the handler in a route labels that
route's decision — the handler is reached if and only if the route matched. The handler is fully
transparent: it only peeks at the prefetched bytes (never consuming them, so subsequent handlers
such as `proxy` still receive them), it never fails a connection because of audit parsing, and it
always continues the chain.

Records are written at INFO level to the logger named `layer4.handlers.audit`; a `log` block with
`include layer4.handlers.audit` routes them to a dedicated audit sink (see the example below).

## Syntax

The handler has the following required field:
- `verdict` is the label recorded in the audit record of every connection, e.g. `allowed` or `denied`.
  Any string is accepted; the module assigns it no semantics.

No [placeholders](https://caddyserver.com/docs/conventions#placeholders) are supported.

### Caddyfile

The handler supports the following syntax:
```caddyfile
audit <verdict>
```

An example config of the Layer 4 app used as a public TLS firewall: each connection gets one audit
record, either `allowed` (forwarded to the internal backend) or `denied` (blackholed), and the records
land in their own log file:
```caddyfile
{
	log "l4-audit" {
		output file /var/log/caddy/l4_audit.log
		include layer4.handlers.audit
	}
	layer4 {
		0.0.0.0:443 {
			@rsvp tls sni rsvp.example.com
			route @rsvp {
				audit allowed
				proxy 10.0.3.14:443
			}
			route {
				audit denied
				proxy 127.0.0.1:9
			}
		}
	}
}
```

Each connection produces exactly one record:
```json
{"level":"info","logger":"layer4.handlers.audit","msg":"audit","verdict":"denied","network":"tcp","local":"0.0.0.0:443","remote":"203.0.113.7:55000","sni":"evil.example.com"}
```

The `sni` field is only present when a TLS ClientHello with a server name has been prefetched by
a matcher before the handler runs — with the config above, the `tls sni` matcher on the first route
reads every ClientHello, so both routes record the SNI. A non-TLS connection (e.g. a plain-HTTP probe)
yields the same record without `sni`, and in a route with no matchers at all nothing has been prefetched,
so the record is likewise emitted without `sni`.

### JSON

JSON equivalent to the caddyfile config provided above (note how Caddy adds the `exclude` filter to
the default logger so that audit records do not appear there twice):
```json
{
    "logging": {
        "logs": {
            "default": {
                "exclude": [
                    "layer4.handlers.audit"
                ]
            },
            "l4-audit": {
                "writer": {
                    "filename": "/var/log/caddy/l4_audit.log",
                    "output": "file"
                },
                "include": [
                    "layer4.handlers.audit"
                ]
            }
        }
    },
    "apps": {
        "layer4": {
            "servers": {
                "srv0": {
                    "listen": [
                        "0.0.0.0:443"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "tls": {
                                        "sni": [
                                            "rsvp.example.com"
                                        ]
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "audit",
                                    "verdict": "allowed"
                                },
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "10.0.3.14:443"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "handle": [
                                {
                                    "handler": "audit",
                                    "verdict": "denied"
                                },
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "127.0.0.1:9"
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
