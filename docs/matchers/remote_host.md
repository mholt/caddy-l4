---
title: Remote Host Matcher
---

# Remote Host Matcher

## Summary

The Remote Host matcher matches connections based on the *remote* host name. The host
name is resolved from the remote IP with a reverse DNS (PTR) lookup, which is handy when
peers are easier to refer to by name than by address, for example containers on a Docker
network.

Because a lookup happens for every connection this matcher inspects, it is not free. Put
it behind a cheaper matcher, or restrict the listener, when it sits in a hot path.

## Syntax

The matcher has a `hosts` field that contains one or many host names. A name may be given
verbatim (`host.example.com`) or as a wildcard (`*.example.com`), which matches any
subdomain of `example.com`. Matching is case insensitive.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
remote_host <hosts...>
```

An example config of the Layer 4 app that proxies connections coming from any host under
`*.trusted.example` on TCP port 8080 to another machine:
```caddyfile
{
    layer4 {
        :8080 {
            @trusted remote_host *.trusted.example
            route @trusted {
                proxy another.machine.local:80
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
                      ":8080"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "remote_host": {
                                        "hosts": [
                                            "*.trusted.example"
                                        ]
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "another.machine.local:80"
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
