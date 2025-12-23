---
title: XMPP Matcher
---

# XMPP Matcher

## Summary

The XMPP matcher allows to match connections that look like [XMPP](https://xmpp.org/about/technology-overview/).
It doesn't do independent raw packet parsing under the hood - it simply tries to find `jabber` in the first 50 bytes,
so it could produce some false positives.

## Syntax

The matcher has no fields and supports no [placeholders](https://caddyserver.com/docs/conventions#placeholders).

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `xmpp` matches any XMPP traffic
xmpp
```

An example config of the Layer 4 app that ...:
```caddyfile
{
    layer4 {
        :80 {
            @a xmpp
            route @a {
                proxy localhost:5222
            }
            route {
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
                            "match": [
                                {
                                    "xmpp": {}
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "localhost:5222"
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
