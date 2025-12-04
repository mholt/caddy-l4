---
title: Not Matcher
---

# Not Matcher

## Summary

The Not matcher negates matching conditions, i.e. allows to match connections *not* matched by inner matching sets.

## Syntax

The matcher provides no configurable fields. It simply matches requests by negating the results of its matcher sets.
A single `not` matcher takes one or more matcher sets. Each matcher set is OR'ed, i.e., if any matcher set returns
true, the final result of the `not` matcher is false. Individual matchers within a set work the same (i.e. different
matchers in the same set are AND'ed).

Note: Caddyfile syntax provides for a single matcher set only, i.e. no OR logic is supported in terms of
the matcher's inner matchers. However, you may use multiple `not` matchers instead. JSON syntax supports
multiple matcher sets, i.e. OR logic may be realised with either many `not` matchers, or many matcher sets
inside a single `not` matcher.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# negate a single matcher with no block options
not <matcher>

# negate a single configurable matcher
not <matcher> {
    <option|submatcher> [<args...>]
}

# negate a matcher set of multiple matchers
not {
    <matcher> {
        <option|submatcher> [<args...>]
    }
    <matcher>
}
```

An example config of the Layer 4 app that proxies HTTP requests *not* for example.com on TCP port 80:
```caddyfile
{
    layer4 {
        :80 {
            @negation not http {
                host example.com
            }
            route @negation {
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
                                    "not": [
                                        {
                                            "http": [
                                                {
                                                    "host": [
                                                        "example.com"
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
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
