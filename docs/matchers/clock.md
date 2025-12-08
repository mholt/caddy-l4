---
title: Clock Matcher
---

# Clock Matcher

## Summary

The clock matcher allows to match connections using the time when their matching occurs.
Do you need to restrict access to some resources in the night? Or use more proxy upstreams during the busy hours?
These are examples of the scenarios can be realised with this matcher.

## Syntax

The matcher returns true, if the connection matching time is greater than or equal to `after` AND less than `before`.
Both fields are mandatory, and each one accepts time in `15:04:05` format. If `before` has `00:00:00` value,
it is treated as `24:00:00`. If `after` is greater than `before`, these time points are automatically swapped.

The matcher also has `timezone` field, which is non-mandatory and may be used to match the time points in any IANA
time zone location or a custom fixed time zone defined by an offset (e.g. `+02`, `-03:30` or even `+12:34:56`)
other than the default UTC (use `Local` to have the system's local time zone).

All the matcher fields support [placeholders](https://caddyserver.com/docs/conventions#placeholders)
which are resolved at provision.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
clock <time_after> <time_before> [<time_zone>]

# shortcut for `clock <time_after> 24:00:00 [<time_zone>]`
clock <after|from> <time_after> [<time_zone>]

# shortcut for `clock 00:00:00 <time_before> [<time_zone>]`
clock <before|till|to|until> <time_before> [<time_zone>]
```

An example config of the Layer 4 app that proxies traffic on TCP ports 8080 and 8888 to different upstreams
depending on the time:
```caddyfile
{
    layer4 {
        :8080 {
            @night_m clock before 05:00:00
            @morning clock 05:00:00 12:00:00
            @afternoon clock 12:00:00 17:00:00
            @evening clock 17:00:00 21:00:00
            @night_e clock after 21:00:00
            route @night_m @night_e {
                proxy 00.upstream.local:8080
            }
            route @morning {
                proxy 01.upstream.local:8080 02.upstream.local:8080
            }
            route @afternoon {
                proxy 03.upstream.local:8080 04.upstream.local:8080 05.upstream.local:8080
            }
            route @evening {
                proxy 06.upstream.local:8080 07.upstream.local:8080
            }
        }
        :8888 {
            @la_is_awake clock 08:00:00 20:00:00 America/Los_Angeles
            route @la_is_awake {
                proxy existing.machine.local:8888
            }
            @la_is_asleep not clock 08:00:00 20:00:00 America/Los_Angeles
            route @la_is_asleep {
                proxy non-existing.machine.local:8888
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
                                    "clock": {
                                        "after": "00:00:00",
                                        "before": "05:00:00"
                                    }
                                },
                                {
                                    "clock": {
                                        "after": "21:00:00",
                                        "before": "00:00:00"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "00.upstream.local:8080"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "clock": {
                                        "after": "05:00:00",
                                        "before": "12:00:00"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "01.upstream.local:8080"
                                            ]
                                        },
                                        {
                                            "dial": [
                                                "02.upstream.local:8080"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "clock": {
                                        "after": "12:00:00",
                                        "before": "17:00:00"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "03.upstream.local:8080"
                                            ]
                                        },
                                        {
                                            "dial": [
                                                "04.upstream.local:8080"
                                            ]
                                        },
                                        {
                                            "dial": [
                                                "05.upstream.local:8080"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "clock": {
                                        "after": "17:00:00",
                                        "before": "21:00:00"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "06.upstream.local:8080"
                                            ]
                                        },
                                        {
                                            "dial": [
                                                "07.upstream.local:8080"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                },
                "srv1": {
                    "listen": [
                        ":8888"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "clock": {
                                        "after": "08:00:00",
                                        "before": "20:00:00",
                                        "timezone": "America/Los_Angeles"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "existing.machine.local:8888"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "not": [
                                        {
                                            "clock": {
                                                "after": "08:00:00",
                                                "before": "20:00:00",
                                                "timezone": "America/Los_Angeles"
                                            }
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
                                                "non-existing.machine.local:8888"
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
