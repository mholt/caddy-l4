---
title: DNS Matcher
---

# DNS Matcher

## Summary

The DNS matcher allows to match connections that look like [DNS](https://www.rfc-editor.org/rfc/rfc1035).
The matcher uses [miekg/dns](https://github.com/miekg/dns) package to parse DNS messages under the hood.

Note: DNS messages sent via TCP are 2 bytes longer then those sent via UDP. Consequently, if Caddy listens on TCP,
it has to proxy DNS messages to TCP upstreams only. The same is true for UDP. No TCP/UDP mixing is allowed.
However, it's technically possible: an intermediary handler is required to add/strip 2 bytes before/after proxy.
Please open a feature request and describe your use case if you need TCP/UDP mixing.

## Syntax

The matcher has `allow` and `deny` fields to filter DNS traffic:
- `allow` contains an optional list of rules to match the question section of the DNS request message against. 
  The matcher returns false if not matched by any of them (in the absence of any deny rules).
- `deny` contains an optional list of rules to match the question section of the DNS request message against.
  The matcher returns false if matched by any of them  (in the absence of any allow rules).

A rule represents a set of filters to match against the question section of the DNS request message.
Full and regular expression matching filters are supported. If both filters are provided for a single field,
the full matcher is evaluated first. An empty rule matches anything.

Each allow and deny rule supports the following fields:
- `class` may contain a string value to match the question class. Use upper case letters, e.g. `IN`, `CH`, `ANY`.
  See the full list of valid class values in [dns.ClassToString](https://github.com/miekg/dns/blob/master/msg.go).
- `class_regexp` may contain a regular expression to match the question class. E.g. `^(IN|CH)$`.


- `name` may contain a string value to match the question domain name. E.g. `example.com.`.
  The domain name must be provided in lower case ending with a dot.
- `name_regexp` may contain a regular expression to match the question domain name.
  E.g. `^(|[-0-9a-z]+\.)example\.com\.$`.


- `type` may contain a string value to match the question type. Use upper case letters, e.g. `A`, `MX`, `NS`.
  See the full list of valid type values in [dns.TypeToString](https://github.com/miekg/dns/blob/master/ztypes.go).
- `type_regexp` may contain a regular expression to match the question type. E.g. `^(MX|NS)$`.

Regular expression fields including `class_regexp`, `name_regexp` and `type_regexp` support
[placeholders](https://caddyserver.com/docs/conventions#placeholders) which are resolved at provision.
Other rule fields including `class`, `name` and `type` support placeholders which are resolved at match.

The matcher also provides `default_deny` and `prefer_allow` fields to adjust filter restrictiveness:
- If `default_deny` is true, DNS request messages that haven't been matched by any allow and deny rules are denied.
  The default action is allow. Use it to make the filter more restrictive when the rules aren't exhaustive.
- If `prefer_allow` is true, DNS request messages that have been matched by both allow and deny rules are allowed.
  The default action is deny. Use it to make the filter less restrictive when the rules are mutually exclusive.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `dns` matches any DNS traffic
dns

# otherwise specify matcher options
dns {
    # multiple `allow`, `allow_regexp`, `deny` and `deny_regexp` options are allowed
    <allow|deny> <*|name> [<*|type> [<*|class>]]
    <allow_regexp|deny_regexp> <*|name_pattern> [<*|type_pattern> [<*|class_pattern>]]
    
    # unless `default_deny` is set, DNS request messages that haven't been matched
    # by `allow`, `allow_regexp`, `deny` or `deny_regexp` rules are allowed
    default_deny
    
    # unless `prefer_allow` is set, DNS request messages that have been matched
    # by both `allow` (or `allow_regexp`) and `deny` (or `deny_regexp`) rules are denied
    prefer_allow
}
```

Note: an asterisk should be used to skip filtering the corresponding question section field.
E.g., `deny * MX IN` option filters out any DNS request with IN class and MX type, while `allow caddyserver.com * IN`
option makes the matcher accept any DNS requests for `caddyserver.com` with IN class.

An example config of the Layer 4 app that proxies some DNS requests received on TCP port 8053 and UDP port 53:
```caddyfile
{
    layer4 {
        tcp/:8053 {
            # proxy to tcp/one.one.one.one:53
            # plain DNS messages received on TCP port 8053
            # requesting records of any type and any class
            # for example.com or any of its subdomains
            @a dns {
                allow_regexp ^(|[-0-9a-z]+\\.)example\\.com\\.$
                default_deny
            }
            route @a {
                proxy tcp/one.one.one.one:53
            }
            
            # match and terminate TLS on TCP port 8053, then proxy to tcp/one.one.one.one:53
            # inner DNS messages requesting records of NS type and any class for example.com
            # or records of any type and non-IN class for any domain (default action is allow),
            # otherwise proxy to localhost:80 any inner HTTP traffic
            @b tls
            route @b {
                tls
                subroute {
                    @c dns {
                        allow example.com. NS
                        deny * * IN
                        prefer_allow
                    }
                    route @c {
                        proxy tcp/one.one.one.one:53
                    }
                    @d http
                    route @d {
                        proxy localhost:80
                    }
                }
            }
        }
        
        # proxy to udp/one.one.one.one:53
        # plain DNS messages received on UDP port 53
        # requesting records of MX or NS type and any class for any domain
        udp/:53 {
            @d dns {
                deny_regexp * ^(MX|NS)$
            }
            route @d {
                proxy udp/one.one.one.one:53
            }
        }
    }
}

# put here other relevant config blocks to let Caddy know
# where certificates should come from for TLS termination 
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
                        "tcp/:8053"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "dns": {
                                        "allow": [
                                            {
                                                "name_regexp": "^(|[-0-9a-z]+\\\\.)example\\\\.com\\\\.$"
                                            }
                                        ],
                                      "default_deny": true
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "tcp/one.one.one.one:53"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "tls": {}
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "tls"
                                },
                                {
                                    "handler": "subroute",
                                    "routes": [
                                        {
                                            "handle": [
                                                {
                                                    "handler": "proxy",
                                                    "upstreams": [
                                                        {
                                                            "dial": [
                                                                "tcp/one.one.one.one:53"
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ],
                                            "match": [
                                                {
                                                    "dns": {
                                                        "allow": [
                                                            {
                                                                "name": "example.com.",
                                                                "type": "NS"
                                                            }
                                                        ],
                                                        "deny": [
                                                            {
                                                                "class": "IN"
                                                            }
                                                        ],
                                                        "prefer_allow": true
                                                    }
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
                                                                "localhost:80"
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ],
                                            "match": [
                                                {
                                                    "http": [
                                                        {}
                                                    ]
                                                }
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
                        "udp/:53"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "dns": {
                                        "deny": [
                                            {
                                                "type_regexp": "^(MX|NS)$"
                                            }
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
                                                "udp/one.one.one.one:53"
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
