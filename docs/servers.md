---
title: Servers
---

# Servers

Servers define where Caddy listens for Layer 4 connections and/or packets and how those are handled.

## Purpose

Caddy-L4 is basically independent of Caddy's HTTP app in terms of what connections and/or packets it handles.
Servers act as distinct top-level configuration blocks that define network listener
while inner [Routes](/docs/routes.md) set the rules for handling the corresponding raw layer 4 traffic.

Note that the Layer 4 app can't bind to the same network addresses the HTTP app is bound to.
However, you can overcome this limitation with wrappers.

### Wrappers

It's sometimes beneficial to *interconnect* the Layer 4 app with the HTTP app, so that some layer 4 rules
could be applied to the traffic before it is consumed by the HTTP app. For this particular purpose,
the Layer 4 app is capable of running as a listener wrapper or a packet connection wrapper:

- **Listener Wrappers** are TCP-only (based on Go's `net.Listener`) servers that don’t directly bind to network
  addresses. Instead, they act as middleware, processing connections managed by Caddy’s HTTP app.
- **PacketConn Wrappers** are UDP-only (based on Go's `net.PacketConn`) servers that don’t directly bind to network
  addresses. Similar to listener wrappers, they act as middleware, processing connections managed by Caddy’s HTTP app.

Note that listener wrappers don't support QUIC since it's essentially UDP traffic, and packet connection wrappers
should be used instead.

## Syntax

A server may have one or many network addresses to bind to. Each network address is parsed with Caddy's
internal function `caddy.ParseNetworkAddress`, so the network address syntax may vary depending on Caddy's version.

Below is a list of valid [network address](https://caddyserver.com/docs/conventions#network-addresses) examples:

| Network address                    | Protocol | Port   | Server IP addresses |
|:-----------------------------------|:---------|:-------|:--------------------|
| `:1-1000`                          | TCP      | 1-1000 | any IPv4 or IPv6    |
| `tcp/:1001`                        | TCP      | 1001   | any IPv4 or IPv6    |
| `tcp4/:1002` or `tcp/0.0.0.0:1002` | TCP      | 1002   | any IPv4            |
| `tcp6/:1003` or `tcp/[::]:1003`    | TCP      | 1003   | any IPv6            |
| `tcp/192.168.0.1:1004`             | TCP      | 1004   | 192.168.0.1         |
| `tcp/[2001:db8::1]:1005`           | TCP      | 1005   | 2001:db8::1         |
| `udp/:1006`                        | UDP      | 1006   | any IPv4 or IPv6    |
| `udp4/:1007` or `udp/0.0.0.0:1007` | UDP      | 1007   | any IPv4            |
| `udp6/:1008` or `udp/[::]:1008`    | UDP      | 1008   | any IPv6            |
| `udp/127.0.0.1:1009`               | UDP      | 1009   | 127.0.0.1           |
| `udp/[fe80::1%eth0]:1010`          | UDP      | 1010   | fe80::1 on eth0     |

| Network address                     | Type       | Server socket path       |
|:------------------------------------|:-----------|:-------------------------|
| `unix//var/run/caddy-l4.sock`       | Unix       | `/var/run/caddy-l4.sock` |
| `unixgram//var/run/caddy-l4.sock`   | Unixgram   | `/var/run/caddy-l4.sock` |
| `unixpacket//var/run/caddy-l4.sock` | Unixpacket | `/var/run/caddy-l4.sock` |

Any server, listener wrapper or packet connection wrapper has `matching_timeout` field which is the maximum time
connections have to complete the matching phase (the first terminal handler is matched). By default, it equals 3s.

### Caddyfile

Standard layer 4 server blocks are placed inside `layer4` global directive, and each server block is introduced with
at least one network address. Wrappers are introduced with `layer4` directive inside `listener_wrappers` or
`packer_conn_wrappers` blocks of `servers` global directive:
```caddyfile
{
    layer4 {
        <network_address> [...] {
            # optionally adjust the matching timeout
            matching_timeout <duration>
            
            # put routes here
        }
        
        # put other servers here
    }
    
    servers [<listener_address>] {
        listener_wrappers {
            # the layer 4 server below handles any TCP traffic
            # that the HTTP app is set to receive, e.g. tcp/:80, tcp/:443
            # (constrained by <listener_address> if present)
            layer4 {
                # optionally adjust the matching timeout
                matching_timeout <duration>
                
                # put routes here
            }
            
            # put other pre-decryption listener wrappers here
            # e.g. http_redirect, proxy_protocol
            
            # note that `tls` directive goes below `layer4`
            # so that layer 4 rules apply to the traffic before
            # it gets decrypted and consumed by the HTTP app
            tls
            
            # put other post-decryption listener wrappers here
        }
        
        packet_conn_wrappers {
            # the layer 4 server below handles any UDP traffic
            # that the HTTP app is set to receive, e.g. udp/:443
            # (constrained by <listener_address> if present)
            layer4 {
                # optionally adjust the matching timeout
                matching_timeout <duration>
                
                # put routes here
            }
            
            # put other packet connection wrappers here
        }
    }
}
```

An example config of the Layer 4 app that echoes everything it gets on TCP4 port 8888:
```caddyfile
{
    layer4 {
        0.0.0.0:8888 {
            route {
                echo
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
                        "0.0.0.0:8888"
                    ],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "echo"
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

## HTTP/2 connection coalescing

Wrappers route whole connections, not individual requests. When a listener wrapper passes TLS traffic through
to an upstream based on SNI, the routing decision is made once, from the ClientHello. Connections it doesn't match
are decrypted and served by the HTTP app, and the Layer 4 app can't see or reroute any requests sent over them later.

HTTP/2 clients may reuse an existing connection for another hostname if the certificate presented on that connection
also covers that hostname (e.g. a wildcard certificate) and both hostnames resolve to the same IP address
(see [RFC 9113, Section 9.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1)). As a result, requests
for a hostname meant to be passed through may reach the HTTP app instead. If no HTTP route matches them, Caddy
responds with an empty `200`, which browsers display as a blank page.

To make clients retry such requests over a new connection with the correct SNI, enable `strict_sni_host` in the
`servers` global directive. Caddy then responds with `421 Misdirected Request` whenever the HTTP `Host` header
differs from the TLS SNI:
```caddyfile
{
    servers {
        strict_sni_host on
        listener_wrappers {
            layer4 {
                @app tls sni app.example.com
                route @app {
                    proxy app.internal:443
                }
            }
            tls
        }
    }
}
```

Note that `strict_sni_host` applies to all hostnames served by the HTTP app, so clients will also have to open
separate connections for those, and requests without SNI (e.g. by IP address) will be rejected. Alternatively,
respond with `421` only for the passed through hostnames in the HTTP app, e.g. `respond @passthrough 421` where
`@passthrough` is a `host` matcher, or avoid presenting certificates covering those hostnames in the HTTP app.
