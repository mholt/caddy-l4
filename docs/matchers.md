---
title: Matchers
---

# Matchers

Matchers in Caddy-L4 are used to conditionally apply configurations based on properties of Layer 4 network traffic —
such as TCP or UDP connections — before forwarding or processing the traffic.

## Purpose

Matchers determine which connections a particular route or handler should apply to, based on characteristics of
the incoming connection. They are essential for routing decisions at Layer 4. Common matching criteria:
- Source IP address or CIDR (e.g., `192.168.1.0/24`)
- Protocol (e.g., DNS, HTTP, SSH, WireGuard)
- TLS client hello (e.g., ALPN, SNI).

Matchers enable fine-grained control over how Caddy-L4 handles different types of Layer 4 traffic.
Without them, all connections would be treated the same, making advanced routing or security policies impossible.

### Use cases enabled by matchers:
- **TLS SNI Routing**: Route TLS connections to different backends based on the SNI hostname
  (similar to HTTP virtual hosting, but at Layer 4).
- **Geo-based Access Control**: Allow or deny connections based on source IP geolocation.
- **Port Multiplexing**: Serve multiple services (e.g., SSH, TLS proxy) on the same IP
  by inspecting connection properties.
- **Security Policies**: Block or log connections from suspicious IPs.

## Available matchers

Caddy-L4 follows a modular design, where matchers act as pluggable components — similar to how Caddy-L4 itself
functions as a module within Caddy. This modularity allows Caddy to integrate custom Layer 4 matchers,
enabling seamless extensibility and enhanced functionality.

Matchers are categorized into different types based on their function:
- **Data matchers** inspect the raw bytes of the first incoming packet.
- **IP matchers** filter connections by source or destination addresses.
- **Special matchers** apply unique conditions (e.g., time-based rules) or adjust the behavior of other matchers.

### Matchers included in the package:

| Type             | Matcher                                                | Matches connections [^1]                                                                                                   |
|:-----------------|:-------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------|
| Data matchers    | [**dns**](/docs/matchers/dns.md)                       | Looking like [DNS](https://www.rfc-editor.org/rfc/rfc1035)                                                                 |
|                  | [**http**](/docs/matchers/http.md)                     | Starting with HTTP requests                                                                                                |
|                  | [**openvpn**](/docs/matchers/openvpn.md)               | Looking like [OpenVPN](https://openvpn.net/community-resources/openvpn-protocol/)                                          |
|                  | [**postgres**](/docs/matchers/postgres.md)             | Looking like [Postgres Wire Protocol](https://www.postgresql.org/docs/current/protocol.html)                               |
|                  | [**proxy_protocol**](/docs/matchers/proxy_protocol.md) | Starting with [HAProxy Proxy Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)                        |
|                  | [**quic**](/docs/matchers/quic.md)                     | Looking like [QUIC](https://quic.xargs.org/)                                                                               |
|                  | [**rdp**](/docs/matchers/rdp.md)                       | Looking like [RDP](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-RDPBCGR/%5BMS-RDPBCGR%5D.pdf) |
|                  | [**regexp**](/docs/matchers/regexp.md)                 | Satisfying a regular expression                                                                                            |
|                  | [**socks4**](/docs/matchers/socks4.md)                 | Looking like [SOCKSv4](https://www.openssh.com/txt/socks4.protocol)                                                        |
|                  | [**socks5**](/docs/matchers/socks5.md)                 | Looking like [SOCKSv5](https://www.rfc-editor.org/rfc/rfc1928)                                                             |
|                  | [**ssh**](/docs/matchers/ssh.md)                       | Looking like [SSH](https://www.rfc-editor.org/rfc/rfc4253)                                                                 |
|                  | [**tls**](/docs/matchers/tls.md)                       | Starting with TLS handshakes                                                                                               |
|                  | [**winbox**](/docs/matchers/winbox.md)                 | Initiated by [MikroTik WinBox](https://help.mikrotik.com/docs/display/ROS/WinBox) [^2]                                     |
|                  | [**wireguard**](/docs/matchers/wireguard.md)           | Looking like [WireGuard](https://www.wireguard.com/protocol/)                                                              |
|                  | [**xmpp**](/docs/matchers/xmpp.md)                     | Looking like [XMPP](https://xmpp.org/about/technology-overview/)                                                           |
| IP matchers      | [**local_ip**](/docs/matchers/local_ip.md)             | Based on *local* IP (or CIDR range)                                                                                        |
|                  | [**remote_ip**](/docs/matchers/remote_ip.md)           | Based on *remote* IP (or CIDR range)                                                                                       |
|                  | [**remote_ip_list**](/docs/matchers/remote_ip_list.md) | Based on *remote* IP (or CIDR range)                                                                                       |
| Special matchers | [**clock**](/docs/matchers/clock.md)                   | Based on *time of matching*                                                                                                |
|                  | [**not**](/docs/matchers/not.md)                       | *Not* matched by inner matcher sets                                                                                        |

[^1]: Both *starting with* and *looking like* refer to matching bytes of the first incoming packet *only*.

[^2]: WinBox is a graphical tool for MikroTik hardware and software routers management.

## Contributing

Any matcher should be placed into a separate Go file within a package starting with *l4* and have at least
the following code. The key part of the code is **Match** function. Try to save resources and keep it as tiny
as possible, since Caddy may process thousands of incoming packets per second, and this function is called
every time a new connection is established.

It is generally recommended to include comments that would be reasonably sufficient to understand how to use
the matcher and what is going on under the hood.

```go
package l4dummy

import (
    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

    "github.com/mholt/caddy-l4/layer4"
)

func init() {
    caddy.RegisterModule(&MatchDummy{})
}

// MatchDummy is able to match dummy connections.
type MatchDummy struct{
    /*
        put here any relevant options to modify matcher behaviour
     */
}

// CaddyModule returns the Caddy module information.
func (*MatchDummy) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "layer4.matchers.dummy",
        New: func() caddy.Module { return new(MatchDummy) },
    }
}

// Match returns true if the connection satisfies the applicable criteria.
func (m *MatchDummy) Match(cx *layer4.Connection) (bool, error) {
    /* 
        put here any matching logic
     */
    
    return true, nil
}

// UnmarshalCaddyfile sets up the MatchDummy from Caddyfile tokens. Syntax:
//
//    dummy
func (m *MatchDummy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
    /*
        put here wrapper name, same-line options and blocks parsing code
     */

    return nil
}

// Interface guards
var (
    _ layer4.ConnMatcher    = (*MatchDummy)(nil)
    _ caddyfile.Unmarshaler = (*MatchDummy)(nil)
)
```
