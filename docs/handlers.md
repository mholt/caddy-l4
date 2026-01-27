---
title: Handlers
---

# Handlers

Handlers in Caddy-L4 are responsible for defining what action to take on a Layer 4 network connection —
such as TCP or UDP — once it has been matched by a route. They represent the "what to do" part of the configuration
after a matcher or a matcher set determines "whether this rule applies".

## Purpose

Handlers define the actions or processing steps applied to a matched connection.
Once a connection is accepted and passes the matcher conditions, the associated handler(s)
are executed to manage, forward, inspect, or terminate the connection.

Think of handlers as the "workers" that perform real work on the traffic.

## Available handlers

Caddy-L4 follows a modular design, where handlers act as pluggable components — similar to how Caddy-L4 itself
functions as a module within Caddy. This modularity allows Caddy to integrate custom Layer 4 handlers,
enabling seamless extensibility and enhanced functionality.

Handlers are categorized into different types based on their relationship with next handlers:
- **Terminal handlers** *never* call the next handler in the chain.
- **Intermediary handlers** *typically* call the next handler in the chain.
- **Special handlers** implement unique logic in terms of calling other handlers.

### Handlers included in the package:

| Type                  | Handler                                                | Implements                                                                                      |
|:----------------------|:-------------------------------------------------------|:------------------------------------------------------------------------------------------------|
| Terminal handlers     | [**close**](/docs/handlers/close.md)                   | Closing action for connection-oriented protocols, e.g. TCP                                      |
|                       | [**echo**](/docs/handlers/echo.md)                     | Echo server, i.e. sends back exactly what it receives                                           |
|                       | [**proxy**](/docs/handlers/proxy.md)                   | Layer 4 proxy, capable of multiple upstreams (with load balancing and health checks)            |
|                       | [**socks5**](/docs/handlers/socks5.md)                 | [SOCKSv5](https://www.rfc-editor.org/rfc/rfc1928) server                                        |
| Intermediary handlers | [**proxy_protocol**](/docs/handlers/proxy_protocol.md) | Receiving [HAProxy Proxy Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) |
|                       | [**tls**](/docs/handlers/tls.md)                       | TLS termination                                                                                 |
|                       | [**throttle**](/docs/handlers/throttle.md)             | Connection throttling to simulate slowness and latency                                          |
| Special handlers      | [**subroute**](/docs/handlers/subroute.md)             | Recursion logic, i.e. allows to match and handle already matched connections                    |
|                       | [**tee**](/docs/handlers/tee.md)                       | Branching logic, i.e. allows to handle connections with concurrent handler chains               |

The most frequently used handlers are `proxy` and `tls`. The former is capable of establishing new TLS connections
to backends, and together with the latter, they make Caddy-L4 a perfect solution for routing and load-balancing
TLS connections. 

## Contributing

Any handler should be placed into a separate Go file within a package starting with *l4* and have at least
the following code. The key part of the code is **Handle** function.

It is generally recommended to include comments that would be reasonably sufficient to understand how to use
the handler and what is going on under the hood.

```go
package l4dummy

import (
    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

    "github.com/mholt/caddy-l4/layer4"
)

func init() {
    caddy.RegisterModule(&HandleDummy{})
}

// HandleDummy is able to handle dummy connections.
type HandleDummy struct{
    /*
       put here any relevant options to modify handler behaviour
    */
}

// CaddyModule returns the Caddy module information.
func (*HandleDummy) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "layer4.handlers.dummy",
        New: func() caddy.Module { return new(HandleDummy) },
    }
}

// Handle handles the connection.
func (h *HandleDummy) Handle(cx *layer4.Connection, next layer4.Handler) error {
    /*
       put here any handling logic
    */
    
    return next.Handle(cx)
}

// UnmarshalCaddyfile sets up the HandleDummy from Caddyfile tokens. Syntax:
//
//    dummy
func (h *HandleDummy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
    /*
       put here wrapper name, same-line options and blocks parsing code
    */

    return nil
}

// Interface guards
var (
    _ caddyfile.Unmarshaler = (*HandleDummy)(nil)
    _ layer4.NextHandler    = (*HandleDummy)(nil)
)
```
