---
title: Welcome
---

# Welcome to Caddy Layer 4

Caddy-L4, originally known as *Project Conncept*, is a Layer 4 app for Caddy.

This app provides a high-performance, modular, and configurable way to handle raw TCP/UDP traffic,
making it ideal for non-HTTP services while leveraging Caddy’s strengths in TLS automation and ease of use.
Its architecture ensures scalability, observability, and flexibility for diverse networking needs.

## Introduction

The Layer 4 app is designed to handle **low-level, non-HTTP network traffic** (TCP, UDP, and Unix sockets)
at the transport layer (OSI Layer 4). Its key purposes include:
- **Proxying Raw TCP/UDP Traffic** – Forwarding connections for protocols like SSH, databases (MySQL, PostgreSQL),
  gaming servers, or custom TCP/UDP services.
- **Port-Based Routing** – Directing traffic based on ports without needing HTTP-specific logic.
- **TLS Termination** – Offloading TLS encryption/decryption for non-HTTP protocols.
- **Load Balancing** – Distributing Layer 4 traffic across backend servers.
- **Protocol Agnosticism** – Supporting any protocol that operates over TCP/UDP
  (unlike Caddy’s HTTP-focused Layer 7 apps).

Difference from Layer 7 (HTTP):
- **Layer 4** deals with raw connections (no HTTP headers, paths, etc.).
- **Layer 7** (Caddy’s HTTP app) handles HTTP-specific features like virtual hosts, cookies, and REST APIs.

Caddy’s Layer 4 app extends its capabilities beyond web traffic, making it a flexible reverse proxy
for diverse networking needs.

## Architecture

The Layer 4 app has a modular and flexible architecture that integrates seamlessly with Caddy’s overall design.
Below is a breakdown of its key architectural components:
- [**Matchers**](/docs/matchers.md) - Do protocol inspection (e.g., detect OpenVPN, RDP, SSH) and filtering
  (e.g., by client IP, time, specific protocol fields).
- [**Handlers**](/docs/handlers.md) - Process each incoming connection (e.g., proxy traffic to backends, terminate TLS) in a chain
  (one by one).
- [**Routes**](/docs/routes.md) - Define sets of matchers and handlers. If a connection matches,
  the associated handlers are invoked.
- [**Servers**](/docs/servers.md) - Apply routes to raw socket connections (TCP/UDP/Unix sockets),
  whether separate ones or those the HTTP app gets bound to.

## Configuration

Both Caddyfile and JSON syntax options are generally available with Caddyfile being the newer and preferred one.
For backwards compatibility, JSON equivalents are provided for almost all Caddyfile configuration examples --
they show how Caddy unmarshalls Caddyfile blocks and options into JSON structures.

## Placeholders

Environment variables having `{$VAR}` syntax are supported in Caddyfile only. They are evaluated once at launch
before Caddyfile is parsed.

Runtime [placeholders](https://caddyserver.com/docs/conventions#placeholders) having `{...}` syntax, including
environment variables referenced as `{env.VAR}`, are supported in both Caddyfile and pure JSON, with some caveats
described below.
- Options of *int*, *float*, *big.int*, *duration*, and other numeric types don't support runtime placeholders at all.
- Options of *string* type containing IPs or CIDRs (e.g. `remote_ip` matcher),
  regular expressions (e.g. `cookie_hash_regexp` of `rdp` matcher), or
  special values (e.g. `commands` and `credentials` of `socks5` handler) support runtime placeholders,
  but they are evaluated **once at provision** due to the existing optimizations. A special case is `dial`
  in `upstream` of `proxy` handler: it is evaluated 2 times: at handler provision for all known placeholders
  (e.g. `{env.*}`) and at dial for all remaining placeholders (e.g. `{l4.*}`).
- Other options of *string* type (e.g. `alpn` of `tls` matcher) generally support runtime placeholders,
  and they are evaluated **each time at match or handle**. However, there are some exceptions, e.g. `tls_*` options
  inside `upstream` of `proxy` handler, and all options inside `connection_policy` of `tls` handler, that don't support
  runtime placeholders at all.

Note: runtime placeholders support depends on handler/matcher implementations. Given some matchers and handlers
are outside of this repository, it's up to their developers to support or restrict usage of runtime placeholders.
For the matchers and handlers included in the package, placeholder support is explicitly described in the docs.
