Project Conncept: a TCP/UDP app for Caddy
=======================================

**Project Conncept** is an experimental layer 4 app for Caddy. It facilitates composable handling of raw TCP/UDP
connections based on properties of the connection or the beginning of the stream.

With it, you can listen on sockets/ports and express logic such as:

- "Echo all input back to the client."
- "Proxy all the raw bytes to 10.0.3.14:1592."
- "If connection is TLS, terminate TLS then proxy all bytes to :5000."
- "Terminate TLS; then if it is HTTP, proxy to localhost:80; otherwise echo."
- "If connection is TLS, proxy to :443 without terminating; if HTTP, proxy to :80; if SSH, proxy to :22."
- "If the HTTP Host is `example.com` or the TLS ServerName is `example.com`, then proxy to 192.168.0.4."
- "Block connections from these IP ranges: ..."
- "Throttle data flow to simulate slow connections."
- And much more!

**⚠️ This app is very capable and flexible, but is still in development. Please expect breaking changes.**

Because this is a Caddy app, it can be used alongside other Caddy apps
such as the [HTTP server](https://caddyserver.com/docs/modules/http)
or [TLS certificate manager](https://caddyserver.com/docs/modules/tls).

**Documentation** is available in the [docs](/docs/) directory -- start with the [welcome page](/docs/README.md).
For better understanding, you may also read the code, especially type definitions and their comments.
It's actually a pretty simple code base. See below for tips and examples writing config.

> [!NOTE]
> This is not an official repository of the [Caddy Web Server](https://github.com/caddyserver) organization.

## Introduction

This app works similarly to the `http` app. You define [servers](/docs/servers.md), and each server consists of
[routes](/docs/routes.md). A route has a set of [matchers](/docs/matchers.md) and [handlers](/docs/handlers.md);
if a connection matches, the associated handlers are invoked.

Refer the docs for lists of [matchers](/docs/matchers.md) and [handlers](/docs/handlers.md) included in the package.


## Compiling

The recommended way is to use [xcaddy](https://github.com/caddyserver/xcaddy):

```
$ xcaddy build --with github.com/mholt/caddy-l4
```

Alternatively, to hack on the plugin code, you can clone it down, then build and run like so:

1. Download or clone this repo: `git clone https://github.com/mholt/caddy-l4.git`
2. In the project folder, run `xcaddy` just like you would run `caddy`.
   For example: `xcaddy list-modules --versions` (you should see the `layer4` modules).


## Writing config

This app supports Caddyfile, but you may also use Caddy's native JSON format to configure it.
I highly recommend [this caddy-json-schema plugin by @abiosoft](https://github.com/abiosoft/caddy-json-schema)
which can give you auto-complete and documentation right in your editor as you write your config!

See below for some examples to help you get started.


## Config examples

The following configuration examples are included in the documentation:
- [DNS-over-TLS](/docs/examples/dns-over-tls.md)
- [Echo Server](/docs/examples/echo_server.md)
- [HTTP & HTTPS Mix](/docs/examples/http_and_https_mix.md)
- [IMAPS with Proxy Protocol](/docs/examples/imaps_with_proxy_protocol.md)
- [Postgres-over-TLS](/docs/examples/postgres-over-tls.md)
- [SOCKS Proxy](/docs/examples/socks_proxy.md)
- [SSH-over-TLS](/docs/examples/ssh-over-tls.md)
- [TLS SNI Dynamic Upstreams](/docs/examples/tls_sni_dynamic_upstreams.md)

Other examples could be found in the documentation files describing specific matchers and handlers, as well as in
[issues](https://github.com/mholt/caddy-l4/issues) and [pull requests](https://github.com/mholt/caddy-l4/pulls).
