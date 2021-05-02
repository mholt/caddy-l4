Project Conncept: a TCP/UDP app for Caddy
=======================================

**Project Conncept** is an experimental layer 4 app for Caddy. It facilitates composable handling of raw TCP/UDP connections based on properties of the connection or the beginning of the stream.

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

Because this is a caddy app, it can be used alongside other Caddy apps such as the [HTTP server](https://caddyserver.com/docs/modules/http) or [TLS certificate manager](https://caddyserver.com/docs/modules/tls).

Note that only JSON config is available at this time. More documentation will come soon. For now, please read the code, especially type definitions and their comments. It's actually a pretty simple code base, and the JSON config isn't that bad once you get used to it! See below for tips and examples writing config.


## Introduction

This app works similarly to the `http` app. You define servers, and each server consists of routes. A route has a set of matchers and handlers; if a connection matches, the assoicated handlers are invoked.

Current matchers:

- **layer4.matchers.http** - matches connections that start with HTTP requests. In addition, any [`http.matchers` modules](https://caddyserver.com/docs/modules/) can be used for matching on HTTP-specific properties of requests, such as header or path. Note that only the first request of each connection can be used for matching.
- **layer4.matchers.tls** - matches connections that start with TLS handshakes. In addition, any [`tls.handshake_match` modules](https://caddyserver.com/docs/modules/) can be used for matching on TLS-specific properties of the ClientHello, such as ServerName (SNI).
- **layer4.matchers.ssh** - matches connections that look like SSH connections.
- **layer4.matchers.ip** - matches connections based on remote IP (or CIDR range).

Current handlers:

- **layer4.handlers.echo** - An echo server.
- **layer4.handlers.proxy** - Powerful layer 4 proxy, capable of multiple upstreams (with load balancing and health checks) and establishing new TLS connections to backends. Optionally supports [HAProxy proxy protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt).
- **layer4.handlers.tee** - Branches the handling of a connection into a concurrent handler chain.
- **layer4.handlers.throttle** - Throttle connections to simulate slowness and latency.
- **layer4.handlers.tls** - TLS termination.

Like the `http` app, some handlers are "terminal" meaning that they don't call the next handler in the chain. For example: `echo` and `proxy` are terminal handlers because they consume the client's input.


## Compiling

The recommended way is to use [xcaddy](https://github.com/caddyserver/xcaddy):

```
$ xcaddy build --with github.com/mholt/caddy-l4
```

Alternatively, to hack on the plugin code, you can clone it down, then build and run like so:

1. Download or clone this repo: `git clone https://github.com/mholt/caddy-l4.git`
2. In the project folder, run `xcaddy` just like you would run `caddy`. For example: `xcaddy list-modules --versions` (you should see the `layer4` modules).


## Writing config

Since this app does not support Caddyfile (yet?), you will have to use Caddy's native JSON format to configure it. I highly recommend [this caddy-json-schema plugin by @abiosoft](https://github.com/abiosoft/caddy-json-schema) which can give you auto-complete and documentation right in your editor as you write your config!

See below for some examples to help you get started.


## Config examples

A simple echo server:

```json
{
	"apps": {
		"layer4": {
			"servers": {
				"example": {
					"listen": ["127.0.0.1:5000"],
					"routes": [
						{
							"handle": [
								{"handler": "echo"}
							]
						}
					]
				}
			}
		}
	}
}
```


A simple echo server with TLS termination that uses a self-signed cert for `localhost`:

```json
{
	"apps": {
		"layer4": {
			"servers": {
				"example": {
					"listen": ["127.0.0.1:5000"],
					"routes": [
						{
							"handle": [
								{"handler": "tls"},
								{"handler": "echo"}
							]
						}
					]
				}
			}
		},
		"tls": {
			"certificates": {
				"automate": ["localhost"]
			},
			"automation": {
				"policies": [
					{
						"issuer": {"module": "internal"}
					}
				]
			}
		}
	}
}
```

A simple TCP reverse proxy with SSL termination on port 993 and proxy protocol to upstreams:

```json
{
	"apps": {
		"layer4": {
			"servers": {
				"imap-example": {
					"listen": ["0.0.0.0:993"],
					"routes": [
						{
							"handle": [
								{
									"handler": "tls",
								},
								{
									"handler": "proxy",
									"proxy_protocol": "v1",
									"upstreams": [
										{"dial": ["localhost:1143"]}
									]
								}
							]
						}
					]
				},
				"imaps-example": {
					"listen": ["0.0.0.0:143"],
					"routes": [
						{
							"handle": [
								{
									"handler": "proxy",
									"proxy_protocol": "v2",
									"upstreams": [
										{"dial": ["localhost:143"]}
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

A multiplexer that proxies HTTP to one backend, and TLS to another (without terminating TLS):

```json
{
	"apps": {
		"layer4": {
			"servers": {
				"example": {
					"listen": ["127.0.0.1:5000"],
					"routes": [
						{
							"match": [
								{
									"http": []
								}
							],
							"handle": [
								{
									"handler": "proxy",
									"upstreams": [
										{"dial": ["localhost:80"]}
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
									"handler": "proxy",
									"upstreams": [
										{"dial": ["localhost:443"]}
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



Same as previous, but filter by HTTP Host header and/or TLS ClientHello ServerName:

```json
{
	"apps": {
		"layer4": {
			"servers": {
				"example": {
					"listen": ["127.0.0.1:5000"],
					"routes": [
						{
							"match": [
								{
									"http": [
										{"host": ["example.com"]}
									]
								}
							],
							"handle": [
								{
									"handler": "proxy",
									"upstreams": [
										{"dial": ["localhost:80"]}
									]
								}
							]
						},
						{
							"match": [
								{
									"tls": {
										"sni": ["example.net"]
									}
								}
							],
							"handle": [
								{
									"handler": "proxy",
									"upstreams": [
										{"dial": ["localhost:443"]}
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
