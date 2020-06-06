Project Conncept: a TCP/UDP app for Caddy
=======================================

**Project Conncept** is an experimental layer 4 app for Caddy. It facilitates composable handling of raw TCP/UDP connections based on properties of the connection or the beginning of the stream.

**⚠️ This app is highly capable, but still in development. Expect breaking changes.**

Because this is a caddy app, it can be used alongside other Caddy apps such as the HTTP server or TLS certificate manager.

Note that only JSON config is available at this time. More documentation will come soon. For now, please read the code, especially type definitions and their comments. It's actually a pretty simple code base, and the JSON config isn't that bad once you get used to it!


## Introduction

This app works similarly to the `http` app. You define servers, and each server consists of routes. A route has a set of matchers and handlers; if a connection matches, the assoicated handlers are invoked.

Current matchers:

- **layer4.matchers.http** - matches connections that start with HTTP requests. Any [`http.matchers` modules](https://caddyserver.com/docs/modules/) can be used as well for matching on HTTP-specific properties of requests, such as header or path.
- **layer4.matchers.tls** - matches connections that start with TLS handshakes. Any [`tls.handshake_match` modules](https://caddyserver.com/docs/modules/) can be used as well for matching on TLS-specific properties of the ClientHello, such as ServerName (SNI).
- **layer4.matchers.ssh** - matches conections that look like SSH connections.
- **layer4.matchers.ip** - matches conections based on remote IP (or CIDR range).

Current handlers:

- **layer4.handlers.echo** - An echo server.
- **layer4.handlers.proxy** - Layer 4 proxy, capable of multiple upstreams (and eventually health checks and load balancing) and establishing a new TLS connection to the backend(s).
- **layer4.handlers.tee** - Branches the handling of a connection into a concurrent handler chain.
- **layer4.handlers.tls** - TLS termination.

Like the `http` app, some handlers are "terminal" meaning that they don't call the next handler in the chain. For example: echo and proxy are terminal handlers.


## Compiling

You can run Caddy with this module plugged in quite easily: 

1. Download or clone this repo: `git clone https://github.com/mholt/caddy-l4.git`
2. In the project folder, run `xcaddy` just like you would run `caddy`. For example: `xcaddy list-modules --versions`

That's it! You can grab [`xcaddy` from here](https://github.com/caddyserver/xcaddy).

This flow allows you to hack on the code, too.


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
