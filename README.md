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

Note that both Caddyfile and JSON configs are available at this time. More documentation will come soon. For now, please read the code, especially type definitions and their comments. It's actually a pretty simple code base. See below for tips and examples writing config.

> [!NOTE]
> This is not an official repository of the [Caddy Web Server](https://github.com/caddyserver) organization.

## Introduction

This app works similarly to the `http` app. You define servers, and each server consists of routes. A route has a set of matchers and handlers; if a connection matches, the associated handlers are invoked.

Current matchers:

- **layer4.matchers.clock** - matches connections on the time they are wrapped/matched.
- **layer4.matchers.dns** - matches connections that look like DNS connections.
- **layer4.matchers.http** - matches connections that start with HTTP requests. In addition, any [`http.matchers` modules](https://caddyserver.com/docs/modules/) can be used for matching on HTTP-specific properties of requests, such as header or path. Note that only the first request of each connection can be used for matching.
- **layer4.matchers.local_ip** - matches connections based on local IP (or CIDR range).
- **layer4.matchers.not** - matches connections that aren't matched by inner matcher sets.
- **layer4.matchers.openvpn** - matches connections that look like [OpenVPN](https://openvpn.net/community-resources/openvpn-protocol/) connections.
- **layer4.matchers.postgres** - matches connections that look like Postgres connections.
- **layer4.matchers.proxy_protocol** - matches connections that start with [HAPROXY proxy protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt).
- **layer4.matchers.quic** - matches connections that look like [QUIC](https://quic.xargs.org/). In addition, any [`tls.handshake_match` modules](https://caddyserver.com/docs/modules/) can be used for matching on TLS-specific properties of the ClientHello, such as ServerName (SNI).
- **layer4.matchers.rdp** - matches connections that look like [RDP](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-RDPBCGR/%5BMS-RDPBCGR%5D.pdf).
- **layer4.matchers.regexp** - matches connections that have the first packet bytes matching a regular expression.
- **layer4.matchers.remote_ip** - matches connections based on remote IP (or CIDR range).
- **layer4.matchers.socks4** - matches connections that look like [SOCKSv4](https://www.openssh.com/txt/socks4.protocol).
- **layer4.matchers.socks5** - matches connections that look like [SOCKSv5](https://www.rfc-editor.org/rfc/rfc1928.html).
- **layer4.matchers.ssh** - matches connections that look like SSH connections.
- **layer4.matchers.tls** - matches connections that start with TLS handshakes. In addition, any [`tls.handshake_match` modules](https://caddyserver.com/docs/modules/) can be used for matching on TLS-specific properties of the ClientHello, such as ServerName (SNI).
- **layer4.matchers.winbox** - matches connections that look like those initiated by [Winbox](https://help.mikrotik.com/docs/display/ROS/WinBox), a graphical tool for MikroTik hardware and software routers management.
- **layer4.matchers.wireguard** - matches connections the look like [WireGuard](https://www.wireguard.com/protocol/) connections.
- **layer4.matchers.xmpp** - matches connections that look like [XMPP](https://xmpp.org/about/technology-overview/).

Current handlers:

- **layer4.handlers.echo** - An echo server.
- **layer4.handlers.proxy** - Powerful layer 4 proxy, capable of multiple upstreams (with load balancing and health checks) and establishing new TLS connections to backends. Optionally supports sending the [HAProxy proxy protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt).
- **layer4.handlers.proxy_protocol** - Accepts the [HAPROXY proxy protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) on the receiving side.
- **layer4.handlers.socks5** - Handles [SOCKSv5](https://www.rfc-editor.org/rfc/rfc1928.html) proxy protocol connections.
- **layer4.handlers.subroute** - Implements recursion logic, i.e. allows to match and handle already matched connections.
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

This app supports Caddyfile, but you may also use Caddy's native JSON format to configure it. I highly recommend [this caddy-json-schema plugin by @abiosoft](https://github.com/abiosoft/caddy-json-schema) which can give you auto-complete and documentation right in your editor as you write your config!

See below for some examples to help you get started.


## Config examples

A simple echo server:

<details>
    <summary>Caddyfile</summary>

```
{
    layer4 {
        127.0.0.1:5000 {
            route {
                echo
            }
        }
    }
}
```
</details>
<details>
    <summary>JSON</summary>

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
</details>


A simple echo server with TLS termination that uses a self-signed cert for `localhost`:

<details>
    <summary>Caddyfile</summary>

```
{
    layer4 {
        127.0.0.1:5000 {
            route {
                tls
                echo
            }
        }
    }
}
```
</details>
<details>
    <summary>JSON</summary>

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
						"issuers": [{"module": "internal"}]
					}
				]
			}
		}
	}
}
```
</details>

A simple TCP reverse proxy that terminates TLS on 993, and sends the PROXY protocol header to 1143 through 143:

<details>
    <summary>Caddyfile</summary>

```
{
    layer4 {
        0.0.0.0:993 {
            route {
                tls
                proxy {
                    proxy_protocol v1
                    upstream localhost:143
                }
            }
        }
        0.0.0.0:143 {
            route {
                proxy_protocol
                proxy {
                    proxy_protocol v2
                    upstream localhost:1143
                }
            }
        }
    }
}
```
</details>
<details>
    <summary>JSON</summary>

```json
{
	"apps": {
		"layer4": {
			"servers": {
				"secure-imap": {
					"listen": ["0.0.0.0:993"],
					"routes": [
						{
							"handle": [
								{
									"handler": "tls"
								},
								{
									"handler": "proxy",
									"proxy_protocol": "v1",
									"upstreams": [
										{"dial": ["localhost:143"]}
									]
								}
							]
						}
					]
				},
				"normal-imap": {
					"listen": ["0.0.0.0:143"],
					"routes": [
						{
							"handle": [
								{
									"handler": "proxy_protocol"
								},
								{
									"handler": "proxy",
									"proxy_protocol": "v2",
									"upstreams": [
										{"dial": ["localhost:1143"]}
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
</details>

A multiplexer that proxies HTTP to one backend, and TLS to another (without terminating TLS):

<details>
    <summary>Caddyfile</summary>

```
{
    layer4 {
        127.0.0.1:5000 {
            @insecure http
            route @insecure {
                proxy localhost:80
            }
            @secure tls
            route @secure {
                proxy localhost:443
            }
        }
    }
}
```
</details>
<details>
    <summary>JSON</summary>

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
</details>

Same as previous, but only applies to HTTP requests with specific hosts:

<details>
    <summary>Caddyfile</summary>

```
{
    layer4 {
        127.0.0.1:5000 {
            @example http host example.com
            route @example {
                subroute {
                    @insecure http
                    route @insecure {
                        proxy localhost:80
                    }
                    @secure tls
                    route @secure {
                        proxy localhost:443
                    }
                }
            }
        }
    }
}
```
</details>
<details>
    <summary>JSON</summary>

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
									"handler": "subroute",
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
							]
						}
					]
				}
			}
		}
	}
}
```
</details>

Same as previous, but filter by HTTP Host header and/or TLS ClientHello ServerName:

<details>
    <summary>Caddyfile</summary>

```
{
    layer4 {
        127.0.0.1:5000 {
            @insecure http host example.com
            route @insecure {
                proxy localhost:80
            }
            @secure tls sni example.net
            route @secure {
                proxy localhost:443
            }
        }
    }
}
```
</details>
<details>
    <summary>JSON</summary>

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
</details>

Forwarding SOCKSv4 to a remote server and handling SOCKSv5 directly in caddy.  
While only allowing connections from a specific network and requiring a username and password for SOCKSv5.

<details>
    <summary>Caddyfile</summary>

```
{
    layer4 {
        0.0.0.0:1080 {
            @s5 {
                socks5
                remote_ip 10.0.0.0/24
            }
            route @s5 {
                socks5 {
                    credentials bob qHoEtVpGRM
                }
            }
            @s4 socks4
            route @s4 {
                proxy 10.64.0.1:1080
            }
        }
    }
}
```
</details>
<details>
    <summary>JSON</summary>

```json
{
	"apps": {
		"layer4": {
			"servers": {
				"socks": {
					"listen": ["0.0.0.0:1080"],
					"routes": [
						{
							"match": [
								{
									"socks5": {},
									"remote_ip": {"ranges": ["10.0.0.0/24"]}
								}
							],
							"handle": [
								{
									"handler": "socks5",
									"credentials": {
										"bob": "qHoEtVpGRM"
									}
								}
							]
						},
						{
							"match": [
								{
									"socks4": {}
								}
							],
							"handle": [
								{
									"handler": "proxy",
									"upstreams": [
										{"dial": ["10.64.0.1:1080"]}
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
</details>

## Placeholders support

Environment variables having `{$VAR}` syntax are supported in Caddyfile only. They are evaluated once at launch before Caddyfile is parsed.

Runtime placeholders having `{...}` syntax, including environment variables referenced as `{env.VAR}`, are supported in both Caddyfile and pure JSON, with some caveats described below.
- Options of *int*, *float*, *big.int*, *duration*, and other numeric types don't support runtime placeholders at all.
- Options of *string* type containing IPs or CIDRs (e.g. `remote_ip` matcher), regular expressions (e.g. `cookie_hash_regexp` of `rdp` matcher), or special values (e.g. `commands` and `credentials` of `socks5` handler)  support runtime placeholders, but they are evaluated __once at provision__ due to the existing optimizations. A special case is `dial` in `upstream` of `proxy` handler: it is evaluated 2 times: at handler provision for all known placeholders (e.g. `{env.*}`) and at dial for all placeholders (e.g. `{l4.*}`).
- Other options of *string* type (e.g. `alpn` of `tls` matcher) generally support runtime placeholders, and they are evaluated __each time at match or handle__. However, there are some exceptions, e.g. `tls_*` options inside `upstream` of `proxy` handler, and all options inside `connection_policy` of `tls` handler, that don't support runtime placeholders at all.

Please note that runtime placeholders support depends on handler/matcher implementations. Given some matchers and handlers are outside of this repository, it's up to their developers to support or restrict usage of runtime placeholders.
