---
title: Vars Handler
---

# Vars Handler

## Summary

The Vars handler enables to set custom variables to have values that can be used in the Layer 4 connection handler
chain. It's similar to the [eponymous directive of the HTTP app](https://caddyserver.com/docs/caddyfile/directives/vars).

The primary way to access variables is with placeholders, which have the form: `{l4.vars.variable_name}`, or with
the [vars](/docs/matchers/vars.md) and [vars_regexp](/docs/matchers/vars_regexp.md) matchers.

## Syntax

Under the hood, the handler is implemented as a map of string to any.
The key is the variable name, and the value is the value of the variable.

Both the names and values may use or contain [placeholders](https://caddyserver.com/docs/conventions#placeholders)
which are resolved at handle.

### Caddyfile

The handler supports the following syntax:
```caddyfile
vars [<variable> <value>] {
    <variable> <value>
    ...
}
```

An example config of the Layer 4 app that terminates TLS, sets the `backend` variable to `{l4.tls.server_name}`
and tests it against a regular expression to decide what TLS upstream and server name to choose:
```caddyfile
{
	layer4 {
		tcp/:4443 {
			route {
				tls
				vars {
					backend {l4.tls.server_name}
				}
				subroute {
					@local vars_regexp test backend ^(caddy|local)\.(?<domain>[-a-z0-9]+\.com)$
					route @local {
						proxy {
							upstream tcp/localhost:443 {
								tls_insecure_skip_verify
								tls_server_name local.{l4.regexp.test.domain}
							}
						}
					}

					route {
						proxy {
							upstream tcp/fallback.local:443 {
								tls_insecure_skip_verify
								tls_server_name {l4.vars.backend}
							}
						}
					}
				}
			}
		}
	}
}

*.domain-1.com *.domain-2.com {
	respond "OK" 200
}
```

### JSON

JSON equivalent to the caddyfile config provided above:
```json
{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":443"
					],
					"routes": [
						{
							"match": [
								{
									"host": [
										"*.domain-1.com",
										"*.domain-2.com"
									]
								}
							],
							"handle": [
								{
									"handler": "subroute",
									"routes": [
										{
											"handle": [
												{
													"body": "OK",
													"handler": "static_response",
													"status_code": 200
												}
											]
										}
									]
								}
							],
							"terminal": true
						}
					]
				}
			}
		},
		"layer4": {
			"servers": {
				"srv0": {
					"listen": [
						"tcp/:4443"
					],
					"routes": [
						{
							"handle": [
								{
									"handler": "tls"
								},
								{
									"backend": "{l4.tls.server_name}",
									"handler": "vars"
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
																"tcp/localhost:443"
															],
															"tls": {
																"insecure_skip_verify": true,
																"server_name": "local.{l4.regexp.test.domain}"
															}
														}
													]
												}
											],
											"match": [
												{
													"vars_regexp": {
														"backend": {
															"name": "test",
															"pattern": "^(caddy|local)\\.(?\u003cdomain\u003e[-a-z0-9]+\\.com)$"
														}
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
																"tcp/fallback.local:443"
															],
															"tls": {
																"insecure_skip_verify": true,
																"server_name": "{l4.vars.backend}"
															}
														}
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
