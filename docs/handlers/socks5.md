---
title: SOCKS5 Handler
---

# SOCKS5 Handler

## Summary

The SOCKS5 handler implements a [SOCKSv5](https://www.rfc-editor.org/rfc/rfc1928) server.
It uses [things-go/go-socks5](github.com/things-go/go-socks5) under the hood.

## Syntax

The handler has the following optional fields:
- `bind_ip` may contain the IP address used for binding in the context of `BIND` or `UDP ASSOCIATE` commands;
- `commands` may contain one or many SOCKSv5 methods to be allowed. E.g. `CONNECT`, `ASSOCIATE`, `BIND`.
  The field is case-insensitive. By default, the list contains `CONNECT` and `ASSOCIATE`;
- `credentials` may contain a map of usernames and passwords for `Username/Password` (0x02) authentication.
  By default, no authentication (0x00) is used. Only plain text passwords are currently supported.

All the handler fields support [placeholders](https://caddyserver.com/docs/conventions#placeholders) which are resolved at provision.

### Caddyfile

The handler supports the following syntax:
```caddyfile
socks5 {
    bind_ip <address>
    commands <values...>
    credentials <username> <password> [<username> <password>]
}
```

An example config of the Layer 4 app that runs a SOCKSv5 server on TCP port 1080 and echoes
if it receives non-SOCKSv5 traffic:
```caddyfile
{
    layer4 {
        :1080 {
            @s5 socks5
            route @s5 {
                socks5 {
                    # only CONNECT and ASSOCIATE commands are allowed
                    # (`commands` option may either appear multiple times
                    # or have multiple arguments - the meaning is the same)
                    commands CONNECT
                    commands ASSOCIATE
                    
                    # multiple usernames and passwords may be set
                    # with one or many `credentials` options
                    credentials account1 password1 account2 password2
                    credentials account3 password3
                }
            }
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
                        ":1080"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "socks5": {}
                                }
                            ],
                            "handle": [
                                {
                                    "commands": [
                                        "CONNECT",
                                        "ASSOCIATE"
                                    ],
                                    "credentials": {
                                        "account1": "password1",
                                        "account2": "password2",
                                        "account3": "password3"
                                    },
                                    "handler": "socks5"
                                }
                            ]
                        },
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
