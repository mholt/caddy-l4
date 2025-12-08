---
title: SOCKS Proxy Example
---

# SOCKS Proxy Example

## Summary

The SOCKS Proxy example shows a proxy forwarding SOCKSv4 to a remote server and handling SOCKSv5 directly in Caddy.
Note: it only allows connections from a specific network and requires a username and a password for SOCKSv5.

## Configuration

### Caddyfile

```caddyfile
{
    layer4 {
        0.0.0.0:1080 {
            @s5 {
                socks5
                remote_ip 10.0.0.0/24
            }
            route @s5 {
                socks5 {
                    credentials alice 8I2T75nZ3x bob qHoEtVpGRM
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

### JSON

```json
{
    "apps":{
        "layer4":{
            "servers":{
                "srv0":{
                    "listen":[
                        "0.0.0.0:1080"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "remote_ip":{
                                        "ranges":[
                                            "10.0.0.0/24"
                                        ]
                                    },
                                    "socks5":{
                                        
                                    }
                                }
                            ],
                            "handle":[
                                {
                                    "credentials":{
                                        "alice":"8I2T75nZ3x",
                                        "bob":"qHoEtVpGRM"
                                    },
                                    "handler":"socks5"
                                }
                            ]
                        },
                        {
                            "match":[
                                {
                                    "socks4":{
                                        
                                    }
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"proxy",
                                    "upstreams":[
                                        {
                                            "dial":[
                                                "10.64.0.1:1080"
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
