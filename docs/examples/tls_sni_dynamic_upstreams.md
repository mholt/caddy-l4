---
title: TLS SNI Dynamic Upstreams Example
---

# TLS SNI Dynamic Upstreams Example

## Summary

This example shows how to enable dynamic upstreams based on TLS SNI.

## Configuration

### Caddyfile

```caddyfile
{
    layer4 {
        # TCP-only, so HTTP/3 is out of scope
        :443 {
            # the upstream hostname includes a part of TLS SNI
            @tls-regexp tls sni_regexp ^(one|two)\\.example\\.com$
            route @tls-regexp {
                proxy {tls.regexp.1}.machine.local:443
            }
            
            # full TLS SNI as the upstream hostname
            @tls-any tls
            route @tls-any {
                proxy {l4.tls.server_name}:443
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
                        ":443"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "tls":{
                                        "sni_regexp":{
                                            "pattern":"^(one|two)\\\\.example\\\\.com$"
                                        }
                                    }
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"proxy",
                                    "upstreams":[
                                        {
                                            "dial":[
                                                "{tls.regexp.1}.machine.local:443"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match":[
                                {
                                    "tls":{
                                        
                                    }
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"proxy",
                                    "upstreams":[
                                        {
                                            "dial":[
                                                "{l4.tls.server_name}:443"
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
