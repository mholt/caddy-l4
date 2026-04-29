---
title: Remote IP List Matcher
---

# Remote IP List Matcher

## Summary

The Remote IP List matcher allows to match connections based on *remote* IP (or CIDR range).

## Syntax

The matcher has `remote_ip_file` field that points to a file which contains one or many IP or CIDR expressions.
The file is continuously monitored in the background so that the matcher uses an up-to-date list of IPs and CIDRs.

No [placeholders](https://caddyserver.com/docs/conventions#placeholders) are supported.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
remote_ip_list <remote_ip_file>
```

An example config of the Layer 4 app that proxies connections on TCP port 12345 to another machine
if they are initiated from IPs or CIDRs listed in `/tmp/remote-ips`:
```caddyfile
{
    layer4 {
        :12345 {
            @f1 remote_ip_list /tmp/remote-ips
            route @f1 {
                proxy f1.machine.local:54321
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
                        ":12345"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                  "remote_ip_list": {
                                        "remote_ip_file": "/tmp/remote-ips"
                                  }
                                }
                            ],
                            "handle": [
                                {
                                  "handler": "proxy",
                                  "upstreams": [
                                        {
                                          "dial": [
                                                "f1.machine.local:54321"
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
