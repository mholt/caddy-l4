---
title: Proxy Handler
---

# Proxy Handler

## Summary

The Proxy handler implements a layer 4 proxy capable of multiple upstreams with load balancing and health checks.
This handler is at the core of the package functionality and supports both TCP and UDP.

## Syntax

The handler has the following optional fields:
- `health_checks` may contain a `l4proxy.HealthChecks` structure which includes `active` (`l4proxy.ActiveHealthChecks`)
  and `passive` (`l4proxy.PassiveHealthChecks`) fields (valid for JSON). In a Caddyfile, multiple options are used to
  fill these structures as described below.


- `load_balancing` may contain a `l4proxy.LoadBalancing` structure (valid for JSON). In a Caddyfile, multiple options
  are used to fill this structure as described below.


- `proxy_protocol` may specify the version of the Proxy Protocol header to add when connecting to any upstreams,
  either `v1` or `v2`.


- `upstreams` may contain a list of `l4proxy.Upstream` structures (valid for JSON). In a Caddyfile, multiple `upstream`
  options or blocks are unmarshalled into a list of such structures.

**Active health checks** occur independently in a background goroutine. They run in the background on a timer.
To minimally enable active health checks, set `active` field equal to an empty structure inside `health_checks` in
a JSON configuration or include any active health check option into a Caddyfile.

Active health check options include `health_interval`, `health_port` and `health_timeout` which correspond to
`interval`, `port` and `timeout` fields of the `l4proxy.ActiveHealthChecks` structure:

- `health_interval` defines how frequently to perform active health checks (by default, it equals `30s`);

- `health_port` is the port to use (if different from the upstream's dial address) for active health checks;

- `health_timeout` sets how long to wait for a connection to be established with a peer (one of the dial addresses)
  before considering it unhealthy (by default, it equals `5s`).

**Passive health checks** monitor proxied connections for errors or timeouts. To minimally enable passive health checks,
set `passive` field equal to an empty structure inside `health_checks` in a JSON configuration or include any passive
health check option into a Caddyfile.

Passive health check options include `fail_duration`, `max_fails` and `unhealthy_connection_count` which correspond to
the similarly named fields of the `l4proxy.PassiveHealthChecks` structure:

- `fail_duration` defines how long to remember a failed connection to this upstream. Any duration greater than zero
  enables passive health checking (by default, it equals `0`);

- `max_fails` is the number of failed connections within the `fail_duration` window to consider this upstream as "down".
  It must be greater or equal to `1`; by default, it is `1`. It requires that `fail_duration` be greater than 0;

- `unhealthy_connection_count` limits the number of simultaneous connections to this upstream by marking it as "down"
  if it has this many or more concurrent connections.

**Load balancing** distributes connections between upstreams. To minimally enable load balancing, set `load_balancing`
field equal to an empty structure in a JSON configuration or include any load balancing option into a Caddyfile. Note:
load balancing makes sense only if the handler has two or more upstreams.

Load balacing options include `lb_policy`, `lb_try_duration` and `lb_try_interval` which correspond to `selection`,
`try_duration` and `try_interval` fields of the `l4proxy.LoadBalancing` structure:
- `lb_policy` is a selection policy which is how to choose an available upstream. By default, it is `random`.
  The following alternatives are supported by the handler:
  - `first` is a policy that selects the first available upstream;
  - `ip_hash` is a policy that selects an upstream based on hashing the remote IP of the connection;
  - `least_conn` is a policy that selects the upstream with the least active connections. If multiple upstreams have
    the same fewest number, one is chosen randomly;
  - `random_choose` is a policy that selects two or more available hosts at random, then chooses the one with
    the least load (Caddyfile syntax is `random_choose [<int>]` with the argument setting the count of available
    hosts to be chosen at random before considering their load);
  - `round_robin` is a policy that selects an upstream based on round-robin ordering.

- `lb_try_duration` defines how long to try selecting available upstreams for each connection if the next available
  host is down. By default, this retry is disabled. Clients will wait for up to this long while the load balancer
  tries to find an available upstream host.

- `lb_try_interval` specifies how long to wait between selecting the next host from the pool. By default, it is `250ms`.
  Only relevant when a connection to an upstream host fails. Note: setting this to 0 with a non-zero `lb_try_duration`
  can cause the CPU to spin if all upstreams are down and latency is very low.

Each `upstream` has the following fields:
- `dial` contains a list of network addresses to dial. Each address must be exactly 1 socket, e.g. `10.1.2.3:80`.
  No port ranges are currently supported by the handler. At least one dial address must be provided per upstream.
  Multiple addresses are dialled one by one until a connection is successfully established.  


- `max_connections` may contain an integer value representing how many connections this upstream is allowed to have
  before being marked as unhealthy (if more than 0).


- `tls` may contain a `reverseproxy.TLSConfig` structure to enable TLS when connecting to this upstream. Refer to the
  [relevant Caddy documentation](https://caddyserver.com/docs/json/apps/http/servers/routes/handle/reverse_proxy/transport/http/tls/)
  for details. In a Caddyfile, this structure is unmarshalled with a set of the following options:
  - bare `tls` option may be used to enable TLS when no other `tls_*` options are defined for this upstream.
    It corresponds to an empty `reverseproxy.TLSConfig` structure, and the default TLS configuration applies;
  - other `tls_*` options are matched to `reverseproxy.TLSConfig` structure fields according to the table below:
    
    | Caddyfile option in a proxy upstream block | JSON field of a `reverseproxy.TLSConfig` structure          |
    |--------------------------------------------|-------------------------------------------------------------|
    | `tls_client_auth` with a single argument   | `client_certificate_automate`                               |
    | `tls_client_auth` with two arguments       | `client_certificate_file` and `client_certificate_key_file` |
    | `tls_curves`                               | `curves`                                                    |
    | `tls_except_ports`                         | `except_ports`                                              |
    | `tls_insecure_skip_verify`                 | `insecure_skip_verify`                                      |
    | `tls_renegotiation`                        | `renegotiation`                                             |
    | `tls_server_name`                          | `server_name`                                               |
    | `tls_timeout`                              | `handshake_timeout`                                         |
    | `tls_trust_pool`                           | `ca`                                                        |


Only two fields support [placeholders](https://caddyserver.com/docs/conventions#placeholders). 
- `dial` (same as arguments after `upstream` and `proxy`) resolves placeholders two times: known once are replaced
  at provision, others are replaced at handle. E.g. `{l4.tls.server_name}:443` enables dynamic TLS SNI based upstreams.
- `proxy_protocol` resolves placeholders at provision.

### Caddyfile

The handler supports the following syntax:
```caddyfile
proxy [<upstreams...>] {
    # active health check options
    health_interval <duration>
    health_port <int>
    health_timeout <duration>
    
    # passive health check options
    fail_duration <duration>
    max_fails <int>
    unhealthy_connection_count <int>
    
    # load balancing options
    lb_policy <name> [<args...>]
    lb_try_duration <duration>
    lb_try_interval <duration>
    
    proxy_protocol <v1|v2>
    
    # multiple upstream options are supported
    upstream [<address:port>] {
        dial <address:port> [<address:port>]
        max_connections <int>
        
        tls
        tls_client_auth <automate_name> | <cert_file> <key_file>
        tls_curves <curves...>
        tls_except_ports <ports...>
        tls_insecure_skip_verify
        tls_renegotiation <never|once|freely>
        tls_server_name <name>
        tls_timeout <duration>
        tls_trust_pool <module>
    }
    upstream <address:port>
}
```

The handler provides a number of **shortcuts** to simplify Caddyfile configuration:
```caddyfile
# handlers 1, 2 and 3 do the same:
# 1 - the short syntax for 1 upstream
proxy 192.168.0.1:8080
# 2 - the mid-length syntax for 1 upstream
proxy {
    upstream 192.168.0.1:8080
}
# 3 - the long syntax for 1 upstream
proxy {
    upstream {
        dial 192.168.0.1:8080
    }
}

# handlers 4, 5 and 6 do the same:
# 4 - the short syntax for 2 upstreams
proxy 192.168.0.1:8080 192.168.0.2:8080
# 5 - the mid-length syntax for 2 upstreams
proxy {
    upstream 192.168.0.1:8080
    upstream 192.168.0.2:8080
}
# 6 - the long syntax for 2 upstreams
proxy {
    upstream {
        dial 192.168.0.1:8080
    }
    upstream {
        dial 192.168.0.2:8080
    }
}

# yet there is no short syntax for handler 7:
# 7 - 3 upstreams with 2 dial addresses per upstream
proxy {
    upstream {
        dial 192.168.0.1:8080 192.168.0.1:8081
    }
    upstream {
        dial 192.168.0.2:8080
        dial 192.168.0.2:8081
    }
    upstream 192.168.0.3:8080 192.168.0.3:8081
}

# it is possible to combine short, mid-length and long syntax
# as shown above for handler 7 and below for handler 8
# 8 - 3 upstreams mixing various syntax options
proxy 192.168.0.1:8080 {
    upstream 192.168.0.2:8080
    upstream {
        dial 192.168.0.3:8080
    }
}
```

An example config of the Layer 4 app that runs two proxies running on TCP4 ports 8765 and 9876 with some options
filled at random:
```caddyfile
{
    layer4 {
        0.0.0.0:8765 {
            route {
                proxy {
                    health_interval 1s
                    health_port 8080
                    health_timeout 2s
                    fail_duration 5s
                    max_fails 10
                    unhealthy_connection_count 5
                    lb_policy round_robin
                    lb_try_duration 5s
                    lb_try_interval 15s
                    proxy_protocol v2
                    upstream 10.0.0.1:8080
                    upstream 10.0.0.2:8080 10.0.0.2:8888
                }
            }
        }
        0.0.0.0:9876 {
            route {
                proxy {
                    lb_policy random_choose 2
                    upstream {
                        dial 10.0.0.3:443 10.0.0.33:443
                        max_connections 2
                        tls
                    }
                    upstream {
                        dial 10.0.0.4:443 10.0.0.44:443
                        max_connections 4
                        tls_insecure_skip_verify
                        tls_renegotiation once
                    }
                }
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
                        "0.0.0.0:8765"
                    ],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "health_checks": {
                                        "active": {
                                            "interval": 1000000000,
                                            "port": 8080,
                                            "timeout": 2000000000
                                        },
                                        "passive": {
                                            "fail_duration": 5000000000,
                                            "max_fails": 10,
                                            "unhealthy_connection_count": 5
                                        }
                                    },
                                    "load_balancing": {
                                        "selection": {
                                            "policy": "round_robin"
                                        },
                                        "try_duration": 5000000000,
                                        "try_interval": 15000000000
                                    },
                                    "proxy_protocol": "v2",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "10.0.0.1:8080"
                                            ]
                                        },
                                        {
                                            "dial": [
                                                "10.0.0.2:8080",
                                                "10.0.0.2:8888"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                },
                "srv1": {
                    "listen": [
                        "0.0.0.0:9876"
                    ],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "load_balancing": {
                                        "selection": {
                                            "choose": 2,
                                            "policy": "random_choose"
                                        }
                                    },
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "10.0.0.3:443",
                                                "10.0.0.33:443"
                                            ],
                                            "max_connections": 2,
                                            "tls": {}
                                        },
                                        {
                                            "dial": [
                                                "10.0.0.4:443",
                                                "10.0.0.44:443"
                                            ],
                                            "max_connections": 4,
                                            "tls": {
                                                "insecure_skip_verify": true,
                                                "renegotiation": "once"
                                            }
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
