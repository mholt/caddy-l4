---
title: OpenVPN Matcher
---

# OpenVPN Matcher

## Summary

The OpenVPN matcher allows to match connections that look
like [OpenVPN](https://openvpn.net/community-resources/openvpn-protocol/).
It does independent raw packet parsing under the hood.

This matcher is capable of:
- matching any of the existing control channel security modes (`plain`, `auth`, `crypt` and `crypt2`);
- matching based on a digest algorithm (`auth` mode);
- matching based on a group key (`auth` and `crypt` modes);
- matching based on a server key (`crypt2` mode);
- matching based on client keys (`crypt2` mode);
- matching both TCP and UDP connections [^1].

These features allow Caddy to multiplex a plethora of diversely configured OpenVPN server instances on a single port.
It is a unique OpenVPN routing solution that goes beyond what is offered by SSLH, Haproxy, Nginx, Traefik and OpenVPN
internal port-sharing.

[^1]: OpenVPN has to renegotiate connections on Caddy restart. For UDP, after the client receives the last packet
from the server, up to 120 seconds (default renegotiation interval) may pass before a previously established connection
goes live again. TCP connections are usually renegotiated much faster.

## Syntax

The matcher has the following universal fields:
- `modes` field contains a list of supported OpenVPN modes to match against incoming client reset messages:

  - `plain` mode messages have no replay protection, authentication or encryption;

  - `auth` mode messages have no encryption, but provide for replay protection and authentication
    with a pre-shared 2048-bit group key, a variable key direction, and plenty digest algorithms;

  - `crypt` mode messages feature replay protection, authentication and encryption with
    a pre-shared 2048-bit group key, a fixed key direction, and SHA-256 + AES-256-CTR algorithms;

  - `crypt2` mode messages are essentially `crypt` messages with an individual 2048-bit client key
    used for authentication and encryption attached to client reset messages in a protected form
    (a 1024-bit server key is used for its authentication end encryption).

  <br>Notes: Each mode shall only be present once in the list. Values in the list are case-insensitive.
  If the list is empty, the matcher considers all modes as accepted and tries them one by one.

The following fields are relevant to `auth`, `crypt` and `crypt2` modes:
- `ignore_crypto` makes the matcher skip decryption and authentication if set to true.

  <br>Notes: `ignore_crypto` impacts `auth`, `crypt` and `crypt2` modes at once and makes sense only if/when
  the relevant static keys are provided. If neither `group_key` nor `group_key_file` is set, decryption
  (if applicable) and authentication are automatically skipped in `auth` and `crypt` modes only. If
  neither `server_key` nor `server_key_file` is provided, decryption and authentication are automatically
  skipped in `crypt2` mode (unless there is a client key). If neither `client_keys` nor `client_key_files`
  are provided, decryption and authentication are automatically skipped in `crypt2` mode (unless
  there is a server key). In `crypt2` mode, when there is a client key and there is no server key,
  decryption of a wrapped key is impossible, and this part of the incoming message is authenticated by
  comparing it with what has been included in the matching client key.


- `ignore_timestamp` makes the matcher skip replay timestamps validation if set to true.

  <br>Note: A 30-seconds time window is applicable by default, i.e. a timestamp of up to 15 seconds behind
  or ahead of now is accepted.

The following fields are relevant to `auth` and `crypt` modes:
- `group_key` contains a hex string representing a pre-shared 2048-bit group key. This key may be
  present in OpenVPN config files inside `<tls-auth/>` or `<tls-crypt/>` blocks or generated with
  `openvpn --genkey tls-auth|tls-crypt` command. No comments (starting with '#' or '-') are allowed.

- `group_key_file` is a path to a file containing a pre-shared 2048-bit group key which may be present
  in OpenVPN config files after `tls-auth` or `tls-crypt` directives. It is the same key as the one
  `group_key` introduces, so these fields are mutually exclusive. If both are set, `group_key` always takes
  precedence. Any comments in the file (starting with '#' or '-') are ignored.

The following fields are relevant to `auth` mode only:
- `auth_digest` is a name of the digest algorithm used for authentication (HMAC generation and validation) of
  `auth` mode messages. If no value is provided, the matcher tries all the algorithms it supports.

  <br>Notes: OpenVPN binaries may support a larger number of digest algorithms thanks to the OpenSSL library
  used under the hood. A few legacy and exotic digest algorithms are known to be missing, so `ignore_crypto`
  may be set to true to ensure successful message matching if a desired digest algorithm isn't listed below.

  <br>List of the supported digest algorithms:
  - MD5
  - SHA-1
  - SHA-224
  - SHA-256
  - SHA-384
  - SHA-512
  - SHA-512/224
  - SHA-512/256
  - SHA3-224
  - SHA3-256
  - SHA3-384
  - SHA3-512
  - BLAKE2s-256
  - BLAKE2b-512
  - SHAKE-128
  - SHAKE-256

  <br>Note: Digest algorithm names are recognised in a number of popular notations, including lowercase.
  Please, refer to the matcher source code for details.


- `group_key_direction` is a group key direction and may contain one of the following three values:

  - `normal` means the server config has `tls-auth [...] 0` or `key-direction 0`,
    while the client configs have `tls-auth [...] 1` or `key-direction 1`;

  - `inverse` means the server config has `tls-auth [...] 1` or `key-direction 1`,
    while the client config have `tls-auth [...] 0` or `key-direction 0`;

  - `bidi` or `bidirectional` means key direction is omitted (e.g. `tls-auth [...]`)
    in both the server config and client configs.

  <br>Notes: Values are case-insensitive. If no value is specified, the normal key direction is implied.
  The inverse key direction is a violation of the OpenVPN official recommendations, and the bidi one
  provides for a lower level of DoS and message replay attacks resilience.

The following fields are relevant to `crypt2` mode only:
- `client_keys` contains a list of base64 strings representing 2048-bit client keys (each one in a decrypted
  form followed by an encrypted and authenticated form also known as WKc in the OpenVPN docs). These keys
  may be present in OpenVPN client config files inside `<tls-crypt-v2/>` block or generated with `openvpn
  --tls-crypt-v2 [server.key] --genkey tls-crypt-v2-client` command. No comments (starting with '#' or '-')
  are allowed.

- `client_key_files` is a list of paths to files containing 2048-bit client key which may be present in OpenVPN
  config files after `tls-crypt-v2` directive. These are the same keys as those `client_keys` introduce, but
  these fields are complementary. If both are set, a joint list of client keys is created. Any comments in
  the files (starting with '#' or '-') are ignored.


- `server_key` contains a base64 string representing a 1024-bit server key used only for authentication and
  encryption of client keys. This key may be present in OpenVPN server config files inside `<tls-crypt-v2/>`
  block or generated with `openvpn --genkey tls-crypt-v2-server` command. No comments (starting with '#'
  or '-') are allowed.

- `server_key_file` is a path to a file containing a 1024-bit server key which may be present in OpenVPN
  config files after `tls-crypt-v2` directive. It is the same key as the one `server_key` introduces, so
  these fields are mutually exclusive. If both are set, `server_key` always takes precedence. Any comments
  in the file (starting with '#' or '-') are ignored.

All the matcher options except `ignore_crypto` and `ignore_timestamp`
support [placeholders](https://caddyserver.com/docs/conventions#placeholders) which are resolved at provision.

### Caddyfile

The matcher supports the following syntax:
```caddyfile
# bare `openvpn` matches any OpenVPN traffic
openvpn

# otherwise specify matcher options
openvpn {
    modes <plain|auth|crypt|crypt2> [<...>]

    ignore_crypto
    ignore_timestamp

    # `group_key` and `group_key_file` are mutually exclusive options
    group_key <hex>
    group_key_file <path>

    auth_digest <digest>
    group_key_direction <normal|inverse|bidi|bidirectional>

    # `server_key` and `server_key_file` are mutually exclusive options
    server_key <base64>
    server_key_file <path>

    # multiple `client_key` and `client_key_file` options are allowed
    client_key <base64>
    client_key_file <path>
}
```

An example config of the Layer 4 app that multiplexes TLS and OpenVPN traffic on TCP port 8843:
```caddyfile
{
    layer4 {
        :8843 {
            # proxy to localhost:1194
            # any `plain` mode OpenVPN traffic on TCP port 8843
            @plain openvpn {
                modes plain
            }
            route @plain {
                proxy localhost:1194
            }
            
            # proxy to localhost:1195
            # any `auth` mode OpenVPN traffic on TCP port 8843
            # with SHA-256 auth digest, `normal` group key direction
            # and the group key accessible at `/etc/openvpn/ta.key`
            @auth openvpn {
                modes auth
                auth_digest sha256
                group_key_direction normal
                group_key_file /etc/openvpn/ta.key
            }
            route @auth {
                proxy localhost:1195
            }
            
            # proxy to localhost:1196
            # any `crypt` mode OpenVPN traffic on TCP port 8843
            # with the provided group key
            @crypt openvpn {
                modes crypt
                group_key 21d94830510107f8753d3b6f3145e01ded37075115afcb0538ecdd8503ee96637218c9ed38d908d594231d7d143c73da5055310f89d336da99c8b3dcb18909c79dd44f540670ebc0f120beb7211e96839cb542572c48bfa7ffaa9a22cb8304b7869b92f4442918e598745bb78ac8877f02b00a7cdef3f2446c130d39a7c451269ef399fd6029cdfc80a7c604041312ab0a969bc906bdee6e6d707afdcbe8c7fb97beb66049c3d328340775025433ceba1e38008a826cf92443d903106199373bdadd9c2c735cf481e580db4e81b99f12e3f46b6159c687cd1b9e689f7712573c0f02735a45573dfb5cd55cf4649423892c7e91f439bdd7337a8ceebd302cfbfa
            }
            route @crypt {
                proxy localhost:1196
            }
            
            # proxy to localhost:1197
            # any `crypt2` mode OpenVPN traffic on TCP port 8843
            # with the server key accessible at `/etc/openvpn/v2-server.key`
            @crypt2 openvpn {
                modes crypt2
                server_key_file /etc/openvpn/v2-server.key
            }
            route @crypt2 {
                proxy localhost:1197
            }
            
            # otherwise terminate TLS on TCP port 8843
            # and proxy decrypted bytes to localhost:8080
            route {
                tls
                proxy localhost:8080
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
                        ":8843"
                    ],
                    "routes": [
                        {
                            "match": [
                                {
                                    "openvpn": {
                                        "modes": [
                                            "plain"
                                        ]
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "localhost:1194"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "openvpn": {
                                        "modes": [
                                            "auth"
                                        ],
                                        "group_key_file": "/etc/openvpn/ta.key",
                                        "auth_digest": "sha256",
                                        "group_key_direction": "normal"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "localhost:1195"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "openvpn": {
                                        "modes": [
                                            "crypt"
                                        ],
                                        "group_key": "21d94830510107f8753d3b6f3145e01ded37075115afcb0538ecdd8503ee96637218c9ed38d908d594231d7d143c73da5055310f89d336da99c8b3dcb18909c79dd44f540670ebc0f120beb7211e96839cb542572c48bfa7ffaa9a22cb8304b7869b92f4442918e598745bb78ac8877f02b00a7cdef3f2446c130d39a7c451269ef399fd6029cdfc80a7c604041312ab0a969bc906bdee6e6d707afdcbe8c7fb97beb66049c3d328340775025433ceba1e38008a826cf92443d903106199373bdadd9c2c735cf481e580db4e81b99f12e3f46b6159c687cd1b9e689f7712573c0f02735a45573dfb5cd55cf4649423892c7e91f439bdd7337a8ceebd302cfbfa"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "localhost:1196"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "match": [
                                {
                                    "openvpn": {
                                        "modes": [
                                            "crypt2"
                                        ],
                                        "server_key_file": "/etc/openvpn/v2-server.key"
                                    }
                                }
                            ],
                            "handle": [
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "localhost:1197"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "handle": [
                                {
                                    "handler": "tls"
                                },
                                {
                                    "handler": "proxy",
                                    "upstreams": [
                                        {
                                            "dial": [
                                                "localhost:8080"
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
