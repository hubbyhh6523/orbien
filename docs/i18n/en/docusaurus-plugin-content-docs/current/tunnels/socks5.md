---
sidebar_position: 5
sidebar_label: SOCKS5
title: SOCKS5
---

# SOCKS5

Expose a public port on the server as a SOCKS5 proxy entry; the client performs the handshake and dialing on the
internal network.

Based on `protocol = "tcp"`, enabled via `[tunnels.plugin]`; both `username` and `password` are required.

## Example

Server:

```toml
# orbien-server.toml
listen = "0.0.0.0:9527"
```

Client:

```toml
# orbien.toml
server = "YOUR_SERVER_IP:9527"

[[tunnels]]
name = "socks5"
protocol = "tcp"
remotePort = 9000

[tunnels.plugin]
type = "socks5"
username = "admin"
password = "123456"
```

Access through the proxy from the public network:

```shell
curl --socks5 YOUR_SERVER_IP:9000 -U admin:123456 http://example.com
```

## Parameters

| Parameter                        | Required | Default  | Description                                     |
|----------------------------------|----------|----------|-------------------------------------------------|
| `name`                           | Yes      |          | Tunnel name; must be unique                     |
| `protocol`                       | Yes      |          | Always `tcp`                                    |
| `remotePort`                     | Yes      |          | Public listen port on the server (SOCKS5 entry) |
| `plugin.type`                    | Yes      |          | Always `socks5`                                 |
| `plugin.username`                | Yes      |          | SOCKS5 username                                 |
| `plugin.password`                | Yes      |          | SOCKS5 password, at least 16 characters (shorter warns at startup; refused in a future release) |
| `plugin.allowPrivateTargets`     | No       | `false`  | Allow loopback / link-local / private-range targets; the client's own server address is always refused (unless listed in `allowedTargets`) |
| `plugin.allowedTargets`          | No       | `[]`     | Destination allow list: CIDRs or single IPs; the resolved address wins over every refusal rule |
| `plugin.authMaxFailures`         | No       | `5`      | Failed logins from one source before lockout; `0` disables lockout |
| `plugin.authLockoutSecs`         | No       | `600`    | Lockout duration in seconds                     |
| `plugin.idleTimeoutSecs`         | No       | `300`    | Idle timeout for a relayed connection, in seconds; `0` disables it |
| `maxConnections`                 | No       | `0`      | Max simultaneous connections for the tunnel; `0` means 64 for SOCKS5 |
| `transport.bandwidth`            | No       | `0`      | Bandwidth cap (Mbps); `0` means unlimited       |
| `transport.bandwidthLimitSide`   | No       | `client` | Limit side: `client` / `server`                 |
| `transport.proxyProtocolVersion` | No       |          | PROXY Protocol: `v1` / `v2`                     |

## Security notes

- **Only public destinations are allowed by default**: non-public addresses (loopback, link-local, private-range, unspecified, multicast, broadcast, documentation, benchmarking, reserved and CGNAT ranges), as well as the client's own server address, are refused. Host names are checked again after the client resolves them. To reach an internal network, list the ranges in `plugin.allowedTargets` (e.g. `10.0.0.0/8`) or set `plugin.allowPrivateTargets` to `true` (the latter still refuses the server address). **Behavior change**: setups that used the proxy to reach internal networks will be refused after upgrading; add an allow-list entry or opt in.
- **Failed logins lock out the source address**: after `plugin.authMaxFailures` consecutive failures from one source (the visitor address passed by the server), further connections from it are dropped for `plugin.authLockoutSecs` seconds; a successful login clears the count; failure logs are throttled to one line per minute.
- **Credentials travel in clear text**: SOCKS5 username/password authentication is unencrypted, and the visitor-to-server path is plain TCP, so anyone on the path can see the credentials and the proxied traffic. Use a long random password (`openssl rand -base64 24`) and do not expose the entry port to untrusted networks. TLS-wrapped SOCKS5 is not a standard protocol and mainstream clients do not speak it, so this project does not offer it.
- **Concurrency and idle**: each SOCKS5 tunnel relays at most `maxConnections` (64 by default) simultaneous connections; extra connections are refused immediately. A relayed connection is closed after `plugin.idleTimeoutSecs` seconds without traffic.
