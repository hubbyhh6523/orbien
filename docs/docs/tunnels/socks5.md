---
sidebar_position: 5
sidebar_label: SOCKS5
title: SOCKS5
---

# SOCKS5

将服务端公网端口作为 SOCKS5 代理入口，由客户端在内网完成握手与拨号。

基于 `protocol = "tcp"`，通过 `[tunnels.plugin]` 启用；须同时配置 `username` 与 `password`。

## 示例

服务端：

```toml
# orbien-server.toml
listen = "0.0.0.0:9527"
```

客户端：

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

公网通过代理访问：

```shell
curl --socks5 YOUR_SERVER_IP:9000 -U admin:123456 http://example.com
```

## 参数

| 参数                               | 必填 | 默认值      | 说明                         |
|----------------------------------|----|----------|----------------------------|
| `name`                           | 是  |          | 隧道名称，唯一                    |
| `protocol`                       | 是  |          | 固定为 `tcp`                  |
| `remotePort`                     | 是  |          | 服务端对外监听端口（SOCKS5 入口）       |
| `plugin.type`                    | 是  |          | 固定为 `socks5`               |
| `plugin.username`                | 是  |          | SOCKS5 用户名                 |
| `plugin.password`                | 是  |          | SOCKS5 密码，至少 16 个字符（不足会在启动时警告，未来版本将拒绝） |
| `plugin.allowPrivateTargets`     | 否  | `false`  | 允许访问 loopback / link-local / 私有地址段目标；客户端自身的服务端地址始终拒绝（除非写进 `allowedTargets`） |
| `plugin.allowedTargets`          | 否  | `[]`     | 目标地址白名单：CIDR 或单个 IP，域名解析后的地址命中即放行，优先于所有拒绝规则 |
| `plugin.authMaxFailures`         | 否  | `5`      | 同一来源连续登录失败多少次后锁定；`0` 表示不锁定 |
| `plugin.authLockoutSecs`         | 否  | `600`    | 锁定持续秒数 |
| `plugin.idleTimeoutSecs`         | 否  | `300`    | 转发连接空闲超时秒数；`0` 表示不限制 |
| `maxConnections`                 | 否  | `0`      | 隧道最大并发连接数；SOCKS5 插件上 `0` 表示默认 64 |
| `transport.bandwidth`            | 否  | `0`      | 带宽上限（Mbps）；`0` 表示不限制       |
| `transport.bandwidthLimitSide`   | 否  | `client` | 限速端：`client` / `server`    |
| `transport.proxyProtocolVersion` | 否  |          | PROXY Protocol：`v1` / `v2` |

## 安全说明

- **目标地址默认只放行公网地址**：非公网地址（loopback、link-local、私有地址段、未指定地址、组播、广播、文档、基准测试、保留、CGNAT 地址段），以及客户端自身的服务端地址，默认一律拒绝；域名会在客户端解析后按解析出的 IP 再检查一次。需要访问内网时，把地址段写进 `plugin.allowedTargets`（例如 `10.0.0.0/8`），或把 `plugin.allowPrivateTargets` 设为 `true`（后者不放行服务端自身地址）。**行为变更**：之前用该代理访问内网的配置，升级后会被拒绝，请按需加白名单或开 opt-in。
- **登录失败会锁定来源地址**：同一来源（服务端传来的访客地址）连续失败 `plugin.authMaxFailures` 次后，该地址的后续连接会被直接丢弃 `plugin.authLockoutSecs` 秒；登录成功会清零计数；失败日志每分钟最多一条。
- **凭据是明文传输的**：SOCKS5 用户名/密码认证本身不加密，访客到服务端端口之间是明文 TCP，路径上的人能看到凭据和代理流量；请使用长随机密码（`openssl rand -base64 24`），不要把入口暴露给不可信网络。TLS 包装 SOCKS5 不是标准协议，主流客户端不支持，本项目不提供。
- **并发与空闲**：每条 SOCKS5 隧道最多同时转发 `maxConnections`（未设置时 64）个连接，满了直接拒绝新连接；转发连接空闲 `plugin.idleTimeoutSecs` 秒后断开。
